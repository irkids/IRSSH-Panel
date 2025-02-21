const { Pool } = require('pg');
const logger = require('../utils/logger');
const config = require('../config');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);

const pool = new Pool(config.database);

class MetricsController {
  async getSystemMetrics(req, res) {
    const client = await pool.connect();
    try {
      // Get CPU usage
      const { stdout: cpuInfo } = await exec('top -bn1 | grep "Cpu(s)"');
      const cpuUsage = 100 - parseFloat(cpuInfo.match(/(\d+\.\d+)\s+id/)[1]);

      // Get memory usage
      const { stdout: memInfo } = await exec('free -m');
      const memLines = memInfo.split('\n');
      const memValues = memLines[1].split(/\s+/);
      const totalMem = parseInt(memValues[1]);
      const usedMem = parseInt(memValues[2]);
      const memoryUsage = (usedMem / totalMem) * 100;

      // Get disk usage
      const { stdout: diskInfo } = await exec('df -h /');
      const diskLines = diskInfo.split('\n');
      const diskValues = diskLines[1].split(/\s+/);
      const diskUsage = parseInt(diskValues[4].replace('%', ''));

      // Get database metrics
      const dbMetrics = await client.query(`
        SELECT json_build_object(
          'connections', (SELECT count(*) FROM pg_stat_activity),
          'size', pg_database_size(current_database()),
          'cache_hit_ratio', (
            SELECT round(100 * sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)), 2)
            FROM pg_statio_user_tables
          )
        ) as db_metrics
      `);

      // Get application metrics
      const appMetrics = await client.query(`
        SELECT json_build_object(
          'active_users', (SELECT COUNT(*) FROM sessions WHERE active = true),
          'protocols', (SELECT COUNT(*) FROM protocols WHERE enabled = true),
          'connections', (SELECT COUNT(*) FROM connections WHERE active = true),
          'error_rate', (
            SELECT ROUND(COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM logs), 0), 2)
            FROM logs
            WHERE level = 'error' AND created_at > NOW() - interval '1 hour'
          )
        ) as app_metrics
      `);

      const metrics = {
        system: {
          cpu: {
            usage: cpuUsage.toFixed(2),
            timestamp: new Date()
          },
          memory: {
            total: totalMem,
            used: usedMem,
            usage: memoryUsage.toFixed(2)
          },
          disk: {
            usage: diskUsage,
            path: '/'
          }
        },
        database: dbMetrics.rows[0].db_metrics,
        application: appMetrics.rows[0].app_metrics
      };

      await logger.info('System metrics collected', {
        timestamp: new Date(),
        metrics: {
          cpu: metrics.system.cpu.usage,
          memory: metrics.system.memory.usage,
          disk: metrics.system.disk.usage
        }
      });

      res.json(metrics);
    } catch (error) {
      await logger.error('Get system metrics error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async getProtocolMetrics(req, res) {
    const client = await pool.connect();
    try {
      const { id } = req.params;
      const { period = '1h' } = req.query;

      const result = await client.query(`
        WITH time_series AS (
          SELECT generate_series(
            date_trunc('hour', NOW()) - $1::interval,
            date_trunc('hour', NOW()),
            '1 minute'
          ) as time
        )
        SELECT 
          ts.time,
          COUNT(c.id) as connections,
          COALESCE(SUM(c.bandwidth_usage), 0) as bandwidth,
          COUNT(CASE WHEN l.level = 'error' THEN 1 END) as errors
        FROM time_series ts
        LEFT JOIN connections c ON 
          c.protocol_id = $2 AND
          c.created_at >= ts.time AND
          c.created_at < ts.time + interval '1 minute'
        LEFT JOIN logs l ON
          l.protocol_id = $2 AND
          l.created_at >= ts.time AND
          l.created_at < ts.time + interval '1 minute'
        GROUP BY ts.time
        ORDER BY ts.time
      `, [period, id]);

      res.json(result.rows);
    } catch (error) {
      await logger.error('Get protocol metrics error', {
        error: error.message,
        stack: error.stack,
        protocolId: req.params.id
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async getUserMetrics(req, res) {
    const client = await pool.connect();
    try {
      const { id } = req.params;

      const result = await client.query(`
        SELECT json_build_object(
          'connections', (
            SELECT json_build_object(
              'total', COUNT(*),
              'active', COUNT(*) FILTER (WHERE active = true),
              'by_protocol', json_agg(json_build_object(
                'protocol', p.name,
                'count', COUNT(*)
              )) 
            )
            FROM connections c
            JOIN protocols p ON c.protocol_id = p.id
            WHERE c.user_id = $1
            GROUP BY c.user_id
          ),
          'bandwidth', (
            SELECT json_build_object(
              'total', SUM(bandwidth_usage),
              'average', AVG(bandwidth_usage),
              'by_protocol', json_agg(json_build_object(
                'protocol', p.name,
                'usage', SUM(bandwidth_usage)
              ))
            )
            FROM connections c
            JOIN protocols p ON c.protocol_id = p.id
            WHERE c.user_id = $1
            GROUP BY c.user_id
          ),
          'activity', (
            SELECT json_agg(json_build_object(
              'date', date_trunc('day', created_at),
              'actions', COUNT(*)
            ))
            FROM logs
            WHERE user_id = $1
            GROUP BY date_trunc('day', created_at)
            ORDER BY date_trunc('day', created_at) DESC
            LIMIT 30
          )
        ) as metrics
      `, [id]);

      res.json(result.rows[0].metrics);
    } catch (error) {
      await logger.error('Get user metrics error', {
        error: error.message,
        stack: error.stack,
        userId: req.params.id
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async getErrorMetrics(req, res) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          error_type,
          COUNT(*) as count,
          MIN(created_at) as first_occurrence,
          MAX(created_at) as last_occurrence,
          json_agg(json_build_object(
            'protocol', p.name,
            'user', u.username,
            'details', l.details,
            'created_at', l.created_at
          ) ORDER BY l.created_at DESC) as occurrences
        FROM logs l
        LEFT JOIN protocols p ON l.protocol_id = p.id
        LEFT JOIN users u ON l.user_id = u.id
        WHERE l.level = 'error'
          AND l.created_at > NOW() - interval '24 hours'
        GROUP BY error_type
        ORDER BY count DESC
      `);

      res.json(result.rows);
    } catch (error) {
      await logger.error('Get error metrics error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }
}

module.exports = new MetricsController();
