const { Pool } = require('pg');
const logger = require('../utils/logger');
const config = require('../config');

const pool = new Pool(config.database);

class DashboardController {
  async getSystemStats(req, res) {
    const client = await pool.connect();
    try {
      const stats = await client.query(`
        SELECT json_build_object(
          'users', (SELECT COUNT(*) FROM users),
          'active_users', (SELECT COUNT(*) FROM sessions WHERE active = true),
          'protocols', (SELECT COUNT(*) FROM protocols),
          'active_connections', (SELECT COUNT(*) FROM connections WHERE active = true),
          'total_bandwidth', (SELECT COALESCE(SUM(bandwidth_usage), 0) FROM connections),
          'error_count', (SELECT COUNT(*) FROM logs WHERE level = 'error' AND created_at > NOW() - interval '24 hours')
        ) as stats
      `);

      res.json(stats.rows[0].stats);
    } catch (error) {
      await logger.error('Get system stats error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async getChartData(req, res) {
    const client = await pool.connect();
    try {
      const { type, period = '24h' } = req.query;

      const timeFormats = {
        '24h': { interval: '1 hour', format: 'YYYY-MM-DD HH24:00:00' },
        '7d': { interval: '1 day', format: 'YYYY-MM-DD' },
        '30d': { interval: '1 day', format: 'YYYY-MM-DD' }
      };

      let query;
      switch (type) {
        case 'connections':
          query = `
            SELECT 
              to_char(date_trunc($1, created_at), $2) as time,
              COUNT(*) as value
            FROM connections
            WHERE created_at >= NOW() - $3::interval
            GROUP BY date_trunc($1, created_at)
            ORDER BY date_trunc($1, created_at)
          `;
          break;
        case 'bandwidth':
          query = `
            SELECT 
              to_char(date_trunc($1, created_at), $2) as time,
              SUM(bandwidth_usage) as value
            FROM connections
            WHERE created_at >= NOW() - $3::interval
            GROUP BY date_trunc($1, created_at)
            ORDER BY date_trunc($1, created_at)
          `;
          break;
        case 'errors':
          query = `
            SELECT 
              to_char(date_trunc($1, created_at), $2) as time,
              COUNT(*) as value
            FROM logs
            WHERE level = 'error'
              AND created_at >= NOW() - $3::interval
            GROUP BY date_trunc($1, created_at)
            ORDER BY date_trunc($1, created_at)
          `;
          break;
        default:
          return res.status(400).json({ error: 'Invalid chart type' });
      }

      const result = await client.query(query, [
        timeFormats[period].interval,
        timeFormats[period].format,
        period
      ]);

      res.json(result.rows);
    } catch (error) {
      await logger.error('Get chart data error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async getTopProtocols(req, res) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          p.name,
          p.type,
          COUNT(c.id) as connection_count,
          SUM(c.bandwidth_usage) as total_bandwidth,
          COUNT(DISTINCT c.user_id) as unique_users
        FROM protocols p
        LEFT JOIN connections c ON p.id = c.protocol_id
        WHERE c.created_at >= NOW() - interval '24 hours'
        GROUP BY p.id
        ORDER BY connection_count DESC
        LIMIT 5
      `);

      res.json(result.rows);
    } catch (error) {
      await logger.error('Get top protocols error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async getRecentActivity(req, res) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          l.id,
          l.action,
          l.level,
          l.details,
          l.created_at,
          u.username,
          p.name as protocol_name
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.id
        LEFT JOIN protocols p ON l.protocol_id = p.id
        ORDER BY l.created_at DESC
        LIMIT 10
      `);

      res.json(result.rows);
    } catch (error) {
      await logger.error('Get recent activity error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }
}

module.exports = new DashboardController();
