const { Pool } = require('pg');
const logger = require('../utils/logger');
const config = require('../config');
const { validateProtocol } = require('../utils/validation');

const pool = new Pool(config.database);

class ProtocolController {
  async getProtocols(req, res) {
    const client = await pool.connect();
    try {
      const { type, status, search } = req.query;
      let query = `
        SELECT 
          p.id,
          p.name,
          p.type,
          p.config,
          p.status,
          p.enabled,
          p.created_at,
          p.updated_at,
          COUNT(DISTINCT c.id) as connection_count,
          u.username as created_by
        FROM protocols p
        LEFT JOIN connections c ON p.id = c.protocol_id AND c.active = true
        LEFT JOIN users u ON p.created_by = u.id
        WHERE 1=1
      `;
      const params = [];

      if (type) {
        query += ` AND p.type = $${params.length + 1}`;
        params.push(type);
      }

      if (status) {
        query += ` AND p.status = $${params.length + 1}`;
        params.push(status);
      }

      if (search) {
        query += ` AND p.name ILIKE $${params.length + 1}`;
        params.push(`%${search}%`);
      }

      query += `
        GROUP BY p.id, u.username
        ORDER BY p.created_at DESC
      `;

      const result = await client.query(query, params);

      await logger.info('Protocols retrieved', {
        count: result.rows.length,
        filters: { type, status, search }
      });

      res.json(result.rows);
    } catch (error) {
      await logger.error('Get protocols error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async getProtocol(req, res) {
    const client = await pool.connect();
    try {
      const { id } = req.params;

      const result = await client.query(`
        SELECT 
          p.*,
          json_agg(DISTINCT jsonb_build_object(
            'id', c.id,
            'ip_address', c.ip_address,
            'connected_at', c.connected_at,
            'username', u.username
          )) as active_connections,
          json_build_object(
            'total_connections', COUNT(DISTINCT c.id),
            'total_bandwidth', SUM(c.bandwidth_usage),
            'error_count', COUNT(DISTINCT l.id)
          ) as metrics
        FROM protocols p
        LEFT JOIN connections c ON p.id = c.protocol_id AND c.active = true
        LEFT JOIN users u ON c.user_id = u.id
        LEFT JOIN logs l ON p.id = l.protocol_id AND l.level = 'error'
        WHERE p.id = $1
        GROUP BY p.id
      `, [id]);

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Protocol not found' });
      }

      await logger.info('Protocol retrieved', {
        protocolId: id,
        type: result.rows[0].type
      });

      res.json(result.rows[0]);
    } catch (error) {
      await logger.error('Get protocol error', {
        error: error.message,
        stack: error.stack,
        protocolId: req.params.id
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async createProtocol(req, res) {
    const client = await pool.connect();
    try {
      const protocolData = req.body;
      
      // Validate protocol data
      const validation = validateProtocol(protocolData);
      if (!validation.success) {
        return res.status(400).json({ errors: validation.errors });
      }

      // Start transaction
      await client.query('BEGIN');

      // Create protocol
      const result = await client.query(`
        INSERT INTO protocols (
          name,
          type,
          config,
          status,
          enabled,
          created_by
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
      `, [
        protocolData.name,
        protocolData.type,
        JSON.stringify(protocolData.config),
        'active',
        true,
        req.user.id
      ]);

      // Create initial metrics
      await client.query(`
        INSERT INTO protocol_metrics (
          protocol_id,
          total_connections,
          bandwidth_usage,
          error_count
        )
        VALUES ($1, 0, 0, 0)
      `, [result.rows[0].id]);

      await client.query('COMMIT');

      await logger.info('Protocol created', {
        protocolId: result.rows[0].id,
        type: result.rows[0].type,
        createdBy: req.user.id
      });

      res.status(201).json(result.rows[0]);
    } catch (error) {
      await client.query('ROLLBACK');
      await logger.error('Create protocol error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async updateProtocol(req, res) {
    const client = await pool.connect();
    try {
      const { id } = req.params;
      const updates = req.body;

      // Validate updates
      const validation = validateProtocol(updates, true);
      if (!validation.success) {
        return res.status(400).json({ errors: validation.errors });
      }

      // Start transaction
      await client.query('BEGIN');

      const result = await client.query(`
        UPDATE protocols
        SET 
          name = COALESCE($1, name),
          config = COALESCE($2, config),
          enabled = COALESCE($3, enabled),
          updated_at = NOW()
        WHERE id = $4
        RETURNING *
      `, [
        updates.name,
        updates.config ? JSON.stringify(updates.config) : null,
        updates.enabled,
        id
      ]);

      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Protocol not found' });
      }

      await client.query('COMMIT');

      await logger.info('Protocol updated', {
        protocolId: id,
        updatedBy: req.user.id,
        updates: Object.keys(updates)
      });

      res.json(result.rows[0]);
    } catch (error) {
      await client.query('ROLLBACK');
      await logger.error('Update protocol error', {
        error: error.message,
        stack: error.stack,
        protocolId: req.params.id
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async deleteProtocol(req, res) {
    const client = await pool.connect();
    try {
      const { id } = req.params;

      // Check for active connections
      const activeConnections = await client.query(`
        SELECT COUNT(*) as count
        FROM connections
        WHERE protocol_id = $1 AND active = true
      `, [id]);

      if (activeConnections.rows[0].count > 0) {
        return res.status(400).json({ 
          error: 'Cannot delete protocol with active connections' 
        });
      }

      // Start transaction
      await client.query('BEGIN');

      // Delete related data
      await client.query('DELETE FROM protocol_metrics WHERE protocol_id = $1', [id]);
      await client.query('DELETE FROM connections WHERE protocol_id = $1', [id]);

      // Delete protocol
      const result = await client.query(
        'DELETE FROM protocols WHERE id = $1 RETURNING *',
        [id]
      );

      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'Protocol not found' });
      }

      await client.query('COMMIT');

      await logger.info('Protocol deleted', {
        protocolId: id,
        deletedBy: req.user.id
      });

      res.json({ message: 'Protocol deleted successfully' });
    } catch (error) {
      await client.query('ROLLBACK');
      await logger.error('Delete protocol error', {
        error: error.message,
        stack: error.stack,
        protocolId: req.params.id
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
      const { period = '24h' } = req.query;

      const intervals = {
        '24h': { interval: '1 hour', format: 'YYYY-MM-DD HH24:00:00' },
        '7d': { interval: '1 day', format: 'YYYY-MM-DD' },
        '30d': { interval: '1 day', format: 'YYYY-MM-DD' }
      };

      const { interval, format } = intervals[period] || intervals['24h'];

      const metrics = await client.query(`
        SELECT 
          to_char(date_trunc($1, created_at), $2) as time,
          COUNT(*) as connections,
          SUM(bandwidth_usage) as bandwidth,
          COUNT(CASE WHEN error = true THEN 1 END) as errors
        FROM connections
        WHERE protocol_id = $3
          AND created_at >= NOW() - $4::interval
        GROUP BY date_trunc($1, created_at)
        ORDER BY date_trunc($1, created_at)
      `, [interval, format, id, period]);

      res.json(metrics.rows);
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
}

module.exports = new ProtocolController();
