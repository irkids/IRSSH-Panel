const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const logger = require('../utils/logger');
const config = require('../config');

const pool = new Pool(config.database);

class UserController {
  async getUsers(req, res) {
    const client = await pool.connect();
    try {
      const { page = 1, limit = 10, search, role } = req.query;
      const offset = (page - 1) * limit;

      let query = `
        SELECT 
          u.id, 
          u.username, 
          u.email, 
          u.role,
          u.created_at,
          u.last_login,
          COUNT(*) OVER() as total_count
        FROM users u
        WHERE 1=1
      `;
      const params = [];

      if (search) {
        query += ` AND (u.username ILIKE $${params.length + 1} OR u.email ILIKE $${params.length + 1})`;
        params.push(`%${search}%`);
      }

      if (role) {
        query += ` AND u.role = $${params.length + 1}`;
        params.push(role);
      }

      query += `
        ORDER BY u.created_at DESC
        LIMIT $${params.length + 1} OFFSET $${params.length + 2}
      `;
      params.push(limit, offset);

      const result = await client.query(query, params);

      const users = result.rows;
      const totalCount = users[0]?.total_count || 0;

      res.json({
        users,
        pagination: {
          total: parseInt(totalCount),
          page: parseInt(page),
          totalPages: Math.ceil(totalCount / limit)
        }
      });
    } catch (error) {
      await logger.error('Get users error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async getUser(req, res) {
    const client = await pool.connect();
    try {
      const { id } = req.params;

      const result = await client.query(`
        SELECT 
          u.id, 
          u.username, 
          u.email, 
          u.role,
          u.created_at,
          u.last_login,
          us.theme,
          us.notifications_enabled,
          us.timezone
        FROM users u
        LEFT JOIN user_settings us ON u.id = us.user_id
        WHERE u.id = $1
      `, [id]);

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Get user statistics
      const statsResult = await client.query(`
        SELECT 
          COUNT(DISTINCT s.id) as total_sessions,
          COUNT(DISTINCT p.id) as total_protocols,
          COUNT(DISTINCT l.id) as total_logs
        FROM users u
        LEFT JOIN sessions s ON u.id = s.user_id
        LEFT JOIN protocols p ON u.id = p.user_id
        LEFT JOIN logs l ON u.id = l.user_id
        WHERE u.id = $1
      `, [id]);

      res.json({
        ...result.rows[0],
        statistics: statsResult.rows[0]
      });
    } catch (error) {
      await logger.error('Get user error', {
        error: error.message,
        stack: error.stack,
        userId: req.params.id
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async updateUser(req, res) {
    const client = await pool.connect();
    try {
      const { id } = req.params;
      const updates = req.body;

      // Start transaction
      await client.query('BEGIN');

      // Update user basic info
      const userResult = await client.query(`
        UPDATE users 
        SET 
          username = COALESCE($1, username),
          email = COALESCE($2, email),
          role = COALESCE($3, role),
          updated_at = NOW()
        WHERE id = $4
        RETURNING *
      `, [updates.username, updates.email, updates.role, id]);

      if (userResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'User not found' });
      }

      // Update user settings if provided
      if (updates.settings) {
        await client.query(`
          INSERT INTO user_settings (user_id, theme, notifications_enabled, timezone)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (user_id) 
          DO UPDATE SET
            theme = EXCLUDED.theme,
            notifications_enabled = EXCLUDED.notifications_enabled,
            timezone = EXCLUDED.timezone
        `, [
          id,
          updates.settings.theme,
          updates.settings.notifications_enabled,
          updates.settings.timezone
        ]);
      }

      // If password update requested
      if (updates.password) {
        const hashedPassword = await bcrypt.hash(updates.password, 12);
        await client.query(
          'UPDATE users SET password = $1 WHERE id = $2',
          [hashedPassword, id]
        );
      }

      await client.query('COMMIT');

      await logger.info('User updated', {
        userId: id,
        updatedBy: req.user.id
      });

      res.json(userResult.rows[0]);
    } catch (error) {
      await client.query('ROLLBACK');
      await logger.error('Update user error', {
        error: error.message,
        stack: error.stack,
        userId: req.params.id
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async deleteUser(req, res) {
    const client = await pool.connect();
    try {
      const { id } = req.params;

      // Start transaction
      await client.query('BEGIN');

      // Delete user sessions
      await client.query('DELETE FROM sessions WHERE user_id = $1', [id]);

      // Delete user settings
      await client.query('DELETE FROM user_settings WHERE user_id = $1', [id]);

      // Delete user
      const result = await client.query(
        'DELETE FROM users WHERE id = $1 RETURNING *',
        [id]
      );

      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'User not found' });
      }

      await client.query('COMMIT');

      await logger.info('User deleted', {
        userId: id,
        deletedBy: req.user.id
      });

      res.json({ message: 'User deleted successfully' });
    } catch (error) {
      await client.query('ROLLBACK');
      await logger.error('Delete user error', {
        error: error.message,
        stack: error.stack,
        userId: req.params.id
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async getUserActivity(req, res) {
    const client = await pool.connect();
    try {
      const { id } = req.params;
      const { from, to } = req.query;

      const result = await client.query(`
        SELECT 
          l.id,
          l.action,
          l.details,
          l.created_at,
          l.ip_address,
          l.user_agent
        FROM logs l
        WHERE l.user_id = $1
          AND ($2::timestamp IS NULL OR l.created_at >= $2)
          AND ($3::timestamp IS NULL OR l.created_at <= $3)
        ORDER BY l.created_at DESC
        LIMIT 100
      `, [id, from, to]);

      res.json(result.rows);
    } catch (error) {
      await logger.error('Get user activity error', {
        error: error.message,
        stack: error.stack,
        userId: req.params.id
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }
}

module.exports = new UserController();
