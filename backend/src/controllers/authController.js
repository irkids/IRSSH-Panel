const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { validateUser } = require('../utils/validation');
const logger = require('../utils/logger');
const config = require('../config');

const pool = new Pool(config.database);

class AuthController {
  async login(req, res) {
    const client = await pool.connect();
    try {
      const { username, password } = req.body;

      const result = await client.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
      );

      const user = result.rows[0];
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Create session
      const sessionResult = await client.query(
        'INSERT INTO sessions (user_id, last_activity) VALUES ($1, NOW()) RETURNING id',
        [user.id]
      );

      const token = jwt.sign(
        { 
          userId: user.id,
          sessionId: sessionResult.rows[0].id 
        },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
      );

      await logger.info('User logged in', {
        userId: user.id,
        username: user.username,
        ip: req.ip
      });

      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          email: user.email
        }
      });
    } catch (error) {
      await logger.error('Login error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async register(req, res) {
    const client = await pool.connect();
    try {
      const userData = req.body;
      
      // Validate user data
      const validation = validateUser(userData);
      if (!validation.success) {
        return res.status(400).json({ errors: validation.errors });
      }

      // Check if user exists
      const existingUser = await client.query(
        'SELECT id FROM users WHERE username = $1 OR email = $2',
        [userData.username, userData.email]
      );

      if (existingUser.rows.length > 0) {
        return res.status(409).json({ error: 'User already exists' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(userData.password, 12);

      // Begin transaction
      await client.query('BEGIN');

      // Insert user
      const result = await client.query(
        `INSERT INTO users (username, email, password, role, created_at)
         VALUES ($1, $2, $3, $4, NOW())
         RETURNING id, username, email, role`,
        [userData.username, userData.email, hashedPassword, userData.role || 'user']
      );

      // Create initial settings
      await client.query(
        'INSERT INTO user_settings (user_id) VALUES ($1)',
        [result.rows[0].id]
      );

      await client.query('COMMIT');

      await logger.info('User registered', {
        userId: result.rows[0].id,
        username: result.rows[0].username
      });

      res.status(201).json(result.rows[0]);
    } catch (error) {
      await client.query('ROLLBACK');
      await logger.error('Registration error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async logout(req, res) {
    const client = await pool.connect();
    try {
      await client.query(
        'UPDATE sessions SET active = false WHERE id = $1',
        [req.session.id]
      );

      await logger.info('User logged out', {
        userId: req.user.id,
        sessionId: req.session.id
      });

      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      await logger.error('Logout error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async verifyToken(req, res) {
    const client = await pool.connect();
    try {
      const result = await client.query(
        `SELECT users.*, sessions.active 
         FROM users 
         JOIN sessions ON users.id = sessions.user_id 
         WHERE sessions.id = $1`,
        [req.session.id]
      );

      if (!result.rows[0] || !result.rows[0].active) {
        return res.status(401).json({ error: 'Invalid session' });
      }

      await client.query(
        'UPDATE sessions SET last_activity = NOW() WHERE id = $1',
        [req.session.id]
      );

      res.json({ valid: true });
    } catch (error) {
      await logger.error('Token verification error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }

  async resetPassword(req, res) {
    const client = await pool.connect();
    try {
      const { email } = req.body;
      
      const result = await client.query(
        'SELECT id FROM users WHERE email = $1',
        [email]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = new Date(Date.now() + 3600000); // 1 hour

      await client.query(
        `UPDATE users 
         SET reset_token = $1, reset_expires = $2 
         WHERE id = $3`,
        [resetToken, resetExpires, result.rows[0].id]
      );

      // Send reset email logic here

      await logger.info('Password reset requested', {
        userId: result.rows[0].id,
        email
      });

      res.json({ message: 'Reset instructions sent' });
    } catch (error) {
      await logger.error('Password reset error', {
        error: error.message,
        stack: error.stack
      });
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      client.release();
    }
  }
}

module.exports = new AuthController();
