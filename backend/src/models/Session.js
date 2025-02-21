const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

const createSessionsTable = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL UNIQUE,
        ip_address INET,
        user_agent TEXT,
        active BOOLEAN DEFAULT true,
        last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
    `);
  } finally {
    client.release();
  }
};

class Session {
  static async create(data) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO sessions (
          user_id, token, ip_address, user_agent, expires_at
        )
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `, [
        data.userId,
        data.token,
        data.ipAddress,
        data.userAgent,
        new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now
      ]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async findByToken(token) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT * FROM sessions
        WHERE token = $1 AND active = true AND expires_at > NOW()
      `, [token]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async deactivate(token) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        UPDATE sessions
        SET active = false, updated_at = NOW()
        WHERE token = $1
        RETURNING *
      `, [token]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async updateActivity(id) {
    const client = await pool.connect();
    try {
      await client.query(`
        UPDATE sessions
        SET last_activity = NOW(), updated_at = NOW()
        WHERE id = $1
      `, [id]);
    } finally {
      client.release();
    }
  }

  static async cleanupExpired() {
    const client = await pool.connect();
    try {
      await client.query(`
        DELETE FROM sessions
        WHERE expires_at < NOW() OR active = false
      `);
    } finally {
      client.release();
    }
  }

  static async getUserSessions(userId) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT * FROM sessions
        WHERE user_id = $1 AND active = true
        ORDER BY created_at DESC
      `, [userId]);

      return result.rows;
    } finally {
      client.release();
    }
  }
}

module.exports = { Session, createSessionsTable };
