const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

const createSettingsTable = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS settings (
        id SERIAL PRIMARY KEY,
        key VARCHAR(100) NOT NULL UNIQUE,
        value JSONB NOT NULL,
        description TEXT,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_by INTEGER REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);
    `);
  } finally {
    client.release();
  }
};

class Setting {
  static async get(key) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT value
        FROM settings
        WHERE key = $1
      `, [key]);

      return result.rows[0]?.value;
    } finally {
      client.release();
    }
  }

  static async set(key, value, userId) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO settings (key, value, updated_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (key) DO UPDATE
        SET 
          value = $2,
          updated_by = $3,
          updated_at = CURRENT_TIMESTAMP
        RETURNING *
      `, [key, value, userId]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async getAll() {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          s.*,
          u.username as updated_by_username
        FROM settings s
        LEFT JOIN users u ON s.updated_by = u.id
        ORDER BY s.key
      `);

      return result.rows;
    } finally {
      client.release();
    }
  }

  static async delete(key) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        DELETE FROM settings
        WHERE key = $1
        RETURNING *
      `, [key]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async bulkUpdate(settings, userId) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const results = [];
      for (const [key, value] of Object.entries(settings)) {
        const result = await client.query(`
          INSERT INTO settings (key, value, updated_by)
          VALUES ($1, $2, $3)
          ON CONFLICT (key) DO UPDATE
          SET 
            value = $2,
            updated_by = $3,
            updated_at = CURRENT_TIMESTAMP
          RETURNING *
        `, [key, value, userId]);
        
        results.push(result.rows[0]);
      }

      await client.query('COMMIT');
      return results;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  static async getHistory(key) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          s.*,
          u.username as updated_by_username
        FROM setting_history s
        LEFT JOIN users u ON s.updated_by = u.id
        WHERE s.key = $1
        ORDER BY s.updated_at DESC
      `, [key]);

      return result.rows;
    } finally {
      client.release();
    }
  }
}

module.exports = { Setting, createSettingsTable };
