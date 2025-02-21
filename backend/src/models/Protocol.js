const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

const createProtocolsTable = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS protocols (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        type VARCHAR(50) NOT NULL,
        config JSONB NOT NULL,
        status VARCHAR(50) DEFAULT 'active',
        enabled BOOLEAN DEFAULT true,
        created_by INTEGER REFERENCES users(id),
        metrics JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_protocols_type ON protocols(type);
      CREATE INDEX IF NOT EXISTS idx_protocols_status ON protocols(status);
    `);
  } finally {
    client.release();
  }
};

class Protocol {
  static async findAll(filters = {}) {
    const client = await pool.connect();
    try {
      let query = 'SELECT * FROM protocols WHERE 1=1';
      const params = [];

      if (filters.type) {
        query += ` AND type = $${params.length + 1}`;
        params.push(filters.type);
      }

      if (filters.status) {
        query += ` AND status = $${params.length + 1}`;
        params.push(filters.status);
      }

      if (filters.enabled !== undefined) {
        query += ` AND enabled = $${params.length + 1}`;
        params.push(filters.enabled);
      }

      query += ' ORDER BY created_at DESC';

      const result = await client.query(query, params);
      return result.rows;
    } finally {
      client.release();
    }
  }

  static async findById(id) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          p.*,
          u.username as created_by_username,
          (
            SELECT json_build_object(
              'connections', COUNT(c.id),
              'active_connections', COUNT(c.id) FILTER (WHERE c.active = true),
              'bandwidth_usage', COALESCE(SUM(c.bandwidth_usage), 0)
            )
            FROM connections c
            WHERE c.protocol_id = p.id
          ) as statistics
        FROM protocols p
        LEFT JOIN users u ON p.created_by = u.id
        WHERE p.id = $1
      `, [id]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async create(data) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO protocols (
          name, type, config, created_by
        )
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `, [
        data.name,
        data.type,
        data.config,
        data.createdBy
      ]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async update(id, data) {
    const client = await pool.connect();
    try {
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
        data.name,
        data.config,
        data.enabled,
        id
      ]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async delete(id) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        DELETE FROM protocols
        WHERE id = $1
        RETURNING *
      `, [id]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async updateMetrics(id, metrics) {
    const client = await pool.connect();
    try {
      await client.query(`
        UPDATE protocols
        SET 
          metrics = metrics || $1::jsonb,
          updated_at = NOW()
        WHERE id = $2
      `, [metrics, id]);
    } finally {
      client.release();
    }
  }
}

module.exports = { Protocol, createProtocolsTable };
