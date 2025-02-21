const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

const createConnectionsTable = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS connections (
        id SERIAL PRIMARY KEY,
        protocol_id INTEGER REFERENCES protocols(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        ip_address INET NOT NULL,
        bandwidth_usage BIGINT DEFAULT 0,
        active BOOLEAN DEFAULT true,
        started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        ended_at TIMESTAMP WITH TIME ZONE,
        metadata JSONB DEFAULT '{}'
      );

      CREATE INDEX IF NOT EXISTS idx_connections_protocol_id ON connections(protocol_id);
      CREATE INDEX IF NOT EXISTS idx_connections_user_id ON connections(user_id);
      CREATE INDEX IF NOT EXISTS idx_connections_active ON connections(active);
    `);
  } finally {
    client.release();
  }
};

class Connection {
  static async create(data) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO connections (
          protocol_id, user_id, ip_address, metadata
        )
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `, [
        data.protocolId,
        data.userId,
        data.ipAddress,
        data.metadata
      ]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async findActive(filters = {}) {
    const client = await pool.connect();
    try {
      let query = `
        SELECT 
          c.*,
          p.name as protocol_name,
          u.username
        FROM connections c
        JOIN protocols p ON c.protocol_id = p.id
        JOIN users u ON c.user_id = u.id
        WHERE c.active = true
      `;
      const params = [];

      if (filters.protocolId) {
        query += ` AND c.protocol_id = $${params.length + 1}`;
        params.push(filters.protocolId);
      }

      if (filters.userId) {
        query += ` AND c.user_id = $${params.length + 1}`;
        params.push(filters.userId);
      }

      const result = await client.query(query, params);
      return result.rows;
    } finally {
      client.release();
    }
  }

  static async close(id, endedAt = new Date()) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        UPDATE connections
        SET 
          active = false,
          ended_at = $2
        WHERE id = $1
        RETURNING *
      `, [id, endedAt]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async updateBandwidth(id, usage) {
    const client = await pool.connect();
    try {
      await client.query(`
        UPDATE connections
        SET bandwidth_usage = bandwidth_usage + $2
        WHERE id = $1
      `, [id, usage]);
    } finally {
      client.release();
    }
  }

  static async getStats(period = '24h') {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          COUNT(*) as total_connections,
          COUNT(DISTINCT user_id) as unique_users,
          SUM(bandwidth_usage) as total_bandwidth,
          AVG(EXTRACT(EPOCH FROM (COALESCE(ended_at, NOW()) - started_at))) as avg_duration
        FROM connections
        WHERE started_at >= NOW() - $1::interval
      `, [period]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }
}

module.exports = { Connection, createConnectionsTable };
