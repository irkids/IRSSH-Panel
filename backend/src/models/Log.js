const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

const createLogsTable = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        level VARCHAR(20) NOT NULL,
        action VARCHAR(50) NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        protocol_id INTEGER REFERENCES protocols(id) ON DELETE SET NULL,
        details TEXT,
        metadata JSONB DEFAULT '{}',
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
      CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs(created_at);
      CREATE INDEX IF NOT EXISTS idx_logs_user_id ON logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_logs_protocol_id ON logs(protocol_id);
    `);
  } finally {
    client.release();
  }
};

class Log {
  static async create(data) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO logs (
          level, action, user_id, protocol_id, details, metadata, ip_address, user_agent
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
      `, [
        data.level,
        data.action,
        data.userId,
        data.protocolId,
        data.details,
        data.metadata,
        data.ipAddress,
        data.userAgent
      ]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async findByFilters(filters = {}) {
    const client = await pool.connect();
    try {
      let query = 'SELECT * FROM logs WHERE 1=1';
      const params = [];

      if (filters.level) {
        query += ` AND level = $${params.length + 1}`;
        params.push(filters.level);
      }

      if (filters.userId) {
        query += ` AND user_id = $${params.length + 1}`;
        params.push(filters.userId);
      }

      if (filters.protocolId) {
        query += ` AND protocol_id = $${params.length + 1}`;
        params.push(filters.protocolId);
      }

      if (filters.from) {
        query += ` AND created_at >= $${params.length + 1}`;
        params.push(filters.from);
      }

      if (filters.to) {
        query += ` AND created_at <= $${params.length + 1}`;
        params.push(filters.to);
      }

      query += ' ORDER BY created_at DESC';

      if (filters.limit) {
        query += ` LIMIT $${params.length + 1}`;
        params.push(filters.limit);
      }

      const result = await client.query(query, params);
      return result.rows;
    } finally {
      client.release();
    }
  }

  static async getMetrics(period = '24h') {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          level,
          COUNT(*) as count,
          COUNT(DISTINCT user_id) as unique_users,
          COUNT(DISTINCT protocol_id) as affected_protocols
        FROM logs
        WHERE created_at >= NOW() - $1::interval
        GROUP BY level
      `, [period]);

      return result.rows;
    } finally {
      client.release();
    }
  }

  static async cleanup(retentionDays = 30) {
    const client = await pool.connect();
    try {
      await client.query(`
        DELETE FROM logs
        WHERE created_at < NOW() - interval '1 day' * $1
      `, [retentionDays]);
    } finally {
      client.release();
    }
  }
}

module.exports = { Log, createLogsTable };
