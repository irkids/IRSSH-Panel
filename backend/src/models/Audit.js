const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

const createAuditTable = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(100) NOT NULL,
        entity_type VARCHAR(50),
        entity_id INTEGER,
        old_values JSONB,
        new_values JSONB,
        ip_address INET,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
      CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_logs(entity_type, entity_id);
      CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);
    `);
  } finally {
    client.release();
  }
};

class Audit {
  static async log(data) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO audit_logs (
          user_id, action, entity_type, entity_id, 
          old_values, new_values, ip_address
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
      `, [
        data.userId,
        data.action,
        data.entityType,
        data.entityId,
        data.oldValues,
        data.newValues,
        data.ipAddress
      ]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async search(filters = {}) {
    const client = await pool.connect();
    try {
      let query = `
        SELECT 
          a.*,
          u.username as user_name
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        WHERE 1=1
      `;
      const params = [];

      if (filters.userId) {
        query += ` AND a.user_id = $${params.length + 1}`;
        params.push(filters.userId);
      }

      if (filters.action) {
        query += ` AND a.action = $${params.length + 1}`;
        params.push(filters.action);
      }

      if (filters.entityType) {
        query += ` AND a.entity_type = $${params.length + 1}`;
        params.push(filters.entityType);
      }

      if (filters.entityId) {
        query += ` AND a.entity_id = $${params.length + 1}`;
        params.push(filters.entityId);
      }

      if (filters.startDate) {
        query += ` AND a.created_at >= $${params.length + 1}`;
        params.push(filters.startDate);
      }

      if (filters.endDate) {
        query += ` AND a.created_at <= $${params.length + 1}`;
        params.push(filters.endDate);
      }

      query += ' ORDER BY a.created_at DESC';

      if (filters.limit) {
        query += ` LIMIT $${params.length + 1}`;
        params.push(filters.limit);
      }

      if (filters.offset) {
        query += ` OFFSET $${params.length + 1}`;
        params.push(filters.offset);
      }

      const result = await client.query(query, params);
      return result.rows;
    } finally {
      client.release();
    }
  }

  static async getEntityHistory(entityType, entityId) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          a.*,
          u.username as user_name
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        WHERE a.entity_type = $1 AND a.entity_id = $2
        ORDER BY a.created_at DESC
      `, [entityType, entityId]);

      return result.rows;
    } finally {
      client.release();
    }
  }

  static async getUserActivity(userId) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          a.*,
          COUNT(*) OVER() as total_count
        FROM audit_logs a
        WHERE a.user_id = $1
        ORDER BY a.created_at DESC
        LIMIT 100
      `, [userId]);

      return {
        records: result.rows,
        totalCount: parseInt(result.rows[0]?.total_count || 0)
      };
    } finally {
      client.release();
    }
  }

  static async cleanup(retentionDays = 90) {
    const client = await pool.connect();
    try {
      await client.query(`
        DELETE FROM audit_logs
        WHERE created_at < NOW() - interval '1 day' * $1
      `, [retentionDays]);
    } finally {
      client.release();
    }
  }
}

module.exports = { Audit, createAuditTable };
