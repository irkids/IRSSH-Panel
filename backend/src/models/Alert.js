const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

const createAlertsTable = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        message TEXT NOT NULL,
        metadata JSONB DEFAULT '{}',
        acknowledged_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP WITH TIME ZONE
      );

      CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
      CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
      CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
    `);
  } finally {
    client.release();
  }
};

class Alert {
  static async create(data) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO alerts (
          name, severity, message, metadata
        )
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `, [
        data.name,
        data.severity,
        data.message,
        data.metadata
      ]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async acknowledge(id, userId) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        UPDATE alerts
        SET 
          status = 'acknowledged',
          acknowledged_by = $2,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
      `, [id, userId]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async resolve(id) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        UPDATE alerts
        SET 
          status = 'resolved',
          resolved_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
      `, [id]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async getActive() {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          a.*,
          u.username as acknowledged_by_username
        FROM alerts a
        LEFT JOIN users u ON a.acknowledged_by = u.id
        WHERE a.status != 'resolved'
        ORDER BY 
          CASE 
            WHEN a.severity = 'critical' THEN 1
            WHEN a.severity = 'high' THEN 2
            WHEN a.severity = 'medium' THEN 3
            ELSE 4
          END,
          a.created_at DESC
      `);

      return result.rows;
    } finally {
      client.release();
    }
  }
}

module.exports = { Alert, createAlertsTable };
