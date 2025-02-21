const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

const createMetricsTable = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS metrics (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        value NUMERIC NOT NULL,
        type VARCHAR(50) NOT NULL,
        labels JSONB DEFAULT '{}',
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(name);
      CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(type);
      CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp);
    `);
  } finally {
    client.release();
  }
};

class Metric {
  static async record(data) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO metrics (
          name, value, type, labels
        )
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `, [
        data.name,
        data.value,
        data.type,
        data.labels
      ]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async query(name, period = '1h', interval = '1m') {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          time_bucket($3, timestamp) AS time,
          AVG(value) as value
        FROM metrics
        WHERE name = $1
          AND timestamp >= NOW() - $2::interval
        GROUP BY time_bucket($3, timestamp)
        ORDER BY time
      `, [name, period, interval]);

      return result.rows;
    } finally {
      client.release();
    }
  }

  static async getLatest(name) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT *
        FROM metrics
        WHERE name = $1
        ORDER BY timestamp DESC
        LIMIT 1
      `, [name]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async cleanup(retention = '30d') {
    const client = await pool.connect();
    try {
      await client.query(`
        DELETE FROM metrics
        WHERE timestamp < NOW() - $1::interval
      `, [retention]);
    } finally {
      client.release();
    }
  }
}

module.exports = { Metric, createMetricsTable };
