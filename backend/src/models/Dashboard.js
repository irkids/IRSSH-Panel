const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

class Dashboard {
  static async getSystemStats() {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT json_build_object(
          'users', (
            SELECT json_build_object(
              'total', COUNT(*),
              'active', COUNT(*) FILTER (WHERE last_login > NOW() - interval '24 hours')
            )
            FROM users
          ),
          'protocols', (
            SELECT json_build_object(
              'total', COUNT(*),
              'active', COUNT(*) FILTER (WHERE enabled = true)
            )
            FROM protocols
          ),
          'connections', (
            SELECT json_build_object(
              'total', COUNT(*),
              'active', COUNT(*) FILTER (WHERE active = true)
            )
            FROM connections
          ),
          'alerts', (
            SELECT json_build_object(
              'total', COUNT(*),
              'critical', COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'active')
            )
            FROM alerts
          )
        ) as stats
      `);

      return result.rows[0].stats;
    } finally {
      client.release();
    }
  }

  static async getChartData(type, period = '24h') {
    const client = await pool.connect();
    try {
      let query;
      switch (type) {
        case 'connections':
          query = `
            SELECT 
              time_bucket('1 hour', created_at) as time,
              COUNT(*) as value
            FROM connections
            WHERE created_at > NOW() - $1::interval
            GROUP BY time_bucket('1 hour', created_at)
            ORDER BY time
          `;
          break;
        case 'bandwidth':
          query = `
            SELECT 
              time_bucket('1 hour', created_at) as time,
              SUM(bandwidth_usage) as value
            FROM connections
            WHERE created_at > NOW() - $1::interval
            GROUP BY time_bucket('1 hour', created_at)
            ORDER BY time
          `;
          break;
        default:
          throw new Error('Invalid chart type');
      }

      const result = await client.query(query, [period]);
      return result.rows;
    } finally {
      client.release();
    }
  }

  static async getTopProtocols() {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          p.name,
          p.type,
          COUNT(c.id) as connection_count,
          SUM(c.bandwidth_usage) as total_bandwidth
        FROM protocols p
        LEFT JOIN connections c ON p.id = c.protocol_id
        WHERE c.created_at > NOW() - interval '24 hours'
        GROUP BY p.id
        ORDER BY connection_count DESC
        LIMIT 5
      `);

      return result.rows;
    } finally {
      client.release();
    }
  }

  static async getRecentActivity() {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT 
          l.action,
          l.details,
          l.created_at,
          u.username,
          p.name as protocol_name
        FROM logs l
        LEFT JOIN users u ON l.user_id = u.id
        LEFT JOIN protocols p ON l.protocol_id = p.id
        ORDER BY l.created_at DESC
        LIMIT 10
      `);

      return result.rows;
    } finally {
      client.release();
    }
  }
}

module.exports = Dashboard;
