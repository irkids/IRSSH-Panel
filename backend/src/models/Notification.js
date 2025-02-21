const { Pool } = require('pg');
const config = require('../config');

const pool = new Pool(config.database);

const createNotificationsTable = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50) NOT NULL,
        title VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT false,
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
      CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
      CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);
    `);
  } finally {
    client.release();
  }
};

class Notification {
  static async create(data) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        INSERT INTO notifications (
          user_id, type, title, message, metadata
        )
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `, [
        data.userId,
        data.type,
        data.title,
        data.message,
        data.metadata
      ]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async markAsRead(id, userId) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        UPDATE notifications
        SET read = true
        WHERE id = $1 AND user_id = $2
        RETURNING *
      `, [id, userId]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async markAllAsRead(userId) {
    const client = await pool.connect();
    try {
      await client.query(`
        UPDATE notifications
        SET read = true
        WHERE user_id = $1 AND read = false
      `, [userId]);
    } finally {
      client.release();
    }
  }

  static async getUserNotifications(userId, limit = 50) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT *
        FROM notifications
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT $2
      `, [userId, limit]);

      return result.rows;
    } finally {
      client.release();
    }
  }

  static async getUnreadCount(userId) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        SELECT COUNT(*)
        FROM notifications
        WHERE user_id = $1 AND read = false
      `, [userId]);

      return parseInt(result.rows[0].count);
    } finally {
      client.release();
    }
  }

  static async delete(id, userId) {
    const client = await pool.connect();
    try {
      const result = await client.query(`
        DELETE FROM notifications
        WHERE id = $1 AND user_id = $2
        RETURNING *
      `, [id, userId]);

      return result.rows[0];
    } finally {
      client.release();
    }
  }

  static async cleanup(days = 30) {
    const client = await pool.connect();
    try {
      await client.query(`
        DELETE FROM notifications
        WHERE read = true
          AND created_at < NOW() - interval '1 day' * $1
      `, [days]);
    } finally {
      client.release();
    }
  }
}

module.exports = { Notification, createNotificationsTable };
