const jwt = require('jsonwebtoken');
const config = require('../config/security');
const { Session } = require('../models/Session');
const logger = require('./logger');

class AuthService {
  async generateToken(user) {
    return jwt.sign(
      {
        id: user.id,
        role: user.role
      },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );
  }

  async verifyToken(token) {
    try {
      const decoded = jwt.verify(token, config.jwt.secret);
      const session = await Session.findByToken(token);

      if (!session) {
        throw new Error('Invalid session');
      }

      return decoded;
    } catch (error) {
      logger.error('Token verification failed:', error);
      throw error;
    }
  }

  async createSession(user, req) {
    try {
      const token = await this.generateToken(user);
      const session = await Session.create({
        userId: user.id,
        token,
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      });

      return {
        token,
        session
      };
    } catch (error) {
      logger.error('Session creation failed:', error);
      throw error;
    }
  }

  async destroySession(token) {
    try {
      await Session.deactivate(token);
    } catch (error) {
      logger.error('Session destruction failed:', error);
      throw error;
    }
  }

  async validatePermission(user, permission) {
    const permissions = {
      admin: ['*'],
      user: ['read', 'write']
    };

    const userPermissions = permissions[user.role] || [];
    return userPermissions.includes('*') || userPermissions.includes(permission);
  }

  hashPassword(password) {
    return require('bcrypt').hash(password, 10);
  }

  comparePassword(password, hash) {
    return require('bcrypt').compare(password, hash);
  }
}

module.exports = new AuthService();
