const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('../utils/redis');
const logger = require('../utils/logger');

const createLimiter = (options) => {
  return rateLimit({
    store: new RedisStore({
      client: redis,
      prefix: 'rate-limit:',
      ...options.redis
    }),
    windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
    max: options.max || 100,
    message: {
      error: 'Too many requests, please try again later.'
    },
    handler: async (req, res) => {
      await logger.warn('Rate limit exceeded', {
        ip: req.ip,
        path: req.path,
        headers: req.headers
      });
      res.status(429).json({
        error: 'Too many requests, please try again later.'
      });
    },
    skip: (req) => {
      // Skip rate limiting for certain conditions
      return req.ip === '127.0.0.1' || req.path === '/health';
    },
    keyGenerator: (req) => {
      // Use custom key for rate limiting
      return req.user ? `${req.user.id}:${req.ip}` : req.ip;
    }
  });
};

module.exports = {
  // General API rate limiter
  apiLimiter: createLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  }),

  // Authentication rate limiter
  authLimiter: createLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5 // limit each IP to 5 login attempts per hour
  }),

  // User actions rate limiter
  userLimiter: createLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: 30 // limit each user to 30 requests per minute
  }),

  // Protocol operations rate limiter
  protocolLimiter: createLimiter({
    windowMs: 60 * 1000, // 1 minute
    max: 20 // limit each user to 20 protocol operations per minute
  })
};
