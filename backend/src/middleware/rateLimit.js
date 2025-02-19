const rateLimit = require('express-rate-limit');
const Log = require('../models/Log');

const createRateLimiter = (options = {}) => {
  return rateLimit({
    windowMs: options.windowMs || 15 * 60 * 1000, // Default 15 minutes
    max: options.max || 100, // Default 100 requests per windowMs
    message: {
      error: 'Too many requests from this IP, please try again later.'
    },
    handler: async (req, res) => {
      try {
        await Log.create({
          action: 'RATE_LIMIT_EXCEEDED',
          ip: req.ip,
          path: req.path,
          details: `Rate limit exceeded: ${req.ip}`
        });
      } catch (error) {
        console.error('Error logging rate limit:', error);
      }
      
      res.status(429).json({
        error: 'Too many requests from this IP, please try again later.'
      });
    },
    standardHeaders: true,
    legacyHeaders: false
  });
};

module.exports = {
  createRateLimiter,
  apiLimiter: createRateLimiter(),
  authLimiter: createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5 // 5 requests per hour
  }),
  userLimiter: createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 50 // 50 requests per 30 minutes
  })
};
