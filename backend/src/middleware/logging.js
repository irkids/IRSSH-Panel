const logger = require('../utils/logger');

const loggingMiddleware = () => {
  return async (req, res, next) => {
    const startTime = process.hrtime();

    // Add request ID
    req.id = require('uuid').v4();

    // Log request
    await logger.info('Incoming request', {
      id: req.id,
      method: req.method,
      path: req.path,
      query: req.query,
      body: req.method === 'POST' ? req.body : undefined,
      ip: req.ip,
      user: req.user ? {
        id: req.user.id,
        username: req.user.username
      } : undefined
    });

    // Capture response
    const originalSend = res.send;
    res.send = function(body) {
      res.send = originalSend;
      res.body = body;
      return res.send(body);
    };

    // Response handler
    res.on('finish', async () => {
      const [seconds, nanoseconds] = process.hrtime(startTime);
      const duration = seconds * 1000 + nanoseconds / 1000000;

      // Log response
      const logLevel = res.statusCode >= 400 ? 'error' : 'info';
      await logger[logLevel]('Request completed', {
        id: req.id,
        method: req.method,
        path: req.path,
        statusCode: res.statusCode,
        duration: `${duration.toFixed(2)}ms`,
        response: res.body ? JSON.parse(res.body) : undefined,
        user: req.user ? {
          id: req.user.id,
          username: req.user.username
        } : undefined
      });

      // Performance monitoring
      if (duration > 1000) {
        await logger.warn('Slow request detected', {
          id: req.id,
          method: req.method,
          path: req.path,
          duration: `${duration.toFixed(2)}ms`
        });
      }
    });

    next();
  };
};

module.exports = loggingMiddleware;
