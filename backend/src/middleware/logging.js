const logger = require('../utils/logger');
const morgan = require('morgan');

// Custom token for request ID
morgan.token('request-id', (req) => req.requestId);

// Custom token for user ID
morgan.token('user-id', (req) => (req.user ? req.user.id : 'anonymous'));

// Custom token for request body
morgan.token('request-body', (req) => {
    if (req.method === 'POST' || req.method === 'PUT') {
        // Filter sensitive data
        const filteredBody = { ...req.body };
        ['password', 'token', 'apiKey'].forEach(key => {
            if (filteredBody[key]) filteredBody[key] = '[FILTERED]';
        });
        return JSON.stringify(filteredBody);
    }
    return '';
});

// Custom format for detailed logging
const detailedFormat = ':request-id [:date[clf]] ":method :url" :status :response-time ms - :user-id :remote-addr ":user-agent" ":request-body"';

const loggingMiddleware = {
    // Request logging middleware
    requestLogger: morgan(detailedFormat, {
        stream: {
            write: (message) => logger.info(message.trim())
        },
        skip: (req) => req.path === '/health' || req.path === '/metrics'
    }),

    // Error logging middleware
    errorLogger: (err, req, res, next) => {
        logger.error('Request Error', {
            error: {
                message: err.message,
                stack: err.stack
            },
            request: {
                id: req.requestId,
                method: req.method,
                url: req.url,
                headers: req.headers,
                params: req.params,
                query: req.query,
                body: req.body
            },
            user: req.user ? {
                id: req.user.id,
                username: req.user.username
            } : 'anonymous'
        });
        next(err);
    },

    // Performance monitoring middleware
    performanceLogger: (req, res, next) => {
        const start = process.hrtime();

        res.on('finish', () => {
            const [seconds, nanoseconds] = process.hrtime(start);
            const duration = seconds * 1000 + nanoseconds / 1000000;

            logger.logPerformanceMetric('request_duration', duration, {
                path: req.path,
                method: req.method,
                status: res.statusCode
            });

            // Log slow requests
            if (duration > 1000) {
                logger.warn('Slow Request Detected', {
                    duration,
                    path: req.path,
                    method: req.method
                });
            }
        });

        next();
    },

    // Security event logging middleware
    securityLogger: (req, res, next) => {
        // Log authentication attempts
        if (req.path === '/api/auth/login') {
            logger.logSecurityEvent('authentication_attempt', {
                username: req.body.username,
                ip: req.ip
            });
        }

        // Log access to sensitive endpoints
        if (req.path.startsWith('/api/admin')) {
            logger.logSecurityEvent('admin_access', {
                user: req.user ? req.user.id : 'anonymous',
                path: req.path,
                method: req.method
            });
        }

        next();
    },

    // Database operation logging middleware
    databaseLogger: (req, res, next) => {
        if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
            logger.logDatabaseOperation(req.method, {
                path: req.path,
                user: req.user ? req.user.id : 'anonymous',
                operation: req.method
            });
        }
        next();
    }
};

module.exports = loggingMiddleware;
