const winston = require('winston');
const { format } = winston;
const DailyRotateFile = require('winston-daily-rotate-file');

class Logger {
    constructor() {
        // Custom format for detailed logging
        const detailedFormat = format.combine(
            format.timestamp(),
            format.errors({ stack: true }),
            format.metadata(),
            format.json()
        );

        // Transport configuration
        const transports = [
            // Console transport
            new winston.transports.Console({
                level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
                format: format.combine(
                    format.colorize(),
                    format.simple()
                )
            }),

            // Daily rotating file transport for all logs
            new DailyRotateFile({
                filename: 'logs/application-%DATE%.log',
                datePattern: 'YYYY-MM-DD',
                maxSize: '20m',
                maxFiles: '14d',
                format: detailedFormat
            }),

            // Daily rotating file transport for errors
            new DailyRotateFile({
                filename: 'logs/error-%DATE%.log',
                datePattern: 'YYYY-MM-DD',
                maxSize: '20m',
                maxFiles: '30d',
                level: 'error',
                format: detailedFormat
            })
        ];

        // Create logger instance
        this.logger = winston.createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: detailedFormat,
            transports,
            exceptionHandlers: [
                new DailyRotateFile({
                    filename: 'logs/exceptions-%DATE%.log',
                    datePattern: 'YYYY-MM-DD',
                    maxSize: '20m',
                    maxFiles: '30d',
                    format: detailedFormat
                })
            ],
            rejectionHandlers: [
                new DailyRotateFile({
                    filename: 'logs/rejections-%DATE%.log',
                    datePattern: 'YYYY-MM-DD',
                    maxSize: '20m',
                    maxFiles: '30d',
                    format: detailedFormat
                })
            ]
        });

        // Add request context middleware
        this.requestMiddleware = this.requestMiddleware.bind(this);
    }

    // Request context middleware
    requestMiddleware(req, res, next) {
        req.requestId = require('uuid').v4();
        req.startTime = Date.now();

        res.on('finish', () => {
            const duration = Date.now() - req.startTime;
            this.logRequest(req, res, duration);
        });

        next();
    }

    // Log HTTP request
    logRequest(req, res, duration) {
        const meta = {
            requestId: req.requestId,
            method: req.method,
            url: req.url,
            status: res.statusCode,
            duration,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            user: req.user ? req.user.id : 'anonymous'
        };

        this.logger.info('HTTP Request', meta);
    }

    // Log methods
    error(message, meta = {}) {
        this.logger.error(message, meta);
    }

    warn(message, meta = {}) {
        this.logger.warn(message, meta);
    }

    info(message, meta = {}) {
        this.logger.info(message, meta);
    }

    debug(message, meta = {}) {
        this.logger.debug(message, meta);
    }

    // Log with stack trace
    errorWithStack(error) {
        this.logger.error({
            message: error.message,
            stack: error.stack,
            ...error
        });
    }

    // Specialized logging methods
    logSecurityEvent(event, meta = {}) {
        this.logger.warn(`Security Event: ${event}`, {
            securityEvent: true,
            ...meta
        });
    }

    logDatabaseOperation(operation, meta = {}) {
        this.logger.debug(`Database Operation: ${operation}`, {
            dbOperation: true,
            ...meta
        });
    }

    logPerformanceMetric(metric, value, meta = {}) {
        this.logger.info('Performance Metric', {
            metric,
            value,
            performanceMetric: true,
            ...meta
        });
    }

    // Monitor specific events
    monitorEvent(eventName, meta = {}) {
        this.logger.info(`Event: ${eventName}`, {
            monitoring: true,
            eventName,
            ...meta
        });
    }
}

module.exports = new Logger();
