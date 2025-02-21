const winston = require('winston');
require('winston-daily-rotate-file');

const config = {
  development: {
    level: 'debug',
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp(),
      winston.format.simple()
    ),
    transports: [
      new winston.transports.Console()
    ]
  },
  production: {
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    ),
    transports: [
      new winston.transports.DailyRotateFile({
        filename: '/var/log/irssh/error-%DATE%.log',
        datePattern: 'YYYY-MM-DD',
        level: 'error',
        maxSize: '20m',
        maxFiles: '30d'
      }),
      new winston.transports.DailyRotateFile({
        filename: '/var/log/irssh/combined-%DATE%.log',
        datePattern: 'YYYY-MM-DD',
        maxSize: '20m',
        maxFiles: '30d'
      })
    ]
  },
  test: {
    level: 'error',
    format: winston.format.simple(),
    transports: [
      new winston.transports.Console()
    ]
  }
};

const env = process.env.NODE_ENV || 'development';
const logger = winston.createLogger(config[env]);

module.exports = {
  logger,
  config: config[env]
};
