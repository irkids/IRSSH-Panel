const config = {
  development: {
    port: parseInt(process.env.WS_PORT || '3001'),
    path: '/ws',
    maxConnections: 1000,
    heartbeat: {
      interval: 30000,
      timeout: 60000
    },
    compression: true
  },
  production: {
    port: parseInt(process.env.WS_PORT || '3001'),
    path: '/ws',
    maxConnections: 5000,
    heartbeat: {
      interval: 30000,
      timeout: 60000
    },
    compression: true,
    ssl: {
      enabled: true,
      key: process.env.SSL_KEY_PATH,
      cert: process.env.SSL_CERT_PATH
    }
  },
  test: {
    port: parseInt(process.env.TEST_WS_PORT || '3002'),
    path: '/ws',
    maxConnections: 100,
    heartbeat: {
      interval: 5000,
      timeout: 10000
    },
    compression: false
  }
};

const env = process.env.NODE_ENV || 'development';
module.exports = config[env];
