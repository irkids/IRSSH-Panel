const config = {
  development: {
    enabled: true,
    store: 'memory',
    ttl: 300, // 5 minutes
    max: 100
  },
  production: {
    enabled: true,
    store: 'redis',
    prefix: 'cache:',
    ttl: 3600, // 1 hour
    redis: {
      host: process.env.REDIS_HOST,
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: 1
    }
  },
  test: {
    enabled: false
  }
};

const env = process.env.NODE_ENV || 'development';
module.exports = config[env];
