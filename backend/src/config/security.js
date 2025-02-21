const config = {
  development: {
    jwt: {
      secret: process.env.JWT_SECRET || 'dev-secret',
      expiresIn: '24h'
    },
    session: {
      secret: process.env.SESSION_SECRET || 'dev-session-secret',
      maxAge: 86400000 // 24 hours
    },
    rateLimit: {
      enabled: true,
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100
    },
    cors: {
      origin: '*',
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization']
    },
    encryption: {
      algorithm: 'aes-256-gcm',
      ivLength: 16,
      saltLength: 32,
      tagLength: 16,
      iterations: 100000,
      keyLength: 32
    }
  },
  production: {
    jwt: {
      secret: process.env.JWT_SECRET,
      expiresIn: '12h'
    },
    session: {
      secret: process.env.SESSION_SECRET,
      maxAge: 43200000 // 12 hours
    },
    rateLimit: {
      enabled: true,
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100
    },
    cors: {
      origin: process.env.ALLOWED_ORIGINS.split(','),
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true
    },
    encryption: {
      algorithm: 'aes-256-gcm',
      ivLength: 16,
      saltLength: 32,
      tagLength: 16,
      iterations: 100000,
      keyLength: 32
    },
    ssl: {
      enabled: true,
      key: process.env.SSL_KEY_PATH,
      cert: process.env.SSL_CERT_PATH
    }
  },
  test: {
    jwt: {
      secret: 'test-secret',
      expiresIn: '1h'
    },
    session: {
      secret: 'test-session-secret',
      maxAge: 3600000 // 1 hour
    },
    rateLimit: {
      enabled: false
    },
    cors: {
      origin: '*'
    },
    encryption: {
      algorithm: 'aes-256-gcm',
      ivLength: 16,
      saltLength: 32,
      tagLength: 16,
      iterations: 100000,
      keyLength: 32
    }
  }
};

const env = process.env.NODE_ENV || 'development';
module.exports = config[env];
