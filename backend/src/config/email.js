const config = {
  development: {
    enabled: true,
    from: 'IRSSH Panel <noreply@localhost>',
    transport: {
      host: 'localhost',
      port: 1025,
      secure: false,
      auth: {
        user: null,
        pass: null
      }
    },
    templates: {
      dir: './templates/email',
      options: {
        strict: true
      }
    }
  },
  production: {
    enabled: true,
    from: process.env.EMAIL_FROM,
    transport: {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    },
    templates: {
      dir: '/opt/irssh/templates/email',
      options: {
        strict: true
      }
    }
  },
  test: {
    enabled: false
  }
};

const env = process.env.NODE_ENV || 'development';
module.exports = config[env];
