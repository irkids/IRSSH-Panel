const config = {
  development: {
    enabled: true,
    interval: 30000,
    metrics: {
      cpu: true,
      memory: true,
      disk: true,
      network: true
    },
    prometheus: {
      enabled: true,
      port: 9090
    },
    alerts: {
      cpu: {
        warning: 70,
        critical: 90
      },
      memory: {
        warning: 80,
        critical: 95
      },
      disk: {
        warning: 80,
        critical: 90
      }
    }
  },
  production: {
    enabled: true,
    interval: 60000,
    metrics: {
      cpu: true,
      memory: true,
      disk: true,
      network: true,
      postgres: true,
      redis: true
    },
    prometheus: {
      enabled: true,
      port: 9090,
      path: '/metrics'
    },
    alerts: {
      cpu: {
        warning: 70,
        critical: 90
      },
      memory: {
        warning: 80,
        critical: 95
      },
      disk: {
        warning: 80,
        critical: 90
      },
      connections: {
        warning: 1000,
        critical: 2000
      }
    },
    retention: {
      metrics: '30d',
      logs: '90d'
    }
  },
  test: {
    enabled: false
  }
};

const env = process.env.NODE_ENV || 'development';
module.exports = config[env];
