const client = require('prom-client');
const register = new client.Registry();

// Enable default metrics
client.collectDefaultMetrics({
  register,
  prefix: 'irssh_'
});

// Custom metrics
const activeConnections = new client.Gauge({
  name: 'irssh_active_connections',
  help: 'Number of active connections',
  labelNames: ['protocol']
});

const requestDuration = new client.Histogram({
  name: 'irssh_request_duration_seconds',
  help: 'Duration of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.5, 1, 2, 5]
});

const errorCounter = new client.Counter({
  name: 'irssh_errors_total',
  help: 'Total number of errors',
  labelNames: ['type', 'protocol']
});

const protocolTraffic = new client.Counter({
  name: 'irssh_protocol_traffic_bytes',
  help: 'Total protocol traffic in bytes',
  labelNames: ['protocol', 'direction']
});

const userActions = new client.Counter({
  name: 'irssh_user_actions_total',
  help: 'Total number of user actions',
  labelNames: ['action', 'user']
});

const sessionDuration = new client.Histogram({
  name: 'irssh_session_duration_seconds',
  help: 'Duration of user sessions',
  labelNames: ['protocol'],
  buckets: [300, 900, 1800, 3600, 7200]
});

register.registerMetric(activeConnections);
register.registerMetric(requestDuration);
register.registerMetric(errorCounter);
register.registerMetric(protocolTraffic);
register.registerMetric(userActions);
register.registerMetric(sessionDuration);

module.exports = {
  register,
  metrics: {
    activeConnections,
    requestDuration,
    errorCounter,
    protocolTraffic,
    userActions,
    sessionDuration
  }
};
