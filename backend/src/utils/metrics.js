const prometheus = require('prom-client');
const config = require('../config/monitor');

// Initialize Prometheus registry
const register = new prometheus.Registry();

// Create metrics
const metrics = {
  // System metrics
  cpuUsage: new prometheus.Gauge({
    name: 'system_cpu_usage',
    help: 'System CPU usage percentage'
  }),

  memoryUsage: new prometheus.Gauge({
    name: 'system_memory_usage',
    help: 'System memory usage percentage'
  }),

  diskUsage: new prometheus.Gauge({
    name: 'system_disk_usage',
    help: 'System disk usage percentage'
  }),

  // Protocol metrics
  activeConnections: new prometheus.Gauge({
    name: 'protocol_active_connections',
    help: 'Number of active connections per protocol',
    labelNames: ['protocol']
  }),

  connectionDuration: new prometheus.Histogram({
    name: 'protocol_connection_duration_seconds',
    help: 'Duration of connections',
    labelNames: ['protocol'],
    buckets: [60, 300, 600, 1800, 3600, 7200]
  }),

  bandwidthUsage: new prometheus.Counter({
    name: 'protocol_bandwidth_bytes',
    help: 'Total bandwidth usage in bytes',
    labelNames: ['protocol', 'direction']
  }),

  // Application metrics
  requestDuration: new prometheus.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests',
    labelNames: ['method', 'route', 'status'],
    buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
  }),

  errorCounter: new prometheus.Counter({
    name: 'application_errors_total',
    help: 'Total number of application errors',
    labelNames: ['type']
  })
};

// Register all metrics
Object.values(metrics).forEach(metric => register.registerMetric(metric));

class MetricsCollector {
  constructor() {
    this.enabled = config.enabled;
    this.interval = config.interval;
    this.collector = null;
  }

  start() {
    if (!this.enabled) return;

    this.collector = setInterval(async () => {
      await this.collectMetrics();
    }, this.interval);
  }

  stop() {
    if (this.collector) {
      clearInterval(this.collector);
    }
  }

  async collectMetrics() {
    try {
      // Collect system metrics
      const systemMetrics = await this.collectSystemMetrics();
      metrics.cpuUsage.set(systemMetrics.cpu);
      metrics.memoryUsage.set(systemMetrics.memory);
      metrics.diskUsage.set(systemMetrics.disk);

      // Collect protocol metrics
      const protocolMetrics = await this.collectProtocolMetrics();
      Object.entries(protocolMetrics).forEach(([protocol, data]) => {
        metrics.activeConnections.set({ protocol }, data.connections);
        metrics.bandwidthUsage.inc({
          protocol,
          direction: 'in'
        }, data.bandwidth.in);
        metrics.bandwidthUsage.inc({
          protocol,
          direction: 'out'
        }, data.bandwidth.out);
      });
    } catch (error) {
      console.error('Error collecting metrics:', error);
    }
  }

  async collectSystemMetrics() {
    // Implementation of system metrics collection
    return {
      cpu: 0,
      memory: 0,
      disk: 0
    };
  }

  async collectProtocolMetrics() {
    // Implementation of protocol metrics collection
    return {};
  }

  getMetrics() {
    return register.metrics();
  }

  recordRequest(method, route, status, duration) {
    if (!this.enabled) return;

    metrics.requestDuration.observe(
      { method, route, status },
      duration
    );
  }

  recordError(type) {
    if (!this.enabled) return;

    metrics.errorCounter.inc({ type });
  }
}

module.exports = new MetricsCollector();
