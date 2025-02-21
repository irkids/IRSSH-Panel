const os = require('os');
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);

class SystemMetricsCollector {
  async collect() {
    const metrics = {
      cpu: await this.getCPUMetrics(),
      memory: await this.getMemoryMetrics(),
      disk: await this.getDiskMetrics(),
      network: await this.getNetworkMetrics(),
      system: await this.getSystemInfo()
    };

    return metrics;
  }

  async getCPUMetrics() {
    const cpus = os.cpus();
    const loadAvg = os.loadavg();

    const { stdout: topOutput } = await exec('top -bn1 | grep "Cpu(s)"');
    const cpuUsage = parseFloat(topOutput.match(/(\d+\.\d+)\s+id/)[1]);

    return {
      cores: cpus.length,
      model: cpus[0].model,
      speed: cpus[0].speed,
      loadAverage: {
        '1min': loadAvg[0],
        '5min': loadAvg[1],
        '15min': loadAvg[2]
      },
      usage: {
        idle: cpuUsage,
        used: 100 - cpuUsage
      }
    };
  }

  async getMemoryMetrics() {
    const total = os.totalmem();
    const free = os.freemem();
    const used = total - free;

    return {
      total,
      free,
      used,
      usedPercentage: (used / total * 100).toFixed(2)
    };
  }

  async getDiskMetrics() {
    const { stdout } = await exec('df -h /');
    const [, total, used, available] = stdout.split('\n')[1].split(/\s+/);

    return {
      total,
      used,
      available,
      mountPoint: '/'
    };
  }

  async getNetworkMetrics() {
    const interfaces = os.networkInterfaces();
    const netStats = {};

    for (const [name, addresses] of Object.entries(interfaces)) {
      netStats[name] = addresses.map(addr => ({
        address: addr.address,
        family: addr.family,
        internal: addr.internal
      }));
    }

    return netStats;
  }

  async getSystemInfo() {
    return {
      platform: os.platform(),
      release: os.release(),
      type: os.type(),
      uptime: os.uptime(),
      hostname: os.hostname()
    };
  }
}

module.exports = new SystemMetricsCollector();
