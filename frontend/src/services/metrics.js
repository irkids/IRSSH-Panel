import { apiService } from './api';

class MetricsService {
  async getSystemMetrics() {
    return apiService.get('/metrics/system');
  }

  async getDashboardMetrics() {
    return apiService.get('/metrics/dashboard');
  }

  async getUserMetrics(userId) {
    return apiService.get(`/metrics/users/${userId}`);
  }

  async getProtocolMetrics(protocolId, period) {
    return apiService.get(`/metrics/protocols/${protocolId}`, { period });
  }

  async getErrorMetrics() {
    return apiService.get('/metrics/errors');
  }

  async getPerformanceMetrics() {
    return apiService.get('/metrics/performance');
  }
}

export const metricsService = new MetricsService();
