import { apiService } from './api';

class DashboardService {
  async getSystemStats() {
    return apiService.get('/dashboard/stats');
  }

  async getChartData(type, period) {
    return apiService.get('/dashboard/chart', { type, period });
  }

  async getTopProtocols() {
    return apiService.get('/dashboard/top-protocols');
  }

  async getRecentActivity() {
    return apiService.get('/dashboard/recent-activity');
  }

  async getPerformanceMetrics() {
    return apiService.get('/dashboard/performance');
  }

  async getErrorSummary() {
    return apiService.get('/dashboard/errors');
  }
}

export const dashboardService = new DashboardService();
