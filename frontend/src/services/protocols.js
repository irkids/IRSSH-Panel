import { apiService } from './api';

class ProtocolService {
  async getAllProtocols() {
    return apiService.get('/protocols');
  }

  async getProtocol(id) {
    return apiService.get(`/protocols/${id}`);
  }

  async createProtocol(data) {
    return apiService.post('/protocols', data);
  }

  async updateProtocol(id, data) {
    return apiService.put(`/protocols/${id}`, data);
  }

  async deleteProtocol(id) {
    return apiService.delete(`/protocols/${id}`);
  }

  async getProtocolMetrics(id, period = '24h') {
    return apiService.get(`/protocols/${id}/metrics`, { period });
  }

  async toggleProtocol(id, enabled) {
    return apiService.put(`/protocols/${id}`, { enabled });
  }

  async getProtocolLogs(id, filters = {}) {
    return apiService.get(`/protocols/${id}/logs`, filters);
  }
}

export const protocolService = new ProtocolService();
