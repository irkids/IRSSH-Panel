import { api } from './api';

class ProtocolService {
  async getAllProtocols() {
    try {
      return await api.get('/protocols');
    } catch (error) {
      throw error;
    }
  }

  async getProtocol(id) {
    try {
      return await api.get(`/protocols/${id}`);
    } catch (error) {
      throw error;
    }
  }

  async createProtocol(protocolData) {
    try {
      return await api.post('/protocols', protocolData);
    } catch (error) {
      throw error;
    }
  }

  async updateProtocol(id, protocolData) {
    try {
      return await api.put(`/protocols/${id}`, protocolData);
    } catch (error) {
      throw error;
    }
  }

  async deleteProtocol(id) {
    try {
      return await api.delete(`/protocols/${id}`);
    } catch (error) {
      throw error;
    }
  }

  async enableProtocol(id) {
    try {
      return await api.put(`/protocols/${id}/enable`);
    } catch (error) {
      throw error;
    }
  }

  async disableProtocol(id) {
    try {
      return await api.put(`/protocols/${id}/disable`);
    } catch (error) {
      throw error;
    }
  }

  async getProtocolMetrics(id) {
    try {
      return await api.get(`/protocols/${id}/metrics`);
    } catch (error) {
      throw error;
    }
  }

  async getProtocolLogs(id, params = {}) {
    try {
      return await api.get(`/protocols/${id}/logs`, { params });
    } catch (error) {
      throw error;
    }
  }

  async testProtocolConnection(id) {
    try {
      return await api.post(`/protocols/${id}/test`);
    } catch (error) {
      throw error;
    }
  }

  async updateProtocolConfig(id, config) {
    try {
      return await api.put(`/protocols/${id}/config`, config);
    } catch (error) {
      throw error;
    }
  }

  async getProtocolStatus(id) {
    try {
      return await api.get(`/protocols/${id}/status`);
    } catch (error) {
      throw error;
    }
  }
}

export const protocolService = new ProtocolService();

// React hook for using protocols
export const useProtocols = () => {
  return protocolService;
};
