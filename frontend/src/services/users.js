import { apiService } from './api';

class UserService {
  async getUsers(params = {}) {
    return apiService.get('/users', params);
  }

  async getUser(id) {
    return apiService.get(`/users/${id}`);
  }

  async createUser(data) {
    return apiService.post('/users', data);
  }

  async updateUser(id, data) {
    return apiService.put(`/users/${id}`, data);
  }

  async deleteUser(id) {
    return apiService.delete(`/users/${id}`);
  }

  async getUserActivity(id, params = {}) {
    return apiService.get(`/users/${id}/activity`, params);
  }

  async getUserMetrics(id) {
    return apiService.get(`/users/${id}/metrics`);
  }
}

export const userService = new UserService();
