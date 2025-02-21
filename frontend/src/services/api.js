import axios from 'axios';
import { authService } from './auth';

class ApiService {
  constructor() {
    this.api = axios.create({
      baseURL: process.env.REACT_APP_API_URL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    this.setupInterceptors();
  }

  setupInterceptors() {
    this.api.interceptors.request.use(
      (config) => {
        const token = authService.getToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    this.api.interceptors.response.use(
      (response) => response.data,
      (error) => {
        if (error.response?.status === 401) {
          authService.logout();
          window.location.href = '/login';
        }
        return Promise.reject(error.response?.data || error);
      }
    );
  }

  // Generic CRUD methods
  async get(endpoint, params = {}) {
    return this.api.get(endpoint, { params });
  }

  async post(endpoint, data = {}) {
    return this.api.post(endpoint, data);
  }

  async put(endpoint, data = {}) {
    return this.api.put(endpoint, data);
  }

  async delete(endpoint) {
    return this.api.delete(endpoint);
  }

  // Specific API methods
  async getSystemMetrics() {
    return this.get('/metrics/system');
  }

  async getProtocolMetrics(id, period) {
    return this.get(`/metrics/protocols/${id}`, { period });
  }

  async getUsers(params) {
    return this.get('/users', params);
  }

  async getProtocols(params) {
    return this.get('/protocols', params);
  }
}

export const apiService = new ApiService();
