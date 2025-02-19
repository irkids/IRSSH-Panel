import axios from 'axios';

class ApiService {
  constructor() {
    this.baseURL = process.env.REACT_APP_API_URL || '/api/v1';
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json'
      }
    });

    // Add request interceptor
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Add response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response) {
          switch (error.response.status) {
            case 401:
              // Handle unauthorized
              localStorage.removeItem('token');
              window.location.href = '/login';
              break;
            case 403:
              // Handle forbidden
              console.error('Access forbidden');
              break;
            case 404:
              // Handle not found
              console.error('Resource not found');
              break;
            case 500:
              // Handle server error
              console.error('Server error');
              break;
            default:
              console.error('API error');
          }
        }
        return Promise.reject(error);
      }
    );
  }

  // Generic request method
  async request(method, url, data = null, config = {}) {
    try {
      const response = await this.client.request({
        method,
        url,
        data,
        ...config
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // HTTP methods
  async get(url, config = {}) {
    return this.request('get', url, null, config);
  }

  async post(url, data, config = {}) {
    return this.request('post', url, data, config);
  }

  async put(url, data, config = {}) {
    return this.request('put', url, data, config);
  }

  async delete(url, config = {}) {
    return this.request('delete', url, null, config);
  }

  async patch(url, data, config = {}) {
    return this.request('patch', url, data, config);
  }

  // Error handling
  handleError(error) {
    if (error.response) {
      // Server responded with error
      const { status, data } = error.response;
      return {
        status,
        message: data.message || 'An error occurred',
        data: data
      };
    } else if (error.request) {
      // Request made but no response
      return {
        status: 0,
        message: 'No response from server',
        data: null
      };
    } else {
      // Request setup error
      return {
        status: 0,
        message: error.message,
        data: null
      };
    }
  }

  // Auth methods
  setToken(token) {
    localStorage.setItem('token', token);
  }

  getToken() {
    return localStorage.getItem('token');
  }

  removeToken() {
    localStorage.removeItem('token');
  }

  // Utility methods
  isAuthenticated() {
    return !!this.getToken();
  }
}

export const api = new ApiService();

// React hook for using the API
export const useApi = () => {
  return api;
};
