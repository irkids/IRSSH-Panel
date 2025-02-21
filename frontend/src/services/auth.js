import { apiService } from './api';
import jwt_decode from 'jwt-decode';

class AuthService {
  constructor() {
    this.token = localStorage.getItem('token');
    this.user = null;
    if (this.token) {
      this.user = this.decodeToken(this.token);
    }
  }

  async login(credentials) {
    try {
      const response = await apiService.post('/auth/login', credentials);
      this.setToken(response.token);
      this.user = this.decodeToken(response.token);
      return response;
    } catch (error) {
      throw new Error(error.message);
    }
  }

  async logout() {
    try {
      await apiService.post('/auth/logout');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      this.clearToken();
      this.user = null;
    }
  }

  async register(userData) {
    const response = await apiService.post('/auth/register', userData);
    this.setToken(response.token);
    this.user = this.decodeToken(response.token);
    return response;
  }

  setToken(token) {
    localStorage.setItem('token', token);
    this.token = token;
  }

  getToken() {
    return this.token;
  }

  clearToken() {
    localStorage.removeItem('token');
    this.token = null;
  }

  decodeToken(token) {
    try {
      return jwt_decode(token);
    } catch (error) {
      return null;
    }
  }

  isAuthenticated() {
    return !!this.token && this.user && !this.isTokenExpired();
  }

  isTokenExpired() {
    if (!this.user?.exp) return true;
    return Date.now() >= this.user.exp * 1000;
  }

  hasRole(role) {
    return this.user?.role === role;
  }

  async refreshToken() {
    try {
      const response = await apiService.post('/auth/refresh');
      this.setToken(response.token);
      this.user = this.decodeToken(response.token);
      return response;
    } catch (error) {
      this.clearToken();
      this.user = null;
      throw error;
    }
  }
}

export const authService = new AuthService();
