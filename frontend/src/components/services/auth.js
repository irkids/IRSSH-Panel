import { api } from './api';

class AuthService {
  async login(credentials) {
    try {
      const response = await api.post('/auth/login', credentials);
      if (response.token) {
        api.setToken(response.token);
        return response;
      }
      throw new Error('Login failed');
    } catch (error) {
      throw error;
    }
  }

  async logout() {
    try {
      await api.post('/auth/logout');
      api.removeToken();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      api.removeToken();
      window.location.href = '/login';
    }
  }

  async register(userData) {
    try {
      const response = await api.post('/auth/register', userData);
      if (response.token) {
        api.setToken(response.token);
        return response;
      }
      throw new Error('Registration failed');
    } catch (error) {
      throw error;
    }
  }

  async verifyToken() {
    try {
      const response = await api.get('/auth/verify');
      return response.valid;
    } catch (error) {
      api.removeToken();
      return false;
    }
  }

  async resetPassword(email) {
    try {
      await api.post('/auth/reset-password', { email });
      return true;
    } catch (error) {
      throw error;
    }
  }

  async changePassword(currentPassword, newPassword) {
    try {
      await api.post('/auth/change-password', {
        currentPassword,
        newPassword
      });
      return true;
    } catch (error) {
      throw error;
    }
  }

  async updateProfile(profileData) {
    try {
      const response = await api.put('/auth/profile', profileData);
      return response;
    } catch (error) {
      throw error;
    }
  }

  isAuthenticated() {
    return api.isAuthenticated();
  }

  getUser() {
    try {
      const token = api.getToken();
      if (!token) return null;
      
      // Decode JWT token
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));

      return JSON.parse(jsonPayload);
    } catch (error) {
      console.error('Error decoding token:', error);
      return null;
    }
  }
}

export const authService = new AuthService();

// React hook for using auth
export const useAuth = () => {
  return authService;
};
