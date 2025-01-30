import axios from '../config/axios';

export const api = {
  auth: {
    login: (credentials) => axios.post('/api/auth/login', credentials),
    logout: () => axios.post('/api/auth/logout'),
  },
  users: {
    getAll: () => axios.get('/api/users'),
    getById: (id) => axios.get(`/api/users/${id}`),
    create: (user) => axios.post('/api/users', user),
    update: (id, user) => axios.put(`/api/users/${id}`, user),
    delete: (id) => axios.delete(`/api/users/${id}`),
  },
  protocols: {
    getStats: () => axios.get('/api/monitoring/protocols'),
    getUsers: (protocol) => axios.get(`/api/protocols/${protocol}/users`),
  },
  monitoring: {
    getSystemInfo: () => axios.get('/api/monitoring/system'),
    getBandwidth: () => axios.get('/api/monitoring/bandwidth'),
  },
  settings: {
    get: () => axios.get('/api/settings'),
    update: (settings) => axios.put('/api/settings', settings),
    backup: () => axios.post('/api/settings/backup'),
    restore: (file) => {
      const formData = new FormData();
      formData.append('backup', file);
      return axios.post('/api/settings/restore', formData);
    },
  },
};
