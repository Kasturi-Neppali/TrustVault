import axios from 'axios';

// Base API URL: Defaults to localhost:5000/api in development, configurable via environment
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true // Crucial: Transmit HttpOnly session cookies across origins
});

// Request Interceptor: Attach Bearer token from localStorage as fallback / dual-auth
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('trustvault_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Response Interceptor: Standardize error extraction and handle 401s
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // If token expired or unauthorized, clear storage
    if (error.response && error.response.status === 401) {
      if (!error.config.url.includes('/auth/login') && !error.config.url.includes('/auth/register')) {
        localStorage.removeItem('trustvault_token');
        localStorage.removeItem('trustvault_user');
      }
    }
    return Promise.reject(error);
  }
);

export const authService = {
  login: (email, password) => api.post('/auth/login', { email, password }),
  register: (name, email, password) => api.post('/auth/register', { name, email, password }),
  logout: () => api.post('/auth/logout'),
  getMe: () => api.get('/auth/me')
};

export const documentService = {
  getAll: () => api.get('/documents'),
  getById: (id) => api.get(`/documents/${id}`),
  upload: (formData) => api.post('/documents/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
  download: (documentId) => api.get(`/documents/${documentId}/download`, { responseType: 'blob' }),
  updateMetadata: (documentId, data) => api.patch(`/documents/${documentId}`, data),
  delete: (documentId) => api.delete(`/documents/${documentId}`),
  getPermissions: (documentId) => api.get(`/documents/${documentId}/permissions`),
  share: (documentId, targetEmail, accessLevel) => api.post(`/documents/${documentId}/share`, { targetEmail, accessLevel }),
  revokeAccess: (documentId, permissionId) => api.delete(`/documents/${documentId}/permissions/${permissionId}`),
  // Backward compatibility
  grantAccess: (documentId, targetUserId, accessLevel) => api.post(`/documents/${documentId}/grant`, { targetUserId, accessLevel })
};

export const adminService = {
  getAuditLogs: (params = {}) => api.get('/admin/audit-logs', { params }),
  verifyAuditLedger: () => api.get('/admin/audit-logs/verify')
};

export default api;
