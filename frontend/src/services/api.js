
import axios from 'axios';

// Base URL points to your running Express server
const API_URL = 'http://localhost:5000/api';

const api = axios.create({
    baseURL: API_URL,
});

// Automatically attach the JWT token to every request if the user is logged in
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('trustvault_token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

export const authService = {
    login: (email, password) => api.post('/auth/login', { email, password }),
    register: (email, password, role) => api.post('/auth/register', { email, password, role })
};

export const documentService = {
    getAll: () => api.get('/documents'),
    upload: (formData) => api.post('/documents/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
    }),
    download: (documentId) => api.get(`/documents/${documentId}/download`, { responseType: 'blob' }),
    grantAccess: (documentId, targetUserId, accessLevel) => api.post(`/documents/${documentId}/grant`, { targetUserId, accessLevel }),
    revokeAccess: (documentId, targetUserId) => api.post(`/documents/${documentId}/revoke`, { targetUserId })
};

export const adminService = {
    getAuditLogs: () => api.get('/admin/audit-logs')
};

export default api;