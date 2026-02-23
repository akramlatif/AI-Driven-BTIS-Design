// API Service Layer for BTIS Frontend
// Handles all communication with the Flask backend

const API_BASE_URL = 'http://localhost:5000/api';

// Token management
export const getToken = (): string | null => localStorage.getItem('btis_token');
export const setToken = (token: string): void => localStorage.setItem('btis_token', token);
export const removeToken = (): void => localStorage.removeItem('btis_token');

// Base fetch wrapper with auth
async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = getToken();
  
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(token && { Authorization: `Bearer ${token}` }),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new Error(error.message || error.error || `HTTP ${response.status}`);
  }

  return response.json();
}

// Auth API
export const authAPI = {
  login: (username: string, password: string) =>
    apiFetch<{ access_token: string; user: any }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  logout: () =>
    apiFetch<{ message: string }>('/auth/logout', { method: 'POST' }),

  verify: () =>
    apiFetch<{ valid: boolean; user: any }>('/auth/verify'),
};

// Dashboard API
export const dashboardAPI = {
  getOverview: () =>
    apiFetch<any>('/dashboard/overview'),

  getUsersAtRisk: () =>
    apiFetch<any>('/dashboard/users-at-risk'),

  getRecentAlerts: () =>
    apiFetch<any>('/dashboard/recent-alerts'),
};

// Alerts API
export const alertsAPI = {
  getAll: (params?: { severity?: string; status?: string; limit?: number }) => {
    const query = params ? '?' + new URLSearchParams(params as any).toString() : '';
    return apiFetch<{ alerts: any[]; total: number }>(`/alerts/${query}`);
  },

  getOne: (alertId: string) =>
    apiFetch<any>(`/alerts/${alertId}`),

  acknowledge: (alertId: string) =>
    apiFetch<any>(`/alerts/${alertId}/acknowledge`, { method: 'POST' }),

  resolve: (alertId: string, resolution?: string) =>
    apiFetch<any>(`/alerts/${alertId}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ resolution }),
    }),

  getStats: () =>
    apiFetch<any>('/alerts/stats'),
};

// Users API
export const usersAPI = {
  getAll: (params?: { flagged?: boolean }) => {
    const query = params ? '?' + new URLSearchParams(params as any).toString() : '';
    return apiFetch<{ users: any[] }>(`/users/${query}`);
  },

  getOne: (userId: number) =>
    apiFetch<any>(`/users/${userId}`),

  flag: (userId: number, flag: boolean, reason?: string) =>
    apiFetch<any>(`/users/${userId}/flag`, {
      method: 'POST',
      body: JSON.stringify({ flag, reason }),
    }),

  getRiskHistory: (userId: number) =>
    apiFetch<any>(`/users/${userId}/risk-history`),
};

// ML API
export const mlAPI = {
  getStatus: () =>
    apiFetch<any>('/ml/status'),

  train: () =>
    apiFetch<any>('/ml/train', { method: 'POST' }),

  detect: (userId?: number) =>
    apiFetch<any>('/ml/detect', {
      method: 'POST',
      body: JSON.stringify({ user_id: userId }),
    }),
};

// Behavior API
export const behaviorAPI = {
  getProfile: (userId: number) =>
    apiFetch<any>(`/behavior/profile/${userId}`),

  getTimeline: (userId: number) =>
    apiFetch<any>(`/behavior/timeline/${userId}`),
};

// Export to CSV utility
export function exportToCSV(data: any[], filename: string) {
  if (data.length === 0) return;
  
  const headers = Object.keys(data[0]);
  const csv = [
    headers.join(','),
    ...data.map(row => headers.map(h => JSON.stringify(row[h] ?? '')).join(','))
  ].join('\n');
  
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
