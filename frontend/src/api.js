const base = '/api';

export async function request(path, token, options = {}) {
  const response = await fetch(`${base}${path}`, {
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers }
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}

export const login = (email, password) => request('/auth/login', null, { method: 'POST', body: JSON.stringify({ email, password }) });
