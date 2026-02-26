// auth-client.js — Copy this to your app
// Reusable authentication client for cross-app auth with the unified auth portal

const AUTH_PORTAL_URL = 'https://auth-portal-xxx.vercel.app'; // ← Change this to your auth portal URL

/**
 * Check for token in URL (from auth portal redirect) or localStorage.
 * If no token found, redirects to auth portal login page.
 * @returns {boolean} true if authenticated, false if redirecting
 */
function checkAuthOrRedirect() {
  const params = new URLSearchParams(window.location.search);
  const tokenFromUrl = params.get('token');
  if (tokenFromUrl) {
    localStorage.setItem('token', tokenFromUrl);
    params.delete('token');
    window.history.replaceState({}, '', window.location.pathname + (params.toString() ? '?' + params : ''));
  }
  const token = localStorage.getItem('token');
  if (!token) {
    window.location.href = AUTH_PORTAL_URL + '/?redirect=' + encodeURIComponent(window.location.href);
    return false;
  }
  return true;
}

/**
 * Get authorization headers for API calls.
 * @returns {Object} Headers object with Content-Type and Authorization
 */
function authHeaders() {
  const token = localStorage.getItem('token');
  return { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) };
}

/**
 * Logout: clear token and redirect to auth portal.
 */
function logout() {
  localStorage.removeItem('token');
  window.location.href = AUTH_PORTAL_URL;
}

/**
 * Get current user info from auth portal.
 * If token is invalid, automatically logs out.
 * @returns {Promise<Object|null>} User object or null
 */
async function getUser() {
  const res = await fetch(AUTH_PORTAL_URL + '/api/me', { headers: authHeaders() });
  if (!res.ok) { logout(); return null; }
  return res.json();
}

/**
 * Get user's API settings from auth portal.
 * @returns {Promise<Object|null>} Settings object or null
 */
async function getApiSettings() {
  const res = await fetch(AUTH_PORTAL_URL + '/api/settings', { headers: authHeaders() });
  if (!res.ok) return null;
  return res.json();
}
