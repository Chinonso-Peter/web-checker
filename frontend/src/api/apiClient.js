const API_BASE = import.meta.env.VITE_API_BASE || "/api";
const AUTH_KEY = "webCheckerAuth";

export function getAuth() {
  try {
    const raw = localStorage.getItem(AUTH_KEY);
    const data = raw ? JSON.parse(raw) : null;
    return data && data.token ? data : null;
  } catch {
    return null;
  }
}

export function setAuth(auth) {
  localStorage.setItem(AUTH_KEY, JSON.stringify(auth));
}

export function clearAuth() {
  localStorage.removeItem(AUTH_KEY);
}

function redirectToLogin() {
  const { pathname } = window.location;
  if (
    pathname !== "/login" &&
    pathname !== "/register"
  ) {
    window.location.href = "/login";
  }
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const auth = getAuth();
  if (auth) headers["Authorization"] = `Bearer ${auth.token}`;

  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...headers },
    ...options,
  });

  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!res.ok) {
    if (res.status === 401 && path !== "/auth/login" && path !== "/auth/register") {
      clearAuth();
      redirectToLogin();
    }
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

export const registerUser = (payload) =>
  request("/auth/register", { method: "POST", body: JSON.stringify(payload) });

export const loginUser = (payload) =>
  request("/auth/login", { method: "POST", body: JSON.stringify(payload) });

export const fetchCurrentUser = () => request("/auth/me");

export const logoutUser = () => request("/auth/logout", { method: "POST" });

export const updateUser = (payload) =>
  request("/auth/me", { method: "PATCH", body: JSON.stringify(payload) });

export const deleteAccount = (password) =>
  request("/auth/me", { method: "DELETE", body: JSON.stringify({ password }) });

export const forgotPassword = (email) =>
  request("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });

export const forgotUsername = (email) =>
  request("/auth/forgot-username", { method: "POST", body: JSON.stringify({ email }) });

export const resetPassword = (token, password) =>
  request("/auth/reset-password", { method: "POST", body: JSON.stringify({ token, password }) });

export const verifyEmail = (token) =>
  request("/auth/verify-email", { method: "POST", body: JSON.stringify({ token }) });

export const resendVerification = (email) =>
  request("/auth/resend-verification", { method: "POST", body: JSON.stringify({ email }) });

export const startScan = (targetUrl, parameters, cookies, headers) =>
  request("/scan/start", {
    method: "POST",
    body: JSON.stringify({ targetUrl, parameters, cookies, headers }),
  });

export const checkScanStatus = (scanId) =>
  request(`/scan/status/${scanId}`);

export const getScanResult = (scanId) =>
  request(`/scan/result/${scanId}`);

export const getReport = (scanId) =>
  request(`/report/generate/${scanId}`);

export const getScanHistory = () =>
  request("/report/history");

export async function downloadReportPdf(scanId) {
  const auth = getAuth();
  const headers = auth ? { Authorization: `Bearer ${auth.token}` } : {};
  const res = await fetch(`${API_BASE}/report/pdf/${scanId}`, {
    headers,
    credentials: "include",
  });

  if (!res.ok) {
    if (res.status === 401) {
      clearAuth();
      redirectToLogin();
    }
    let message = `Request failed (${res.status})`;
    try {
      const data = await res.json();
      message = data.error || message;
    } catch {
      /* not JSON */
    }
    throw new Error(message);
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `web_checker_report_${scanId}.pdf`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}