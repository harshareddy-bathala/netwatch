/**
 * api.js - NetWatch API Client (ES Module)
 * ==========================================
 * Clean fetch wrapper with timeout, retry, and every endpoint.
 * Exports a singleton `api` object consumed by app.js and components.
 */

const BASE  = window.location.origin + '/api';
const TIMEOUT = 10000;
const MAX_RETRIES = 2;
const RETRY_DELAY = 800;
const HEADERS = { 'Content-Type': 'application/json', Accept: 'application/json' };

/**
 * Optional API key for authenticated deployments.
 * Read from localStorage on load.
 */
let _apiKey = localStorage.getItem('netwatch-api-key') || '';

/* ── Core fetch ────────────────────────────────────── */

async function request(endpoint, opts = {}, retries = MAX_RETRIES) {
  const url = BASE + endpoint;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT);

  // Inject X-API-Key header when configured
  const headers = { ...HEADERS, ...opts.headers };
  if (_apiKey) headers['X-API-Key'] = _apiKey;

  try {
    const res = await fetch(url, {
      ...opts,
      headers,
      signal: ctrl.signal,
    });
    clearTimeout(timer);

    let data = null;
    try { data = await res.json(); } catch (_) { /* empty */ }

    if (!res.ok) {
      if (res.status >= 500 && retries > 0) {
        await sleep(RETRY_DELAY);
        return request(endpoint, opts, retries - 1);
      }
      return { error: true, status: res.status, message: (data && data.message) || res.statusText };
    }
    return data;
  } catch (err) {
    clearTimeout(timer);
    if (retries > 0) {
      await sleep(RETRY_DELAY);
      return request(endpoint, opts, retries - 1);
    }
    console.error(`[api] ${endpoint}:`, err.message);
    return { error: true, status: 0, message: err.message || 'Network error' };
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ── Public API ────────────────────────────────────── */

const api = {
  // Dashboard (single batch endpoint)
  getDashboard:     ()                   => request('/dashboard'),

  // Stats
  getRealtimeStats: ()                   => request('/stats/realtime'),
  getHealthScore:   ()                   => request('/health'),

  // Devices
  getAllDevices:     (limit=50, offset=0) => request(`/devices?limit=${limit}&offset=${offset}`),
  getDeviceDetails: (ip)                 => request(`/devices/${encodeURIComponent(ip)}`),
  updateDeviceName: (ip, hostname, mac)   => request('/devices/update-name', {
      method: 'POST', body: JSON.stringify({ ip_address: ip, hostname, mac }),
  }),

  // Protocols & Traffic
  getProtocols:       (hours=1)                      => request(`/protocols?hours=${hours}`),
  getBandwidthDual:   (hours=1, interval='minute')   => request(`/bandwidth/dual?hours=${hours}&interval=${interval}`),

  // Alerts
  getAlerts: (limit=50, severity=null, acknowledged=null) => {
    let url = `/alerts?limit=${limit}`;
    if (severity) url += `&severity=${severity}`;
    if (acknowledged !== null) url += `&acknowledged=${acknowledged}`;
    return request(url);
  },
  getAlertStats:     ()        => request('/alerts/stats'),
  acknowledgeAlert:  (id)      => request(`/alerts/${id}/acknowledge`, { method: 'POST' }),
  resolveAlert:      (id)      => request(`/alerts/${id}/resolve`,     { method: 'POST' }),

  // Interface
  getInterfaceStatus: () => request('/interface/status'),
  refreshInterface:   () => request('/interface/refresh', { method: 'POST' }),

  // Data export
  getExportUrl: (fmt='csv', type='devices', hours=24, deviceIp=null) => {
    let url = `${BASE}/export/${fmt}?type=${type}&hours=${hours}`;
    if (deviceIp) url += `&device_ip=${encodeURIComponent(deviceIp)}`;
    return url;
  },

  // Custom alert rules
  getAlertRules:    ()            => request('/alert-rules'),
  createAlertRule:  (rule)        => request('/alert-rules', { method: 'POST', body: JSON.stringify(rule) }),
  updateAlertRule:  (id, updates) => request(`/alert-rules/${id}`, { method: 'PUT', body: JSON.stringify(updates) }),
  deleteAlertRule:  (id)          => request(`/alert-rules/${id}`, { method: 'DELETE' }),

  // SSE — returns an EventSource (caller must close)
  streamUpdates: (interval=3) => {
    const url = `${BASE}/stream?interval=${interval}`;
    return new EventSource(url);
  },
};

export default api;
