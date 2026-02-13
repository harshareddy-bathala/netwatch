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

/* ── Core fetch ────────────────────────────────────── */

async function request(endpoint, opts = {}, retries = MAX_RETRIES) {
  const url = BASE + endpoint;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT);

  try {
    const res = await fetch(url, {
      ...opts,
      headers: { ...HEADERS, ...opts.headers },
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
      return null;
    }
    return data;
  } catch (err) {
    clearTimeout(timer);
    if (retries > 0) {
      await sleep(RETRY_DELAY);
      return request(endpoint, opts, retries - 1);
    }
    console.error(`[api] ${endpoint}:`, err.message);
    return null;
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ── Public API ────────────────────────────────────── */

const api = {
  // Dashboard (single batch endpoint)
  getDashboard:     ()                   => request('/dashboard'),

  // Stats
  getStatus:        ()                   => request('/status'),
  getRealtimeStats: ()                   => request('/stats/realtime'),
  getMetrics:       ()                   => request('/metrics'),
  getHealthScore:   ()                   => request('/health'),

  // Devices
  getTopDevices:    (limit=10, hours=1)  => request(`/devices/top?limit=${limit}&hours=${hours}`),
  getAllDevices:     (limit=50, offset=0) => request(`/devices?limit=${limit}&offset=${offset}`),
  getDeviceDetails: (ip)                 => request(`/devices/${encodeURIComponent(ip)}`),
  updateDeviceName: (ip, hostname, mac)   => request('/devices/update-name', {
      method: 'POST', body: JSON.stringify({ ip_address: ip, hostname, mac }),
  }),

  // Protocols & Traffic
  getProtocols:       (hours=1)                      => request(`/protocols?hours=${hours}`),
  getBandwidthHistory:(hours=1, interval='minute')   => request(`/bandwidth/history?hours=${hours}&interval=${interval}`),
  getBandwidthDual:   (hours=1, interval='minute')   => request(`/bandwidth/dual?hours=${hours}&interval=${interval}`),
  getTrafficSummary:  (hours=24)                     => request(`/traffic?hours=${hours}`),

  // Alerts
  getAlerts: (limit=50, severity=null, acknowledged=null) => {
    let url = `/alerts?limit=${limit}`;
    if (severity) url += `&severity=${severity}`;
    if (acknowledged !== null) url += `&acknowledged=${acknowledged}`;
    return request(url);
  },
  getRecentAlerts:   (limit=5) => request(`/alerts/recent?limit=${limit}`),
  getAlertsSummary:  ()        => request('/alerts/summary'),
  getAlertStats:     ()        => request('/alerts/stats'),
  acknowledgeAlert:  (id)      => request(`/alerts/${id}/acknowledge`, { method: 'POST' }),
  resolveAlert:      (id)      => request(`/alerts/${id}/resolve`,     { method: 'POST' }),
  createAlert:       (data)    => request('/alerts', { method: 'POST', body: JSON.stringify(data) }),

  // Activity
  getActivity: (limit=10) => request(`/activity?limit=${limit}`),

  // Interface
  getInterfaceStatus: () => request('/interface/status'),
  refreshInterface:   () => request('/interface/refresh', { method: 'POST' }),
  listInterfaces:     () => request('/interface/list'),
  selectInterface:    (name) => request('/interface/select', {
    method: 'POST', body: JSON.stringify({ interface: name }),
  }),

  // Data export
  getExportUrl: (fmt='csv', type='devices', hours=24) =>
    `${BASE}/export/${fmt}?type=${type}&hours=${hours}`,

  // GeoIP
  getGeoIP:      (ip) => request(`/geoip/${encodeURIComponent(ip)}`),
  getGeoIPBatch: (ips) => request('/geoip/batch', { method: 'POST', body: JSON.stringify({ ips }) }),

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
