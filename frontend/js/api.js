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

async function request(endpoint, opts = {}, retries) {
  // Per-call overrides: `timeout` (ms) and `retries` let slow endpoints
  // (e.g. LLM investigations that run tens of seconds) opt out of the
  // short default budget without changing every other call.
  const { timeout, retries: optRetries, ...fetchOpts } = opts;
  const budget = timeout || TIMEOUT;
  if (retries === undefined) retries = optRetries !== undefined ? optRetries : MAX_RETRIES;

  const url = BASE + endpoint;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), budget);

  // Inject X-API-Key header when configured
  const headers = { ...HEADERS, ...fetchOpts.headers };
  if (_apiKey) headers['X-API-Key'] = _apiKey;

  try {
    const res = await fetch(url, {
      ...fetchOpts,
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
    // Never auto-retry an aborted request: for a slow endpoint the retry
    // just starts a second expensive run while the first may still be
    // executing server-side (compounding load on a constrained host).
    if (err.name !== 'AbortError' && retries > 0) {
      await sleep(RETRY_DELAY);
      return request(endpoint, opts, retries - 1);
    }
    console.error(`[api] ${endpoint}:`, err.message);
    const aborted = err.name === 'AbortError';
    return {
      error: true,
      status: 0,
      aborted,
      message: aborted ? `Request timed out after ${Math.round(budget / 1000)}s` : (err.message || 'Network error'),
    };
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

  // Digital twin & intelligence (Phase 1)
  getTwin:            (maxEdges=500)     => request(`/twin?max_edges=${maxEdges}`),
  getTwinStats:       ()                 => request('/twin/stats'),
  getRecentFlows:     (limit=100, mac='') =>
    request(`/flows/recent?limit=${limit}${mac ? `&mac=${encodeURIComponent(mac)}` : ''}`),
  getRecentDns:       (limit=100, mac='') =>
    request(`/dns/recent?limit=${limit}${mac ? `&mac=${encodeURIComponent(mac)}` : ''}`),
  getBehaviorProfile: (mac)              =>
    request(`/behavior/profiles/${encodeURIComponent(mac)}`),

  // Devices
  getAllDevices:     (limit=50, offset=0, includeControl=false) =>
    request(`/devices?limit=${limit}&offset=${offset}&include_control=${includeControl ? 'true' : 'false'}`),
  getDeviceDetails: (ip, includeControl=false) =>
    request(`/devices/${encodeURIComponent(ip)}?include_control=${includeControl ? 'true' : 'false'}`),
  updateDeviceName: (ip, hostname, mac)   => request('/devices/update-name', {
      method: 'POST', body: JSON.stringify({ ip_address: ip, hostname, mac }),
  }),

  // Protocols & Traffic
  getProtocols:       (hours=1)                      => request(`/protocols?hours=${hours}`),
  getBandwidthDual:   (hours=1, interval='minute')   => request(`/bandwidth/dual?hours=${hours}&interval=${interval}`),

  // Forecasting (Phase 2)
  getForecastBandwidth: (horizon=30) => request(`/forecast/bandwidth?horizon=${horizon}`),
  getForecastDevices:   (horizon=6)  => request(`/forecast/devices?horizon=${horizon}`),

  // Incidents (Phase 2)
  getIncidents:     (status=null, limit=50) =>
    request(`/incidents?limit=${limit}${status ? `&status=${status}` : ''}`),
  getIncident:      (id)   => request(`/incidents/${id}`),
  getIncidentStats: ()     => request('/incidents/stats'),
  resolveIncident:  (id)   => request(`/incidents/${id}/resolve`, { method: 'POST' }),

  // Ask NetWatch — LLM investigations (Phase 3)
  getInvestigateStatus: ()        => request('/investigate/status'),
  getInvestigateTools:  ()        => request('/investigate/tools'),
  // Investigations run a local LLM through a multi-step tool loop; on a
  // modest host this legitimately takes tens of seconds. Give it a long
  // budget and never auto-retry (a retry would launch a second run).
  investigate:          (question) => request('/investigate', {
      method: 'POST', body: JSON.stringify({ question }),
      timeout: 240000, retries: 0,
  }),

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
    const params = new URLSearchParams({ interval: String(interval) });
    // EventSource cannot send custom headers, so API-key auth must use query params.
    if (_apiKey) params.set('api_key', _apiKey);
    const url = `${BASE}/stream?${params.toString()}`;
    return new EventSource(url);
  },
};

export default api;
