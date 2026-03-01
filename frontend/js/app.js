/**
 * app.js - Main Application Controller
 * =======================================
 * Boots the SPA: initialises router, sidebar, store subscriptions,
 * and the single update loop that batch-fetches all API data.
 */

import Router from './router.js';
import store from './store.js';
import api from './api.js';
import { showToast } from './utils/toast.js';
import Sidebar from './components/Sidebar.js';
import Dashboard from './components/Dashboard.js';
import DeviceList from './components/DeviceList.js';
import AlertFeed from './components/AlertFeed.js';

class App {
  constructor() {
    this.UPDATE_INTERVAL = 10000;  // 10 s between fetches (light on CPU/DB)
    this._timerId = null;
    this._isActive = true;
    this._currentView = null;
    this._hours = 1;              // bandwidth time range
    this._sse = null;             // SSE EventSource (real-time push)
    this._sseHealthy = false;     // true while SSE is connected and receiving
    this._sseReconnectTimer = null; // pending SSE reconnect timeout (#53)
    this._updating = false;       // guard against concurrent _update() calls (#49)
    this._unsubscribes = [];      // cleanup hooks from store.subscribe()

    this.router = new Router();
    this.sidebar = null;
  }

  /* ─────────────────── Bootstrap ─────────────────── */

  init() {
    // Sidebar
    this.sidebar = new Sidebar(
      document.getElementById('sidebar'),
      this.router,
    );

    // Routes
    const viewContainer = document.getElementById('view-container');
    const titleEl = document.getElementById('page-title');

    const loadView = (ViewClass, title, route) => {
      // Destroy old view
      if (this._currentView?.destroy) this._currentView.destroy();

      titleEl.textContent = title;
      this.sidebar.setActive(route);

      // Mount new view immediately — no delay, no data clearing.
      // Components render with whatever data the store already has,
      // then update reactively when fresh data arrives via SSE.
      viewContainer.classList.remove('view-active');
      viewContainer.classList.add('view-enter');

      this._currentView = new ViewClass(viewContainer);
      this._currentView.render();

      // Animate in
      requestAnimationFrame(() => {
        viewContainer.classList.remove('view-enter');
        viewContainer.classList.add('view-active');
      });
    };

    this.router
      .on('/',        () => loadView(Dashboard, 'Dashboard', '/'))
      .on('/devices', () => loadView(DeviceList, 'Devices', '/devices'))
      .on('/alerts',  () => loadView(AlertFeed, 'Alerts', '/alerts'))
      .start();

    // Global events
    this._setupVisibility();
    this._setupRefresh();
    this._setupHamburger();
    this._setupTimeRange();
    this._setupClock();
    this._setupThemeToggle();

    // Read persisted time-range before first data fetch
    const savedHours = parseInt(localStorage.getItem('netwatch-time-range'), 10);
    if (savedHours && savedHours > 0) this._hours = savedHours;

    // Kick off data fetching
    this._update();
    this._initSSE();

    // Clean up SSE on page unload (#51)
    window.addEventListener('beforeunload', () => this._sse?.close());

    // User-visible error notifications (#47)
    this._setupErrorToasts();
  }

  /* ─────────────────── Error Toasts ───────────── */

  _setupErrorToasts() {
    let wasConnected = true;
    this._unsubscribes.push(
      store.subscribe('connected', connected => {
        if (!connected && wasConnected) {
          this._showToast('Connection lost — retrying…', 'error');
        } else if (connected && !wasConnected) {
          this._showToast('Connection restored', 'success');
        }
        wasConnected = connected;
      })
    );
  }

  /** Show a toast notification. type: 'error' | 'success' | 'warning' | 'info' */
  _showToast(message, type = 'error') {
    showToast(message, type);
  }

  /* ─────────────────── SSE Real-Time ─────────────── */

  _initSSE() {
    if (typeof EventSource === 'undefined') return;
    try {
      this._sse = api.streamUpdates(3);

      this._sse.onopen = () => {
        this._sseHealthy = true;
        // SSE is live — stop the polling fallback timer
        if (this._timerId) { clearTimeout(this._timerId); this._timerId = null; }
      };

      // Phase 5: listen for named 'mode_changed' events from backend
      this._sse.addEventListener('mode_changed', (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.disconnected) {
            showToast('Network disconnected', 'warning');
          } else {
            showToast(`Switching to ${data.mode || 'new'} mode…`, 'info');
          }
          // Dispatch so Sidebar shows transition indicator
          window.dispatchEvent(new CustomEvent('netwatch:mode_transition', { detail: data }));
        } catch (_) { /* ignore */ }
      });

      this._sse.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);

          // Core stats (bandwidth, device count, pps)
          if (data.stats)       store.setState('stats', data.stats);
          // Alert badge count
          if (data.alert_stats) store.setState('alertStats', data.alert_stats);
          // Health score
          if (data.health)      store.setState('health', data.health);

          // Full alerts list (fixes stale alerts page)
          // NOTE: SSE sends only 5 recent alerts from in-memory cache.
          // Do NOT overwrite the store 'alerts' key — AlertFeed manages
          // its own full list via _fetchFreshAlerts().  Writing the
          // truncated SSE list here would (a) replace the full 50-alert
          // fetch with just 5 entries and (b) push stale resolved/acked
          // status that overwrites fresh data, making resolve appear broken.
          // Use a separate key for the dashboard's recent-alerts widget.
          if (data.alerts)      store.setState('recentAlerts', data.alerts);
          // Protocol distribution (fixes blank protocol chart)
          if (data.protocols)   store.setState('protocols', data.protocols);
          // Top devices
          if (data.devices)     store.setState('devices', data.devices);
          // Network mode (fixes stale mode after hotspot detection)
          if (data.mode) {
            const prev = store.get('mode');
            store.setState('mode', data.mode);
            // Notify user on mode change
            if (prev && prev.mode && data.mode.mode && prev.mode !== data.mode.mode) {
              const label = data.mode.mode_display || data.mode.mode;
              showToast(`Network mode changed: ${label}`, 'info');
            }
          }

          // Bandwidth: use the pre-merged history from the backend directly.
          // All DB + live merging happens server-side so the chart gets a
          // single stable array — no point count changes, no past-wave drift.
          // Only update from SSE when viewing 1H range — SSE always sends
          // 1H merged data.  For 6H/24H the timerange handler fetches the
          // correct data from the DB endpoint and we must not overwrite it.
          if (data.bandwidth_history && Array.isArray(data.bandwidth_history) && data.bandwidth_history.length > 0) {
            if (this._hours <= 1) {
              store.setState('bandwidth', { history: data.bandwidth_history });
            }
          }

          store.setState('connected', true);
        } catch (_) { /* ignore parse errors */ }
      };

      this._sse.onerror = () => {
        // SSE disconnected — re-enable polling fallback
        this._sseHealthy = false;
        if (this._sse) { this._sse.close(); this._sse = null; }
        // Restart polling if not already running
        if (!this._timerId) this._update();
        // Cancel any pending reconnect before scheduling a new one (#53)
        if (this._sseReconnectTimer) { clearTimeout(this._sseReconnectTimer); this._sseReconnectTimer = null; }
        // Try to re-establish SSE after a short delay
        this._sseReconnectTimer = setTimeout(() => {
          this._sseReconnectTimer = null;
          if (!this._sse) this._initSSE();
        }, 5000);
      };
    } catch (_) { /* SSE not supported — polling only */ }
  }

  /* ─────────────────── Data Loop ─────────────────── */

  async _update() {
    if (!this._isActive) return;
    // Guard against concurrent update cycles (#49)
    if (this._updating) return;
    this._updating = true;
    store.setState('loading', true);

    try {
      // Single batch: 6 concurrent requests = 72 calls/min at 5s interval.
      // If /api/dashboard works, use it for a single request instead.
      const dashboard = await api.getDashboard();

      if (dashboard && !dashboard.error) {
        // Backend returned everything in one payload
        if (dashboard.stats)     store.setState('stats', dashboard.stats);
        if (dashboard.devices)   store.setState('devices', dashboard.devices);
        if (dashboard.alerts)    store.setState('recentAlerts', dashboard.alerts);
        if (dashboard.protocols) store.setState('protocols', dashboard.protocols);
        if (dashboard.mode)      store.setState('mode', dashboard.mode);
        if (dashboard.health)    store.setState('health', dashboard.health);
        if (dashboard.alert_stats) store.setState('alertStats', dashboard.alert_stats);
        // Only set bandwidth from REST when SSE is NOT the live source —
        // otherwise the unfiltered REST data and the merged SSE data keep
        // overwriting each other, causing the chart to jump back and forth.
        if (dashboard.bandwidth && !this._sseHealthy) store.setState('bandwidth', dashboard.bandwidth);
      } else {
        // Fallback: individual parallel requests
        await this._individualFetch();
      }

      // Fetch bandwidth separately only when dashboard didn't include it
      // and SSE is not managing bandwidth in real time.
      if (!this._sseHealthy && (!dashboard || dashboard.error || !dashboard.bandwidth)) {
        const bwInterval = this._hours >= 24 ? 'hour' : this._hours <= 1 ? '10s' : 'minute';
        const bw = await api.getBandwidthDual(this._hours, bwInterval);
        if (bw && !bw.error && (bw.data || bw.history)) store.setState('bandwidth', bw);
      }

      store.setState('connected', true);
      store.setState('lastUpdated', new Date().toISOString());
    } catch (err) {
      console.error('[App] update error:', err);
      store.setState('connected', false);
    } finally {
      store.setState('loading', false);
      this._updating = false;
    }

    // Only schedule the next polling tick when SSE is NOT healthy
    if (!this._sseHealthy) {
      this._timerId = setTimeout(() => this._update(), this.UPDATE_INTERVAL);
    }
  }

  async _individualFetch() {
    const [stats, bandwidth, devices, alerts, protocols, mode, health, alertStats] =
      await Promise.allSettled([
        api.getRealtimeStats(),
        api.getBandwidthDual(this._hours),
        api.getAllDevices(),
        api.getAlerts(),
        api.getProtocols(),
        api.getInterfaceStatus(),
        api.getHealthScore(),
        api.getAlertStats(),
      ]);

    if (stats.status === 'fulfilled' && !stats.value?.error)      store.setState('stats', stats.value);
    if (!this._sseHealthy && bandwidth.status === 'fulfilled' && !bandwidth.value?.error)   store.setState('bandwidth', bandwidth.value);
    if (devices.status === 'fulfilled' && !devices.value?.error)     store.setState('devices', devices.value);
    if (alerts.status === 'fulfilled' && !alerts.value?.error)      store.setState('alerts', alerts.value);
    if (protocols.status === 'fulfilled' && !protocols.value?.error)   store.setState('protocols', protocols.value);
    if (mode.status === 'fulfilled' && !mode.value?.error)        store.setState('mode', mode.value);
    if (health.status === 'fulfilled' && !health.value?.error)      store.setState('health', health.value);
    if (alertStats.status === 'fulfilled' && !alertStats.value?.error)  store.setState('alertStats', alertStats.value);
  }

  /* ─────────────────── Visibility ────────────────── */

  _setupVisibility() {
    document.addEventListener('visibilitychange', () => {
      this._isActive = !document.hidden;
      if (this._isActive) {
        this._update(); // immediate refresh on return
      } else {
        clearTimeout(this._timerId);
      }
    });

    // Connection status indicator
    this._unsubscribes.push(
      store.subscribe('connected', connected => {
        const dot = document.getElementById('status-dot');
        if (dot) dot.classList.toggle('disconnected', !connected);
      })
    );

    this._unsubscribes.push(
      store.subscribe('lastUpdated', ts => {
        // Clock is handled by _setupClock(), no need to overwrite here
      })
    );
  }

  /* ─────────────────── Refresh button ────────────── */

  _setupRefresh() {
    window.addEventListener('netwatch:refresh', async () => {
      clearTimeout(this._timerId);
      // Trigger backend mode re-detection + cache invalidation
      try { await api.refreshInterface(); } catch (_) { /* best-effort */ }
      // Force data refresh — reset guard so update is not skipped
      this._updating = false;
      this._update();
    });
  }

  /* ─────────────────── Hamburger (mobile) ────────── */

  _setupHamburger() {
    const btn = document.getElementById('hamburger');
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    if (!btn || !sidebar) return;

    const toggle = () => {
      sidebar.classList.toggle('open');
      overlay?.classList.toggle('open');
    };

    btn.addEventListener('click', toggle);
    overlay?.addEventListener('click', toggle);
  }

  /* ─────────────────── Time range ────────────────── */

  _setupTimeRange() {
    window.addEventListener('netwatch:timerange', async (e) => {
      this._hours = e.detail.hours || 1;
      localStorage.setItem('netwatch-time-range', String(this._hours));

      // Only re-fetch bandwidth history for the new range — don't
      // trigger a full _update() which would overwrite alerts / health
      // from the dashboard payload and cause a visible flash.
      try {
        const bwInterval = this._hours >= 24 ? 'hour' : this._hours <= 1 ? '10s' : 'minute';
        const bw = await api.getBandwidthDual(this._hours, bwInterval);
        if (bw && !bw.error && (bw.data || bw.history)) {
          store.setState('bandwidth', bw);
        }
      } catch (_) { /* best-effort */ }
    });
  }

  /* ─────────────────── Real-time clock ────────────── */

  _setupClock() {
    const el = document.getElementById('last-updated');
    if (!el) return;

    const tick = () => {
      const now = new Date();
      const h = String(now.getHours()).padStart(2, '0');
      const m = String(now.getMinutes()).padStart(2, '0');
      const s = String(now.getSeconds()).padStart(2, '0');
      el.textContent = `${h}:${m}:${s}`;
    };

    tick();
    setInterval(tick, 1000);
  }

  /* ─────────────────── Theme toggle ──────────────── */

  _setupThemeToggle() {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;

    let transitioning = false;

    const applyTheme = (theme) => {
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('netwatch-theme', theme);
    };

    btn.addEventListener('click', () => {
      // Prevent overlapping transitions
      if (transitioning) return;
      transitioning = true;

      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const newTheme = current === 'dark' ? 'light' : 'dark';

      // Get button center position for the expanding circle origin
      const rect = btn.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;

      // Calculate the max radius needed to cover the entire viewport
      const maxRadius = Math.hypot(
        Math.max(cx, window.innerWidth - cx),
        Math.max(cy, window.innerHeight - cy)
      );

      // Create a full-screen overlay that mirrors the page under the new theme
      const overlay = document.createElement('div');
      overlay.className = 'theme-bloom-overlay';
      overlay.setAttribute('data-theme', newTheme);

      // Set the new theme CSS variables on the overlay itself
      if (newTheme === 'dark') {
        overlay.style.setProperty('--color-bg-primary', '#1a1a1a');
        overlay.style.setProperty('--color-text-primary', '#efefef');
      } else {
        overlay.style.setProperty('--color-bg-primary', '#f5f5f5');
        overlay.style.setProperty('--color-text-primary', '#1a1a1a');
      }
      overlay.style.background = newTheme === 'dark' ? '#1a1a1a' : '#f5f5f5';

      // Start with a tiny circle clip-path at the button position
      overlay.style.clipPath = `circle(0px at ${cx}px ${cy}px)`;
      document.body.appendChild(overlay);

      // Trigger the slow bloom expansion in the next frame
      requestAnimationFrame(() => {
        overlay.style.clipPath = `circle(${maxRadius}px at ${cx}px ${cy}px)`;
      });

      // Apply the actual theme halfway through the bloom so elements
      // smoothly adopt new colors as the circle passes over them
      setTimeout(() => {
        applyTheme(newTheme);
      }, 500);

      // Remove the overlay after the bloom finishes
      setTimeout(() => {
        overlay.remove();
        transitioning = false;
      }, 1200);
    });
  }
}

/* ─────────────────── Boot ─────────────────── */

document.addEventListener('DOMContentLoaded', () => {
  const app = new App();
  app.init();
});
