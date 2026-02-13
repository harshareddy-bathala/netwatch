/**
 * app.js - Main Application Controller
 * =======================================
 * Boots the SPA: initialises router, sidebar, store subscriptions,
 * and the single update loop that batch-fetches all API data.
 */

import Router from './router.js';
import store from './store.js';
import api from './api.js';
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

      // Animate out old content
      viewContainer.classList.remove('view-active');
      viewContainer.classList.add('view-enter');

      titleEl.textContent = title;
      this.sidebar.setActive(route);

      // Create new view
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

    // Kick off data fetching
    this._update();
    this._initSSE();
  }

  /* ─────────────────── SSE Real-Time ─────────────── */

  _initSSE() {
    if (typeof EventSource === 'undefined') return;
    try {
      this._sse = api.streamUpdates(3);
      this._sse.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.stats)       store.setState('stats', data.stats);
          if (data.alert_stats) store.setState('alertStats', data.alert_stats);
          if (data.health)      store.setState('health', data.health);

          // Merge live bandwidth data into the chart for real-time updates
          if (data.bandwidth_live && data.bandwidth_live.history) {
            const current = store.get('bandwidth');
            if (current) {
              const existing = current.history || current || [];
              if (Array.isArray(existing) && existing.length > 0) {
                // Remove stale live points from previous pushes
                const dbPoints = existing.filter(p => !p.live);
                // Append fresh live data points
                const merged = [...dbPoints, ...data.bandwidth_live.history];
                // Keep total points reasonable (last 360 for 1H @ 10s)
                const trimmed = merged.slice(-360);
                store.setState('bandwidth', { history: trimmed });
              }
            } else {
              // No existing data yet — use live data directly
              store.setState('bandwidth', { history: data.bandwidth_live.history });
            }
          }

          store.setState('connected', true);
        } catch (_) { /* ignore parse errors */ }
      };
      this._sse.onerror = () => {
        // On SSE failure, fall back silently to polling (already running)
        if (this._sse) { this._sse.close(); this._sse = null; }
      };
    } catch (_) { /* SSE not supported — polling only */ }
  }

  /* ─────────────────── Data Loop ─────────────────── */

  async _update() {
    if (!this._isActive) return;
    store.setState('loading', true);

    try {
      // Single batch: 6 concurrent requests = 72 calls/min at 5s interval.
      // If /api/dashboard works, use it for a single request instead.
      const dashboard = await api.getDashboard();

      if (dashboard) {
        // Backend returned everything in one payload
        if (dashboard.stats)     store.setState('stats', dashboard.stats);
        if (dashboard.devices)   store.setState('devices', dashboard.devices);
        if (dashboard.alerts)    store.setState('alerts', dashboard.alerts);
        if (dashboard.protocols) store.setState('protocols', dashboard.protocols);
        if (dashboard.mode)      store.setState('mode', dashboard.mode);
        if (dashboard.health)    store.setState('health', dashboard.health);
        if (dashboard.alert_stats) store.setState('alertStats', dashboard.alert_stats);
      } else {
        // Fallback: individual parallel requests
        await this._individualFetch();
      }

      // Always fetch bandwidth with the user's selected time range
      // Auto-select interval: 1H → 10s, 6H → minute, 24H → hour
      // 10s matches BandwidthCalculator's sliding window for accurate chart
      const bwInterval = this._hours >= 24 ? 'hour' : this._hours <= 1 ? '10s' : 'minute';
      const bw = await api.getBandwidthDual(this._hours, bwInterval);
      if (bw) store.setState('bandwidth', bw);

      store.setState('connected', true);
      store.setState('lastUpdated', new Date().toISOString());
    } catch (err) {
      console.error('[App] update error:', err);
      store.setState('connected', false);
    } finally {
      store.setState('loading', false);
    }

    this._timerId = setTimeout(() => this._update(), this.UPDATE_INTERVAL);
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

    if (stats.status === 'fulfilled')      store.setState('stats', stats.value);
    if (bandwidth.status === 'fulfilled')   store.setState('bandwidth', bandwidth.value);
    if (devices.status === 'fulfilled')     store.setState('devices', devices.value);
    if (alerts.status === 'fulfilled')      store.setState('alerts', alerts.value);
    if (protocols.status === 'fulfilled')   store.setState('protocols', protocols.value);
    if (mode.status === 'fulfilled')        store.setState('mode', mode.value);
    if (health.status === 'fulfilled')      store.setState('health', health.value);
    if (alertStats.status === 'fulfilled')  store.setState('alertStats', alertStats.value);
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
    store.subscribe('connected', connected => {
      const dot = document.getElementById('status-dot');
      if (dot) dot.classList.toggle('disconnected', !connected);
    });

    store.subscribe('lastUpdated', ts => {
      // Clock is handled by _setupClock(), no need to overwrite here
    });
  }

  /* ─────────────────── Refresh button ────────────── */

  _setupRefresh() {
    window.addEventListener('netwatch:refresh', () => {
      clearTimeout(this._timerId);
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
    window.addEventListener('netwatch:timerange', e => {
      this._hours = e.detail.hours || 1;
      clearTimeout(this._timerId);
      this._update();
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
