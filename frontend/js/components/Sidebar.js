/**
 * Sidebar.js - Navigation Sidebar Component
 * ===========================================
 */

import store from '../store.js';

const MODE_SVG = {
  hotspot:        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3v12"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 01-9 9"/></svg>',
  ethernet:       '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M15 2v2M15 20v2M2 15h2M20 15h2M9 2v2M9 20v2M2 9h2M20 9h2"/></svg>',
  port_mirror:    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
  public_network: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>',
  none:           '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0119 12.55"/><path d="M5 12.55a10.94 10.94 0 015.17-2.39"/><path d="M10.71 5.05A16 16 0 0122.56 9"/><path d="M1.42 9a15.91 15.91 0 014.7-2.88"/><path d="M8.53 16.11a6 6 0 016.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>',
};

const MODE_CONFIG = {
  hotspot:        { label: 'Hotspot Mode',    hint: 'Device discovery ON — sees connected clients' },
  ethernet:       { label: 'Ethernet',        hint: 'LAN monitoring ON — discovers local devices' },
  port_mirror:    { label: 'Port Mirror',     hint: 'Full traffic visibility — promiscuous capture' },
  public_network: { label: 'Public Network',  hint: 'Safe mode — own traffic only, no scanning' },
  none:           { label: 'Disconnected',    hint: 'No network connection detected' },
};

export default class Sidebar {
  constructor(el, router) {
    this.el = el;
    this.router = router;
    this._unsubs = [];
    this.render();
    this._bind();
  }

  render() {
    this.el.innerHTML = `
      <div class="sidebar__logo">
        <a href="/" class="sidebar__logo-link" data-route="/">
          <div class="sidebar__logo-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="2"/>
              <path d="M16.24 7.76a6 6 0 010 8.49M7.76 16.24a6 6 0 010-8.49"/>
              <path d="M19.07 4.93a10 10 0 010 14.14M4.93 19.07a10 10 0 010-14.14"/>
            </svg>
          </div>
          <span class="sidebar__logo-text">NetWatch</span>
        </a>
      </div>

      <nav class="sidebar__nav">
        <a href="/" class="sidebar__nav-item" data-route="/">
          <svg class="sidebar__nav-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          Dashboard
        </a>
        <a href="/devices" class="sidebar__nav-item" data-route="/devices">
          <svg class="sidebar__nav-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
          Devices
        </a>
        <a href="/alerts" class="sidebar__nav-item" data-route="/alerts">
          <svg class="sidebar__nav-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
          Alerts
          <span class="sidebar__nav-badge" id="alert-badge" style="display:none">0</span>
        </a>
      </nav>

      <div class="sidebar__footer">
        <div class="mode-indicator">
          <div class="mode-badge" id="mode-badge" data-mode="none">
            <span class="mode-icon" id="mode-icon-span">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0119 12.55"/><path d="M5 12.55a10.94 10.94 0 015.17-2.39"/><path d="M10.71 5.05A16 16 0 0122.56 9"/><path d="M1.42 9a15.91 15.91 0 014.7-2.88"/><path d="M8.53 16.11a6 6 0 016.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
            </span>
            <span class="mode-text">Detecting…</span>
          </div>
          <button class="btn-refresh" id="btn-sidebar-refresh" title="Refresh">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
          </button>
          <button class="btn-mode-info" id="btn-mode-info" title="Connection details" style="display:none;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          </button>
        </div>
        <div class="mode-info">
          <div class="mode-hint" id="mode-hint"></div>
          <div class="mode-detail-popup" id="mode-detail-popup" style="display:none;"></div>
          <div class="mode-transition" id="mode-transition">Switching mode…</div>
        </div>
      </div>
    `;
  }

  _bind() {
    // Logo click → go to dashboard
    this.el.querySelector('.sidebar__logo-link')?.addEventListener('click', e => {
      e.preventDefault();
      this.router.navigate('/');
    });

    // Navigation clicks
    this.el.querySelectorAll('.sidebar__nav-item').forEach(link => {
      link.addEventListener('click', e => {
        e.preventDefault();
        this.router.navigate(link.dataset.route);
      });
    });

    // Refresh button
    this.el.querySelector('#btn-sidebar-refresh')?.addEventListener('click', () => {
      const btn = this.el.querySelector('#btn-sidebar-refresh');
      const svg = btn.querySelector('svg');
      svg.classList.add('spinning');
      // Dispatch custom event for app to handle
      window.dispatchEvent(new CustomEvent('netwatch:refresh'));
      setTimeout(() => svg.classList.remove('spinning'), 800);
    });

    // Info button — toggle connection details popup
    this.el.querySelector('#btn-mode-info')?.addEventListener('click', () => {
      const popup = this.el.querySelector('#mode-detail-popup');
      if (popup) popup.style.display = popup.style.display === 'none' ? '' : 'none';
    });

    // Close popup when clicking outside
    document.addEventListener('click', (e) => {
      const popup = this.el.querySelector('#mode-detail-popup');
      const btn = this.el.querySelector('#btn-mode-info');
      if (popup && popup.style.display !== 'none' && !popup.contains(e.target) && !btn?.contains(e.target)) {
        popup.style.display = 'none';
      }
    });

    // Subscribe to mode changes
    this._unsubs.push(store.subscribe('mode', data => this._updateMode(data)));

    // Subscribe to alert count
    this._unsubs.push(store.subscribe('alertStats', data => this._updateAlertBadge(data)));

    // Phase 5: listen for mode transition events to show indicator
    this._modeTransitionHandler = () => {
      const transEl = this.el.querySelector('#mode-transition');
      if (transEl) transEl.style.display = 'block';
    };
    window.addEventListener('netwatch:mode_transition', this._modeTransitionHandler);
  }

  setActive(route) {
    this.el.querySelectorAll('.sidebar__nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.route === route);
    });
  }

  _updateMode(data) {
    const badge = this.el.querySelector('#mode-badge');
    if (!badge || !data) return;
    const mode = data.mode || 'none';
    const cfg = MODE_CONFIG[mode] || MODE_CONFIG.none;
    badge.dataset.mode = mode;

    const iconSpan = badge.querySelector('.mode-icon');
    if (iconSpan) {
      iconSpan.innerHTML = MODE_SVG[mode] || MODE_SVG.none;
    }

    badge.querySelector('.mode-text').textContent = data.mode_display || cfg.label;

    // Phase 5: update mode capability hint
    const hintEl = this.el.querySelector('#mode-hint');
    if (hintEl) {
      hintEl.textContent = cfg.hint || '';
    }

    // Show/hide info button and build popup content
    const infoBtn = this.el.querySelector('#btn-mode-info');
    const popup = this.el.querySelector('#mode-detail-popup');
    if (infoBtn && popup) {
      const iface = data.interface || {};
      const hasInfo = !!(iface.ip || iface.ssid || iface.gateway);
      infoBtn.style.display = hasInfo ? '' : 'none';

      // Build compact detail lines
      const lines = [];
      if (iface.ssid) lines.push(`<b>Network:</b> ${this._esc(iface.ssid)}`);
      if (iface.ip) lines.push(`<b>IP:</b> ${this._esc(iface.ip)}`);
      if (iface.gateway) lines.push(`<b>Gateway:</b> ${this._esc(iface.gateway)}`);
      if (iface.name) lines.push(`<b>Interface:</b> ${this._esc(iface.name)}`);
      popup.innerHTML = lines.join('<br>');
    }

    // Phase 5: hide transition indicator once new mode data arrives
    const transEl = this.el.querySelector('#mode-transition');
    if (transEl) {
      transEl.style.display = 'none';
    }

    // Show mode-info container only when there is hint text
    const infoEl = this.el.querySelector('.mode-info');
    if (infoEl) {
      infoEl.style.display = (cfg.hint) ? '' : 'none';
    }
  }

  /** Minimal HTML escape */
  _esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  _updateAlertBadge(data) {
    const badge = this.el.querySelector('#alert-badge');
    if (!badge) return;
    const count = data?.total_unresolved ?? data?.unacknowledged ?? 0;
    badge.textContent = count;
    badge.style.display = count > 0 ? '' : 'none';
  }

  destroy() {
    this._unsubs.forEach(fn => fn());
    if (this._modeTransitionHandler) {
      window.removeEventListener('netwatch:mode_transition', this._modeTransitionHandler);
    }
  }
}
