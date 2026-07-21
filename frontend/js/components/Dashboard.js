/**
 * Dashboard.js - Dashboard View Component
 * ==========================================
 * Renders stat cards, charts, and top-devices widget.
 */

import store from '../store.js';
import StatsCard from './StatsCard.js';
import BandwidthChart from './BandwidthChart.js';
import ProtocolChart from './ProtocolChart.js';
import { formatBytes, formatMbps, escapeHtml } from '../utils/formatters.js';

export default class Dashboard {
  /** How often the briefing re-reads the last 10 minutes on its own. */
  static BRIEFING_INTERVAL_MS = 10 * 60 * 1000;

  constructor(container) {
    this.container = container;
    this._unsubs = [];
    this._briefingTimer = null;
    this._briefingMetaTimer = null;
    this._briefingInFlight = false;
    this._briefingAt = 0;
    this._cards = {};
    this._bandwidthChart = null;
    this._protocolChart = null;
    this._prevStats = null;
    this._isArpCacheMode = false;
    this._currentMode = 'none';
    this._showControlOverhead = !!store.get('includeControlTraffic');
  }

  render() {
    // Define stat cards (using SVG snippets for icons)
    this._cards = {
      bandwidth: new StatsCard({ id: 'bandwidth', label: 'Bandwidth',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><polyline points="8 8 12 12 16 8"/><line x1="12" y1="3" x2="12" y2="12"/></svg>',
        iconClass: 'stats-card__icon--bandwidth' }),
      devices: new StatsCard({ id: 'devices', label: 'Active Devices',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
        iconClass: 'stats-card__icon--devices' }),
      health: new StatsCard({ id: 'health', label: 'Health Score',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.42 4.58a5.4 5.4 0 00-7.65 0L12 5.36l-.77-.78a5.4 5.4 0 00-7.65 7.65l1.06 1.06L12 20.71l7.36-7.36 1.06-1.06a5.4 5.4 0 000-7.65z"/></svg>',
        iconClass: 'stats-card__icon--health' }),
      alerts: new StatsCard({ id: 'alerts', label: 'Unresolved Alerts',
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        iconClass: 'stats-card__icon--alerts' }),
    };

    this.container.innerHTML = `
      <div class="dashboard-grid stagger">
        ${this._cards.bandwidth.html()}
        ${this._cards.devices.html()}
        ${this._cards.health.html()}
        ${this._cards.alerts.html()}

        <div class="dashboard-grid__charts">
          <div class="chart-card">
            <div class="chart-card__header">
              <div class="chart-card__title-group">
                <span class="chart-card__title">Bandwidth History</span>
                <span class="speed-badge" id="bw-live-speed"></span>
              </div>
              <div class="chart-card__header-actions">
                <div class="time-range-toggle">
                  <button class="time-range-toggle__btn active" data-hours="1">1H</button>
                  <button class="time-range-toggle__btn" data-hours="6">6H</button>
                  <button class="time-range-toggle__btn" data-hours="24">24H</button>
                </div>
              </div>
            </div>
            <div class="chart-card__canvas-wrap">
              <canvas id="bandwidth-canvas"></canvas>
            </div>
          </div>

          <div class="chart-card chart-card--protocol">
            <div class="chart-card__header">
              <span class="chart-card__title">Protocols</span>
            </div>
            <div class="chart-card__protocol-body">
              <div class="chart-card__canvas-wrap chart-card__canvas-wrap--doughnut">
                <canvas id="protocol-canvas"></canvas>
              </div>
            </div>
          </div>
        </div>

        <div class="briefing-card" id="briefing-card">
          <div class="briefing-card__head">
            <div class="briefing-card__title-group">
              <span class="briefing-card__title">What just happened?</span>
              <span class="briefing-card__meta" id="briefing-meta"></span>
            </div>
            <button class="btn btn--sm" id="briefing-btn">Refresh now</button>
          </div>
          <div class="briefing-card__body" id="briefing-body">
            <span class="briefing-card__hint">Reading the last 10 minutes…</span>
          </div>
        </div>

        <div class="dashboard-grid__bottom">
          <div class="top-devices" id="top-devices-widget">
            <div class="top-devices__title">Top Devices</div>
            <div id="top-devices-list" class="empty-state">
              <span class="empty-state__text">Loading\u2026</span>
            </div>
          </div>
        </div>
      </div>
    `;

    // Init charts after DOM paint, then subscribe to store
    // (subscription is deferred until charts are ready to prevent
    // data arriving before chart objects exist)
    requestAnimationFrame(() => {
      this._wireBriefing();
      this._bandwidthChart = new BandwidthChart('bandwidth-canvas');
      this._bandwidthChart.init();

      this._protocolChart = new ProtocolChart('protocol-canvas');
      this._protocolChart.init();

      // Now that charts are ready, subscribe to store updates
      this._unsubs.push(store.subscribe('stats', d => this._onStats(d)));
      this._unsubs.push(store.subscribe('health', d => this._onHealth(d)));
      this._unsubs.push(store.subscribe('alertStats', d => this._onAlertStats(d)));
      this._unsubs.push(store.subscribe('topDevices', d => this._onDevices(d)));
      this._unsubs.push(store.subscribe('mode', d => this._onMode(d)));
      this._unsubs.push(store.subscribe('includeControlTraffic', v => this._onControlPreference(v)));

      // Replay current store values so charts render immediately
      // if data arrived before subscription was set up
      const currentStats = store.get('stats');
      if (currentStats) this._onStats(currentStats);
      const currentHealth = store.get('health');
      if (currentHealth) this._onHealth(currentHealth);
      const currentAlertStats = store.get('alertStats');
      if (currentAlertStats) this._onAlertStats(currentAlertStats);
      const currentDevices = store.get('topDevices');
      if (currentDevices) this._onDevices(currentDevices);
    });

    const controlToggle = this.container.querySelector('#control-overhead-toggle');
    if (controlToggle) {
      controlToggle.addEventListener('change', () => {
        store.setState('includeControlTraffic', !!controlToggle.checked);
      });
    }

    // Time range pill toggle
    this.container.querySelectorAll('.time-range-toggle__btn').forEach(btn => {
      btn.addEventListener('click', () => {
        this.container.querySelectorAll('.time-range-toggle__btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        // Dispatch event for app to re-fetch with new range
        window.dispatchEvent(new CustomEvent('netwatch:timerange', { detail: { hours: parseInt(btn.dataset.hours) } }));
      });
    });
  }

  /* ── Store handlers ──────────────────────────── */

  /**
   * Wire the "What just happened?" briefing.
   *
   * Refreshes itself every 10 minutes so the card always reflects the last 10
   * minutes without anyone asking — it is a status panel, not a chat prompt.
   * "Refresh now" is there for the moment you actually want to look, e.g.
   * right after something happened on stage.
   *
   * Not tied to the SSE tick: generating a paragraph can take seconds on a
   * local model, and regenerating it every few seconds would queue model
   * calls behind each other and make the text flicker.
   */
  _wireBriefing() {
    const btn = this.container.querySelector('#briefing-btn');
    const body = this.container.querySelector('#briefing-body');
    if (!btn || !body) return;

    btn.addEventListener('click', () => this._refreshBriefing(true));

    // First fill immediately (unforced, so a warm server cache answers fast).
    this._refreshBriefing(false);

    this._briefingTimer = setInterval(
      () => this._refreshBriefing(true), Dashboard.BRIEFING_INTERVAL_MS,
    );
    // Keep the "updated N ago" label honest between refreshes.
    this._briefingMetaTimer = setInterval(() => this._renderBriefingMeta(), 30000);
  }

  async _refreshBriefing(force) {
    const btn = this.container.querySelector('#briefing-btn');
    const body = this.container.querySelector('#briefing-body');
    if (!btn || !body || this._briefingInFlight) return;

    this._briefingInFlight = true;
    btn.disabled = true;
    if (force) btn.textContent = 'Thinking…';
    body.classList.add('briefing-card__body--loading');

    let resp;
    try {
      const api = (await import('../api.js')).default;
      resp = await api.getBriefing(10, force);
    } finally {
      this._briefingInFlight = false;
    }

    // The view may have been torn down while the model was thinking.
    if (!body.isConnected) return;
    btn.disabled = false;
    btn.textContent = 'Refresh now';
    body.classList.remove('briefing-card__body--loading');

    if (!resp || resp.error || !resp.data) {
      body.innerHTML =
        '<span class="briefing-card__hint">Briefing unavailable.</span>';
      return;
    }

    const d = resp.data;
    body.innerHTML = '';

    const text = document.createElement('p');
    text.className = 'briefing-card__text';
    text.textContent = d.narrative || '';
    body.appendChild(text);

    // Name the author. A model-written paragraph and a computed one are both
    // fine to show, but the viewer should know which they are reading.
    const src = document.createElement('span');
    src.className = 'briefing-card__source';
    src.textContent = d.source === 'model'
      ? 'Written by the local model from live data'
      : 'Computed directly from live data';
    body.appendChild(src);

    this._briefingAt = Date.now();
    this._renderBriefingMeta();
  }

  _renderBriefingMeta() {
    const meta = this.container.querySelector('#briefing-meta');
    if (!meta || !this._briefingAt) return;
    const ageMin = Math.floor((Date.now() - this._briefingAt) / 60000);
    const nextMin = Math.max(0, Math.round(
      (Dashboard.BRIEFING_INTERVAL_MS - (Date.now() - this._briefingAt)) / 60000));
    const when = ageMin < 1 ? 'just now' : `${ageMin} min ago`;
    meta.textContent = `updated ${when} · auto-refresh in ${nextMin} min`;
  }

  _onStats(stats) {
    if (!stats) return;

    const appMbps = stats.bandwidth_mbps || 0;
    const controlMbps =
      stats.control_bandwidth_mbps ??
      stats.control_total_mbps ??
      0;
    const combinedMbps =
      stats.combined_bandwidth_mbps ??
      stats.combined_total_mbps ??
      (appMbps + controlMbps);

    const mbps = this._showControlOverhead ? combinedMbps : appMbps;

    // Use pre-computed Mbps from the backend directly.
    // NOTE: bandwidth_bps is in *bits*/sec (backend already converts bytes→bits).
    // splitBandwidthRate() expects *bytes*/sec and would multiply by 8 again,
    // causing an 8× inflation (e.g. 4 Mbps displayed as 40 Mbps).
    let val, unit;
    if (mbps >= 1) {
      val = mbps.toFixed(1);
      unit = 'Mbps';
    } else if (mbps >= 0.001) {
      const kbps = mbps * 1000;
      val = kbps.toFixed(1);
      unit = 'Kbps';
    } else {
      // Sub-Kbps: convert Mbps → bytes/sec for readable display
      const bytesPerSec = (mbps * 1_000_000) / 8;
      if (bytesPerSec >= 1) {
        val = Math.round(bytesPerSec).toString();
        unit = 'B/s';
      } else {
        val = '0';
        unit = 'B/s';
      }
    }

    // Show upload/download breakdown as trend line using pre-computed Mbps
    let trend = '', dir = '';
    const dlMbps = stats.download_mbps || 0;
    const ulMbps = stats.upload_mbps || 0;
    if (dlMbps > 0 || ulMbps > 0 || (this._showControlOverhead && controlMbps > 0)) {
      const appTrend = `App ↓ ${formatMbps(dlMbps)}  ↑ ${formatMbps(ulMbps)}`;
      trend = this._showControlOverhead
        ? `${appTrend}  •  Ctrl ${formatMbps(controlMbps)}`
        : appTrend;
      dir = dlMbps > ulMbps ? 'down' : 'up';
    } else {
      trend = '— idle';
    }

    this._cards.bandwidth.update(val, unit, trend, dir);
    this._prevStats = stats;

    // Device count from stats — traffic-active only
    const devCount = stats.active_devices ?? '--';
    const devTrend = this._getDeviceTrend();
    this._cards.devices.update(devCount, 'devices', devTrend);
  }

  _onControlPreference(enabled) {
    this._showControlOverhead = !!enabled;

    const toggle = this.container.querySelector('#control-overhead-toggle');
    if (toggle) toggle.checked = this._showControlOverhead;

    if (this._prevStats) this._onStats(this._prevStats);

    const devices = store.get('topDevices');
    if (devices) this._onDevices(devices);
  }

  _onMode(data) {
    if (!data) return;
    this._currentMode = data.mode || 'none';
    this._isArpCacheMode = data.can_arp_scan === false && !!data.can_arp_cache_scan;
    // Re-render the device card trend text when mode changes
    if (this._prevStats) {
      const devCount = this._prevStats.active_devices ?? '--';
      const devTrend = this._getDeviceTrend();
      this._cards.devices.update(devCount, 'devices', devTrend);
    }
  }

  /** Build device-card trend text based on mode + capabilities. */
  _getDeviceTrend() {
    const ownTrafficModes = ['public_network'];
    if (ownTrafficModes.includes(this._currentMode)) {
      return 'own traffic only';
    }
    return this._isArpCacheMode ? 'traffic-active only' : '';
  }

  _onHealth(health) {
    if (!health) return;
    const score = health.score ?? 0;
    const label = score >= 80 ? 'Good' : score >= 50 ? 'Fair' : 'Poor';
    this._cards.health.update(score, `/ 100 ${label}`);
  }

  _onAlertStats(data) {
    if (!data) return;
    const count = data.total_unresolved ?? 0;
    this._cards.alerts.update(count, count === 1 ? 'alert' : 'alerts');
  }

  _onDevices(data) {
    const devices = Array.isArray(data)
      ? data
      : (Array.isArray(data?.devices)
          ? data.devices
          : (Array.isArray(data?.data) ? data.data : []));
    const list = document.getElementById('top-devices-list');
    if (!list) return;

    const title = this.container.querySelector('#top-devices-widget .top-devices__title');
    if (title) {
      title.textContent = this._showControlOverhead
        ? 'Top Devices (App + Control)'
        : 'Top Devices (App Only)';
    }

    if (!Array.isArray(devices) || devices.length === 0) {
      list.className = 'empty-state';
      list.innerHTML = '<div class="empty-state"><span class="empty-state__text">No devices detected yet</span></div>';
      return;
    }

    // Remove the empty-state class so items are left-aligned, not centered
    list.className = '';

    const top5 = devices.slice(0, 5);
    list.innerHTML = top5.map(d => `
      <div class="top-devices__item">
        <div>
          <div class="top-devices__name">${escapeHtml(d.hostname || d.device_name || d.ip_address || 'Unknown')}</div>
          <div class="top-devices__ip">${escapeHtml(d.ip_address || '')}</div>
          ${this._showControlOverhead ? this._renderControlOverhead(d) : ''}
        </div>
        <div class="top-devices__bandwidth">${formatBytes(this._getDeviceDisplayBytes(d))}</div>
      </div>
    `).join('');
  }

  _getDeviceDisplayBytes(device) {
    const appBytes = device?.total_bytes_app ?? device?.total_bytes ?? device?.bytes ?? 0;
    const controlBytes = device?.total_bytes_control ?? 0;
    const totalBytes = device?.total_bytes_total ?? (appBytes + controlBytes);
    return this._showControlOverhead ? totalBytes : appBytes;
  }

  _renderControlOverhead(device) {
    const appBytes = device?.total_bytes_app ?? device?.total_bytes ?? 0;
    const controlBytes = device?.total_bytes_control ?? 0;
    const totalBytes = device?.total_bytes_total ?? (appBytes + controlBytes);
    if (!controlBytes || totalBytes <= 0) {
      return '<div class="top-devices__overhead">Ctrl 0%</div>';
    }
    const pct = Math.round((controlBytes / totalBytes) * 100);
    return `<div class="top-devices__overhead">Ctrl ${pct}% • ${formatBytes(controlBytes)}</div>`;
  }

  destroy() {
    this._unsubs.forEach(fn => fn());
    // Timers outlive the DOM otherwise, and a navigated-away dashboard would
    // keep firing model calls in the background.
    if (this._briefingTimer) clearInterval(this._briefingTimer);
    if (this._briefingMetaTimer) clearInterval(this._briefingMetaTimer);
    this._briefingTimer = this._briefingMetaTimer = null;
    if (this._bandwidthChart) this._bandwidthChart.destroy();
    if (this._protocolChart) this._protocolChart.destroy();
  }
}
