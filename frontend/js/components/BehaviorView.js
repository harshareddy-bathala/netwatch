/**
 * BehaviorView.js - Standalone Behavior view (W6)
 * ================================================
 * Per-device learned baselines: pick a device, see its hour-of-week means
 * (± std) for bytes / flows / unique-destinations / DNS. Reads
 * /api/behavior/profiles/<mac>, with the device list from /api/devices.
 */

import api from '../api.js';
import { formatBytes } from '../utils/formatters.js';

const METRIC_LABELS = {
  bytes: 'Traffic volume (bytes/window)',
  flows: 'Connections/window',
  unique_dests: 'Distinct destinations/window',
  dns_queries: 'DNS lookups/window',
};

export default class BehaviorView {
  constructor(el) {
    this.el = el;
    this._destroyed = false;
    this._devices = [];
    this._selected = '';
  }

  render() {
    this.el.innerHTML = `
      <div class="behavior">
        <div class="view-explainer">
          What "normal" looks like for each device — learned per hour-of-week,
          so an alert means "unusual <em>for this device</em>", not a global
          threshold. Baselines build up as the device is observed.
        </div>
        <div class="behavior__toolbar">
          <select class="activity__filter" id="behavior-device"></select>
        </div>
        <div class="behavior__body" id="behavior-body">
          <div class="activity__empty">Pick a device to see its baselines.</div>
        </div>
      </div>
    `;
    const sel = this.el.querySelector('#behavior-device');
    sel.addEventListener('change', () => {
      this._selected = sel.value;
      this._loadProfile();
    });
    this._loadDevices();
  }

  destroy() { this._destroyed = true; }

  async _loadDevices() {
    const resp = await api.getAllDevices(200, 0, false);
    if (this._destroyed) return;
    const d = resp && (resp.devices || resp.data || resp);
    this._devices = (Array.isArray(d) ? d : []).filter(x => x.mac_address);
    const sel = this.el.querySelector('#behavior-device');
    if (!sel) return;
    sel.innerHTML = '';
    const ph = document.createElement('option');
    ph.value = ''; ph.textContent = this._devices.length ? 'Choose a device…' : 'No devices yet';
    sel.appendChild(ph);
    for (const dev of this._devices) {
      const opt = document.createElement('option');
      opt.value = dev.mac_address;
      opt.textContent = dev.hostname || dev.device_name || dev.ip_address || dev.mac_address;
      sel.appendChild(opt);
    }
  }

  async _loadProfile() {
    const body = this.el.querySelector('#behavior-body');
    if (!body) return;
    if (!this._selected) {
      body.innerHTML = '<div class="activity__empty">Pick a device to see its baselines.</div>';
      return;
    }
    body.innerHTML = '<div class="activity__empty">Loading baselines…</div>';
    const resp = await api.getBehaviorProfile(this._selected);
    if (this._destroyed) return;
    const data = (resp && resp.data) || {};
    this._renderProfile(data);
  }

  _renderProfile(data) {
    const body = this.el.querySelector('#behavior-body');
    if (!body) return;
    body.innerHTML = '';
    const metrics = data.metrics || {};
    const nonEmpty = Object.keys(metrics).filter(m => (metrics[m] || []).length);
    if (!nonEmpty.length) {
      const empty = document.createElement('div');
      empty.className = 'activity__empty';
      empty.textContent = 'No baselines learned for this device yet — they build up as it is observed across hours of the week.';
      body.appendChild(empty);
      return;
    }
    for (const metric of nonEmpty) {
      body.appendChild(this._metricCard(metric, metrics[metric]));
    }
  }

  _metricCard(metric, entries) {
    const card = document.createElement('div');
    card.className = 'behavior-card card';
    const title = document.createElement('div');
    title.className = 'behavior-card__title';
    title.textContent = METRIC_LABELS[metric] || metric;
    card.appendChild(title);

    const isBytes = metric === 'bytes';
    const maxMean = Math.max(1, ...entries.map(e => e.mean || 0));

    const list = document.createElement('div');
    list.className = 'behavior-card__bars';
    for (const e of entries) {
      const row = document.createElement('div');
      row.className = 'behavior-bar';
      const label = document.createElement('span');
      label.className = 'behavior-bar__label';
      label.textContent = this._hourLabel(e.hour_of_week);
      const track = document.createElement('span');
      track.className = 'behavior-bar__track';
      const fill = document.createElement('span');
      fill.className = 'behavior-bar__fill';
      fill.style.width = `${Math.round(100 * (e.mean || 0) / maxMean)}%`;
      track.appendChild(fill);
      const val = document.createElement('span');
      val.className = 'behavior-bar__val';
      val.textContent = isBytes
        ? `${formatBytes(e.mean)} ±${formatBytes(e.std)}`
        : `${e.mean} ±${e.std}`;
      row.appendChild(label);
      row.appendChild(track);
      row.appendChild(val);
      list.appendChild(row);
    }
    card.appendChild(list);
    return card;
  }

  _hourLabel(how) {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const d = Math.floor((how % 168) / 24);
    const h = how % 24;
    return `${days[d] || '?'} ${String(h).padStart(2, '0')}:00`;
  }
}
