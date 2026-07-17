/**
 * ThreatsView.js - Standalone Threats view (W6)
 * ==============================================
 * A first-class list of fired threat detections (port scan, beaconing,
 * DNS tunneling, rogue device, lateral movement, VPN), grouped by type,
 * each with its evidence and confidence. Reads /api/threats/recent.
 *
 * All text comes from the network / detectors, so every write uses
 * textContent / DOM APIs.
 */

import api from '../api.js';
import { formatRelativeTime, severityClass } from '../utils/formatters.js';

const REFRESH_MS = 10000;

const TYPE_LABELS = {
  port_scan: 'Port scans', beaconing: 'Beaconing (possible C2)',
  dns_tunneling: 'DNS tunneling', rogue_device: 'New / unrecognized devices',
  lateral_movement: 'Lateral movement', vpn: 'VPN / encrypted tunnels',
};

export default class ThreatsView {
  constructor(el) {
    this.el = el;
    this._timer = null;
    this._destroyed = false;
    this._threats = [];
  }

  render() {
    this.el.innerHTML = `
      <div class="threats">
        <div class="view-explainer">
          Every named detection the intelligence layer has raised, grouped by
          type with its supporting evidence. Related detections are fused into
          <a href="#/incidents">Incidents</a>.
        </div>
        <div class="threats__summary" id="threats-summary"></div>
        <div class="threats__groups" id="threats-groups">
          <div class="activity__empty">Loading detections…</div>
        </div>
      </div>
    `;
    this._load();
    this._timer = setInterval(() => this._load(), REFRESH_MS);
  }

  destroy() {
    this._destroyed = true;
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  async _load() {
    const resp = await api.getRecentThreats(200);
    if (this._destroyed || !resp || resp.error) return;
    this._threats = (resp.data) || [];
    this._renderSummary();
    this._renderGroups();
  }

  _renderSummary() {
    const el = this.el.querySelector('#threats-summary');
    if (!el) return;
    const n = this._threats.length;
    const crit = this._threats.filter(t => t.severity === 'critical').length;
    el.textContent = n
      ? `${n} active detection${n === 1 ? '' : 's'} · ${crit} critical`
      : 'No active detections — the network looks clean.';
  }

  _renderGroups() {
    const wrap = this.el.querySelector('#threats-groups');
    if (!wrap) return;
    wrap.innerHTML = '';
    if (!this._threats.length) {
      const empty = document.createElement('div');
      empty.className = 'activity__empty';
      empty.textContent = 'Nothing detected in the recent window.';
      wrap.appendChild(empty);
      return;
    }
    const byType = new Map();
    for (const t of this._threats) {
      if (!byType.has(t.threat_type)) byType.set(t.threat_type, []);
      byType.get(t.threat_type).push(t);
    }
    for (const [type, items] of byType) {
      wrap.appendChild(this._group(type, items));
    }
  }

  _group(type, items) {
    const card = document.createElement('div');
    card.className = 'threats-group card';

    const head = document.createElement('div');
    head.className = 'threats-group__head';
    const title = document.createElement('span');
    title.className = 'threats-group__title';
    title.textContent = TYPE_LABELS[type] || type;
    const count = document.createElement('span');
    count.className = 'threats-group__count';
    count.textContent = String(items.length);
    head.appendChild(title);
    head.appendChild(count);
    card.appendChild(head);

    for (const t of items) card.appendChild(this._row(t));
    return card;
  }

  _row(t) {
    const row = document.createElement('div');
    row.className = 'threats-row';

    const top = document.createElement('div');
    top.className = 'threats-row__top';
    const sev = document.createElement('span');
    sev.className = `alert-item__severity alert-item__severity--${severityClass(t.severity)}`;
    sev.textContent = t.severity || 'info';
    const time = document.createElement('span');
    time.className = 'threats-row__time';
    time.textContent = formatRelativeTime(t.timestamp);
    top.appendChild(sev);
    top.appendChild(time);
    row.appendChild(top);

    const msg = document.createElement('div');
    msg.className = 'threats-row__msg';
    msg.textContent = t.message || '';
    row.appendChild(msg);

    const meta = document.createElement('div');
    meta.className = 'threats-row__meta';
    const bits = [];
    if (t.confidence != null) bits.push(`confidence ${Math.round(t.confidence * 100)}%`);
    const ev = Array.isArray(t.evidence) ? t.evidence[0] : null;
    if (ev && ev.signal) bits.push(`signal: ${ev.signal}`);
    if (t.incident_id) bits.push(`incident #${t.incident_id}`);
    meta.textContent = bits.join(' · ');
    row.appendChild(meta);

    return row;
  }
}
