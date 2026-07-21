/**
 * ParentalView.js - Parental controls / quotas (W5)
 * ==================================================
 * Per-device internet controls: pause now, a daily data cap, and blocked
 * time windows (bedtime). Enforced by the DNS sinkhole in hotspot mode; the
 * view says so plainly when it can't enforce.
 *
 * All device names/MACs come from the network, so every write uses
 * textContent / DOM APIs — never HTML string interpolation.
 */

import api from '../api.js';
import { formatBytes, formatRelativeTime } from '../utils/formatters.js';

const REFRESH_MS = 5000;

export default class ParentalView {
  constructor(el) {
    this.el = el;
    this._timer = null;
    this._destroyed = false;
    this._policies = [];
    this._devices = [];
    this._status = null;
  }

  render() {
    this.el.innerHTML = `
      <div class="parental">
        <div class="view-explainer">
          Set per-device internet rules — pause now, a daily data cap, or a
          blocked time window. Enforced in <strong>hotspot mode</strong> the
          same way domain blocking is; outside hotspot, rules are saved but not
          applied.
        </div>
        <div class="activity__hint" id="parental-hint"></div>
        <div class="parental__add card" id="parental-add"></div>
        <div class="parental__list" id="parental-list">
          <div class="activity__empty">Loading device controls…</div>
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
    const [pol, devs] = await Promise.all([
      api.getParentalPolicies(),
      api.getAllDevices(200, 0, false),
    ]);
    if (this._destroyed) return;
    this._policies = (pol && pol.data) || [];
    this._status = (pol && pol.status) || null;
    const d = devs && (devs.devices || devs.data || devs);
    this._devices = Array.isArray(d) ? d : [];
    this._renderHint();
    this._renderAdd();
    this._renderList();
  }

  _deviceName(mac) {
    const dev = this._devices.find(x => (x.mac_address || '').toLowerCase() === (mac || '').toLowerCase());
    return dev ? (dev.hostname || dev.device_name || dev.ip_address || mac) : mac;
  }

  _shortTime(ts) {
    // Stored as 'YYYY-MM-DD HH:MM:SS' local time; show just the clock.
    const m = /(\d{2}):(\d{2})/.exec(String(ts || ''));
    return m ? `${m[1]}:${m[2]}` : String(ts || '');
  }

  _renderHint() {
    const hint = this.el.querySelector('#parental-hint');
    if (!hint) return;
    if (this._status && !this._status.enforcing && this._status.reason) {
      hint.textContent = this._status.reason;
      hint.className = 'activity__hint activity__hint--warn';
    } else {
      hint.textContent = '';
      hint.className = 'activity__hint';
    }
  }

  _renderAdd() {
    const box = this.el.querySelector('#parental-add');
    if (!box) return;
    // Devices without a policy yet.
    const managed = new Set(this._policies.map(p => (p.device_mac || '').toLowerCase()));
    const candidates = this._devices.filter(
      d => d.mac_address && !managed.has(d.mac_address.toLowerCase()));
    box.innerHTML = '';

    const title = document.createElement('div');
    title.className = 'parental__add-title';
    title.textContent = 'Add a device';
    box.appendChild(title);

    const row = document.createElement('div');
    row.className = 'parental__add-row';

    const select = document.createElement('select');
    select.className = 'activity__filter';
    const ph = document.createElement('option');
    ph.value = ''; ph.textContent = candidates.length ? 'Choose a device…' : 'All devices already have controls';
    select.appendChild(ph);
    for (const d of candidates) {
      const opt = document.createElement('option');
      opt.value = d.mac_address;
      opt.textContent = `${d.hostname || d.device_name || d.ip_address || d.mac_address}`;
      select.appendChild(opt);
    }
    row.appendChild(select);

    const add = document.createElement('button');
    add.className = 'btn btn--sm btn--primary';
    add.textContent = 'Add controls';
    add.addEventListener('click', async () => {
      if (!select.value) return;
      add.disabled = true;
      await api.setParentalPolicy(select.value, { paused: false });
      await this._load();
    });
    row.appendChild(add);
    box.appendChild(row);
  }

  _renderList() {
    const list = this.el.querySelector('#parental-list');
    if (!list) return;
    list.innerHTML = '';
    if (!this._policies.length) {
      const empty = document.createElement('div');
      empty.className = 'activity__empty';
      empty.textContent = 'No device controls yet. Add one above.';
      list.appendChild(empty);
      return;
    }
    for (const p of this._policies) list.appendChild(this._policyCard(p));
  }

  _policyCard(p) {
    const card = document.createElement('div');
    card.className = 'parental-card card';
    if (p.blocked_now) card.classList.add('parental-card--blocked');

    const head = document.createElement('div');
    head.className = 'parental-card__head';
    const name = document.createElement('div');
    name.className = 'parental-card__name';
    name.textContent = this._deviceName(p.device_mac);
    head.appendChild(name);

    const state = document.createElement('span');
    state.className = 'parental-card__state';
    if (p.blocked_now) {
      const reasons = { paused: 'Paused', quota_exceeded: 'Over data cap', schedule: 'Bedtime' };
      let label = reasons[p.block_reason] || 'Blocked';
      // Say when a pause ends. A block with no visible end is how a device
      // stayed cut off for hours after a demo with nothing explaining it.
      if (p.block_reason === 'paused') {
        label += p.pause_expires_at
          ? ` until ${this._shortTime(p.pause_expires_at)}`
          : ' (until resumed)';
      }
      state.textContent = label;
      state.classList.add('parental-card__state--blocked');
    } else {
      state.textContent = 'Allowed';
      state.classList.add('parental-card__state--ok');
    }
    head.appendChild(state);
    card.appendChild(head);

    const usage = document.createElement('div');
    usage.className = 'parental-card__usage';
    usage.textContent = `Today: ${formatBytes(p.usage_today_bytes || 0)}` +
      (p.daily_quota_mb ? ` of ${p.daily_quota_mb} MB cap` : ' · no cap');
    card.appendChild(usage);

    // Controls row
    const controls = document.createElement('div');
    controls.className = 'parental-card__controls';

    const pauseBtn = document.createElement('button');
    pauseBtn.className = 'btn btn--sm';
    pauseBtn.textContent = p.paused ? 'Resume' : 'Pause now';
    pauseBtn.addEventListener('click', async () => {
      pauseBtn.disabled = true;
      await (p.paused ? api.resumeDevice(p.device_mac) : api.pauseDevice(p.device_mac));
      await this._load();
    });
    controls.appendChild(pauseBtn);

    const quota = document.createElement('input');
    quota.type = 'number';
    quota.min = '0';
    quota.className = 'parental-card__quota';
    quota.placeholder = 'Daily MB';
    if (p.daily_quota_mb) quota.value = p.daily_quota_mb;
    quota.addEventListener('change', async () => {
      await api.setParentalPolicy(p.device_mac, { daily_quota_mb: parseInt(quota.value, 10) || 0 });
      await this._load();
    });
    controls.appendChild(quota);

    // Bedtime window (single start/end for simplicity).
    const w = (p.blocked_windows && p.blocked_windows[0]) || {};
    const start = document.createElement('input');
    start.type = 'time'; start.className = 'parental-card__time'; start.value = w.start || '';
    const end = document.createElement('input');
    end.type = 'time'; end.className = 'parental-card__time'; end.value = w.end || '';
    const applyWin = async () => {
      const windows = (start.value && end.value) ? [{ start: start.value, end: end.value }] : [];
      await api.setParentalPolicy(p.device_mac, { blocked_windows: windows });
      await this._load();
    };
    start.addEventListener('change', applyWin);
    end.addEventListener('change', applyWin);
    const winWrap = document.createElement('span');
    winWrap.className = 'parental-card__window';
    const lbl = document.createElement('span');
    lbl.className = 'parental-card__window-label';
    lbl.textContent = 'Block';
    winWrap.appendChild(lbl);
    winWrap.appendChild(start);
    const dash = document.createElement('span'); dash.textContent = '–'; winWrap.appendChild(dash);
    winWrap.appendChild(end);
    controls.appendChild(winWrap);

    const del = document.createElement('button');
    del.className = 'btn btn--sm btn--danger';
    del.textContent = 'Remove';
    del.addEventListener('click', async () => {
      del.disabled = true;
      await api.clearParentalPolicy(p.device_mac);
      await this._load();
    });
    controls.appendChild(del);

    card.appendChild(controls);
    return card;
  }
}
