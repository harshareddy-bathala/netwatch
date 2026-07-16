/**
 * IncidentsView.js - Incident Triage & Timeline (Phase 2)
 * ========================================================
 * Reads /api/incidents and /api/incidents/<id>:
 *   - master list of fused incidents (open / resolved filter)
 *   - selecting one shows its alert timeline (member alerts in order)
 *   - resolve action closes an open incident
 *
 * All text (titles, messages, device MACs) comes from the network, so
 * every write uses textContent / DOM APIs — never HTML interpolation of
 * untrusted values.
 */

import api from '../api.js';
import { formatTimestamp, formatRelativeTime, severityClass } from '../utils/formatters.js';

const REFRESH_MS = 15000;

export default class IncidentsView {
  constructor(el) {
    this.el = el;
    this._timer = null;
    this._destroyed = false;
    this._status = 'open';        // 'open' | 'resolved' | 'all'
    this._selectedId = null;
    this._incidents = [];
  }

  render() {
    this.el.innerHTML = `
      <div class="incidents">
        <div class="incidents__toolbar">
          <div class="incidents__summary" id="incidents-summary"></div>
          <div class="incidents__filter" role="tablist">
            <button class="incidents__filter-btn active" data-status="open">Open</button>
            <button class="incidents__filter-btn" data-status="resolved">Resolved</button>
            <button class="incidents__filter-btn" data-status="all">All</button>
          </div>
        </div>
        <div class="incidents__body">
          <div class="incidents__list card" id="incidents-list">
            <div class="incidents__empty">Loading incidents…</div>
          </div>
          <div class="incidents__detail card" id="incidents-detail">
            <div class="incidents__empty">Select an incident to see its timeline.</div>
          </div>
        </div>
      </div>
    `;

    this.el.querySelectorAll('.incidents__filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        this._status = btn.dataset.status;
        this.el.querySelectorAll('.incidents__filter-btn').forEach(b =>
          b.classList.toggle('active', b === btn));
        this._selectedId = null;
        this._renderDetail(null);
        this._load();
      });
    });

    this._load();
    this._timer = setInterval(() => this._load(), REFRESH_MS);
  }

  destroy() {
    this._destroyed = true;
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  async _load() {
    const status = this._status === 'all' ? null : this._status;
    const [listResp, statsResp] = await Promise.all([
      api.getIncidents(status, 100),
      api.getIncidentStats(),
    ]);
    if (this._destroyed) return;
    this._incidents = (listResp && listResp.data) || [];
    this._renderSummary(statsResp && statsResp.data);
    this._renderList();
    // Refresh the open detail so its timeline / status stays current.
    if (this._selectedId != null) this._loadDetail(this._selectedId);
  }

  _renderSummary(stats) {
    const el = this.el.querySelector('#incidents-summary');
    if (!el) return;
    const open = stats ? stats.open_count : 0;
    const triage = (stats && stats.triage) || null;
    let text = `${open} open incident${open === 1 ? '' : 's'}`;
    if (triage && triage.triaged_count != null) {
      text += ` · ${triage.triaged_count} alerts fused · ${triage.window_minutes}m window`;
    }
    el.textContent = text;
  }

  _renderList() {
    const list = this.el.querySelector('#incidents-list');
    if (!list) return;
    list.innerHTML = '';

    if (!this._incidents.length) {
      const empty = document.createElement('div');
      empty.className = 'incidents__empty';
      empty.textContent = this._status === 'open'
        ? 'No open incidents. The network is quiet.'
        : 'No incidents to show.';
      list.appendChild(empty);
      return;
    }

    for (const inc of this._incidents) {
      list.appendChild(this._incidentRow(inc));
    }
  }

  _incidentRow(inc) {
    const row = document.createElement('button');
    row.className = 'incident-row';
    row.classList.toggle('incident-row--selected', inc.id === this._selectedId);
    row.classList.toggle('incident-row--resolved', inc.status === 'resolved');

    const sev = document.createElement('span');
    sev.className = `alert-item__severity alert-item__severity--${severityClass(inc.severity)}`;
    sev.textContent = inc.severity || 'info';

    const main = document.createElement('div');
    main.className = 'incident-row__main';

    const title = document.createElement('div');
    title.className = 'incident-row__title';
    title.textContent = inc.title || 'Incident';

    const meta = document.createElement('div');
    meta.className = 'incident-row__meta';
    const cats = Array.isArray(inc.categories) ? inc.categories.join(', ') : '';
    const count = inc.alert_count || 0;
    meta.textContent =
      `${count} alert${count === 1 ? '' : 's'}` +
      (cats ? ` · ${cats}` : '') +
      ` · ${formatRelativeTime(inc.updated_at)}`;

    main.appendChild(title);
    main.appendChild(meta);

    if (inc.status === 'resolved') {
      const chip = document.createElement('span');
      chip.className = 'incident-row__resolved-chip';
      chip.textContent = 'resolved';
      main.appendChild(chip);
    }

    row.appendChild(sev);
    row.appendChild(main);

    row.addEventListener('click', () => {
      this._selectedId = inc.id;
      this._renderList();
      this._loadDetail(inc.id);
    });
    return row;
  }

  async _loadDetail(id) {
    const resp = await api.getIncident(id);
    if (this._destroyed) return;
    if (!resp || resp.error || !resp.data) {
      this._renderDetail(null);
      return;
    }
    this._renderDetail(resp.data);
  }

  _renderDetail(inc) {
    const panel = this.el.querySelector('#incidents-detail');
    if (!panel) return;
    panel.innerHTML = '';

    if (!inc) {
      const empty = document.createElement('div');
      empty.className = 'incidents__empty';
      empty.textContent = 'Select an incident to see its timeline.';
      panel.appendChild(empty);
      return;
    }

    // Header
    const header = document.createElement('div');
    header.className = 'incident-detail__header';

    const titleWrap = document.createElement('div');
    const title = document.createElement('h3');
    title.className = 'incident-detail__title';
    title.textContent = inc.title || 'Incident';
    const sub = document.createElement('div');
    sub.className = 'incident-detail__sub';
    sub.textContent =
      `${inc.device_mac ? inc.device_mac : 'network-wide'} · ` +
      `opened ${formatTimestamp(inc.created_at)} · ` +
      `${(inc.alerts || []).length} alerts`;
    titleWrap.appendChild(title);
    titleWrap.appendChild(sub);

    const sev = document.createElement('span');
    sev.className = `alert-item__severity alert-item__severity--${severityClass(inc.severity)}`;
    sev.textContent = inc.severity || 'info';

    header.appendChild(titleWrap);
    header.appendChild(sev);
    panel.appendChild(header);

    const alerts = inc.alerts || [];

    // The summary is often a copy of an alert's message; showing it above a
    // timeline that repeats the same text reads as duplication. Only show it
    // when it actually adds something the alerts don't already say.
    const norm = (s) => (s || '').trim().toLowerCase();
    const alertMessages = new Set(alerts.map(a => norm(a.message)));
    if (inc.summary && !alertMessages.has(norm(inc.summary))) {
      const summary = document.createElement('div');
      summary.className = 'incident-detail__summary';
      summary.textContent = inc.summary;
      panel.appendChild(summary);
    }

    // Timeline of member alerts. Consecutive alerts with an identical
    // message (e.g. the same rogue-device notice re-firing) collapse into a
    // single row with an occurrence count, so the timeline shows the story
    // once instead of three near-identical lines.
    const timeline = document.createElement('div');
    timeline.className = 'incident-timeline';
    if (!alerts.length) {
      const none = document.createElement('div');
      none.className = 'incidents__empty';
      none.textContent = 'No member alerts recorded.';
      timeline.appendChild(none);
    } else {
      for (const group of this._collapseAlerts(alerts)) {
        timeline.appendChild(this._timelineItem(group.alert, group.count, group.lastTimestamp));
      }
    }
    panel.appendChild(timeline);

    // Resolve action (open incidents only)
    if (inc.status === 'open') {
      const actions = document.createElement('div');
      actions.className = 'incident-detail__actions';
      const btn = document.createElement('button');
      btn.className = 'btn btn--primary';
      btn.textContent = 'Resolve incident';
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        btn.textContent = 'Resolving…';
        const res = await api.resolveIncident(inc.id);
        if (res && !res.error) {
          this._load();
          this._loadDetail(inc.id);
        } else {
          btn.disabled = false;
          btn.textContent = 'Resolve failed — retry';
        }
      });
      actions.appendChild(btn);
      panel.appendChild(actions);
    }
  }

  /** Merge runs of consecutive alerts that share the same type + message
   *  into one group, counting occurrences and tracking the latest time. */
  _collapseAlerts(alerts) {
    const groups = [];
    for (const alert of alerts) {
      const prev = groups[groups.length - 1];
      const sameStory = prev
        && (prev.alert.alert_type || '') === (alert.alert_type || '')
        && (prev.alert.message || '') === (alert.message || '');
      if (sameStory) {
        prev.count += 1;
        prev.lastTimestamp = alert.timestamp;
      } else {
        groups.push({ alert, count: 1, lastTimestamp: alert.timestamp });
      }
    }
    return groups;
  }

  _timelineItem(alert, count = 1, lastTimestamp = null) {
    const item = document.createElement('div');
    item.className = 'incident-timeline__item';

    const dot = document.createElement('span');
    dot.className = `incident-timeline__dot incident-timeline__dot--${severityClass(alert.severity)}`;

    const body = document.createElement('div');
    body.className = 'incident-timeline__body';

    const top = document.createElement('div');
    top.className = 'incident-timeline__top';
    const type = document.createElement('span');
    type.className = 'incident-timeline__type';
    type.textContent = (alert.alert_type || 'alert') + (count > 1 ? ` ×${count}` : '');
    const time = document.createElement('span');
    time.className = 'incident-timeline__time';
    // For a collapsed run, show when it started and last recurred.
    time.textContent = count > 1 && lastTimestamp && lastTimestamp !== alert.timestamp
      ? `${formatTimestamp(alert.timestamp)} → ${formatTimestamp(lastTimestamp)}`
      : formatTimestamp(alert.timestamp);
    top.appendChild(type);
    top.appendChild(time);

    const msg = document.createElement('div');
    msg.className = 'incident-timeline__msg';
    msg.textContent = alert.message || '';

    body.appendChild(top);
    body.appendChild(msg);

    // Evidence, if the alert carried structured details
    const evidence = this._parseEvidence(alert.details);
    if (evidence) {
      const ev = document.createElement('div');
      ev.className = 'incident-timeline__evidence';
      ev.textContent = evidence;
      body.appendChild(ev);
    }

    item.appendChild(dot);
    item.appendChild(body);
    return item;
  }

  /** Pull a short human-readable evidence/confidence line from the alert
   *  details JSON, tolerating both plain strings and structured payloads. */
  _parseEvidence(details) {
    if (!details) return '';
    let obj;
    try {
      obj = typeof details === 'string' ? JSON.parse(details) : details;
    } catch {
      return '';
    }
    if (!obj || typeof obj !== 'object') return '';
    const parts = [];
    if (obj.confidence != null) parts.push(`confidence ${Math.round(obj.confidence * 100)}%`);
    const ev = Array.isArray(obj.evidence) ? obj.evidence[0] : null;
    if (ev && ev.signal) parts.push(`signal: ${ev.signal}`);
    return parts.join(' · ');
  }
}
