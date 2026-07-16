/**
 * ActivityView.js - Live Client Activity (real-time DNS feed)
 * ============================================================
 * Shows, in near-real-time, what each connected client is doing on the
 * network: the domains it is resolving (a good proxy for the sites and
 * apps it is using). Data comes from /api/activity/recent, which joins the
 * captured DNS queries to each device's friendly name.
 *
 * This works best in hotspot mode, where every client's traffic — and so
 * its DNS lookups — routes through this host and is captured directly.
 *
 * All domains/hostnames come from the network, so every text write uses
 * textContent / DOM APIs — never HTML string interpolation.
 */

import api from '../api.js';
import { formatRelativeTime } from '../utils/formatters.js';

const REFRESH_MS = 3000;
const WINDOW_MINUTES = 15;
const MAX_DOMAINS_PER_DEVICE = 15;

export default class ActivityView {
  constructor(el) {
    this.el = el;
    this._timer = null;
    this._destroyed = false;
    this._filter = '';
    this._rows = [];
  }

  render() {
    this.el.innerHTML = `
      <div class="activity">
        <div class="activity__toolbar">
          <div class="activity__summary" id="activity-summary">Listening for activity…</div>
          <input type="text" id="activity-filter" class="activity__filter"
                 autocomplete="off" placeholder="Filter by device or domain…" />
        </div>
        <div class="activity__hint" id="activity-hint"></div>
        <div class="activity__grid" id="activity-grid">
          <div class="activity__empty">Waiting for DNS activity from clients…</div>
        </div>
      </div>
    `;

    const filterEl = this.el.querySelector('#activity-filter');
    filterEl.addEventListener('input', () => {
      this._filter = (filterEl.value || '').trim().toLowerCase();
      this._renderGrid();
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
    const resp = await api.getActivity(WINDOW_MINUTES, 500);
    if (this._destroyed || !resp || resp.error) return;
    this._rows = Array.isArray(resp.data) ? resp.data : [];
    this._renderSummary();
    this._renderGrid();
  }

  /** Group the flat DNS rows into one bucket per client device. */
  _group() {
    const byDevice = new Map();
    for (const r of this._rows) {
      const key = r.source_mac || r.source_ip || 'unknown';
      let g = byDevice.get(key);
      if (!g) {
        g = {
          key,
          name: r.device_name || r.source_ip || r.source_mac || 'Unknown device',
          ip: r.source_ip || '',
          mac: r.source_mac || '',
          total: 0,
          latest: r.timestamp,
          domains: [],      // {qname, timestamp}
          seen: new Set(),  // dedup domains, keep the most recent occurrence
        };
        byDevice.set(key, g);
      }
      g.total += 1;
      if (r.timestamp > g.latest) g.latest = r.timestamp;
      const dom = (r.qname || '').replace(/\.$/, '');
      if (dom && !g.seen.has(dom)) {
        g.seen.add(dom);
        g.domains.push({ qname: dom, timestamp: r.timestamp });
      }
    }
    // Rows arrive newest-first, so each device's domains are already newest
    // first; sort devices by most recent activity.
    return [...byDevice.values()].sort((a, b) => (a.latest < b.latest ? 1 : -1));
  }

  _renderSummary() {
    const el = this.el.querySelector('#activity-summary');
    const hint = this.el.querySelector('#activity-hint');
    if (!el) return;
    const groups = this._group();
    const totalLookups = this._rows.length;
    el.textContent =
      `${groups.length} active client${groups.length === 1 ? '' : 's'} · ` +
      `${totalLookups} lookup${totalLookups === 1 ? '' : 's'} in the last ${WINDOW_MINUTES} min`;
    if (hint) {
      hint.textContent = totalLookups === 0
        ? 'No DNS lookups captured yet. In hotspot mode this fills as clients ' +
          'browse; on other networks only this host\'s own lookups are visible.'
        : '';
    }
  }

  _renderGrid() {
    const grid = this.el.querySelector('#activity-grid');
    if (!grid) return;
    grid.innerHTML = '';

    let groups = this._group();
    if (this._filter) {
      groups = groups
        .map(g => this._applyFilter(g))
        .filter(Boolean);
    }

    if (!groups.length) {
      const empty = document.createElement('div');
      empty.className = 'activity__empty';
      empty.textContent = this._filter
        ? 'No activity matches that filter.'
        : 'Waiting for DNS activity from clients…';
      grid.appendChild(empty);
      return;
    }

    for (const g of groups) grid.appendChild(this._deviceCard(g));
  }

  /** Return a copy of the group narrowed to the filter, or null if nothing
   *  in it matches (device name/IP match keeps all domains). */
  _applyFilter(g) {
    const f = this._filter;
    const deviceMatches =
      g.name.toLowerCase().includes(f) ||
      g.ip.toLowerCase().includes(f) ||
      g.mac.toLowerCase().includes(f);
    if (deviceMatches) return g;
    const domains = g.domains.filter(d => d.qname.toLowerCase().includes(f));
    if (!domains.length) return null;
    return { ...g, domains };
  }

  _deviceCard(g) {
    const card = document.createElement('div');
    card.className = 'activity-card card';

    const head = document.createElement('div');
    head.className = 'activity-card__head';

    const name = document.createElement('div');
    name.className = 'activity-card__name';
    name.textContent = g.name;
    head.appendChild(name);

    const meta = document.createElement('div');
    meta.className = 'activity-card__meta';
    const metaBits = [];
    if (g.ip && g.ip !== g.name) metaBits.push(g.ip);
    metaBits.push(`${g.total} lookup${g.total === 1 ? '' : 's'}`);
    metaBits.push(formatRelativeTime(g.latest));
    meta.textContent = metaBits.join(' · ');
    head.appendChild(meta);

    card.appendChild(head);

    const list = document.createElement('ul');
    list.className = 'activity-card__domains';
    const shown = g.domains.slice(0, MAX_DOMAINS_PER_DEVICE);
    for (const d of shown) {
      const li = document.createElement('li');
      li.className = 'activity-domain';
      const dom = document.createElement('span');
      dom.className = 'activity-domain__name';
      dom.textContent = d.qname;
      const t = document.createElement('span');
      t.className = 'activity-domain__time';
      t.textContent = formatRelativeTime(d.timestamp);
      li.appendChild(dom);
      li.appendChild(t);
      list.appendChild(li);
    }
    if (g.domains.length > shown.length) {
      const more = document.createElement('li');
      more.className = 'activity-domain activity-domain--more';
      more.textContent = `+${g.domains.length - shown.length} more domains`;
      list.appendChild(more);
    }
    card.appendChild(list);
    return card;
  }
}
