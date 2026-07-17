/**
 * ActivityView.js - Live Client Activity (real-time DNS feed) + blocking
 * =======================================================================
 * Shows, in near-real-time, what each connected client is doing on the
 * network: the domains it is resolving (a good proxy for the sites and
 * apps it is using). Data comes from /api/activity/recent, which joins the
 * captured DNS queries to each device's friendly name.
 *
 * Each domain can be blocked straight from the feed — that writes a rule to
 * /api/blocking/rules, which the capture-side DNS blocker enforces by
 * answering the client's next lookup with NXDOMAIN.
 *
 * This works best in hotspot mode, where every client's traffic — and so
 * its DNS lookups — routes through this host and is captured directly.
 * Blocking *only* works there, and the view says so when it doesn't apply.
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
    this._rules = [];
    this._status = null;
    this._showRules = false;
  }

  render() {
    this.el.innerHTML = `
      <div class="activity">
        <div class="activity__toolbar">
          <div class="activity__summary" id="activity-summary">Listening for activity…</div>
          <input type="text" id="activity-filter" class="activity__filter"
                 autocomplete="off" placeholder="Filter by device or domain…" />
          <button type="button" class="btn btn--sm" id="activity-rules-toggle">Blocked</button>
        </div>
        <div class="activity__hint" id="activity-hint"></div>
        <div class="activity__rules" id="activity-rules" hidden></div>
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

    this.el.querySelector('#activity-rules-toggle').addEventListener('click', () => {
      this._showRules = !this._showRules;
      this._renderRules();
    });

    this._loadRules();
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

  async _loadRules() {
    const resp = await api.getBlockingRules();
    if (this._destroyed || !resp || resp.error) return;
    this._rules = Array.isArray(resp.data) ? resp.data : [];
    this._status = resp.status || null;
    this._renderRules();
    this._renderSummary();
    this._renderGrid();
  }

  /** True when an enabled rule blocks *domain* for the client at *mac*.
   *  Mirrors the server's match: a rule on instagram.com also covers
   *  www.instagram.com, and a rule with no device_mac covers every client. */
  _isBlocked(domain, mac) {
    const name = (domain || '').toLowerCase();
    const m = (mac || '').toLowerCase();
    return this._rules.some(r => {
      if (!r.enabled) return false;
      if (r.device_mac && r.device_mac.toLowerCase() !== m) return false;
      const d = (r.domain || '').toLowerCase();
      return name === d || name.endsWith(`.${d}`);
    });
  }

  /** Group the flat rows into one bucket per client device, and within a
   *  device collapse many subdomains of one service into a single readable
   *  entry ("Instagram", not graph/i/i-fallback.instagram.com). */
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
          domains: [],      // collapsed: {label, site, qname, count, timestamp, protocol}
          bySite: new Map(),
        };
        byDevice.set(key, g);
      }
      g.total += 1;
      if (r.timestamp > g.latest) g.latest = r.timestamp;
      const qname = (r.qname || '').replace(/\.$/, '');
      if (!qname) continue;
      // Collapse by friendly app name when known, else by registered domain.
      const site = r.site || qname;
      const label = r.app || site;
      const siteKey = (r.app || site).toLowerCase();
      let entry = g.bySite.get(siteKey);
      if (!entry) {
        entry = { label, site, qname, count: 0, timestamp: r.timestamp,
                  protocol: r.protocol, org: r.org };
        g.bySite.set(siteKey, entry);
        g.domains.push(entry);
      }
      entry.count += 1;
      if (r.timestamp > entry.timestamp) {
        entry.timestamp = r.timestamp;
        entry.qname = qname;            // freshest example subdomain
        entry.protocol = r.protocol;
      }
    }
    // Newest-active device first; within a device, newest site first.
    for (const g of byDevice.values()) {
      g.domains.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
    }
    return [...byDevice.values()].sort((a, b) => (a.latest < b.latest ? 1 : -1));
  }

  _renderSummary() {
    const el = this.el.querySelector('#activity-summary');
    const hint = this.el.querySelector('#activity-hint');
    const toggle = this.el.querySelector('#activity-rules-toggle');
    if (!el) return;
    const groups = this._group();
    const totalLookups = this._rows.length;
    el.textContent =
      `${groups.length} active client${groups.length === 1 ? '' : 's'} · ` +
      `${totalLookups} lookup${totalLookups === 1 ? '' : 's'} in the last ${WINDOW_MINUTES} min`;

    if (toggle) {
      const active = this._rules.filter(r => r.enabled).length;
      toggle.textContent = active ? `Blocked (${active})` : 'Blocked';
    }

    if (hint) {
      // The enforcement warning matters more than the empty-feed nudge: a
      // rules page that silently does nothing is worse than no rules page.
      if (this._status && !this._status.enforcing && this._rules.length) {
        hint.textContent = this._status.reason || '';
        hint.className = 'activity__hint activity__hint--warn';
      } else if (totalLookups === 0) {
        hint.textContent =
          'No activity captured yet. In hotspot mode this fills as clients browse ' +
          '(from their DNS lookups and TLS connections); on other networks only ' +
          'this host\'s own activity is visible.';
        hint.className = 'activity__hint';
      } else {
        hint.textContent = '';
        hint.className = 'activity__hint';
      }
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
    const domains = g.domains.filter(d =>
      (d.label || '').toLowerCase().includes(f) ||
      (d.site || '').toLowerCase().includes(f) ||
      (d.qname || '').toLowerCase().includes(f));
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
      list.appendChild(this._domainRow(d, g));
    }
    if (g.domains.length > shown.length) {
      const more = document.createElement('li');
      more.className = 'activity-domain activity-domain--more';
      more.textContent = `+${g.domains.length - shown.length} more sites`;
      list.appendChild(more);
    }
    card.appendChild(list);
    return card;
  }

  _domainRow(d, g) {
    const li = document.createElement('li');
    li.className = 'activity-domain';
    // Block by the registered domain so a rule covers all subdomains.
    const blockTarget = d.site || d.qname;
    const blocked = this._isBlocked(blockTarget, g.mac);
    if (blocked) li.classList.add('activity-domain--blocked');

    const dom = document.createElement('span');
    dom.className = 'activity-domain__name';
    // Primary = friendly app/site name; the raw domain is secondary context.
    const primary = document.createElement('span');
    primary.className = 'activity-domain__label';
    primary.textContent = d.label || d.qname;
    dom.appendChild(primary);
    if (d.count > 1) {
      const c = document.createElement('span');
      c.className = 'activity-domain__count';
      c.textContent = `×${d.count}`;
      dom.appendChild(c);
    }
    // Show the raw domain only when it differs from the friendly label.
    if (d.site && d.site !== (d.label || '').toLowerCase() && d.label !== d.site) {
      const sub = document.createElement('span');
      sub.className = 'activity-domain__sub';
      sub.textContent = d.site;
      sub.title = d.qname;
      dom.appendChild(sub);
    }
    const chipInfo = this._sourceChip(d.protocol);
    if (chipInfo) {
      const chip = document.createElement('span');
      chip.className = 'activity-domain__chip';
      chip.textContent = chipInfo.label;
      chip.title = chipInfo.title;
      dom.appendChild(chip);
    }

    const t = document.createElement('span');
    t.className = 'activity-domain__time';
    t.textContent = blocked ? 'blocked' : formatRelativeTime(d.timestamp);

    li.appendChild(dom);
    li.appendChild(t);

    // Org-/VPN-inferred rows name a company or tunnel, not a resolvable
    // domain — no block button.
    if (!blocked && g.mac && d.protocol !== 'ORG' && d.protocol !== 'VPN') {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'activity-domain__block';
      btn.textContent = 'Block';
      btn.title = `Block ${blockTarget} for ${g.name}`;
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        const resp = await api.addBlockingRule(blockTarget, g.mac);
        if (resp && resp.error) {
          btn.disabled = false;
          btn.textContent = 'Failed';
          return;
        }
        await this._loadRules();
      });
      li.appendChild(btn);
    }
    return li;
  }

  /** Map a row's evidence source to a small chip. Plain DNS gets none
   *  (it's the default); encrypted-DNS-recovered sources are labelled so
   *  the user understands how a name was seen without a DNS lookup. */
  _sourceChip(protocol) {
    switch (protocol) {
      case 'QUIC':
        return { label: 'quic', title: 'Recovered from the QUIC (HTTP/3) ' +
          'connection itself — this client hides its DNS, but the site it ' +
          'connected to is still visible.' };
      case 'TLS':
        return { label: 'tls', title: 'Seen in the TLS connection itself — ' +
          'this client hides its DNS lookups, but the site is still visible.' };
      case 'ORG':
        return { label: 'via IP', title: 'Inferred from the destination IP ' +
          "address's owner — exact site is encrypted (ECH/VPN), so only the " +
          'operator is known.' };
      case 'VPN':
        return { label: 'vpn', title: 'This device is tunneling through a VPN. ' +
          'The provider and volume are visible; the sites inside the tunnel are ' +
          'encrypted and cannot be seen passively.' };
      default:
        return null;
    }
  }

  _renderRules() {
    const panel = this.el.querySelector('#activity-rules');
    if (!panel) return;
    panel.hidden = !this._showRules;
    if (!this._showRules) return;

    panel.innerHTML = '';

    const form = document.createElement('form');
    form.className = 'activity-rules__form';
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'activity__filter';
    input.placeholder = 'Block a domain for every client (e.g. instagram.com)';
    input.autocomplete = 'off';
    const add = document.createElement('button');
    add.type = 'submit';
    add.className = 'btn btn--sm';
    add.textContent = 'Block';
    const err = document.createElement('div');
    err.className = 'activity-rules__error';

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const domain = (input.value || '').trim();
      if (!domain) return;
      add.disabled = true;
      const resp = await api.addBlockingRule(domain, null);
      add.disabled = false;
      if (resp && resp.error) {
        err.textContent = resp.message || `Could not block "${domain}".`;
        return;
      }
      input.value = '';
      err.textContent = '';
      await this._loadRules();
    });

    form.appendChild(input);
    form.appendChild(add);
    panel.appendChild(form);
    panel.appendChild(err);

    if (this._status && !this._status.enforcing) {
      const warn = document.createElement('div');
      warn.className = 'activity__hint activity__hint--warn';
      warn.textContent = this._status.reason || '';
      panel.appendChild(warn);
    }

    if (!this._rules.length) {
      const empty = document.createElement('div');
      empty.className = 'activity__empty';
      empty.textContent = 'Nothing is blocked. Use Block on a domain in the feed, or add one above.';
      panel.appendChild(empty);
      return;
    }

    const list = document.createElement('ul');
    list.className = 'activity-rules__list';
    for (const r of this._rules) list.appendChild(this._ruleRow(r));
    panel.appendChild(list);
  }

  _ruleRow(r) {
    const li = document.createElement('li');
    li.className = 'activity-rule';
    if (!r.enabled) li.classList.add('activity-rule--off');

    const dom = document.createElement('span');
    dom.className = 'activity-rule__domain';
    dom.textContent = r.domain;
    li.appendChild(dom);

    const scope = document.createElement('span');
    scope.className = 'activity-rule__scope';
    scope.textContent = r.device_mac
      ? (r.device_name || r.device_mac)
      : 'All clients';
    li.appendChild(scope);

    const hits = document.createElement('span');
    hits.className = 'activity-rule__hits';
    hits.textContent = r.hit_count
      ? `${r.hit_count} blocked · ${formatRelativeTime(r.last_hit)}`
      : 'no attempts yet';
    li.appendChild(hits);

    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'btn btn--sm';
    toggle.textContent = r.enabled ? 'Disable' : 'Enable';
    toggle.addEventListener('click', async () => {
      toggle.disabled = true;
      await api.setBlockingRuleEnabled(r.id, !r.enabled);
      await this._loadRules();
    });
    li.appendChild(toggle);

    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'btn btn--sm btn--danger';
    del.textContent = 'Remove';
    del.addEventListener('click', async () => {
      del.disabled = true;
      await api.deleteBlockingRule(r.id);
      await this._loadRules();
    });
    li.appendChild(del);

    return li;
  }
}
