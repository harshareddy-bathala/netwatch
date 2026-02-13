/**
 * AlertFeed.js - Alerts View Component
 * =======================================
 * Filterable alert list with acknowledge / resolve actions.
 */

import store from '../store.js';
import api from '../api.js';
import { formatRelativeTime, escapeHtml, severityClass } from '../utils/formatters.js';
import { delegate } from '../utils/dom.js';
import AlertRules from './AlertRules.js';

export default class AlertFeed {
  constructor(container) {
    this.container = container;
    this._unsubs = [];
    this._alerts = [];
    this._filter = 'all';
  }

  render() {
    this.container.innerHTML = `
      <div id="alert-rules-container"></div>

      <div class="alert-controls">
        <div class="severity-filter">
          <button class="severity-filter__btn active" data-filter="all">All</button>
          <button class="severity-filter__btn" data-filter="critical">Critical</button>
          <button class="severity-filter__btn" data-filter="warning">Warning</button>
          <button class="severity-filter__btn" data-filter="info">Info</button>
        </div>
        <span class="device-count" id="alert-count-label">— alerts</span>
      </div>

      <div id="alert-list">
        <div class="empty-state"><span class="empty-state__text">Loading…</span></div>
      </div>
    `;

    // Mount alert rules manager
    this._alertRules = new AlertRules(this.container.querySelector('#alert-rules-container'));
    this._alertRules.render();

    this._bindFilters();
    this._bindActions();

    this._unsubs.push(store.subscribe('alerts', data => {
      this._alerts = data?.alerts || data || [];
      this._renderList();
    }));
  }

  _bindFilters() {
    // Delegate filter buttons from the controls container
    this._unsubs.push(delegate(this.container, 'click', '.severity-filter__btn', (_e, btn) => {
      this.container.querySelectorAll('.severity-filter__btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      this._filter = btn.dataset.filter;
      this._renderList();
    }));
  }

  _bindActions() {
    // Single delegated listener for all alert action buttons (survives re-renders)
    const listEl = this.container.querySelector('#alert-list');
    if (!listEl) return;

    this._unsubs.push(delegate(listEl, 'click', '.btn-ack', async (_e, btn) => {
      btn.disabled = true;
      btn.textContent = '…';
      try {
        await api.acknowledgeAlert(parseInt(btn.dataset.id));
        window.dispatchEvent(new CustomEvent('netwatch:refresh'));
      } catch (e) { console.error(e); }
    }));

    this._unsubs.push(delegate(listEl, 'click', '.btn-resolve', async (_e, btn) => {
      btn.disabled = true;
      btn.textContent = '…';
      try {
        await api.resolveAlert(parseInt(btn.dataset.id));
        window.dispatchEvent(new CustomEvent('netwatch:refresh'));
      } catch (e) { console.error(e); }
    }));
  }

  _renderList() {
    const listEl = document.getElementById('alert-list');
    if (!listEl) return;

    let filtered = [...this._alerts];
    if (this._filter !== 'all') {
      filtered = filtered.filter(a => (a.severity || '').toLowerCase() === this._filter);
    }

    const countLabel = document.getElementById('alert-count-label');
    if (countLabel) countLabel.textContent = `${filtered.length} alert${filtered.length !== 1 ? 's' : ''}`;

    if (filtered.length === 0) {
      listEl.innerHTML = `
        <div class="empty-state">
          <div class="empty-state__icon">🔔</div>
          <span class="empty-state__text">No alerts to show</span>
        </div>`;
      return;
    }

    listEl.innerHTML = filtered.map(a => {
      const sev = severityClass(a.severity);
      return `
        <div class="alert-item alert-item--${sev}" data-id="${a.id}">
          <div class="alert-item__header">
            <span class="alert-item__severity alert-item__severity--${sev}">
              ${escapeHtml(a.severity || 'info')}
            </span>
            <span style="font-size:var(--font-size-xs);color:var(--color-text-tertiary)">
              ${formatRelativeTime(a.created_at || a.timestamp)}
            </span>
          </div>
          <div class="alert-item__message">${escapeHtml(a.message || a.alert_type || '')}</div>
          <div class="alert-item__meta">
            ${a.source_ip ? `<span>Source: ${escapeHtml(a.source_ip)}</span>` : ''}
            ${a.alert_type ? `<span>Type: ${escapeHtml(a.alert_type)}</span>` : ''}
          </div>
          <div class="alert-item__actions">
            ${!a.acknowledged ? `<button class="btn btn--ghost btn-ack" data-id="${a.id}">Acknowledge</button>` : ''}
            ${!a.resolved ? `<button class="btn btn--success btn-resolve" data-id="${a.id}">Resolve</button>` : ''}
          </div>
        </div>
      `;
    }).join('');
  }

  destroy() {
    this._unsubs.forEach(fn => fn());
  }
}
