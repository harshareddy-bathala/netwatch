/**
 * AlertRules.js - Custom Alert Rules Manager
 * =============================================
 * CRUD interface embedded in the Alerts view for user-defined rules.
 * Renders as a collapsible section at the top of AlertFeed.
 */

import api from '../api.js';
import { escapeHtml } from '../utils/formatters.js';
import { delegate } from '../utils/dom.js';

const METRICS = [
  { value: 'bandwidth_bps', label: 'Bandwidth (bps)' },
  { value: 'device_count',  label: 'Device Count' },
  { value: 'packet_rate',   label: 'Packet Rate' },
  { value: 'protocol_bytes', label: 'Protocol Bytes' },
];
const OPERATORS = ['>', '<', '>=', '<=', '=='];
const SEVERITIES = ['info', 'warning', 'critical'];

export default class AlertRules {
  constructor(container) {
    this._container = container;
    this._rules = [];
    this._expanded = false;
    this._unsubs = [];
  }

  async render() {
    this._container.innerHTML = `
      <div class="alert-rules">
        <button class="alert-rules__toggle" id="rules-toggle">
          <span>Custom Alert Rules</span>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2">
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </button>
        <div class="alert-rules__body" id="rules-body" style="display:none;">
          <div id="rules-list">Loading…</div>
          <button class="btn btn--sm" id="add-rule-btn">+ New Rule</button>
        </div>
      </div>
    `;

    this._container.querySelector('#rules-toggle')
      .addEventListener('click', () => this._toggleExpand());

    this._container.querySelector('#add-rule-btn')
      .addEventListener('click', () => this._showForm());

    // Delegate rule actions (survives re-renders of #rules-list)
    const rulesListEl = this._container.querySelector('#rules-list');
    this._unsubs.push(delegate(rulesListEl, 'click', '.toggle-btn', async (e) => {
      const id = +e.target.closest('.alert-rules__item').dataset.id;
      const rule = this._rules.find(r => r.id === id);
      if (rule) {
        await api.updateAlertRule(id, { enabled: rule.enabled ? 0 : 1 });
        await this._loadRules();
      }
    }));

    this._unsubs.push(delegate(rulesListEl, 'click', '.delete-btn', async (e) => {
      const id = +e.target.closest('.alert-rules__item').dataset.id;
      if (confirm('Delete this rule?')) {
        await api.deleteAlertRule(id);
        await this._loadRules();
      }
    }));

    await this._loadRules();
  }

  /* ── Data ────────────────────────────────── */

  async _loadRules() {
    const res = await api.getAlertRules();
    this._rules = res?.rules || [];
    this._renderList();
  }

  _renderList() {
    const el = this._container.querySelector('#rules-list');
    if (!el) return;

    if (this._rules.length === 0) {
      el.innerHTML = '<p class="alert-rules__empty">No custom rules yet.</p>';
      return;
    }

    el.innerHTML = this._rules.map(r => `
      <div class="alert-rules__item" data-id="${r.id}">
        <div class="alert-rules__item-main">
          <span class="alert-rules__name">${escapeHtml(r.name)}</span>
          <span class="alert-rules__expr">
            ${escapeHtml(r.metric)} ${escapeHtml(r.operator)} ${r.threshold}
          </span>
          <span class="badge badge--${r.severity}">${r.severity}</span>
          <span class="alert-rules__status ${r.enabled ? 'on' : 'off'}">
            ${r.enabled ? 'ON' : 'OFF'}
          </span>
        </div>
        <div class="alert-rules__actions">
          <button class="alert-rules__btn toggle-btn" title="Toggle">${r.enabled ? '⏸' : '▶'}</button>
          <button class="alert-rules__btn delete-btn" title="Delete">🗑</button>
        </div>
      </div>
    `).join('');
  }

  /* ── Expand/Collapse ─────────────────────── */

  _toggleExpand() {
    this._expanded = !this._expanded;
    const body = this._container.querySelector('#rules-body');
    if (body) body.style.display = this._expanded ? 'block' : 'none';
    const svg = this._container.querySelector('#rules-toggle svg');
    if (svg) svg.style.transform = this._expanded ? 'rotate(180deg)' : '';
  }

  /* ── Create Form ─────────────────────────── */

  _showForm() {
    const body = this._container.querySelector('#rules-body');
    if (!body) return;

    // Remove existing form if any
    body.querySelector('.alert-rules__form')?.remove();

    const form = document.createElement('div');
    form.className = 'alert-rules__form';
    form.innerHTML = `
      <input class="form-input" name="name" placeholder="Rule name" required />
      <select class="form-select" name="metric">
        ${METRICS.map(m => `<option value="${m.value}">${m.label}</option>`).join('')}
      </select>
      <select class="form-select" name="operator">
        ${OPERATORS.map(o => `<option value="${o}">${escapeHtml(o)}</option>`).join('')}
      </select>
      <input class="form-input" name="threshold" type="number" placeholder="Threshold" required />
      <select class="form-select" name="severity">
        ${SEVERITIES.map(s => `<option value="${s}">${s}</option>`).join('')}
      </select>
      <div class="alert-rules__form-actions">
        <button class="btn btn--sm" id="save-rule">Save</button>
        <button class="btn btn--outline btn--sm" id="cancel-rule">Cancel</button>
      </div>
    `;

    body.insertBefore(form, body.querySelector('#add-rule-btn'));

    form.querySelector('#cancel-rule').addEventListener('click', () => form.remove());
    form.querySelector('#save-rule').addEventListener('click', async () => {
      const get = (n) => form.querySelector(`[name="${n}"]`).value;
      const rule = {
        name: get('name'),
        metric: get('metric'),
        operator: get('operator'),
        threshold: parseFloat(get('threshold')),
        severity: get('severity'),
      };
      if (!rule.name || isNaN(rule.threshold)) return;

      await api.createAlertRule(rule);
      form.remove();
      await this._loadRules();
    });
  }

  destroy() {
    this._unsubs.forEach(fn => fn());
  }
}
