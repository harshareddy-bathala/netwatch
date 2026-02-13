/**
 * DeviceList.js - Devices View Component
 * ========================================
 * Sortable table, inline hostname editing, search.
 */

import store from '../store.js';
import api from '../api.js';
import { formatBytes, formatRelativeTime, escapeHtml } from '../utils/formatters.js';
import { debounce } from '../utils/debounce.js';
import { delegate } from '../utils/dom.js';
import DeviceDetail from './DeviceDetail.js';

export default class DeviceList {
  constructor(container) {
    this.container = container;
    this._unsubs = [];
    this._devices = [];
    this._sortKey = 'total_bytes';
    this._sortAsc = false;
    this._search = '';
    this._isEditing = false;   // guard: skip re-render while editing
    this._editingIp = null;    // IP of device currently being edited
  }

  render() {
    this.container.innerHTML = `
      <div class="device-controls">
        <div class="search-box">
          <svg class="search-box__icon" width="15" height="15" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
          </svg>
          <input class="search-box__input" id="device-search"
                 placeholder="Search by IP, MAC, or hostname…" type="text" />
        </div>
        <span class="device-count" id="device-count">— devices</span>
      </div>

      <div class="chart-card">
        <div class="device-table" id="device-table">
          <div class="device-table__header" id="device-table-header">
            ${this._renderHeaderCells()}
          </div>
          <div id="device-rows">
            <div class="empty-state"><span class="empty-state__text">Loading…</span></div>
          </div>
        </div>
      </div>
    `;

    this._bindSort();
    this._bindSearch();
    this._bindRowActions();

    this._unsubs.push(store.subscribe('devices', data => {
      this._devices = data?.devices || data || [];
      // Don't re-render rows while user is editing a hostname
      if (!this._isEditing) {
        this._renderRows();
      }
    }));
  }

  /* ── Column header rendering ─────────────── */

  _renderHeaderCells() {
    const cols = [
      { key: 'ip_address', label: 'IP' },
      { key: 'mac_address', label: 'MAC' },
      { key: 'hostname', label: 'Hostname' },
      { key: 'total_bytes', label: 'Usage' },
      { key: 'last_seen', label: 'Last Seen' },
    ];
    return cols
      .map(c => {
        const sorted = this._sortKey === c.key;
        const arrow = sorted ? (this._sortAsc ? ' ↑' : ' ↓') : '';
        return `<div class="device-table__header-cell${sorted ? ' sorted' : ''}" data-sort="${c.key}">${c.label}${arrow}</div>`;
      })
      .join('');
  }

  /* ── Sort ────────────────────────────────── */

  _bindSort() {
    this.container.querySelectorAll('.device-table__header-cell').forEach(cell => {
      cell.addEventListener('click', () => {
        const key = cell.dataset.sort;
        if (this._sortKey === key) { this._sortAsc = !this._sortAsc; }
        else { this._sortKey = key; this._sortAsc = true; }

        // Re-render header with sort arrows and rows
        const header = document.getElementById('device-table-header');
        if (header) {
          header.innerHTML = this._renderHeaderCells();
          this._bindSort();
        }
        this._renderRows();
      });
    });
  }

  /* ── Search ──────────────────────────────── */

  _bindSearch() {
    const input = this.container.querySelector('#device-search');
    if (!input) return;
    const onSearch = debounce(val => {
      this._search = val.toLowerCase();
      this._renderRows();
    }, 200);
    input.addEventListener('input', e => onSearch(e.target.value));
  }

  /** Delegated listeners for row interactions (survive re-renders). */
  _bindRowActions() {
    const rowsEl = this.container.querySelector('#device-rows');
    if (!rowsEl) return;

    // Edit icon click
    this._unsubs.push(delegate(rowsEl, 'click', '.device-row__hostname-edit', (e) => {
      e.stopPropagation();
      const row = e.target.closest('.device-row');
      if (!row) return;
      const ip = row.dataset.ip;
      const mac = row.dataset.mac;
      const span = row.querySelector('.hostname-text');
      if (span) this._inlineEdit(span, ip, mac);
    }));

    // Row click → device detail modal
    this._unsubs.push(delegate(rowsEl, 'click', '.device-row', (e) => {
      if (e.target.closest('.device-row__hostname-edit') || e.target.closest('.hostname-input')) return;
      const row = e.target.closest('.device-row');
      const ip = row?.dataset.ip;
      if (ip) new DeviceDetail(this.container, ip).open();
    }));
  }

  /* ── Render rows ─────────────────────────── */

  _renderRows() {
    const rowsEl = document.getElementById('device-rows');
    if (!rowsEl) return;

    let filtered = [...this._devices];

    // Filter
    if (this._search) {
      filtered = filtered.filter(d =>
        (d.ip_address || '').toLowerCase().includes(this._search) ||
        (d.hostname || '').toLowerCase().includes(this._search) ||
        (d.mac_address || '').toLowerCase().includes(this._search)
      );
    }

    // Sort
    filtered.sort((a, b) => {
      let va = a[this._sortKey] ?? '';
      let vb = b[this._sortKey] ?? '';
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return this._sortAsc ? -1 : 1;
      if (va > vb) return this._sortAsc ? 1 : -1;
      return 0;
    });

    // Count
    const countEl = document.getElementById('device-count');
    if (countEl) countEl.textContent = `${filtered.length} device${filtered.length !== 1 ? 's' : ''}`;

    if (filtered.length === 0) {
      rowsEl.innerHTML = '<div class="empty-state"><span class="empty-state__text">No devices found</span></div>';
      return;
    }

    rowsEl.innerHTML = filtered.map(d => `
      <div class="device-row" data-ip="${escapeHtml(d.ip_address)}" data-mac="${escapeHtml(d.mac_address || '')}">
        <div class="device-row__ip">${escapeHtml(d.ip_address)}</div>
        <div class="device-row__mac">${escapeHtml(d.mac_address || '—')}</div>
        <div class="device-row__hostname">
          <span class="hostname-text">${escapeHtml(d.hostname || d.ip_address)}</span>
          <span class="device-row__hostname-edit" title="Edit hostname">✎</span>
        </div>
        <div class="device-row__bandwidth">${formatBytes(d.total_bytes || 0)}</div>
        <div class="device-row__seen">${formatRelativeTime(d.last_seen)}</div>
      </div>
    `).join('');
  }

  /* ── Inline hostname edit ────────────────── */

  _inlineEdit(span, ip, mac) {
    // Prevent opening multiple editors
    if (this._isEditing) return;
    this._isEditing = true;
    this._editingIp = ip;

    const current = span.textContent;
    const input = document.createElement('input');
    input.className = 'hostname-input';
    input.value = current;
    span.replaceWith(input);

    // Focus after a microtask so the input is fully in the DOM
    requestAnimationFrame(() => {
      input.focus();
      input.select();
    });

    let saved = false; // prevent double-save from blur+enter

    const save = async () => {
      if (saved) return;
      saved = true;
      this._isEditing = false;
      this._editingIp = null;

      const newName = input.value.trim() || current;
      const newSpan = document.createElement('span');
      newSpan.className = 'hostname-text';
      newSpan.textContent = newName;
      if (input.parentNode) {
        input.replaceWith(newSpan);
      }

      if (newName !== current) {
        // Locally update the device list so next render keeps the new name
        const device = this._devices.find(d => d.ip_address === ip);
        if (device) {
          device.hostname = newName;
        }

        try {
          await api.updateDeviceName(ip, newName, mac);
        } catch (err) {
          console.error('Failed to update hostname:', err);
          newSpan.textContent = current;
          // Revert local change
          if (device) device.hostname = current;
        }
      }

      // Re-render now that editing is done to sync with latest data
      this._renderRows();
    };

    input.addEventListener('blur', () => {
      // Small delay to allow click events (e.g. Enter key) to fire first
      setTimeout(save, 100);
    });
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); save(); }
      if (e.key === 'Escape') { input.value = current; save(); }
    });
  }

  destroy() {
    this._unsubs.forEach(fn => fn());
  }
}
