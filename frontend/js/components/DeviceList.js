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
import { showToast } from '../utils/toast.js';
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
    this._openModal = null;    // track currently open DeviceDetail modal (#48)
    this._modeData = null;     // current mode capabilities from store
    this._pendingRenames = new Map(); // ip → newName; preserved across store updates until server confirms
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

      <div id="device-discovery-banner" class="discovery-banner" style="display:none">
        <span class="discovery-banner__inline">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:6px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span id="device-discovery-banner-text">Device discovery is not available in this mode. Only your own traffic is monitored.</span>
        </span>
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
      const rawDevices = data?.devices || data || [];
      // Preserve any pending renames so SSE updates don't revert the UI
      // while waiting for the server to reflect the change.
      if (this._pendingRenames.size > 0) {
        this._devices = rawDevices.map(d => {
          const override = this._pendingRenames.get(d.ip_address);
          if (override !== undefined) {
            // Server has caught up — drop the override
            if (d.hostname === override) {
              this._pendingRenames.delete(d.ip_address);
              return d;
            }
            return { ...d, hostname: override };
          }
          return d;
        });
      } else {
        this._devices = rawDevices;
      }
      // Don't re-render rows while user is editing a hostname
      if (!this._isEditing) {
        this._renderRows();
      }
    }));

    // Phase 5 + Phase B: show/hide discovery banner based on mode capabilities
    this._unsubs.push(store.subscribe('mode', data => {
      this._modeData = data || null;
      const banner = this.container.querySelector('#device-discovery-banner');
      const bannerText = this.container.querySelector('#device-discovery-banner-text');
      if (banner && data) {
        const canArp = data.can_arp_scan;
        const canArpCache = data.can_arp_cache_scan;
        if (canArp === false && canArpCache) {
          // ARP cache scanning enabled — show informational banner
          banner.style.display = '';
          if (bannerText) {
            bannerText.textContent = 'Showing devices from network ARP cache. Only your own traffic is monitored.';
          }
        } else if (canArp === false) {
          // No discovery at all
          banner.style.display = '';
          if (bannerText) {
            bannerText.textContent = 'Device discovery is not available in this mode. Only your own traffic is monitored.';
          }
        } else {
          banner.style.display = 'none';
        }
      }
      // Re-render rows to update ARP-only styling
      if (!this._isEditing) this._renderRows();
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
      if (ip) {
        // Close any existing modal before opening a new one (#48)
        if (this._openModal) { this._openModal.close(); this._openModal = null; }
        const modal = new DeviceDetail(this.container, ip);
        this._openModal = modal;
        modal.open();
      }
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

    // Incremental DOM patching: reuse existing rows, update changed cells (#52)
    const existingRows = rowsEl.querySelectorAll('.device-row');
    const existingByIp = new Map();
    existingRows.forEach(el => existingByIp.set(el.dataset.ip, el));

    const fragment = document.createDocumentFragment();
    const seen = new Set();

    for (const d of filtered) {
      const ip = d.ip_address;
      const ipDisplay = ip || '—';
      seen.add(ip);

      let row = existingByIp.get(ip);
      if (row) {
        // Patch changed cells in-place
        const ipCell = row.querySelector('.device-row__ip');
        if (ipCell && ipCell.textContent !== ipDisplay) ipCell.textContent = ipDisplay;

        const macCell = row.querySelector('.device-row__mac');
        const macText = d.mac_address || '—';
        if (macCell && macCell.textContent !== macText) macCell.textContent = macText;
        if (row.dataset.mac !== (d.mac_address || '')) row.dataset.mac = d.mac_address || '';

        const hostnameSpan = row.querySelector('.hostname-text');
        const hnText = d.hostname || d.device_name || d.ip_address || '—';
        if (hostnameSpan && hostnameSpan.textContent !== hnText) hostnameSpan.textContent = hnText;

        const bwCell = row.querySelector('.device-row__bandwidth');
        const bwText = formatBytes(d.total_bytes || 0);
        if (bwCell && bwCell.textContent !== bwText) bwCell.textContent = bwText;

        const seenCell = row.querySelector('.device-row__seen');
        const seenText = formatRelativeTime(d.last_seen);
        if (seenCell && seenCell.textContent !== seenText) seenCell.textContent = seenText;

        fragment.appendChild(row);
      } else {
        // Create new row
        const div = document.createElement('div');
        div.className = 'device-row';
        div.dataset.ip = ip;
        div.dataset.mac = d.mac_address || '';
        div.innerHTML = `
          <div class="device-row__ip">${this._statusDot(d)}${escapeHtml(ipDisplay)}</div>
          <div class="device-row__mac">${escapeHtml(d.mac_address || '—')}</div>
          <div class="device-row__hostname">
            <span class="hostname-text">${escapeHtml(d.hostname || d.device_name || d.ip_address || '—')}</span>
            <span class="device-row__hostname-edit" title="Edit hostname">✎</span>
          </div>
          <div class="device-row__bandwidth">${formatBytes(d.total_bytes || 0)}</div>
          <div class="device-row__seen">${formatRelativeTime(d.last_seen)}</div>
        `;
        fragment.appendChild(div);
      }

      // Apply ARP-only styling (dimmed) for devices with no traffic
      const rowEl = fragment.lastElementChild || row;
      if (rowEl) {
        const isArpOnly = this._isArpOnlyDevice(d);
        rowEl.classList.toggle('device-row--arp-only', isArpOnly);
      }
    }

    // Remove stale rows (devices that disappeared)
    existingRows.forEach(el => {
      if (!seen.has(el.dataset.ip)) el.remove();
    });

    // Replace contents in correct sorted order
    rowsEl.textContent = '';
    rowsEl.appendChild(fragment);
  }

  /* ── ARP-only device helpers ─────────────── */

  /**
   * Returns true when a device was discovered via ARP cache only
   * (no traffic recorded).  We check: total_bytes === 0 and the mode
   * is public_network (i.e. can_arp_scan is false).
   */
  _isArpOnlyDevice(d) {
    const hasTraffic = (d.total_bytes || 0) > 0
                    || (d.total_bytes_sent || 0) > 0
                    || (d.total_bytes_received || 0) > 0;
    if (hasTraffic) return false;
    // In modes with full discovery, zero-traffic devices are still
    // actively scanned — only flag them in ARP-cache-only modes.
    const mode = this._modeData;
    if (mode && mode.can_arp_scan === false && mode.can_arp_cache_scan) {
      return true;
    }
    return false;
  }

  /**
   * Render a small status dot before the IP address.
   * Green = traffic-active, grey = ARP-only (no traffic observed).
   */
  _statusDot(d) {
    const isArpOnly = this._isArpOnlyDevice(d);
    const color = isArpOnly ? 'var(--text-muted,#666)' : 'var(--success,#4caf50)';
    const title = isArpOnly ? 'ARP cache only — no traffic observed' : 'Traffic active';
    return `<span class="device-status-dot" title="${title}" style="background:${color}"></span>`;
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
        // Register as pending so store subscription won't revert it
        this._pendingRenames.set(ip, newName);

        try {
          const result = await api.updateDeviceName(ip, newName, mac);
          if (result && result.error) {
            throw new Error(result.message || 'Update failed');
          }
          showToast('Device renamed', 'success');
        } catch (err) {
          console.error('Failed to update hostname:', err);
          showToast('Failed to rename device', 'error');
          newSpan.textContent = current;
          // Revert local change
          if (device) device.hostname = current;
          this._pendingRenames.delete(ip);
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
    // Close any open DeviceDetail modal (#48)
    if (this._openModal) { this._openModal.close(); this._openModal = null; }
    this._unsubs.forEach(fn => fn());
  }
}
