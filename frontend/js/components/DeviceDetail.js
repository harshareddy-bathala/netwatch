/**
 * DeviceDetail.js - Per-Device Traffic Detail Modal
 * =====================================================
 * Shows full details for a single device: metadata, traffic
 * breakdown, per-protocol bytes, and an export button.
 *
 * Opened by clicking a device row in DeviceList.
 */

import api from '../api.js';
import store from '../store.js';
import { formatBytes, formatRelativeTime, escapeHtml } from '../utils/formatters.js';
import { showToast } from '../utils/toast.js';

export default class DeviceDetail {
  /**
   * @param {HTMLElement} container - The root container of the view.
   * @param {string} ip - Device IP to display.
   */
  constructor(container, ip, includeControl = null) {
    this._container = container;
    this._ip = ip;
    this._overlay = null;
    this._includeControl = includeControl == null
      ? !!store.get('includeControlTraffic')
      : !!includeControl;
  }

  async open() {
    // Fetch device data — backend wraps in { data: device }
    const response = await api.getDeviceDetails(this._ip, this._includeControl);
    const device = response?.data || response;
    if (!device || device.error) {
      this._showToast('Device not found');
      return;
    }

    const appSent = device.total_bytes_sent_app ?? device.total_bytes_sent ?? 0;
    const appReceived = device.total_bytes_received_app ?? device.total_bytes_received ?? 0;
    const appTotal = device.total_bytes_app ?? (appSent + appReceived);
    const controlTotal = device.total_bytes_control ?? 0;
    const combinedTotal = device.total_bytes_total ?? (appTotal + controlTotal);
    const appPackets = device.packet_count_24h_app ?? device.total_packets ?? 0;
    const controlPackets = device.packet_count_24h_control ?? device.control_packets ?? 0;
    const overheadRatio = combinedTotal > 0
      ? (controlTotal / combinedTotal)
      : (device.control_overhead_ratio || 0);
    const overheadPct = Math.round(overheadRatio * 100);

    // Build overlay
    this._overlay = document.createElement('div');
    this._overlay.className = 'device-detail-overlay';
    this._overlay.innerHTML = `
      <div class="device-detail-modal">
        <header class="device-detail__header">
          <h2>${escapeHtml(device.hostname || device.device_name || device.ip_address)}</h2>
          <button class="device-detail__close" title="Close">&times;</button>
        </header>

        <div class="device-detail__body">
          <!-- Meta -->
          <section class="device-detail__section">
            <h3>Device Info</h3>
            <table class="device-detail__table">
              <tr><td>IP Address</td><td>${escapeHtml(device.ip_address || '—')}</td></tr>
              <tr><td>MAC Address</td><td>${escapeHtml(device.mac_address || '—')}</td></tr>
              <tr><td>Vendor</td><td>${escapeHtml(device.vendor || '—')}</td></tr>
              <tr><td>First Seen</td><td>${escapeHtml(device.first_seen || '—')}</td></tr>
              <tr><td>Last Seen</td><td>${formatRelativeTime(device.last_seen)}</td></tr>
            </table>
          </section>

          <!-- Traffic -->
          <section class="device-detail__section">
            <h3>${this._includeControl ? 'Traffic (App + Control View)' : 'Traffic (App View)'}</h3>
            <div class="device-detail__traffic-grid">
              <div class="device-detail__stat">
                <span class="device-detail__stat-label">App Sent</span>
                <span class="device-detail__stat-value">${formatBytes(appSent)}</span>
              </div>
              <div class="device-detail__stat">
                <span class="device-detail__stat-label">App Received</span>
                <span class="device-detail__stat-value">${formatBytes(appReceived)}</span>
              </div>
              <div class="device-detail__stat">
                <span class="device-detail__stat-label">App Total</span>
                <span class="device-detail__stat-value">${formatBytes(appTotal)}</span>
              </div>
              <div class="device-detail__stat">
                <span class="device-detail__stat-label">App Packets</span>
                <span class="device-detail__stat-value">${(appPackets || 0).toLocaleString()}</span>
              </div>
            </div>
            ${this._renderControlSummary(controlTotal, combinedTotal, controlPackets, overheadPct)}
          </section>

          <!-- Protocol breakdown (if available) -->
          ${this._renderProtocols(device.protocols)}

          <!-- Export link -->
          <section class="device-detail__section device-detail__actions">
            <a href="${api.getExportUrl('csv', 'traffic', 24, this._ip)}" download
               class="btn btn--sm">Export Traffic CSV</a>
            <a href="${api.getExportUrl('json', 'traffic', 24, this._ip)}" download
               class="btn btn--sm btn--outline">Export JSON</a>
          </section>
        </div>
      </div>
    `;

    // Event listeners
    this._overlay.querySelector('.device-detail__close')
      .addEventListener('click', () => this.close());
    this._overlay.addEventListener('click', e => {
      if (e.target === this._overlay) this.close();
    });

    // Export button feedback
    this._overlay.querySelectorAll('.device-detail__actions a[download]').forEach(link => {
      link.addEventListener('click', () => {
        showToast('Export started — check your downloads', 'info');
      });
    });

    document.body.appendChild(this._overlay);
    requestAnimationFrame(() => this._overlay.classList.add('open'));
  }

  close() {
    if (!this._overlay) return;
    this._overlay.classList.remove('open');
    this._overlay.addEventListener('transitionend', () => this._overlay.remove(), { once: true });
    // Fallback if no transition
    setTimeout(() => { if (this._overlay?.parentNode) this._overlay.remove(); }, 400);
    this._overlay = null;
  }

  _renderProtocols(protocols) {
    if (!protocols || !Array.isArray(protocols) || protocols.length === 0) return '';
    const rows = protocols.map(p => `
      <tr>
        <td>${escapeHtml(p.protocol || '—')}</td>
        <td>${formatBytes(p.bytes || 0)}</td>
        <td>${(p.count || 0).toLocaleString()}</td>
      </tr>
    `).join('');
    return `
      <section class="device-detail__section">
        <h3>Protocol Breakdown</h3>
        <table class="device-detail__table">
          <thead><tr><th>Protocol</th><th>Bytes</th><th>Count</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </section>
    `;
  }

  _renderControlSummary(controlTotal, combinedTotal, controlPackets, overheadPct) {
    if (!controlTotal && !controlPackets && !this._includeControl) return '';

    return `
      <div class="device-detail__control-summary">
        <div class="device-detail__control-item">
          <span class="device-detail__control-label">Control Overhead</span>
          <span class="device-detail__control-value">${formatBytes(controlTotal)} (${overheadPct}%)</span>
        </div>
        <div class="device-detail__control-item">
          <span class="device-detail__control-label">Combined Total</span>
          <span class="device-detail__control-value">${formatBytes(combinedTotal)}</span>
        </div>
        <div class="device-detail__control-item">
          <span class="device-detail__control-label">Control Packets</span>
          <span class="device-detail__control-value">${(controlPackets || 0).toLocaleString()}</span>
        </div>
      </div>
    `;
  }

  _showToast(msg, type = 'error') {
    showToast(msg, type);
  }
}
