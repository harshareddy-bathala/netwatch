/**
 * ProtocolChart.js - Protocol Distribution Doughnut
 * ===================================================
 * Smooth hover with offset + tooltip. No center text.
 */

import store from '../store.js';

const PALETTE = [
  '#d97706', '#10b981', '#3b82f6', '#ef4444', '#8b5cf6',
  '#f59e0b', '#06b6d4', '#ec4899', '#6b7280', '#14b8a6',
];

export default class ProtocolChart {
  constructor(canvasId) {
    this.canvasId = canvasId;
    this.chart = null;
    this._unsub = null;
    this._firstUpdate = true;
  }

  init() {
    const canvas = document.getElementById(this.canvasId);
    if (!canvas || typeof Chart === 'undefined') return;

    if (this.chart) { this.chart.destroy(); this.chart = null; }

    this.chart = new Chart(canvas.getContext('2d'), {
      type: 'doughnut',
      data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0, hoverOffset: 14 }] },
      options: {
        animation: {
          duration: 800,
          easing: 'easeOutQuart',
          animateRotate: true,
          animateScale: false,
        },
        transitions: {
          active: {
            animation: { duration: 200 }
          }
        },
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        layout: {
          padding: {
            right: 16,
          }
        },
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#a0a0a0',
              padding: 14,
              usePointStyle: true,
              pointStyle: 'circle',
              font: { size: 11, weight: 500 },
              boxWidth: 8,
              boxHeight: 8,
            }
          },
          tooltip: {
            backgroundColor: '#1a1a1a',
            titleColor: '#efefef',
            bodyColor: '#efefef',
            borderColor: '#3a3a3a',
            borderWidth: 1,
            cornerRadius: 6,
            padding: 10,
            callbacks: {
              label(ctx) {
                const label = ctx.label || '';
                const value = ctx.parsed;
                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                const pct = total > 0 ? ((value / total) * 100).toFixed(1) : '0';
                return ` ${label}: ${pct}%`;
              }
            }
          }
        },
      }
    });

    this._unsub = store.subscribe('protocols', data => this.update(data));
  }

  update(raw) {
    if (!this.chart || !raw) return;
    const protocols = raw.protocols || raw || [];
    if (!Array.isArray(protocols) || protocols.length === 0) return;

    // Use 'name' first (from dashboard endpoint), fallback to 'protocol' (from standalone endpoint)
    this.chart.data.labels = protocols.map(p => p.name || p.protocol || 'Unknown');
    // Prefer bytes for sizing, fallback to count or percentage
    this.chart.data.datasets[0].data = protocols.map(p => p.bytes || p.total_bytes || p.count || p.packet_count || p.percentage || 0);

    if (this._firstUpdate) {
      this._firstUpdate = false;
      this.chart.update();
    } else {
      this.chart.update({
        duration: 400,
        easing: 'easeInOutQuart',
      });
    }
  }

  destroy() {
    if (this._unsub) this._unsub();
    if (this.chart) { this.chart.destroy(); this.chart = null; }
  }
}
