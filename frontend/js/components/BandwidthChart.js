/**
 * BandwidthChart.js - Real-time Bandwidth Line Chart
 * ====================================================
 * Wraps Chart.js. Updates with chart.update('none') for zero flicker.
 */

import { formatMbps, formatTimestamp } from '../utils/formatters.js';
import store from '../store.js';

const COLORS = {
  download:     '#10b981',
  downloadFill: 'rgba(16, 185, 129, 0.08)',
  upload:       '#3b82f6',
  uploadFill:   'rgba(59, 130, 246, 0.08)',
  grid:         'rgba(255,255,255,0.04)',
  text:         '#6b6b6b',
};

export default class BandwidthChart {
  constructor(canvasId) {
    this.canvasId = canvasId;
    this.chart = null;
    this._unsub = null;
    this._firstUpdate = true;
  }

  /** Call after the canvas element is in the DOM */
  init() {
    const canvas = document.getElementById(this.canvasId);
    if (!canvas || typeof Chart === 'undefined') return;

    if (this.chart) { this.chart.destroy(); this.chart = null; }

    const ctx = canvas.getContext('2d');

    this.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Download',
            data: [],
            borderColor: COLORS.download,
            backgroundColor: COLORS.downloadFill,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 5,
            borderWidth: 2,
          },
          {
            label: 'Upload',
            data: [],
            borderColor: COLORS.upload,
            backgroundColor: COLORS.uploadFill,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 5,
            borderWidth: 2,
          }
        ]
      },
      options: {
        animation: {
          duration: 750,
          easing: 'easeOutQuart',
        },
        transitions: {
          active: {
            animation: { duration: 0 }  // instant tooltip on hover
          }
        },
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: {
            display: true,
            position: 'top',
            align: 'end',
            labels: {
              color: COLORS.text,
              usePointStyle: true,
              pointStyle: 'circle',
              padding: 16,
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
                return `${ctx.dataset.label}: ${formatMbps(ctx.parsed.y)}`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: COLORS.text, maxTicksLimit: 8, maxRotation: 0, font: { size: 11 } },
            border: { display: false }
          },
          y: {
            beginAtZero: true,
            grid: { color: COLORS.grid },
            ticks: {
              color: COLORS.text,
              padding: 8,
              font: { size: 11 },
              callback: v => formatMbps(v),
              maxTicksLimit: 6
            },
            border: { display: false }
          }
        }
      }
    });

    // Subscribe to bandwidth data
    this._unsub = store.subscribe('bandwidth', data => this.update(data));
  }

  update(raw) {
    if (!this.chart || !raw) return;
    const history = raw.history || raw || [];
    if (!Array.isArray(history) || history.length === 0) return;

    this.chart.data.labels = history.map(d => formatTimestamp(d.timestamp));
    this.chart.data.datasets[0].data = history.map(d => d.download_mbps ?? d.bytes_per_second ?? 0);
    this.chart.data.datasets[1].data = history.map(d => d.upload_mbps ?? 0);

    if (this._firstUpdate) {
      // Smooth initial draw
      this._firstUpdate = false;
      this.chart.update();
    } else {
      // Smooth transition for real-time updates (300ms)
      this.chart.update({
        duration: 300,
        easing: 'easeInOutQuart',
      });
    }
  }

  destroy() {
    if (this._unsub) this._unsub();
    if (this.chart) { this.chart.destroy(); this.chart = null; }
  }
}
