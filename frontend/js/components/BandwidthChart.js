/**
 * BandwidthChart.js - Real-time Bandwidth Line Chart
 * ====================================================
 * Wraps Chart.js. Updates with chart.update('none') for zero flicker.
 */

import { formatMbps, formatTimestamp } from '../utils/formatters.js';
import store from '../store.js';

/** Read a CSS custom property from the document root. */
function cssVar(name, fallback = '') {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

/** Build a fresh color map from the current CSS variables (theme-aware). */
function getColors() {
  return {
    download:     cssVar('--chart-download',      '#10b981'),
    downloadFill: cssVar('--chart-download-fill',  'rgba(16,185,129,0.08)'),
    upload:       cssVar('--chart-upload',         '#3b82f6'),
    uploadFill:   cssVar('--chart-upload-fill',    'rgba(59,130,246,0.08)'),
    grid:         cssVar('--chart-grid',           'rgba(255,255,255,0.04)'),
    text:         cssVar('--chart-text',           '#6b6b6b'),
    tooltipBg:    cssVar('--chart-tooltip-bg',     '#1a1a1a'),
    tooltipText:  cssVar('--chart-tooltip-text',   '#efefef'),
    tooltipBorder:cssVar('--chart-tooltip-border', '#3a3a3a'),
  };
}

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
    const COLORS = getColors();

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
          duration: 300,
          easing: 'easeInOutQuart',
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
            backgroundColor: COLORS.tooltipBg,
            titleColor: COLORS.tooltipText,
            bodyColor: COLORS.tooltipText,
            borderColor: COLORS.tooltipBorder,
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

    // Listen for theme changes and re-apply colors
    this._themeObserver = new MutationObserver(() => this._applyThemeColors());
    this._themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    // Subscribe to bandwidth data
    this._unsub = store.subscribe('bandwidth', data => this.update(data));
  }

  update(raw) {
    if (!this.chart) return;

    const history = (raw && (raw.history || raw.data || raw)) || [];
    const hasData = Array.isArray(history) && history.length > 0;

    // Show / hide "no data" overlay
    this._toggleNoData(!hasData);

    if (!hasData) {
      // Clear stale data so the chart isn't stuck on the old interface
      this.chart.data.labels = [];
      this.chart.data.datasets[0].data = [];
      this.chart.data.datasets[1].data = [];
      this.chart.update('none');
      return;
    }

    this.chart.data.labels = history.map(d => formatTimestamp(d.timestamp));
    this.chart.data.datasets[0].data = history.map(d => d.download_mbps ?? d.bytes_per_second ?? 0);
    this.chart.data.datasets[1].data = history.map(d => d.upload_mbps ?? d.upload_bytes_per_second ?? 0);

    if (this._firstUpdate) {
      // Smooth initial draw
      this._firstUpdate = false;
      this.chart.update();
    } else {
      // Let chart-level animation config handle transitions
      this.chart.update();
    }
  }

  /** Show or hide a "No data yet" overlay on the canvas container. */
  _toggleNoData(show) {
    const canvas = document.getElementById(this.canvasId);
    if (!canvas) return;
    const container = canvas.parentElement;
    if (!container) return;

    let overlay = container.querySelector('.chart-no-data');
    if (show && !overlay) {
      overlay = document.createElement('div');
      overlay.className = 'chart-no-data';
      overlay.textContent = 'Waiting for bandwidth data…';
      container.style.position = 'relative';
      overlay.style.cssText =
        'position:absolute;inset:0;display:flex;align-items:center;justify-content:center;' +
        'color:#6b6b6b;font-size:13px;pointer-events:none;z-index:2;';
      container.appendChild(overlay);
    } else if (!show && overlay) {
      overlay.remove();
    }
  }

  destroy() {
    if (this._unsub) this._unsub();
    if (this._themeObserver) { this._themeObserver.disconnect(); this._themeObserver = null; }
    if (this.chart) { this.chart.destroy(); this.chart = null; }
  }

  /** Re-apply CSS variable colors after a theme switch. */
  _applyThemeColors() {
    if (!this.chart) return;
    const C = getColors();
    const ds = this.chart.data.datasets;
    ds[0].borderColor = C.download;
    ds[0].backgroundColor = C.downloadFill;
    ds[1].borderColor = C.upload;
    ds[1].backgroundColor = C.uploadFill;
    this.chart.options.plugins.legend.labels.color = C.text;
    this.chart.options.plugins.tooltip.backgroundColor = C.tooltipBg;
    this.chart.options.plugins.tooltip.titleColor = C.tooltipText;
    this.chart.options.plugins.tooltip.bodyColor = C.tooltipText;
    this.chart.options.plugins.tooltip.borderColor = C.tooltipBorder;
    this.chart.options.scales.x.ticks.color = C.text;
    this.chart.options.scales.y.grid.color = C.grid;
    this.chart.options.scales.y.ticks.color = C.text;
    this.chart.update('none');
  }
}
