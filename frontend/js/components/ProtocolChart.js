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

/** Read a CSS custom property from the document root. */
function cssVar(name, fallback = '') {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

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

    const legendColor = cssVar('--chart-legend-text', '#a0a0a0');
    const tooltipBg = cssVar('--chart-tooltip-bg', '#1a1a1a');
    const tooltipText = cssVar('--chart-tooltip-text', '#efefef');
    const tooltipBorder = cssVar('--chart-tooltip-border', '#3a3a3a');

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
              color: legendColor,
              padding: 14,
              usePointStyle: true,
              pointStyle: 'circle',
              font: { size: 11, weight: 500 },
              boxWidth: 8,
              boxHeight: 8,
            }
          },
          tooltip: {
            backgroundColor: tooltipBg,
            titleColor: tooltipText,
            bodyColor: tooltipText,
            borderColor: tooltipBorder,
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

    // Listen for theme changes and re-apply colors
    this._themeObserver = new MutationObserver(() => this._applyThemeColors());
    this._themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    this._unsub = store.subscribe('protocols', data => this.update(data));
  }

  update(raw) {
    if (!this.chart) return;

    const protocols = (raw && (raw.protocols || raw.data || raw)) || [];
    const hasData = Array.isArray(protocols) && protocols.length > 0;

    // Show / hide "no data" overlay
    this._toggleNoData(!hasData);

    if (!hasData) {
      // Clear stale data so the chart isn't stuck on the old interface
      this.chart.data.labels = [];
      this.chart.data.datasets[0].data = [];
      this.chart.update('none');
      return;
    }

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
      overlay.textContent = 'Waiting for protocol data…';
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
    const legendColor = cssVar('--chart-legend-text', '#a0a0a0');
    const tooltipBg = cssVar('--chart-tooltip-bg', '#1a1a1a');
    const tooltipText = cssVar('--chart-tooltip-text', '#efefef');
    const tooltipBorder = cssVar('--chart-tooltip-border', '#3a3a3a');
    this.chart.options.plugins.legend.labels.color = legendColor;
    this.chart.options.plugins.tooltip.backgroundColor = tooltipBg;
    this.chart.options.plugins.tooltip.titleColor = tooltipText;
    this.chart.options.plugins.tooltip.bodyColor = tooltipText;
    this.chart.options.plugins.tooltip.borderColor = tooltipBorder;
    this.chart.update('none');
  }
}
