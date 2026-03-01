/**
 * BandwidthChart.js - Real-time Bandwidth Line Chart
 * ====================================================
 * Wraps Chart.js with gradient area fills, vertical crosshair,
 * dynamic y-axis scaling, and smooth animation.  SSE pushes every
 * ~3 s; Chart.js animates transitions over 600 ms.
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
    upload:       cssVar('--chart-upload',         '#3b82f6'),
    grid:         cssVar('--chart-grid',           'rgba(255,255,255,0.04)'),
    text:         cssVar('--chart-text',           '#6b6b6b'),
    tooltipBg:    cssVar('--chart-tooltip-bg',     '#1a1a1a'),
    tooltipText:  cssVar('--chart-tooltip-text',   '#efefef'),
    tooltipBorder:cssVar('--chart-tooltip-border', '#3a3a3a'),
    crosshair:    cssVar('--chart-crosshair',      'rgba(255,255,255,0.08)'),
  };
}

/** Format a Mbps value dynamically: Mbps, Kbps, or B/s. */
function dynamicFormat(mbps) {
  if (mbps == null || isNaN(mbps) || mbps <= 0) return '0 B/s';
  if (mbps >= 1)     return mbps.toFixed(1) + ' Mbps';
  if (mbps >= 0.001) return (mbps * 1000).toFixed(1) + ' Kbps';
  const bps = (mbps * 1_000_000) / 8;
  if (bps >= 1)      return Math.round(bps) + ' B/s';
  return '0 B/s';
}

/**
 * Chart.js plugin: vertical crosshair line on hover.
 */
const crosshairPlugin = {
  id: 'crosshair',
  afterDraw(chart) {
    const { ctx, tooltip, chartArea } = chart;
    if (!tooltip || !tooltip.opacity || !tooltip.caretX) return;
    const x = tooltip.caretX;
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x, chartArea.top);
    ctx.lineTo(x, chartArea.bottom);
    ctx.lineWidth = 1;
    ctx.strokeStyle = chart._crosshairColor || 'rgba(255,255,255,0.08)';
    ctx.stroke();
    ctx.restore();
  }
};

export default class BandwidthChart {
  constructor(canvasId) {
    this.canvasId = canvasId;
    this.chart = null;
    this._unsub = null;
    this._firstUpdate = true;
    this._lastFingerprint = '';
  }

  /** Call after the canvas element is in the DOM */
  init() {
    const canvas = document.getElementById(this.canvasId);
    if (!canvas || typeof Chart === 'undefined') return;

    if (this.chart) { this.chart.destroy(); this.chart = null; }

    // Register crosshair plugin if not already registered
    if (!Chart.registry.plugins.get('crosshair')) {
      Chart.register(crosshairPlugin);
    }

    const ctx = canvas.getContext('2d');
    const COLORS = getColors();

    // Create gradient fills
    this._buildGradients(ctx, canvas);

    this.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Download',
            data: [],
            borderColor: COLORS.download,
            backgroundColor: this._dlGrad,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 5,
            pointHoverBackgroundColor: COLORS.download,
            pointHoverBorderColor: '#fff',
            pointHoverBorderWidth: 2,
            borderWidth: 2,
          },
          {
            label: 'Upload',
            data: [],
            borderColor: COLORS.upload,
            backgroundColor: this._ulGrad,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 5,
            pointHoverBackgroundColor: COLORS.upload,
            pointHoverBorderColor: '#fff',
            pointHoverBorderWidth: 2,
            borderWidth: 2,
          }
        ]
      },
      options: {
        animation: {
          duration: 600,
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
            cornerRadius: 8,
            padding: 12,
            titleFont: { size: 11, weight: 600 },
            bodyFont: { size: 12 },
            bodySpacing: 6,
            displayColors: true,
            boxWidth: 8,
            boxHeight: 8,
            boxPadding: 4,
            callbacks: {
              title(items) {
                if (!items.length) return '';
                return items[0].label || '';
              },
              label(ctx) {
                const label = ctx.dataset.label || '';
                return ` ${label}: ${dynamicFormat(ctx.parsed.y)}`;
              },
              afterBody(items) {
                if (items.length < 2) return '';
                const dl = items[0]?.parsed?.y || 0;
                const ul = items[1]?.parsed?.y || 0;
                return `  Total: ${dynamicFormat(dl + ul)}`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: COLORS.text,
              maxTicksLimit: 8,
              maxRotation: 0,
              font: { size: 10 },
            },
            border: { display: false }
          },
          y: {
            beginAtZero: true,
            grid: { color: COLORS.grid },
            ticks: {
              color: COLORS.text,
              padding: 8,
              font: { size: 10 },
              callback: v => dynamicFormat(v),
              maxTicksLimit: 6
            },
            border: { display: false }
          }
        }
      }
    });

    // Store crosshair color for the plugin
    this.chart._crosshairColor = COLORS.crosshair;

    // Listen for theme changes and re-apply colors
    this._themeObserver = new MutationObserver(() => this._applyThemeColors());
    this._themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    // Subscribe to bandwidth data
    this._unsub = store.subscribe('bandwidth', data => this.update(data));
  }

  /** Build gradient objects for the download/upload area fills. */
  _buildGradients(ctx, canvas) {
    const h = canvas.parentElement?.clientHeight || 280;

    const dlGrad = ctx.createLinearGradient(0, 0, 0, h);
    dlGrad.addColorStop(0,   'rgba(16, 185, 129, 0.25)');
    dlGrad.addColorStop(0.5, 'rgba(16, 185, 129, 0.08)');
    dlGrad.addColorStop(1,   'rgba(16, 185, 129, 0)');
    this._dlGrad = dlGrad;

    const ulGrad = ctx.createLinearGradient(0, 0, 0, h);
    ulGrad.addColorStop(0,   'rgba(59, 130, 246, 0.2)');
    ulGrad.addColorStop(0.5, 'rgba(59, 130, 246, 0.06)');
    ulGrad.addColorStop(1,   'rgba(59, 130, 246, 0)');
    this._ulGrad = ulGrad;
  }

  update(raw) {
    if (!this.chart) return;

    const history = (raw && (raw.history || raw.data || raw)) || [];
    const hasData = Array.isArray(history) && history.length > 0;

    // Show / hide "no data" overlay
    this._toggleNoData(!hasData);

    if (!hasData) {
      this.chart.data.labels = [];
      this.chart.data.datasets[0].data = [];
      this.chart.data.datasets[1].data = [];
      this.chart.update('none');
      this._updateSpeedBadge([], []);
      return;
    }

    // Change-detection: skip re-render when data hasn't meaningfully changed
    const fp = history.length + ':' +
      (history[0]?.timestamp || '') + ':' +
      (history[history.length - 1]?.timestamp || '') + ':' +
      (history[history.length - 1]?.download_mbps ?? 0) + ':' +
      (history[history.length - 1]?.upload_mbps ?? 0);
    if (fp === this._lastFingerprint && !this._firstUpdate) return;
    this._lastFingerprint = fp;

    // Extract raw data
    let dlData = history.map(d => d.download_mbps ?? d.bytes_download ?? 0);
    let ulData = history.map(d => d.upload_mbps ?? d.bytes_upload ?? 0);

    // Apply 3-point weighted moving average for smoother chart appearance.
    dlData = this._smooth(dlData);
    ulData = this._smooth(ulData);

    this.chart.data.labels = history.map(d => formatTimestamp(d.timestamp));
    this.chart.data.datasets[0].data = dlData;
    this.chart.data.datasets[1].data = ulData;

    // Update live speed badge
    this._updateSpeedBadge(dlData, ulData);

    // First paint: instant render.  Subsequent: smooth 600 ms transition.
    if (this._firstUpdate) {
      this._firstUpdate = false;
      this.chart.update('none');
    } else {
      this.chart.update();
    }
  }

  /** Update the live speed badge above the chart. */
  _updateSpeedBadge(dlData, ulData) {
    const badge = document.getElementById('bw-live-speed');
    if (!badge) return;
    const latestDl = dlData.length ? dlData[dlData.length - 1] : 0;
    const latestUl = ulData.length ? ulData[ulData.length - 1] : 0;
    if (latestDl <= 0 && latestUl <= 0) {
      badge.innerHTML = '<span class="speed-badge__idle">idle</span>';
      return;
    }
    badge.innerHTML =
      `<span class="speed-badge__dl">\u2193 ${dynamicFormat(latestDl)}</span>` +
      `<span class="speed-badge__sep">/</span>` +
      `<span class="speed-badge__ul">\u2191 ${dynamicFormat(latestUl)}</span>`;
  }

  /**
   * 5-point weighted moving average for visual smoothing.
   * Centre-weighted (0.1, 0.2, 0.4, 0.2, 0.1) preserves peaks while
   * softening abrupt spikes from YouTube's bursty download pattern.
   * Wider than a 3-point kernel to better absorb the 3-5 s burst/pause
   * cycle typical of adaptive bitrate streaming.
   */
  _smooth(data) {
    if (!data || data.length < 5) return data;
    const result = [data[0], data[1]];
    for (let i = 2; i < data.length - 2; i++) {
      result.push(
        data[i - 2] * 0.1 + data[i - 1] * 0.2 + data[i] * 0.4 +
        data[i + 1] * 0.2 + data[i + 2] * 0.1
      );
    }
    result.push(data[data.length - 2]);
    result.push(data[data.length - 1]);
    return result;
  }

  /** Show or hide a styled "no data" overlay on the canvas container. */
  _toggleNoData(show) {
    const canvas = document.getElementById(this.canvasId);
    if (!canvas) return;
    const container = canvas.parentElement;
    if (!container) return;

    let overlay = container.querySelector('.chart-no-data');
    if (show && !overlay) {
      overlay = document.createElement('div');
      overlay.className = 'chart-no-data';
      overlay.innerHTML = '<div class="chart-no-data__icon">\u2014</div><div>Waiting for bandwidth data\u2026</div>';
      container.style.position = 'relative';
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
    const canvas = document.getElementById(this.canvasId);
    const ctx = canvas?.getContext('2d');

    if (ctx && canvas) {
      this._buildGradients(ctx, canvas);
    }

    const ds = this.chart.data.datasets;
    ds[0].borderColor = C.download;
    ds[0].backgroundColor = this._dlGrad;
    ds[0].pointHoverBackgroundColor = C.download;
    ds[1].borderColor = C.upload;
    ds[1].backgroundColor = this._ulGrad;
    ds[1].pointHoverBackgroundColor = C.upload;
    this.chart.options.plugins.legend.labels.color = C.text;
    this.chart.options.plugins.tooltip.backgroundColor = C.tooltipBg;
    this.chart.options.plugins.tooltip.titleColor = C.tooltipText;
    this.chart.options.plugins.tooltip.bodyColor = C.tooltipText;
    this.chart.options.plugins.tooltip.borderColor = C.tooltipBorder;
    this.chart.options.scales.x.ticks.color = C.text;
    this.chart.options.scales.y.grid.color = C.grid;
    this.chart.options.scales.y.ticks.color = C.text;
    this.chart._crosshairColor = C.crosshair;
    this.chart.update('none');
  }
}
