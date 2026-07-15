/**
 * BandwidthChart.js - Real-time Bandwidth Line Chart
 * ====================================================
 * Wraps Chart.js with gradient area fills, vertical crosshair,
 * dynamic y-axis scaling, and smooth animation.  SSE pushes every
 * ~3 s; Chart.js animates transitions over 600 ms.
 */

import { formatTimestamp } from '../utils/formatters.js';
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
    controlDownload: cssVar('--chart-control-download', '#f59e0b'),
    controlUpload:   cssVar('--chart-control-upload',   '#ef4444'),
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

/** Axis formatter: keep consistent units/width to reduce y-axis reflow jitter. */
function axisFormat(mbps) {
  const val = Number(mbps || 0);
  if (!isFinite(val) || val <= 0) return '0.0 Mbps';
  if (val < 0.1) return '0.1 Mbps';
  return `${val.toFixed(1)} Mbps`;
}

// Hide tiny baseline jitter in chart rendering so idle traffic stays flat.
const IDLE_FLOOR_MBPS = 0.015;

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
    this._unsubBandwidth = null;
    this._unsubControl = null;
    this._firstUpdate = true;
    this._lastFingerprint = '';
    this._lastRaw = null;
    this._showControlOverhead = !!store.get('includeControlTraffic');
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
            stack: 'download',
            trafficClass: 'app',
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 5,
            pointHoverBackgroundColor: COLORS.download,
            pointHoverBorderColor: '#fff',
            pointHoverBorderWidth: 2,
            borderWidth: 2,
          },
          {
            label: 'Download (Control)',
            data: [],
            borderColor: COLORS.controlDownload,
            backgroundColor: this._controlDlGrad,
            fill: true,
            stack: 'download',
            trafficClass: 'control',
            borderDash: [6, 4],
            tension: 0.35,
            pointRadius: 0,
            pointHoverRadius: 4,
            pointHoverBackgroundColor: COLORS.controlDownload,
            pointHoverBorderColor: '#fff',
            pointHoverBorderWidth: 1.5,
            borderWidth: 1.5,
            hidden: !this._showControlOverhead,
          },
          {
            label: 'Upload',
            data: [],
            borderColor: COLORS.upload,
            backgroundColor: this._ulGrad,
            fill: true,
            stack: 'upload',
            trafficClass: 'app',
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 5,
            pointHoverBackgroundColor: COLORS.upload,
            pointHoverBorderColor: '#fff',
            pointHoverBorderWidth: 2,
            borderWidth: 2,
          },
          {
            label: 'Upload (Control)',
            data: [],
            borderColor: COLORS.controlUpload,
            backgroundColor: this._controlUlGrad,
            fill: true,
            stack: 'upload',
            trafficClass: 'control',
            borderDash: [6, 4],
            tension: 0.35,
            pointRadius: 0,
            pointHoverRadius: 4,
            pointHoverBackgroundColor: COLORS.controlUpload,
            pointHoverBorderColor: '#fff',
            pointHoverBorderWidth: 1.5,
            borderWidth: 1.5,
            hidden: !this._showControlOverhead,
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
                if (!items.length) return '';

                let total = 0;
                let appTotal = 0;
                let controlTotal = 0;
                for (const item of items) {
                  const value = item?.parsed?.y || 0;
                  total += value;
                  if (item?.dataset?.trafficClass === 'control') {
                    controlTotal += value;
                  } else {
                    appTotal += value;
                  }
                }

                if (controlTotal > 0) {
                  return [
                    `  App: ${dynamicFormat(appTotal)}`,
                    `  Ctrl: ${dynamicFormat(controlTotal)}`,
                    `  Total: ${dynamicFormat(total)}`,
                  ];
                }
                return `  Total: ${dynamicFormat(total)}`;
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
            stacked: false,
            grid: { color: COLORS.grid },
            ticks: {
              color: COLORS.text,
              padding: 8,
              font: { size: 10, family: 'var(--font-mono)' },
              callback: v => axisFormat(v),
              maxTicksLimit: 6
            },
            afterFit: (scale) => {
              // Keep a stable left gutter so plot area does not shift.
              scale.width = Math.max(scale.width, 72);
            },
            border: { display: false }
          }
        }
      }
    });

    // Store crosshair color for the plugin
    this.chart._crosshairColor = COLORS.crosshair;
    this._syncDisplayMode();

    // Listen for theme changes and re-apply colors
    this._themeObserver = new MutationObserver(() => this._applyThemeColors());
    this._themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    // Subscribe to bandwidth data
    this._unsubBandwidth = store.subscribe('bandwidth', data => this.update(data));
    this._unsubControl = store.subscribe('includeControlTraffic', enabled => {
      this._showControlOverhead = !!enabled;
      this._syncDisplayMode();
      this.update(this._lastRaw || store.get('bandwidth') || [], true);
    });
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

    const controlDlGrad = ctx.createLinearGradient(0, 0, 0, h);
    controlDlGrad.addColorStop(0,   'rgba(245, 158, 11, 0.16)');
    controlDlGrad.addColorStop(0.5, 'rgba(245, 158, 11, 0.06)');
    controlDlGrad.addColorStop(1,   'rgba(245, 158, 11, 0)');
    this._controlDlGrad = controlDlGrad;

    const controlUlGrad = ctx.createLinearGradient(0, 0, 0, h);
    controlUlGrad.addColorStop(0,   'rgba(239, 68, 68, 0.14)');
    controlUlGrad.addColorStop(0.5, 'rgba(239, 68, 68, 0.05)');
    controlUlGrad.addColorStop(1,   'rgba(239, 68, 68, 0)');
    this._controlUlGrad = controlUlGrad;
  }

  update(raw, forceRender = false) {
    if (!this.chart) return;

    this._lastRaw = raw;

    const history = (raw && (raw.history || raw.data || raw)) || [];
    const hasData = Array.isArray(history) && history.length > 0;

    // Show / hide "no data" overlay
    this._toggleNoData(!hasData);

    if (!hasData) {
      this.chart.data.labels = [];
      this.chart.data.datasets.forEach(ds => { ds.data = []; });
      this.chart.update('none');
      this._updateSpeedBadge([], [], [], []);
      return;
    }

    // Change-detection: fingerprint all plotted points so mid-series
    // corrections from server-side merge logic still trigger a render.
    const fp = history.map(d => {
      const ts = d?.timestamp || '';
      const dl = d?.download_mbps ?? d?.bytes_download ?? 0;
      const ul = d?.upload_mbps ?? d?.bytes_upload ?? 0;
      const cdl = d?.control_download_mbps ?? 0;
      const cul = d?.control_upload_mbps ?? 0;
      return `${ts}|${dl}|${ul}|${cdl}|${cul}`;
    }).join(';');
    const chartMode = this._showControlOverhead ? 'control' : 'app';
    const modeAwareFingerprint = `${chartMode}:${fp}`;
    if (modeAwareFingerprint === this._lastFingerprint && !this._firstUpdate && !forceRender) return;
    this._lastFingerprint = modeAwareFingerprint;

    // Extract raw data
    let dlData = history.map(d => d.download_mbps ?? d.bytes_download ?? 0);
    let ulData = history.map(d => d.upload_mbps ?? d.bytes_upload ?? 0);
    let controlDlData = history.map(d => d.control_download_mbps ?? 0);
    let controlUlData = history.map(d => d.control_upload_mbps ?? 0);

    // Apply 3-point weighted moving average for smoother chart appearance.
    dlData = this._applyIdleFloor(this._smooth(dlData));
    ulData = this._applyIdleFloor(this._smooth(ulData));
    controlDlData = this._applyIdleFloor(this._smooth(controlDlData));
    controlUlData = this._applyIdleFloor(this._smooth(controlUlData));

    this.chart.data.labels = history.map(d => formatTimestamp(d.timestamp));
    this.chart.data.datasets[0].data = dlData;
    this.chart.data.datasets[1].data = controlDlData;
    this.chart.data.datasets[2].data = ulData;
    this.chart.data.datasets[3].data = controlUlData;

    // Update live speed badge
    this._updateSpeedBadge(dlData, ulData, controlDlData, controlUlData);

    // First paint: instant render.  Subsequent: smooth 600 ms transition.
    if (this._firstUpdate) {
      this._firstUpdate = false;
      this.chart.update('none');
    } else {
      this.chart.update();
    }
  }

  /** Update the live speed badge above the chart. */
  _updateSpeedBadge(dlData, ulData, controlDlData = [], controlUlData = []) {
    const badge = document.getElementById('bw-live-speed');
    if (!badge) return;
    const latestDl = dlData.length ? dlData[dlData.length - 1] : 0;
    const latestUl = ulData.length ? ulData[ulData.length - 1] : 0;
    const latestControlDl = controlDlData.length ? controlDlData[controlDlData.length - 1] : 0;
    const latestControlUl = controlUlData.length ? controlUlData[controlUlData.length - 1] : 0;
    const latestControlTotal = latestControlDl + latestControlUl;

    if (latestDl <= 0 && latestUl <= 0 && latestControlTotal <= 0) {
      badge.innerHTML = '<span class="speed-badge__idle">idle</span>';
      return;
    }
    let html =
      `<span class="speed-badge__dl">\u2193 ${dynamicFormat(latestDl)}</span>` +
      `<span class="speed-badge__sep">/</span>` +
      `<span class="speed-badge__ul">\u2191 ${dynamicFormat(latestUl)}</span>`;

    if (this._showControlOverhead && latestControlTotal > 0) {
      html += `<span class="speed-badge__ctrl">+ ctrl ${dynamicFormat(latestControlTotal)}</span>`;
    }

    badge.innerHTML = html;
  }

  _syncDisplayMode() {
    if (!this.chart) return;

    const showControl = !!this._showControlOverhead;
    const datasets = this.chart.data.datasets || [];

    if (datasets[0]) datasets[0].label = showControl ? 'Download (App)' : 'Download';
    if (datasets[1]) datasets[1].hidden = !showControl;
    if (datasets[2]) datasets[2].label = showControl ? 'Upload (App)' : 'Upload';
    if (datasets[3]) datasets[3].hidden = !showControl;

    if (this.chart.options?.scales?.y) {
      this.chart.options.scales.y.stacked = false;
    }
    this.chart.update();
  }

  /**
   * Causal trailing smoothing for stable historical rendering.
   *
   * Uses only current and past points, never future points. This prevents
   * already-rendered buckets from being recomputed when new data arrives.
   */
  _smooth(data) {
    if (!data || data.length < 3) return data;
    const result = [];
    for (let i = 0; i < data.length; i++) {
      const x0 = data[i] ?? 0;
      const x1 = data[i - 1] ?? x0;
      const x2 = data[i - 2] ?? x1;
      const x3 = data[i - 3] ?? x2;
      const x4 = data[i - 4] ?? x3;
      result.push(
        x0 * 0.40 +
        x1 * 0.30 +
        x2 * 0.15 +
        x3 * 0.10 +
        x4 * 0.05
      );
    }
    return result;
  }

  _applyIdleFloor(data) {
    if (!Array.isArray(data)) return data;
    return data.map(v => {
      const value = Number(v || 0);
      return value < IDLE_FLOOR_MBPS ? 0 : value;
    });
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
    if (this._unsubBandwidth) this._unsubBandwidth();
    if (this._unsubControl) this._unsubControl();
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
    ds[1].borderColor = C.controlDownload;
    ds[1].backgroundColor = this._controlDlGrad;
    ds[1].pointHoverBackgroundColor = C.controlDownload;
    ds[2].borderColor = C.upload;
    ds[2].backgroundColor = this._ulGrad;
    ds[2].pointHoverBackgroundColor = C.upload;
    ds[3].borderColor = C.controlUpload;
    ds[3].backgroundColor = this._controlUlGrad;
    ds[3].pointHoverBackgroundColor = C.controlUpload;
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
