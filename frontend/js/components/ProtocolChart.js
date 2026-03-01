/**
 * ProtocolChart.js - Protocol Distribution Doughnut
 * ===================================================
 * Centered doughnut. Default center text shows the dominant protocol.
 * Hovering a segment updates the center text with that protocol's details.
 * No side legend — all info surfaces through hover interaction.
 */

import store from '../store.js';
import { formatBytes } from '../utils/formatters.js';

const PALETTE = [
  '#d97706', '#10b981', '#3b82f6', '#ef4444', '#8b5cf6',
  '#f59e0b', '#06b6d4', '#ec4899', '#6b7280', '#14b8a6',
];

/** Threshold below which protocols are grouped into "Other". */
const OTHER_THRESHOLD_PCT = 2;

/** Read a CSS custom property from the document root. */
function cssVar(name, fallback = '') {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

/**
 * Chart.js plugin: draw protocol info in the center cutout.
 * - Default: dominant protocol name + percentage
 * - On hover: hovered protocol name + percentage + bytes
 */
const centerTextPlugin = {
  id: 'centerText',
  afterDraw(chart) {
    const { ctx, chartArea } = chart;
    if (!chartArea) return;

    // Decide what to show — hover takes priority
    const active = chart.getActiveElements();
    let meta;
    if (active.length > 0) {
      const items = chart._centerTextItems;
      meta = (items && items[active[0].index]) || chart._centerTextMeta;
    } else {
      meta = chart._centerTextMeta;
    }
    if (!meta || !meta.label) return;

    const cx = (chartArea.left + chartArea.right) / 2;
    const cy = (chartArea.top + chartArea.bottom) / 2;

    const textColor = cssVar('--color-text-primary', '#efefef');
    const subColor  = cssVar('--color-text-tertiary', '#6b6b6b');
    const bodyFont  = getComputedStyle(document.body).fontFamily;
    const hasBytes  = Boolean(meta.bytes);

    ctx.save();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';

    // Vertical layout: shift up a bit when 3 lines
    const topY = hasBytes ? cy - 13 : cy - 7;

    // Line 1: Protocol name
    ctx.fillStyle = textColor;
    ctx.font = `600 13px ${bodyFont}`;
    ctx.fillText(meta.label, cx, topY);

    // Line 2: Percentage
    ctx.fillStyle = subColor;
    ctx.font = `500 11px ${bodyFont}`;
    ctx.fillText(meta.pct, cx, topY + 16);

    // Line 3: Bytes — only on hover
    if (hasBytes) {
      ctx.fillStyle = subColor;
      ctx.font = `400 10px ${bodyFont}`;
      ctx.fillText(meta.bytes, cx, topY + 30);
    }

    ctx.restore();
  }
};

export default class ProtocolChart {
  constructor(canvasId) {
    this.canvasId = canvasId;
    this.chart = null;
    this._unsub = null;
    this._firstUpdate = true;
    this._lastPercentages = [];
    this._lastBytes = [];
    this._lastFingerprint = '';
  }

  init() {
    const canvas = document.getElementById(this.canvasId);
    if (!canvas || typeof Chart === 'undefined') return;

    if (this.chart) { this.chart.destroy(); this.chart = null; }

    if (!Chart.registry.plugins.get('centerText')) {
      Chart.register(centerTextPlugin);
    }

    this.chart = new Chart(canvas.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: PALETTE,
          borderWidth: 0,
          // No pop-out on hover; subtle white border instead
          hoverOffset: 0,
          hoverBorderWidth: 2,
          hoverBorderColor: 'rgba(255,255,255,0.2)',
        }]
      },
      options: {
        animation: {
          duration: 800,
          easing: 'easeOutQuart',
          animateRotate: true,
          animateScale: false,
        },
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        layout: { padding: 4 },
        plugins: {
          legend: { display: false },
          tooltip: { enabled: false },  // Center text replaces tooltip
        },
      }
    });

    // Redraw when theme toggles so center text picks up new CSS vars
    this._themeObserver = new MutationObserver(() => {
      if (this.chart) this.chart.draw();
    });
    this._themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });

    this._unsub = store.subscribe('protocols', data => this.update(data));
  }

  update(raw) {
    if (!this.chart) return;

    const protocols = (raw && (raw.protocols || raw.data || raw)) || [];
    const hasData = Array.isArray(protocols) && protocols.length > 0;

    this._toggleNoData(!hasData);

    if (!hasData) {
      this._lastPercentages = [];
      this._lastBytes = [];
      this.chart.data.labels = [];
      this.chart.data.datasets[0].data = [];
      this.chart._centerTextMeta = null;
      this.chart._centerTextItems = null;
      this.chart.update('none');
      return;
    }

    // Normalize
    let entries = protocols.map(p => ({
      label: p.name || p.protocol || 'Unknown',
      value: p.bytes || p.total_bytes || p.count || p.packet_count || 0,
      pct: p.percentage,
    }));

    const total = entries.reduce((sum, e) => sum + (e.value || 0), 0);
    entries = entries.map(e => ({
      ...e,
      computedPct: (e.pct != null && !isNaN(e.pct))
        ? Number(e.pct)
        : total > 0 ? (e.value / total) * 100 : 0,
    }));

    // Group small protocols into "Other"
    const main = [];
    let otherValue = 0;
    let otherPct = 0;
    for (const e of entries) {
      if (e.computedPct < OTHER_THRESHOLD_PCT && entries.length > 5) {
        otherValue += e.value;
        otherPct += e.computedPct;
      } else {
        main.push(e);
      }
    }
    if (otherValue > 0) {
      main.push({ label: 'Other', value: otherValue, computedPct: otherPct });
    }

    const fingerprint = main.map(e => `${e.label}:${e.value}`).join('|');
    if (fingerprint === this._lastFingerprint) return;
    this._lastFingerprint = fingerprint;

    this._lastPercentages = main.map(e => e.computedPct);
    this._lastBytes = main.map(e => e.value);

    this.chart.data.labels = main.map(e => e.label);
    this.chart.data.datasets[0].data = main.map(e => e.value || 0);

    // Default center: dominant protocol (no bytes — keep it clean)
    if (main.length > 0) {
      const top = main[0];
      this.chart._centerTextMeta = {
        label: top.label,
        pct: top.computedPct.toFixed(1) + '%',
      };
    } else {
      this.chart._centerTextMeta = null;
    }

    // Per-index hover metadata (includes bytes)
    this.chart._centerTextItems = main.map(e => ({
      label: e.label,
      pct: e.computedPct.toFixed(1) + '%',
      bytes: formatBytes(e.value),
    }));

    if (this._firstUpdate) {
      this._firstUpdate = false;
      this.chart.update();
    } else {
      this.chart.update({ duration: 400, easing: 'easeInOutQuart' });
    }
  }

  _escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  _toggleNoData(show) {
    const canvas = document.getElementById(this.canvasId);
    if (!canvas) return;
    const container = canvas.parentElement;
    if (!container) return;

    let overlay = container.querySelector('.chart-no-data');
    if (show && !overlay) {
      overlay = document.createElement('div');
      overlay.className = 'chart-no-data';
      overlay.innerHTML = '<div class="chart-no-data__icon">\u25CB</div><div>Waiting for protocol data\u2026</div>';
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
}
