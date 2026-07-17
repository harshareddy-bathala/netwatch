/**
 * ForecastView.js - Standalone Forecast view (W6)
 * ================================================
 * Promotes the bandwidth + device-count forecasts from a chart overlay to a
 * page: current vs predicted, saturation ETA, and device-count trend.
 * Dependency-free (no Chart.js); reads /api/forecast/*.
 */

import api from '../api.js';

const REFRESH_MS = 15000;

export default class ForecastView {
  constructor(el) {
    this.el = el;
    this._timer = null;
    this._destroyed = false;
  }

  render() {
    this.el.innerHTML = `
      <div class="forecast">
        <div class="view-explainer">
          Short-horizon predictions from the telemetry: where bandwidth is
          heading, when it may saturate, and how the device count is trending.
        </div>
        <div class="forecast__cards">
          <div class="forecast-card card" id="forecast-bw">Loading bandwidth forecast…</div>
          <div class="forecast-card card" id="forecast-dev">Loading device forecast…</div>
        </div>
      </div>
    `;
    this._load();
    this._timer = setInterval(() => this._load(), REFRESH_MS);
  }

  destroy() {
    this._destroyed = true;
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  async _load() {
    const [bw, dev] = await Promise.all([
      api.getForecastBandwidth(30),
      api.getForecastDevices(6),
    ]);
    if (this._destroyed) return;
    this._renderBandwidth((bw && bw.data) || bw || {});
    this._renderDevices((dev && dev.data) || dev || {});
  }

  _renderBandwidth(f) {
    const el = this.el.querySelector('#forecast-bw');
    if (!el) return;
    el.innerHTML = '';
    el.appendChild(this._title('Bandwidth forecast'));
    if (f.available === false) {
      el.appendChild(this._note(f.reason || 'Not enough history yet — check back after a few minutes of capture.'));
      return;
    }
    const points = Array.isArray(f.points) ? f.points : [];
    const cur = f.model && f.model.level_mbps != null ? f.model.level_mbps : null;
    const pred = points.length ? points[points.length - 1].mbps : null;
    el.appendChild(this._stat('Now', cur != null ? `${Number(cur).toFixed(2)} Mbps` : '—'));
    el.appendChild(this._stat(`In ~${f.horizon_minutes || 30} min`,
      pred != null ? `${Number(pred).toFixed(2)} Mbps` : '—'));
    const eta = f.saturation && f.saturation.eta_minutes;
    if (f.saturation) {
      el.appendChild(this._stat('Saturation ETA',
        eta ? `~${Math.round(eta)} min` : 'not predicted within horizon',
        !!eta && eta < 30));
    }
    const trendPm = f.model && f.model.trend_mbps_per_min;
    if (trendPm != null) {
      el.appendChild(this._note(
        `Trend: ${trendPm >= 0 ? '+' : ''}${(trendPm * 60).toFixed(3)} Mbps/hour`));
    }
  }

  _renderDevices(f) {
    const el = this.el.querySelector('#forecast-dev');
    if (!el) return;
    el.innerHTML = '';
    el.appendChild(this._title('Device-count trend'));
    if (f.available === false) {
      el.appendChild(this._note(f.reason || 'Not enough history yet.'));
      return;
    }
    const points = Array.isArray(f.points) ? f.points : [];
    const cur = f.current_count != null ? f.current_count : null;
    const pred = points.length ? points[points.length - 1].count : null;
    el.appendChild(this._stat('Now', cur != null ? `${cur} devices` : '—'));
    el.appendChild(this._stat(`In ~${f.horizon_hours || 6} h`,
      pred != null ? `${Math.round(pred)} devices` : '—'));
    const tph = f.model && f.model.trend_per_hour;
    if (tph != null) {
      el.appendChild(this._note(
        `Trend: ${tph >= 0 ? '+' : ''}${tph.toFixed(2)} devices/hour`));
    }
  }

  _title(text) {
    const h = document.createElement('div');
    h.className = 'forecast-card__title';
    h.textContent = text;
    return h;
  }

  _stat(label, value, warn = false) {
    const row = document.createElement('div');
    row.className = 'forecast-card__stat';
    const l = document.createElement('span');
    l.className = 'forecast-card__label';
    l.textContent = label;
    const v = document.createElement('span');
    v.className = 'forecast-card__value' + (warn ? ' forecast-card__value--warn' : '');
    v.textContent = value;
    row.appendChild(l);
    row.appendChild(v);
    return row;
  }

  _note(text) {
    const n = document.createElement('div');
    n.className = 'forecast-card__note';
    n.textContent = text;
    return n;
  }
}
