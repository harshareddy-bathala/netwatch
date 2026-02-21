/**
 * StatsCard.js - Stat Card Component
 * =====================================
 */

export default class StatsCard {
  /**
   * @param {object} opts - { id, label, icon, iconClass, unit }
   */
  constructor(opts) {
    this.opts = opts;
    this._prevValue = null;
    this._valEl = null;    // cached DOM ref
    this._trendEl = null;  // cached DOM ref
  }

  html() {
    const { id, label, iconClass } = this.opts;
    return `
      <div class="stats-card" id="card-${id}">
        <div class="stats-card__header">
          <span class="stats-card__label">${label}</span>
          <span class="stats-card__icon ${iconClass}">${this.opts.icon || ''}</span>
        </div>
        <div class="stats-card__value" id="val-${id}">
          <span class="skeleton skeleton--value"></span>
        </div>
        <div class="stats-card__trend" id="trend-${id}"></div>
      </div>
    `;
  }

  /** Cache DOM refs after first render (lazy). */
  _ensureRefs() {
    if (!this._valEl) {
      this._valEl = document.getElementById(`val-${this.opts.id}`);
      this._trendEl = document.getElementById(`trend-${this.opts.id}`);
    }
  }

  update(value, unit, trendText, trendDir) {
    this._ensureRefs();
    const valEl = this._valEl;
    const trendEl = this._trendEl;
    if (!valEl) return;

    const display = `${value}<span class="stats-card__unit">${unit || ''}</span>`;
    valEl.innerHTML = display;

    // Brief flash on change
    if (this._prevValue !== null && this._prevValue !== value) {
      valEl.classList.add('value-updated');
      setTimeout(() => valEl.classList.add('settle'), 50);
      setTimeout(() => { valEl.classList.remove('value-updated', 'settle'); }, 600);
    }
    this._prevValue = value;

    if (trendEl && trendText) {
      trendEl.textContent = trendText;
      trendEl.className = `stats-card__trend ${trendDir || ''}`;
    }
  }
}
