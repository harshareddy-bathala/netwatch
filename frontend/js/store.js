/**
 * store.js - Centralized State Management
 * =========================================
 * Single source of truth. Components subscribe to slices.
 * Only notifies when values actually change (deep compare for objects).
 */

/**
 * Fast recursive deep equality check for plain JSON-like objects / arrays.
 * Returns true when `a` and `b` are structurally identical.
 */
function _deepEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;

  const isArrayA = Array.isArray(a);
  const isArrayB = Array.isArray(b);
  if (isArrayA !== isArrayB) return false;

  if (isArrayA) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!_deepEqual(a[i], b[i])) return false;
    }
    return true;
  }

  const keysA = Object.keys(a);
  const keysB = Object.keys(b);
  if (keysA.length !== keysB.length) return false;
  for (const k of keysA) {
    if (!Object.prototype.hasOwnProperty.call(b, k)) return false;
    if (!_deepEqual(a[k], b[k])) return false;
  }
  return true;
}

class Store {
  constructor() {
    this.state = {
      stats: null,
      bandwidth: null,
      devices: null,
      alerts: null,
      protocols: null,
      mode: null,
      health: null,
      alertStats: null,
      loading: false,
      connected: true,
      lastUpdated: null,
    };
    this._listeners = {};
  }

  /** Get current value for a key */
  get(key) {
    return this.state[key];
  }

  /** Update a state key and notify subscribers */
  setState(key, value) {
    // Deep equality check — prevents spurious re-renders for objects/arrays
    if (this.state[key] === value) return;
    if (typeof value === 'object' && value !== null && _deepEqual(this.state[key], value)) return;
    this.state[key] = value;
    this._notify(key, value);
  }

  /** Subscribe to changes on a key. Returns unsubscribe function.
   *  Options:
   *    skipInitial: true  — don't fire the callback with the current value
   */
  subscribe(key, callback, opts = {}) {
    if (!this._listeners[key]) this._listeners[key] = [];
    this._listeners[key].push(callback);

    // Immediately fire with current value unless caller opts out
    if (!opts.skipInitial &&
        this.state[key] !== null && this.state[key] !== undefined) {
      try { callback(this.state[key]); } catch (e) { console.error('[Store]', e); }
    }

    return () => {
      this._listeners[key] = this._listeners[key].filter(cb => cb !== callback);
    };
  }

  /** Null out view-specific keys without notifying subscribers.
   *  Called before mounting a new view so components never see
   *  stale data from the previous route.
   */
  clearViewData() {
    const keys = ['stats', 'bandwidth', 'devices', 'protocols', 'alerts', 'alertStats'];
    for (const k of keys) {
      this.state[k] = null;
    }
  }

  _notify(key, value) {
    (this._listeners[key] || []).forEach(cb => {
      try { cb(value); } catch (e) { console.error('[Store] subscriber error:', e); }
    });
  }
}

// Singleton
const store = new Store();
export default store;
