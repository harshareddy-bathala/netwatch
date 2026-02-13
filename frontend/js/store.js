/**
 * store.js - Centralized State Management
 * =========================================
 * Single source of truth. Components subscribe to slices.
 * Only notifies when values actually change (shallow compare).
 */

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
    // Shallow equality skip (primitive or same ref)
    if (this.state[key] === value) return;
    this.state[key] = value;
    this._notify(key, value);
  }

  /** Batch update multiple keys, then notify */
  setBatch(updates) {
    const changed = [];
    for (const [key, value] of Object.entries(updates)) {
      if (this.state[key] !== value) {
        this.state[key] = value;
        changed.push(key);
      }
    }
    changed.forEach(key => this._notify(key, this.state[key]));
  }

  /** Subscribe to changes on a key. Returns unsubscribe function. */
  subscribe(key, callback) {
    if (!this._listeners[key]) this._listeners[key] = [];
    this._listeners[key].push(callback);

    // Immediately fire with current value if it exists
    if (this.state[key] !== null && this.state[key] !== undefined) {
      try { callback(this.state[key]); } catch (e) { console.error('[Store]', e); }
    }

    return () => {
      this._listeners[key] = this._listeners[key].filter(cb => cb !== callback);
    };
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
