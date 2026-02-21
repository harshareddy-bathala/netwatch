/**
 * router.js - Client-side SPA Router
 * ====================================
 * Hash-based routing (/#/path) so it works without server config.
 * Supports browser back/forward buttons via popstate.
 */

export default class Router {
  constructor() {
    this._routes = {};       // path → handler
    this._current = null;
  }

  /** Register a route */
  on(path, handler) {
    this._routes[path] = handler;
    return this;
  }

  /** Navigate to a path programmatically */
  navigate(path) {
    if (path === this._current) return;
    window.location.hash = '#' + path;
  }

  /** Start listening for route changes */
  start() {
    window.addEventListener('hashchange', () => this._resolve());
    // Handle initial route
    this._resolve();
  }

  _resolve() {
    const hash = window.location.hash.slice(1) || '/';
    if (hash === this._current) return;
    this._current = hash;

    const handler = this._routes[hash] || this._routes['/'];
    if (handler) handler(hash);
  }

  get currentRoute() {
    return this._current || '/';
  }
}
