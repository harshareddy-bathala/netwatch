/**
 * dom.js - DOM Utilities
 * ========================
 * Event delegation helper and cached element queries.
 * Reduces per-element listener binding in list components.
 */

/**
 * Delegate events from a parent container to matching child selectors.
 * Returns a cleanup function that removes the listener.
 *
 * @param {HTMLElement} parent  - Container to listen on
 * @param {string}      event   - Event type ('click', 'input', etc.)
 * @param {string}      selector - CSS selector to match against
 * @param {Function}    handler  - Called with (event, matchedElement)
 * @returns {Function} Unsubscribe function
 */
export function delegate(parent, event, selector, handler) {
  const listener = (e) => {
    const target = e.target.closest(selector);
    if (target && parent.contains(target)) {
      handler(e, target);
    }
  };
  parent.addEventListener(event, listener);
  return () => parent.removeEventListener(event, listener);
}
