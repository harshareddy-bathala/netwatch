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

/**
 * Shorthand for querySelector scoped to a root.
 * @param {string} sel - CSS selector
 * @param {HTMLElement} [root=document] - Root element
 * @returns {HTMLElement|null}
 */
export function $(sel, root = document) {
  return root.querySelector(sel);
}

/**
 * Shorthand for querySelectorAll (returns real Array).
 * @param {string} sel - CSS selector
 * @param {HTMLElement} [root=document] - Root element
 * @returns {HTMLElement[]}
 */
export function $$(sel, root = document) {
  return Array.from(root.querySelectorAll(sel));
}
