/**
 * toast.js - Toast Notification Utility
 * ========================================
 * Shared helper for showing dismissible toast notifications.
 * Import in any component: `import { showToast } from '../utils/toast.js';`
 */

/**
 * Show a toast notification with an exit animation.
 * @param {string} message  - Text to display.
 * @param {'error'|'success'|'warning'|'info'} [type='error'] - Visual style.
 * @param {number} [duration=4000] - Auto-dismiss delay in ms.
 */
export function showToast(message, type = 'error', duration = 4000) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast--${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  const dismiss = () => {
    if (!toast.parentNode) return;
    toast.classList.add('toast-exit');
    toast.addEventListener('animationend', () => toast.remove(), { once: true });
    // Fallback if animationend doesn't fire
    setTimeout(() => { if (toast.parentNode) toast.remove(); }, 400);
  };

  setTimeout(dismiss, duration);
}
