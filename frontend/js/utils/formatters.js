/**
 * formatters.js - Display Formatting Utilities
 * ==============================================
 * Pure functions for formatting bytes, dates, and other values.
 */

export function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 B';
  if (!bytes || isNaN(bytes)) return '-- B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[Math.min(i, sizes.length - 1)];
}

/**
 * Format a bandwidth RATE in bytes/sec to human-readable Mbps/Kbps/B/s.
 * This is the network-standard display: bytes → bits → Mbps.
 * Use this for dashboard bandwidth cards and device current rates.
 */
export function formatBandwidthRate(bytesPerSecond) {
  if (!bytesPerSecond || bytesPerSecond <= 0) return '0 B/s';
  const mbps = (bytesPerSecond * 8) / 1_000_000;
  if (mbps >= 1) return mbps.toFixed(1) + ' Mbps';
  const kbps = (bytesPerSecond * 8) / 1_000;
  if (kbps >= 1) return kbps.toFixed(1) + ' Kbps';
  return Math.round(bytesPerSecond) + ' B/s';
}

/**
 * Format a value that is already in Mbps into a human-readable string.
 * Always uses Mbps to stay consistent with the dashboard card unit.
 * Sub-Mbps values are shown as fractional Mbps (e.g. "0.30 Mbps" not "300 Kbps").
 */
export function formatMbps(mbps) {
  if (mbps == null || isNaN(mbps) || mbps <= 0) return '0 B/s';
  if (mbps >= 1)     return mbps.toFixed(1) + ' Mbps';
  if (mbps >= 0.01)  return mbps.toFixed(2) + ' Mbps';   // 0.01–0.99 Mbps
  if (mbps >= 0.001) return mbps.toFixed(3) + ' Mbps';   // 0.001–0.009 Mbps
  // Extremely small — fall back to Kbps / B/s for readability
  const kbps = mbps * 1000;
  if (kbps >= 1)   return kbps.toFixed(1) + ' Kbps';
  const bytesPerSec = (mbps * 1_000_000) / 8;
  if (bytesPerSec >= 1) return Math.round(bytesPerSec) + ' B/s';
  return '0 B/s';
}

/**
 * Split a bandwidth rate (bytes/sec) into {value, unit} for card display.
 * Matches formatBandwidthRate() thresholds exactly.
 */
export function splitBandwidthRate(bytesPerSecond) {
  if (!bytesPerSecond || bytesPerSecond <= 0) return { value: '0', unit: 'B/s' };
  const mbps = (bytesPerSecond * 8) / 1_000_000;
  if (mbps >= 1) return { value: mbps.toFixed(1), unit: 'Mbps' };
  const kbps = (bytesPerSecond * 8) / 1_000;
  if (kbps >= 1) return { value: kbps.toFixed(1), unit: 'Kbps' };
  return { value: Math.round(bytesPerSecond).toString(), unit: 'B/s' };
}

export function formatTimestamp(ts) {
  if (!ts) return '--:--';
  // Normalise "YYYY-MM-DD HH:MM:SS" → ISO 8601 "YYYY-MM-DDTHH:MM:SS"
  // so browsers that only accept the 'T' separator don't return NaN.
  const d = new Date(typeof ts === 'string' ? ts.replace(' ', 'T') : ts);
  if (isNaN(d.getTime())) return '--:--';
  // Show seconds for sub-minute data (e.g. 10s/30s buckets) so that chart
  // x-axis labels are distinct within the same minute.
  if (d.getSeconds() !== 0) {
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
}

export function formatRelativeTime(ts) {
  if (!ts) return 'unknown';
  const seconds = Math.floor((Date.now() - new Date(typeof ts === 'string' ? ts.replace(' ', 'T') : ts).getTime()) / 1000);
  if (seconds < 0 || seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

export function severityClass(severity) {
  const map = { critical: 'critical', high: 'critical', warning: 'warning', medium: 'warning', info: 'info', low: 'info' };
  return map[severity?.toLowerCase()] || 'info';
}
