/**
 * TopologyView.js - Network Digital Twin Topology (Phase 1)
 * ==========================================================
 * Dependency-free SVG rendering of /api/twin:
 *   - gateway at the center, "self" beside it
 *   - local devices on an inner ring
 *   - external endpoints on an outer ring (top talkers)
 *   - edges weighted by bytes transferred
 *
 * All node labels come from the network (hostnames, IPs), so every text
 * write uses the DOM API (textContent / createElementNS) — never HTML
 * string interpolation.
 */

import api from '../api.js';
import { formatBytes, formatRelativeTime } from '../utils/formatters.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
const REFRESH_MS = 10000;
const MAX_EXTERNAL_SHOWN = 24;
const MAX_DEVICES_SHOWN = 40;

const W = 1000;
const H = 700;
const CX = W / 2;
const CY = H / 2;
const INNER_R = 175;
const OUTER_R = 300;

export default class TopologyView {
  constructor(el) {
    this.el = el;
    this._timer = null;
    this._tooltip = null;
    this._destroyed = false;
  }

  render() {
    this.el.innerHTML = `
      <div class="topology">
        <div class="topology__toolbar">
          <div class="topology__stats" id="topology-stats"></div>
          <div class="topology__legend">
            <span class="topology__legend-item"><span class="topo-dot topo-dot--self"></span>This host</span>
            <span class="topology__legend-item"><span class="topo-dot topo-dot--gateway"></span>Gateway</span>
            <span class="topology__legend-item"><span class="topo-dot topo-dot--device"></span>Device</span>
            <span class="topology__legend-item"><span class="topo-dot topo-dot--external"></span>External</span>
          </div>
        </div>
        <div class="topology__canvas card" id="topology-canvas">
          <div class="topology__empty" id="topology-empty">Building the network twin — waiting for traffic…</div>
        </div>
        <div class="topology__tooltip" id="topology-tooltip" style="display:none"></div>
      </div>
    `;
    this._tooltip = this.el.querySelector('#topology-tooltip');
    this._load();
    this._timer = setInterval(() => this._load(), REFRESH_MS);
  }

  destroy() {
    this._destroyed = true;
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  async _load() {
    const resp = await api.getTwin();
    if (this._destroyed || !resp || resp.error) return;
    const twin = resp.data || resp;
    this._renderStats(twin);
    this._renderGraph(twin);
  }

  _renderStats(twin) {
    const el = this.el.querySelector('#topology-stats');
    if (!el) return;
    const s = twin.stats || {};
    el.textContent =
      `${s.device_count || 0} local devices · ` +
      `${s.external_count || 0} external endpoints · ` +
      `${s.edge_count || 0} connections · mode: ${twin.mode || 'unknown'}`;
  }

  /* ── Layout ─────────────────────────────────────── */

  _layout(twin) {
    const nodes = twin.nodes || [];
    const bySide = { self: [], gateway: [], device: [], external: [] };
    for (const n of nodes) (bySide[n.type] || bySide.device).push(n);

    // Cap what we draw; prefer highest-traffic nodes
    const traffic = (n) => (n.bytes_in || 0) + (n.bytes_out || 0);
    bySide.device.sort((a, b) => traffic(b) - traffic(a));
    bySide.external.sort((a, b) => traffic(b) - traffic(a));
    const devices = bySide.device.slice(0, MAX_DEVICES_SHOWN);
    const externals = bySide.external.slice(0, MAX_EXTERNAL_SHOWN);

    const pos = new Map();
    if (bySide.gateway.length) pos.set(bySide.gateway[0].id, { x: CX, y: CY });
    if (bySide.self.length) {
      pos.set(bySide.self[0].id, {
        x: bySide.gateway.length ? CX + 90 : CX,
        y: bySide.gateway.length ? CY - 60 : CY,
      });
    }
    devices.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / Math.max(devices.length, 1) - Math.PI / 2;
      pos.set(n.id, {
        x: CX + INNER_R * Math.cos(angle),
        y: CY + INNER_R * Math.sin(angle),
      });
    });
    externals.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / Math.max(externals.length, 1) - Math.PI / 2
        + Math.PI / Math.max(externals.length, 1);
      pos.set(n.id, {
        x: CX + OUTER_R * Math.cos(angle),
        y: CY + OUTER_R * Math.sin(angle),
      });
    });

    const drawn = [...bySide.gateway.slice(0, 1), ...bySide.self.slice(0, 1),
                   ...devices, ...externals];
    return { drawn, pos, hiddenExternal: bySide.external.length - externals.length };
  }

  /* ── SVG rendering (DOM API only) ───────────────── */

  _renderGraph(twin) {
    const canvas = this.el.querySelector('#topology-canvas');
    const empty = this.el.querySelector('#topology-empty');
    if (!canvas) return;

    const { drawn, pos, hiddenExternal } = this._layout(twin);
    if (!drawn.length) {
      if (empty) empty.style.display = '';
      canvas.querySelector('svg')?.remove();
      return;
    }
    if (empty) empty.style.display = 'none';

    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('class', 'topology__svg');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Network topology graph');

    // Edges under nodes
    const maxBytes = Math.max(1, ...(twin.edges || []).map(e => e.bytes || 0));
    for (const edge of twin.edges || []) {
      const a = pos.get(edge.source);
      const b = pos.get(edge.target);
      if (!a || !b) continue;
      const line = document.createElementNS(SVG_NS, 'line');
      line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
      line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
      const weight = 0.75 + 3.5 * Math.log1p(edge.bytes || 0) / Math.log1p(maxBytes);
      line.setAttribute('stroke-width', weight.toFixed(2));
      line.setAttribute('class', 'topology__edge');
      this._hover(line, () => this._edgeTooltip(edge));
      svg.appendChild(line);
    }

    for (const node of drawn) {
      const p = pos.get(node.id);
      if (!p) continue;
      const g = document.createElementNS(SVG_NS, 'g');
      g.setAttribute('class', `topology__node topology__node--${node.type}`);
      g.setAttribute('transform', `translate(${p.x},${p.y})`);

      const r = node.type === 'gateway' ? 22 : node.type === 'self' ? 18 :
                node.type === 'device' ? 14 : 9;
      const circle = document.createElementNS(SVG_NS, 'circle');
      circle.setAttribute('r', r);
      g.appendChild(circle);

      const label = document.createElementNS(SVG_NS, 'text');
      label.setAttribute('y', r + 14);
      label.setAttribute('text-anchor', 'middle');
      label.textContent = this._label(node);
      g.appendChild(label);

      this._hover(g, () => this._nodeTooltip(node));
      svg.appendChild(g);
    }

    if (hiddenExternal > 0) {
      const note = document.createElementNS(SVG_NS, 'text');
      note.setAttribute('x', W - 12);
      note.setAttribute('y', H - 12);
      note.setAttribute('text-anchor', 'end');
      note.setAttribute('class', 'topology__note');
      note.textContent = `+${hiddenExternal} more external endpoints`;
      svg.appendChild(note);
    }

    canvas.querySelector('svg')?.remove();
    canvas.appendChild(svg);
  }

  _label(node) {
    const raw = node.hostname || node.ip || node.mac || node.id;
    return raw.length > 18 ? raw.slice(0, 17) + '…' : raw;
  }

  /* ── Tooltip (textContent only) ─────────────────── */

  _hover(el, buildLines) {
    el.addEventListener('mousemove', (e) => {
      const t = this._tooltip;
      if (!t) return;
      t.replaceChildren(...buildLines().map(text => {
        const div = document.createElement('div');
        div.textContent = text;
        return div;
      }));
      t.style.display = 'block';
      t.style.left = `${e.clientX + 14}px`;
      t.style.top = `${e.clientY + 14}px`;
    });
    el.addEventListener('mouseleave', () => {
      if (this._tooltip) this._tooltip.style.display = 'none';
    });
  }

  _nodeTooltip(node) {
    const lines = [];
    lines.push(node.hostname ? `${node.hostname}` : (node.ip || node.mac));
    if (node.hostname && node.ip) lines.push(`IP: ${node.ip}`);
    if (node.mac) lines.push(`MAC: ${node.mac}`);
    if (node.vendor) lines.push(`Vendor: ${node.vendor}`);
    lines.push(`Type: ${node.type}`);
    lines.push(`In: ${formatBytes(node.bytes_in || 0)} · Out: ${formatBytes(node.bytes_out || 0)}`);
    if (node.protocols?.length) lines.push(`Protocols: ${node.protocols.join(', ')}`);
    if (node.recent_dns?.length) {
      lines.push(`Recent DNS: ${node.recent_dns.slice(-3).join(', ')}`);
    }
    if (node.last_seen) lines.push(`Last seen: ${formatRelativeTime(node.last_seen * 1000)}`);
    return lines;
  }

  _edgeTooltip(edge) {
    return [
      `${edge.source} → ${edge.target}`,
      `Bytes: ${formatBytes(edge.bytes || 0)} · Packets: ${edge.packets || 0}`,
      edge.protocols?.length ? `Protocols: ${edge.protocols.join(', ')}` : '',
    ].filter(Boolean);
  }
}
