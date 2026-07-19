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
const MAX_EXTERNAL_SHOWN = 14;
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
    this._showExternal = localStorage.getItem('netwatch-topo-external') !== 'off';
    this._twin = null;
    // Pan/zoom viewport + per-node drag offsets. Persisted to localStorage so
    // a graph the user arranged survives both the 10s refresh AND navigating
    // away and back (previously reset on remount).
    this._view = { tx: 0, ty: 0, scale: 1 };
    this._dragOffsets = new Map();
    this._dragging = false;
    this._loadLayout();
  }

  _loadLayout() {
    try {
      const raw = localStorage.getItem('netwatch-topo-layout');
      if (!raw) return;
      const saved = JSON.parse(raw);
      if (saved.view) this._view = saved.view;
      if (saved.offsets) this._dragOffsets = new Map(Object.entries(saved.offsets));
    } catch (_) { /* ignore corrupt layout */ }
  }

  _saveLayout() {
    try {
      localStorage.setItem('netwatch-topo-layout', JSON.stringify({
        view: this._view,
        offsets: Object.fromEntries(this._dragOffsets),
      }));
    } catch (_) { /* quota / disabled — non-fatal */ }
  }

  render() {
    this.el.innerHTML = `
      <div class="topology">
        <div class="topology__toolbar">
          <div class="topology__stats" id="topology-stats"></div>
          <div class="topology__legend">
            <span class="topology__legend-item" title="The machine running NetWatch"><span class="topo-dot topo-dot--self"></span>This host</span>
            <span class="topology__legend-item" title="The router — in hotspot mode this is also this host"><span class="topo-dot topo-dot--gateway"></span>Gateway</span>
            <span class="topology__legend-item" title="Clients seen on the local network right now"><span class="topo-dot topo-dot--device"></span>Device</span>
            <span class="topology__legend-item" title="Internet endpoints (servers/CDNs) your devices talked to — not devices on your network"><span class="topo-dot topo-dot--external"></span>External</span>
            <button type="button" class="btn btn--sm" id="topology-external-toggle"></button>
          </div>
        </div>
        <div class="topology__canvas card" id="topology-canvas">
          <div class="topology__empty" id="topology-empty">Building the network twin — waiting for traffic…</div>
        </div>
        <div class="topology__tooltip" id="topology-tooltip" style="display:none"></div>
      </div>
    `;
    this._tooltip = this.el.querySelector('#topology-tooltip');
    // Reparent the tooltip to <body>. It is position:fixed, but an ancestor
    // view keeps a CSS `transform` (the .view-enter mount animation), which
    // makes THAT element the containing block for fixed descendants — so the
    // tooltip anchored to the panel, not the viewport, and appeared far from
    // the cursor. On <body> it truly follows clientX/clientY.
    if (this._tooltip) document.body.appendChild(this._tooltip);
    const toggle = this.el.querySelector('#topology-external-toggle');
    this._syncToggle();
    toggle.addEventListener('click', () => {
      this._showExternal = !this._showExternal;
      localStorage.setItem('netwatch-topo-external', this._showExternal ? 'on' : 'off');
      this._syncToggle();
      if (this._twin) {
        this._renderStats(this._twin);
        this._renderGraph(this._twin);
      }
    });
    this._load();
    this._timer = setInterval(() => this._load(), REFRESH_MS);
  }

  _syncToggle() {
    const toggle = this.el.querySelector('#topology-external-toggle');
    if (toggle) {
      toggle.textContent = this._showExternal ? 'Hide external' : 'Show external';
    }
  }

  destroy() {
    this._destroyed = true;
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
    this._saveLayout();
    // The tooltip lives on <body> (reparented in render), so tear it down
    // explicitly — the view's own DOM removal won't reach it.
    if (this._tooltip) { this._tooltip.remove(); this._tooltip = null; }
  }

  async _load() {
    const resp = await api.getTwin();
    if (this._destroyed || !resp || resp.error) return;
    const twin = resp.data || resp;
    this._twin = twin;
    this._renderStats(twin);
    this._renderGraph(twin);
  }

  _renderStats(twin) {
    const el = this.el.querySelector('#topology-stats');
    if (!el) return;
    const s = twin.stats || {};
    const devices = s.device_count || 0;
    const ext = s.external_count || 0;
    el.textContent =
      `${devices} connected device${devices === 1 ? '' : 's'} · ` +
      `${ext} external endpoint${ext === 1 ? '' : 's'}` +
      (this._showExternal ? '' : ' (hidden)') +
      ` · mode: ${twin.mode || 'unknown'}`;
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
    const externals = this._showExternal
      ? bySide.external.slice(0, MAX_EXTERNAL_SHOWN)
      : [];

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

  /** Edges to draw: the twin's real edges, plus a "routes through" link for
   *  any client left with no visible connection.
   *
   *  A client's edges point at the internet endpoints it talked to, so hiding
   *  external nodes (the default) left clients floating unconnected — the map
   *  implied they weren't on the network. In hotspot every client's traffic
   *  genuinely does traverse this host, so linking them to it is accurate, not
   *  decorative. Drawn dashed to distinguish it from a measured flow. */
  _withRoutingEdges(twin, drawn) {
    const edges = [...(twin.edges || [])];
    const drawnIds = new Set(drawn.map(n => n.id));
    const host = drawn.find(n => n.type === 'self') ||
                 drawn.find(n => n.type === 'gateway');
    if (!host) return edges;

    const connected = new Set();
    for (const e of edges) {
      if (drawnIds.has(e.source) && drawnIds.has(e.target)) {
        connected.add(e.source); connected.add(e.target);
      }
    }
    for (const node of drawn) {
      if (node.type !== 'device' || connected.has(node.id)) continue;
      edges.push({
        source: node.id, target: host.id,
        bytes: (node.bytes_in || 0) + (node.bytes_out || 0),
        packets: 0, protocols: [], routed: true,
      });
    }
    return edges;
  }

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

    // Everything lives inside a viewport <g> we pan/zoom (Obsidian-style).
    const view = document.createElementNS(SVG_NS, 'g');
    view.setAttribute('class', 'topology__viewport');
    svg.appendChild(view);

    // Apply any persisted per-node drag offsets on top of the layout.
    const finalPos = (id) => {
      const base = pos.get(id);
      if (!base) return null;
      const off = this._dragOffsets.get(id);
      return off ? { x: base.x + off.dx, y: base.y + off.dy } : base;
    };

    // Edges under nodes — keep refs so dragging a node moves its lines.
    const edgeEls = [];
    const allEdges = this._withRoutingEdges(twin, drawn);
    const maxBytes = Math.max(1, ...allEdges.map(e => e.bytes || 0));
    for (const edge of allEdges) {
      const a = finalPos(edge.source);
      const b = finalPos(edge.target);
      if (!a || !b) continue;
      const line = document.createElementNS(SVG_NS, 'line');
      line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
      line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
      const weight = 0.75 + 3.5 * Math.log1p(edge.bytes || 0) / Math.log1p(maxBytes);
      line.setAttribute('stroke-width', weight.toFixed(2));
      line.setAttribute('class', 'topology__edge' +
        (edge.routed ? ' topology__edge--routed' : ''));
      if (edge.routed) line.setAttribute('stroke-dasharray', '4 4');
      this._hover(line, () => this._edgeTooltip(edge));
      view.appendChild(line);
      edgeEls.push({ el: line, source: edge.source, target: edge.target });
    }

    for (const node of drawn) {
      const p = finalPos(node.id);
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
      this._makeDraggable(g, node.id, pos, edgeEls, svg);
      view.appendChild(g);
    }

    if (hiddenExternal > 0 && this._showExternal) {
      const note = document.createElementNS(SVG_NS, 'text');
      note.setAttribute('x', W - 12);
      note.setAttribute('y', H - 12);
      note.setAttribute('text-anchor', 'end');
      note.setAttribute('class', 'topology__note');
      note.textContent = `+${hiddenExternal} more external endpoints`;
      view.appendChild(note);
    }

    this._applyView(view);
    this._bindPanZoom(svg, view);
    canvas.querySelector('svg')?.remove();
    canvas.appendChild(svg);
  }

  /* ── Pan / zoom / drag (Obsidian-style) ─────────── */

  _applyView(view) {
    const v = this._view;
    view.setAttribute('transform', `translate(${v.tx},${v.ty}) scale(${v.scale})`);
  }

  /** SVG user-units per screen pixel, for translating mouse deltas. */
  _unitsPerPixel(svg) {
    const rect = svg.getBoundingClientRect();
    return rect.width ? (W / rect.width) / this._view.scale : 1;
  }

  _bindPanZoom(svg, view) {
    // Pan by dragging empty space.
    svg.addEventListener('mousedown', (e) => {
      if (e.target.closest('.topology__node')) return;   // node drag handles itself
      const upp = this._unitsPerPixel(svg) * this._view.scale;
      const start = { x: e.clientX, y: e.clientY, tx: this._view.tx, ty: this._view.ty };
      const move = (ev) => {
        this._view.tx = start.tx + (ev.clientX - start.x) * upp;
        this._view.ty = start.ty + (ev.clientY - start.y) * upp;
        this._applyView(view);
      };
      const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); };
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    });
    // Zoom toward the cursor.
    svg.addEventListener('wheel', (e) => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1;
      const next = Math.min(4, Math.max(0.3, this._view.scale * factor));
      const rect = svg.getBoundingClientRect();
      const mx = (e.clientX - rect.left) * (W / rect.width);
      const my = (e.clientY - rect.top) * (H / rect.height);
      // keep the point under the cursor fixed
      this._view.tx = mx - (mx - this._view.tx) * (next / this._view.scale);
      this._view.ty = my - (my - this._view.ty) * (next / this._view.scale);
      this._view.scale = next;
      this._applyView(view);
    }, { passive: false });
  }

  _makeDraggable(g, nodeId, pos, edgeEls, svg) {
    g.style.cursor = 'grab';
    g.addEventListener('mousedown', (e) => {
      e.stopPropagation();       // don't start a pan
      this._dragging = true;
      if (this._tooltip) this._tooltip.style.display = 'none';
      const upp = this._unitsPerPixel(svg) * this._view.scale;
      const base = pos.get(nodeId) || { x: 0, y: 0 };
      const cur = this._dragOffsets.get(nodeId) || { dx: 0, dy: 0 };
      const start = { x: e.clientX, y: e.clientY, dx: cur.dx, dy: cur.dy };
      const move = (ev) => {
        const dx = start.dx + (ev.clientX - start.x) * upp;
        const dy = start.dy + (ev.clientY - start.y) * upp;
        this._dragOffsets.set(nodeId, { dx, dy });
        const nx = base.x + dx, ny = base.y + dy;
        g.setAttribute('transform', `translate(${nx},${ny})`);
        for (const { el, source, target } of edgeEls) {
          if (source === nodeId) { el.setAttribute('x1', nx); el.setAttribute('y1', ny); }
          if (target === nodeId) { el.setAttribute('x2', nx); el.setAttribute('y2', ny); }
        }
      };
      const up = () => {
        this._dragging = false;
        this._saveLayout();          // persist the arranged position
        document.removeEventListener('mousemove', move);
        document.removeEventListener('mouseup', up);
      };
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    });
  }

  _label(node) {
    const raw = node.hostname || node.ip || node.mac || node.id;
    return raw.length > 18 ? raw.slice(0, 17) + '…' : raw;
  }

  /* ── Tooltip (textContent only) ─────────────────── */

  _hover(el, buildLines) {
    el.addEventListener('mousemove', (e) => {
      const t = this._tooltip;
      if (!t || this._dragging) return;
      t.replaceChildren(...buildLines().map(text => {
        const div = document.createElement('div');
        div.textContent = text;
        return div;
      }));
      t.style.display = 'block';
      // Clamp to the viewport so the box never overflows off-screen: flip to
      // the other side of the cursor when it would spill past an edge.
      const r = t.getBoundingClientRect();
      const pad = 8;
      let left = e.clientX + 14;
      let top = e.clientY + 14;
      if (left + r.width > window.innerWidth - pad) left = e.clientX - r.width - 14;
      if (top + r.height > window.innerHeight - pad) top = e.clientY - r.height - 14;
      t.style.left = `${Math.max(pad, left)}px`;
      t.style.top = `${Math.max(pad, top)}px`;
    });
    el.addEventListener('mouseleave', () => {
      if (this._tooltip) this._tooltip.style.display = 'none';
    });
  }

  _nodeTooltip(node) {
    const lines = [];
    // Lead with a friendly name: hostname, or a role label for host/gateway.
    const roleName = node.type === 'self' ? 'This host'
      : node.type === 'gateway' ? 'Gateway (this host)' : null;
    const name = node.hostname || roleName || node.ip || node.mac;
    lines.push(name);
    if (name !== node.ip && node.ip) lines.push(`IP: ${node.ip}`);
    if (node.mac) lines.push(`MAC: ${node.mac}`);
    if (node.vendor) lines.push(`Vendor: ${node.vendor}`);
    const typeLabel = { self: 'This host', gateway: 'Gateway', device: 'Device',
                        external: 'Internet endpoint' }[node.type] || node.type;
    lines.push(`Type: ${typeLabel}`);
    lines.push(`In: ${formatBytes(node.bytes_in || 0)} · Out: ${formatBytes(node.bytes_out || 0)}`);
    if (node.protocols?.length) lines.push(`Protocols: ${node.protocols.join(', ')}`);
    if (node.recent_dns?.length) {
      lines.push(`Recent DNS: ${node.recent_dns.slice(-3).join(', ')}`);
    }
    if (node.last_seen) lines.push(`Last seen: ${formatRelativeTime(node.last_seen * 1000)}`);
    return lines;
  }

  _edgeTooltip(edge) {
    if (edge.routed) {
      return [
        'Routed through this host',
        'This client reaches the internet through this machine.',
        `Traffic: ${formatBytes(edge.bytes || 0)}`,
        'Turn on “Show external” to see the sites it connected to.',
      ];
    }
    return [
      `${edge.source} → ${edge.target}`,
      `Bytes: ${formatBytes(edge.bytes || 0)} · Packets: ${edge.packets || 0}`,
      edge.protocols?.length ? `Protocols: ${edge.protocols.join(', ')}` : '',
    ].filter(Boolean);
  }
}
