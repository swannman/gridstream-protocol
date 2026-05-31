#!/usr/bin/env python3
"""Render an *egocentric* GridStream mesh activity graph from a capture corpus.

This is deliberately not a god's-eye routing map. A capture comes from a single
receiver, so what we have is "every frame that one antenna could hear." Nodes
we sit close to (above all our own meter) are heard loudly and completely;
distant nodes are heard faintly or not at all. So node prominence here tracks
*proximity to the receiver*, not true network centrality — in this corpus the
busiest "hub" is the author's own residential meter, which is obviously not the
head-end. The tool surfaces that honestly rather than inventing a hierarchy.

What the graph shows:

  * node            = a meter LAN ID we heard transmit, OR one addressed as a
                      0xD5 destination by a frame we heard (most nodes are the
                      latter: we catch our own meter naming peers we never hear)
  * node size       = total frames heard involving it (how much we caught)
  * node colour     = distinct peers, sends+receives (a heat scale, NOT a role)
  * node shape      = LAN-ID prefix byte: circle = 0x90 (the endpoint-meter
                      pool, the only prefix ever heard transmitting); square =
                      0x80, triangle = 0x50, diamond = 0x40 — the upstream
                      collectors/aggregators meters report toward. The shape is
                      the prefix (an observed fact); the endpoint-vs-collector
                      reading is a working hypothesis (~), consistent with the
                      corpus but confounded by single-antenna capture (a distant
                      node is "never heard transmitting" either way). See the
                      in-page node-shape legend.
  * directed edge   = a 0xD5 frame we heard, src -> dst, width by count;
                      reciprocity is ~1% in real captures, so direction matters
  * edge colour     = the message kind, i.e. the CI byte of the directed frames
                      the edge carries — directed data (0x21/0x22/0x29), status
                      push (0x51/0x55), etc.; a mixed edge takes its modal CI.
                      See the in-page legend and the "by message kind" table.
  * receiver node   = highlighted (default 90000000, the author's meter; the
                      vantage point of the whole capture)

0x55 self-broadcasts (a meter bubbling up its own data to the broadcast address)
and 0xA5 beacons are one-to-many, so they are per-node tallies, not edges. 0xD2
frames use a one-byte short address (no full LAN ID) and are counted globally.

Two views over the same fixed layout:

  * Aggregate  — the all-time structure, edge width by total frames heard.
  * Timeline   — scrub/play through the capture in file order; edges glow as
                 they fire and fade. These logs carry no timestamps (only SNR),
                 so the axis is capture sequence, not wall-clock time.

If the corpus is a raw capture (lines still carry ``SNR:``), per-node median SNR
is shown as a proximity proxy. The published, anonymized corpus has SNR stripped.

Usage:
    python tools/mesh_topology.py [OUT.html] [CORPUS ...] [--me LANID] [--steps N]
    # defaults: OUT=visualizations/mesh_topology.html  CORPUS=capture/corpus.log
    #           me=90000000  steps=240
"""
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gridstream_parser import SYNC, header_len_for, lan_addrs  # noqa: E402

ANSI = re.compile(r"\x1b\[[0-9;]*m")
LINE = re.compile(r"\[CRC:\s?(OK|BAD)\]\s+([0-9A-Fa-f]+)")
SNR_RE = re.compile(r"SNR:\s*(-?\d+(?:\.\d+)?)")

FAMILY = {0x55: "0x55 self-broadcast", 0xA5: "0xA5 beacon",
          0xD5: "0xD5 directed", 0xD2: "0xD2 short-addr"}

# Edge colour = the CI byte (message kind) of the 0xD5 frames an edge carries.
# Colours are picked to stay distinct from the node heat ramp; the legend only
# renders kinds that actually occur, so it self-adapts to a different capture.
CI_KIND = {
    0x29: ("directed data (0x29)", "#58a6ff"),         # blue
    0x21: ("directed data (0x21)", "#3fb950"),         # green
    0x22: ("directed data (0x22)", "#e3b341"),         # amber
    0x51: ("status push (0x51)", "#f85149"),           # red
    0x55: ("status push · event (0x55)", "#db61a2"),   # pink
    0x52: ("encrypted (0x52)", "#bc8cff"),             # purple
    0x53: ("directed short (0x53)", "#ff9f1c"),        # orange
    0x81: ("bulk transfer (0x81)", "#39c5cf"),         # cyan
}
CI_KIND_OTHER = ("other CI", "#8b949e")                # gray

# Node shape = LAN-ID prefix byte. In the PSE corpus the prefix tracks device
# tier: 0x90 is the endpoint-meter pool (the only prefix ever heard
# transmitting), while 0x40/0x50/0x80 belong to the upstream collectors and
# aggregators meters report toward. The shape encodes the prefix (a fact); the
# tier reading is a working hypothesis (~), not validated — "never heard
# transmitting" is also what egocentric single-antenna capture does to distant
# nodes. Unknown prefixes are assigned the next free shape in build().
PREFIX_SHAPE = {"90": 0, "80": 1, "50": 2, "40": 3}
SHAPE_NAMES = ["circle", "square", "triangle", "diamond", "pentagon", "hexagon"]
PREFIX_ROLE = {
    "90": "endpoint meter",
    "80": "upstream — collector / aggregator",
    "50": "upstream — collector / aggregator",
    "40": "data collector",
}


def read_frames(paths):
    """Yield (type, src, dst, ci, length, snr) for each CRC-OK, sync-intact
    frame, in file order. src/dst are uppercase hex or None; ci is the CI byte
    (int) or None; snr is float or None."""
    for path in paths:
        with open(path, errors="replace") as fh:
            for raw in fh:
                clean = ANSI.sub("", raw)
                m = LINE.search(clean)
                if not m or m.group(1) != "OK":
                    continue
                try:
                    p = bytes.fromhex(m.group(2))
                except ValueError:
                    continue
                if len(p) < 6 or p[:3] != SYNC:
                    continue
                t = p[3]
                # Addresses are located structurally by the parser (by position,
                # length-driven), never by a prefix heuristic — so the 0x40
                # collector/gateway is read like any meter.
                ad = lan_addrs(p)
                src = ad["src"].hex().upper() if "src" in ad else None
                dst = ad["dst"].hex().upper() if "dst" in ad else None
                sm = SNR_RE.search(clean)
                hl = header_len_for(t)
                ci = p[hl] if hl < len(p) else None
                yield (t, src, dst, ci, len(p), float(sm.group(1)) if sm else None)


def build(frames, me, steps):
    edges = defaultdict(Counter)          # (src,dst) -> Counter(length)
    edge_ci = defaultdict(Counter)        # (src,dst) -> Counter(CI byte)
    tx = Counter(); rx = Counter()
    bcast = Counter(); beacon = Counter()
    out_peers = defaultdict(set); in_peers = defaultdict(set)
    snr = defaultdict(list)
    family = Counter(); d5_len = Counter()
    meters = set()      # every LAN ID seen, in any address field
    heard = set()       # LAN IDs we actually received a frame *from* (a source)
    d2 = 0
    seq = []                              # (type, src, dst) for the 0xD5 stream

    for t, s, d, ci, ln, sn in frames:
        family[t] += 1
        if s:
            meters.add(s); heard.add(s)
            if sn is not None:
                snr[s].append(sn)
        if t == 0xD5:
            d5_len[ln] += 1
            if d:
                meters.add(d)
            if s and d and s != d:
                edges[(s, d)][ln] += 1
                if ci is not None:
                    edge_ci[(s, d)][ci] += 1
                tx[s] += 1; rx[d] += 1
                out_peers[s].add(d); in_peers[d].add(s)
                seq.append((s, d))
        elif t == 0x55 and s:
            bcast[s] += 1
        elif t == 0xA5 and s:
            beacon[s] += 1
        elif t == 0xD2:
            d2 += 1

    # Graph nodes = anything that took part in a directed link.
    ids = sorted(set(out_peers) | set(in_peers))
    idx = {n: i for i, n in enumerate(ids)}
    deg = {n: len(out_peers.get(n, frozenset()) | in_peers.get(n, frozenset())) for n in ids}
    max_deg = max(deg.values()) if deg else 1

    # Shape-code nodes by LAN-ID prefix byte (see PREFIX_SHAPE). Known prefixes
    # keep their fixed shape; any extra prefix in this corpus takes the next
    # free shape so the graph still distinguishes it.
    shape_of = dict(PREFIX_SHAPE)
    nxt = max(shape_of.values(), default=-1) + 1
    for pf in sorted({n[:2] for n in ids}):
        if pf not in shape_of:
            shape_of[pf] = nxt
            nxt += 1

    nodes = []
    for n in ids:
        med = round(statistics.median(snr[n]), 1) if snr.get(n) else None
        nodes.append({
            "id": n, "f": tx[n] + rx[n] + bcast[n] + beacon[n],
            "tx": tx[n], "rx": rx[n], "bc": bcast[n], "bn": beacon[n],
            "out": len(out_peers.get(n, ())), "in": len(in_peers.get(n, ())),
            "deg": deg[n], "snr": med, "pfx": n[:2], "sh": shape_of[n[:2]],
        })

    # Edge list (stable order = by count desc), with an index for the timeline.
    pairs = sorted(edges, key=lambda k: sum(edges[k].values()), reverse=True)
    eidx = {p: i for i, p in enumerate(pairs)}

    # Classify each directed edge by the modal CI byte of the frames it carries
    # (its on-wire "message kind"). Only kinds actually present become legend
    # entries, ordered by frame volume, so the colour key self-adapts to a
    # different capture. CI bytes outside CI_KIND collapse to a single "other".
    modal_ci = {pr: edge_ci[pr].most_common(1)[0][0] for pr in pairs if edge_ci[pr]}

    def _kkey(b):
        return b if b in CI_KIND else -1

    def _klc(kk):
        return CI_KIND[kk] if kk in CI_KIND else CI_KIND_OTHER

    kind_edges, kind_frames = Counter(), Counter()
    for pr in pairs:
        kk = _kkey(modal_ci.get(pr))
        kind_edges[kk] += 1
        kind_frames[kk] += sum(edge_ci[pr].values())
    kk_order = [kk for kk, _ in kind_frames.most_common()]
    kk_to_i = {kk: i for i, kk in enumerate(kk_order)}
    kinds = [{"k": i, "ci": (f"0x{kk:02X}" if kk != -1 else "—"),
              "label": _klc(kk)[0], "color": _klc(kk)[1],
              "edges": kind_edges[kk], "frames": kind_frames[kk]}
             for i, kk in enumerate(kk_order)]

    elist = [{"s": idx[s], "t": idx[d], "n": sum(edges[(s, d)].values()),
              "k": kk_to_i[_kkey(modal_ci.get((s, d)))],
              "ci": (f"0x{modal_ci[(s, d)]:02X}" if (s, d) in modal_ci else "—"),
              "len": {str(k): v for k, v in sorted(edges[(s, d)].items())}}
             for (s, d) in pairs]

    # Timeline: bucket the 0xD5 stream (file order) into `steps` and record,
    # per step, the edges that fired and how many times. No timestamps exist in
    # the logs, so this is capture sequence, not wall-clock time.
    total = max(1, len(seq))
    tl = [defaultdict(int) for _ in range(steps)]
    for i, (s, d) in enumerate(seq):
        st = min(steps - 1, i * steps // total)
        tl[st][eidx[(s, d)]] += 1
    tl = [[[ei, c] for ei, c in step.items()] for step in tl]

    top_links = [{"s": s, "t": d, "n": sum(edges[(s, d)].values()),
                  "len": max(edges[(s, d)], key=edges[(s, d)].get),
                  "ci": (f"0x{modal_ci[(s, d)]:02X}" if (s, d) in modal_ci else "—"),
                  "kind": _klc(_kkey(modal_ci.get((s, d))))[0],
                  "color": _klc(_kkey(modal_ci.get((s, d))))[1]}
                 for (s, d) in pairs[:30]]
    most_heard = sorted(nodes, key=lambda x: x["f"], reverse=True)[:20]
    broadcasters = [{"id": n, "n": c} for n, c in bcast.most_common(15)]
    families = [{"name": FAMILY.get(t, hex(t)), "n": c}
                for t, c in sorted(family.items(), key=lambda kv: -kv[1])]
    d5len = [{"len": k, "n": v}
             for k, v in sorted(d5_len.items(), key=lambda kv: -kv[1])]

    # Node-shape legend: one entry per LAN-ID prefix present, biggest pool first
    # (so 0x90 leads). `tx` = how many of that prefix's nodes we heard transmit —
    # the evidence behind the endpoint/collector reading.
    pfx_count = Counter(n["pfx"] for n in nodes)
    pfx_tx = Counter(n["pfx"] for n in nodes if n["tx"] > 0)
    prefixes = [{"pfx": "0x" + pf, "sh": shape_of[pf],
                 "shape": SHAPE_NAMES[shape_of[pf]] if shape_of[pf] < len(SHAPE_NAMES) else "circle",
                 "role": PREFIX_ROLE.get(pf, "unknown role"),
                 "n": pfx_count[pf], "tx": pfx_tx[pf]}
                for pf in sorted(pfx_count, key=lambda p: (-pfx_count[p], p))]

    stats = {
        "ok": sum(family.values()), "meters": len(meters),
        "heard": len(heard), "addressed": len(meters - heard),
        "nodes": len(nodes), "edges": len(elist), "max_deg": max_deg,
        "unicast": sum(tx.values()), "broadcast": sum(bcast.values()),
        "beacon": sum(beacon.values()), "d2": d2,
        "recip": sum(1 for (a, b) in edges if (b, a) in edges),
        "steps": steps, "me": me, "hasSNR": any(n["snr"] is not None for n in nodes),
        "d5frames": total,
    }
    return {"nodes": nodes, "edges": elist, "tl": tl, "stats": stats,
            "topLinks": top_links, "mostHeard": most_heard, "kinds": kinds,
            "prefixes": prefixes,
            "broadcasters": broadcasters, "families": families, "d5len": d5len}


HEAD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GridStream mesh — egocentric activity graph</title>
<style>
  :root{color-scheme:dark;}
  *{box-sizing:border-box;}
  body{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;}
  header{padding:10px 16px;border-bottom:1px solid #21262d;}
  header h1{margin:0;font-size:16px;}
  header .sub{color:#8b949e;font-size:12px;margin-top:2px;}
  .bias{background:#2d2410;border:1px solid #6b5618;color:#e8d9a8;padding:8px 16px;font-size:12px;}
  .bias b{color:#ffd54f;}
  .toolbar{display:flex;gap:14px;align-items:center;padding:8px 16px;border-bottom:1px solid #21262d;flex-wrap:wrap;font-size:12px;}
  .toolbar button{background:#21262d;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:5px 12px;cursor:pointer;font-size:12px;}
  .toolbar button.on{background:#1f6feb;border-color:#1f6feb;}
  .toolbar input[type=range]{vertical-align:middle;}
  .toolbar .grp{display:flex;gap:6px;align-items:center;}
  .toolbar .muted{color:#8b949e;}
  #wrap{display:flex;height:62vh;min-height:440px;}
  #g{flex:1;display:block;background:#0d1117;cursor:grab;}
  #g:active{cursor:grabbing;}
  #side{width:300px;border-left:1px solid #21262d;padding:12px 14px;overflow:auto;}
  #side h2{font-size:13px;margin:14px 0 6px;color:#ffd54f;}
  #side h2:first-child{margin-top:0;}
  #side .muted{color:#8b949e;}
  .peer{font-family:monospace;font-size:12px;cursor:pointer;color:#79c0ff;}
  .peer:hover{text-decoration:underline;}
  #tip{position:fixed;pointer-events:none;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:6px 8px;font:12px monospace;display:none;z-index:9;white-space:pre;}
  .tables{padding:14px 16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:20px;}
  .tables h2{font-size:13px;color:#ffd54f;margin:0 0 6px;}
  table{border-collapse:collapse;width:100%;font-size:12px;}
  th,td{text-align:left;padding:3px 8px;border-bottom:1px solid #21262d;}
  th{color:#8b949e;font-weight:600;}
  .mono{font-family:monospace;}
  .num{text-align:right;font-variant-numeric:tabular-nums;}
  .legend{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
  .ramp{height:10px;width:120px;border-radius:3px;background:linear-gradient(90deg,#2c3e8c,#1f9d8a,#9bd64a,#f6d743,#f5732e);}
  .ksw{display:inline-flex;align-items:center;gap:4px;color:#8b949e;}
  .ksw i,.kd{display:inline-block;width:9px;height:9px;border-radius:2px;}
  .kd{margin-right:5px;vertical-align:middle;}
</style></head><body>
<header>
  <h1>GridStream mesh &mdash; egocentric activity graph</h1>
  <div class="sub" id="meta"></div>
</header>
<div class="bias" id="bias"></div>
<div class="toolbar">
  <div class="grp"><b>View</b>
    <button id="bAgg" class="on">Aggregate</button>
    <button id="bTl">Timeline</button>
  </div>
  <div class="grp" id="aggCtl"><span class="muted">min edge weight</span>
    <input type="range" id="minw" min="1" max="50" value="1">
    <span id="minwv" class="muted">1</span>
  </div>
  <div class="grp" id="tlCtl" style="display:none">
    <button id="play">&#9654; Play</button>
    <input type="range" id="scrub" min="0" value="0" style="width:240px">
    <span id="scrubv" class="muted"></span>
    <span class="muted">speed</span>
    <input type="range" id="speed" min="1" max="20" value="6">
  </div>
  <div class="grp legend"><span class="muted">node: fewer peers</span><span class="ramp"></span><span class="muted">more</span></div>
  <div class="grp legend" id="kindLegend"></div>
  <div class="grp legend" id="shapeLegend"></div>
</div>
<div id="wrap">
  <canvas id="g"></canvas>
  <div id="side"></div>
</div>
<div id="tip"></div>
<div class="tables" id="tables"></div>
<script>
const DATA = """

JS = r""";
const cv = document.getElementById('g'), ctx = cv.getContext('2d');
const tip = document.getElementById('tip'), side = document.getElementById('side');
const S = DATA.stats;

const nodes = DATA.nodes.map(d => Object.assign({}, d));
const byId = {}; nodes.forEach(n => byId[n.id] = n);
const byIdx = nodes;                 // edges reference node array index
const edges = DATA.edges.map((e, i) => ({s: byIdx[e.s], t: byIdx[e.t], n: e.n, len: e.len, k: e.k, ci: e.ci, idx: i}));
const meNode = byId[S.me] || null;
const collectorNodes = nodes.filter(n => n.pfx === '40');   // 0x40 = utility data collector

const maxF = Math.max(1, ...nodes.map(n => n.f));
const maxEdge = Math.max(1, ...edges.map(e => e.n));
nodes.forEach(n => n.r = 3 + 15 * Math.sqrt(n.f / maxF));

// edge colour = message kind (CI byte); legend is data-driven from DATA.kinds
const KINDS = DATA.kinds || [];
const kindColor = KINDS.map(k => k.color);
function eColor(e){ return kindColor[e.k] || '#8b949e'; }

// node shape = LAN-ID prefix; legend + role map are data-driven from DATA.prefixes
const PREFIXES = DATA.prefixes || [];
const SHAPE_GLYPH = ['●', '■', '▲', '◆', '⬟', '⬢']; // circle square triangle diamond pentagon hexagon
const ROLE_BY_PFX = {}; PREFIXES.forEach(p => ROLE_BY_PFX[p.pfx.slice(2)] = p.role);
function hexA(h, a){ const n = parseInt(h.slice(1), 16); return 'rgba(' + ((n>>16)&255) + ',' + ((n>>8)&255) + ',' + (n&255) + ',' + a + ')'; }
function kindDot(k){ return '<i class="kd" style="background:' + (kindColor[k] || '#8b949e') + '"></i>'; }

// colour heat by distinct peers (NOT a role) -------------------------------
const STOPS = [[44,62,140],[31,157,138],[155,214,74],[246,215,67],[245,115,46]];
function heat(t){
  t = Math.max(0, Math.min(1, t)); const x = t * (STOPS.length - 1);
  const i = Math.min(STOPS.length - 2, Math.floor(x)), f = x - i;
  const a = STOPS[i], b = STOPS[i + 1];
  return 'rgb(' + Math.round(a[0]+(b[0]-a[0])*f) + ',' + Math.round(a[1]+(b[1]-a[1])*f) + ',' + Math.round(a[2]+(b[2]-a[2])*f) + ')';
}
nodes.forEach(n => n.col = heat(Math.sqrt(n.deg / S.max_deg)));

// ---- layout (force, settled once, then frozen) ---------------------------
let view = {x: 0, y: 0, k: 1};
function resize(){ cv.width = cv.clientWidth; cv.height = cv.clientHeight; }
window.addEventListener('resize', () => { resize(); needDraw = true; });
resize();
const R0 = Math.min(cv.width, cv.height) * 0.42;
nodes.forEach((n, i) => {
  const a = 2 * Math.PI * i / nodes.length;
  n.x = cv.width / 2 + Math.cos(a) * R0; n.y = cv.height / 2 + Math.sin(a) * R0;
  n.vx = 0; n.vy = 0;
});
const K = 140;
function tick(){
  for (let i = 0; i < nodes.length; i++){
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++){
      const b = nodes[j];
      let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy + 0.01;
      let d = Math.sqrt(d2), f = (K * K) / d2 * 0.5;
      a.vx += f * dx / d; a.vy += f * dy / d; b.vx -= f * dx / d; b.vy -= f * dy / d;
    }
  }
  edges.forEach(e => {
    let dx = e.t.x - e.s.x, dy = e.t.y - e.s.y, d = Math.sqrt(dx * dx + dy * dy) + 0.01;
    let f = (d - K) / d * 0.03 * (1 + Math.log(1 + e.n) * 0.06);
    e.s.vx += f * dx; e.s.vy += f * dy; e.t.vx -= f * dx; e.t.vy -= f * dy;
  });
  const cx = cv.width / 2, cy = cv.height / 2;
  nodes.forEach(n => {
    if (n === dragNode) return;
    n.vx += (cx - n.x) * 0.003; n.vy += (cy - n.y) * 0.003;
    n.vx *= 0.85; n.vy *= 0.85;
    n.x += Math.max(-40, Math.min(40, n.vx)); n.y += Math.max(-40, Math.min(40, n.vy));
  });
}

// ---- state ---------------------------------------------------------------
let mode = 'agg', sel = null, focus = new Set();
let dragNode = null, panning = false, moved = false, last = null;
let minW = 1, needDraw = true, simLeft = 220;
const glow = new Float32Array(edges.length);
let step = 0, playing = false, speed = 6, frameCt = 0;

function setFocus(n){
  sel = n; focus = new Set();
  if (n){ focus.add(n.idx === undefined ? null : n); edges.forEach(e => { if (e.s === n) focus.add(e.t); if (e.t === n) focus.add(e.s); }); }
  renderSide(); needDraw = true;
}

// ---- drawing -------------------------------------------------------------
function arrow(a, b, w){
  let dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 1;
  let ux = dx / d, uy = dy / d, px = -uy, py = ux, off = 3 / view.k;
  let sx = a.x + ux * a.r + px * off, sy = a.y + uy * a.r + py * off;
  let ex = b.x - ux * (b.r + 3.5 / view.k) + px * off, ey = b.y - uy * (b.r + 3.5 / view.k) + py * off;
  ctx.lineWidth = w; ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(ex, ey); ctx.stroke();
  let ah = Math.min(9, 4 + w * 2) / view.k;
  ctx.beginPath(); ctx.moveTo(ex, ey);
  ctx.lineTo(ex - ux * ah - px * ah * 0.5, ey - uy * ah - py * ah * 0.5);
  ctx.lineTo(ex - ux * ah + px * ah * 0.5, ey - uy * ah + py * ah * 0.5);
  ctx.closePath(); ctx.fillStyle = ctx.strokeStyle; ctx.fill();
}
// node outline by LAN-ID prefix (n.sh); sizes tuned for ~equal visual footprint
function shapePath(n){
  const x = n.x, y = n.y, r = n.r;
  ctx.beginPath();
  switch (n.sh){
    case 1: { const a = r * 0.9; ctx.rect(x - a, y - a, 2 * a, 2 * a); break; }      // square (0x80)
    case 2: { const h = r * 1.2;                                                     // triangle (0x50)
      ctx.moveTo(x, y - h); ctx.lineTo(x + h * 0.87, y + h * 0.55); ctx.lineTo(x - h * 0.87, y + h * 0.55); ctx.closePath(); break; }
    case 3: { const a = r * 1.25;                                                    // diamond (0x40)
      ctx.moveTo(x, y - a); ctx.lineTo(x + a, y); ctx.lineTo(x, y + a); ctx.lineTo(x - a, y); ctx.closePath(); break; }
    case 4: case 5: {                                                                // pentagon / hexagon
      const sides = n.sh === 4 ? 5 : 6, rr = r * 1.12;
      for (let i = 0; i < sides; i++){ const a = -Math.PI / 2 + i * 2 * Math.PI / sides, px = x + Math.cos(a) * rr, py = y + Math.sin(a) * rr; if (i) ctx.lineTo(px, py); else ctx.moveTo(px, py); }
      ctx.closePath(); break; }
    default: ctx.arc(x, y, r, 0, 7);                                                 // circle (0x90 + fallback)
  }
}
function draw(){
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.fillStyle = '#0d1117'; ctx.fillRect(0, 0, cv.width, cv.height);
  ctx.setTransform(view.k, 0, 0, view.k, view.x, view.y);

  if (mode === 'tl'){
    edges.forEach(e => {                 // faint base structure
      ctx.strokeStyle = 'rgba(120,140,170,0.05)';
      ctx.lineWidth = 0.5 / view.k;
      ctx.beginPath(); ctx.moveTo(e.s.x, e.s.y); ctx.lineTo(e.t.x, e.t.y); ctx.stroke();
    });
    let mg = 0.001; for (let i = 0; i < glow.length; i++) if (glow[i] > mg) mg = glow[i];
    edges.forEach(e => {
      const g = glow[e.idx]; if (g <= 0.02) return;
      const a = Math.min(1, g / mg);
      ctx.strokeStyle = hexA(eColor(e), 0.15 + 0.85 * a);   // glow tinted by message kind
      arrow(e.s, e.t, (0.6 + 3 * a) / view.k);
    });
  } else {
    edges.forEach(e => {
      if (e.n < minW && !(sel && (e.s === sel || e.t === sel))) return;
      const hl = sel && (e.s === sel || e.t === sel);
      ctx.strokeStyle = (sel && !hl) ? 'rgba(120,140,170,0.05)' : hexA(eColor(e), hl ? 0.95 : 0.5);
      arrow(e.s, e.t, (0.4 + 3 * Math.sqrt(e.n / maxEdge)) / view.k);
    });
  }

  nodes.forEach(n => {
    const dim = sel && sel !== n && !focus.has(n);
    ctx.globalAlpha = dim ? 0.22 : 1;
    shapePath(n);
    ctx.fillStyle = n.col; ctx.fill();
    if (n === meNode){ ctx.lineWidth = 2.5 / view.k; ctx.strokeStyle = '#fff'; ctx.stroke(); }
    else if (n === sel){ ctx.lineWidth = 2 / view.k; ctx.strokeStyle = '#fff'; ctx.stroke(); }
    if (n === meNode || n === sel || n.r > 9 || (sel && focus.has(n))){
      ctx.fillStyle = '#e6edf3'; ctx.font = (11 / view.k) + 'px monospace';
      ctx.fillText(n.id + (n === meNode ? '  (receiver)' : ''), n.x + n.r + 2 / view.k, n.y + 4 / view.k);
    }
    ctx.globalAlpha = 1;
  });
}
function loop(){
  if (simLeft > 0){ tick(); simLeft--; needDraw = true; }
  if (playing){ advance(); }
  if (needDraw){ draw(); needDraw = false; }
  requestAnimationFrame(loop);
}
for (let i = 0; i < 120; i++) tick();   // pre-settle
loop();

// ---- timeline ------------------------------------------------------------
function recomputeGlow(toStep){
  glow.fill(0); const W = 16;
  for (let s = Math.max(0, toStep - W + 1); s <= toStep; s++){
    const dk = Math.pow(0.8, toStep - s), ev = DATA.tl[s] || [];
    for (let i = 0; i < ev.length; i++) glow[ev[i][0]] += ev[i][1] * dk;
  }
}
function setStep(s){
  step = Math.max(0, Math.min(S.steps - 1, s));
  recomputeGlow(step);
  scrub.value = step;
  scrubv.textContent = 'step ' + (step + 1) + ' / ' + S.steps + '  ·  ' +
    ((DATA.tl[step] || []).length) + ' links firing';
  needDraw = true;
}
function advance(){
  frameCt++; if (frameCt % Math.max(1, 21 - speed) !== 0) return;
  if (step >= S.steps - 1){ setStep(0); }
  else {
    step++;
    for (let i = 0; i < glow.length; i++) glow[i] *= 0.8;
    const ev = DATA.tl[step] || [];
    for (let i = 0; i < ev.length; i++) glow[ev[i][0]] += ev[i][1];
    scrub.value = step;
    scrubv.textContent = 'step ' + (step + 1) + ' / ' + S.steps + '  ·  ' + ev.length + ' links firing';
  }
  needDraw = true;
}

// ---- side panel ----------------------------------------------------------
function fmt(x){ return x.toLocaleString(); }
function peerSpan(id){ return '<span class="peer" data-id="' + id + '">' + id + '</span>'; }
function renderSide(){
  if (!sel){
    side.innerHTML = '<h2>Node detail</h2><div class="muted">Click any meter. ' +
      (meNode ? 'The white-ringed node ' + peerSpan(S.me) + ' is the receiver (this capture’s vantage point). ' : '') +
      collectorNodes.map(c => 'The ' + (SHAPE_GLYPH[c.sh] || '◆') + ' ' + peerSpan(c.id) +
        ' is the utility data collector the meters report to (~).').join(' ') + '</div>';
    bindPeers(side); return;
  }
  const n = sel;
  const out = edges.filter(e => e.s === n).sort((a, b) => b.n - a.n);
  const inc = edges.filter(e => e.t === n).sort((a, b) => b.n - a.n);
  let h = '<h2>' + n.id + (n === meNode ? ' (receiver)' : '') + '</h2>';
  h += '<div class="muted">0x' + n.pfx + ' · ' + (ROLE_BY_PFX[n.pfx] || 'unknown role') + ' (~) · ' + n.deg + ' distinct peers</div>';
  h += '<table>' +
    '<tr><th>frames heard</th><td class="num">' + fmt(n.f) + '</td></tr>' +
    '<tr><th>0xD5 tx →</th><td class="num">' + fmt(n.tx) + '</td></tr>' +
    '<tr><th>0xD5 rx ←</th><td class="num">' + fmt(n.rx) + '</td></tr>' +
    '<tr><th>0x55 self-bcast</th><td class="num">' + fmt(n.bc) + '</td></tr>' +
    '<tr><th>0xA5 beacon</th><td class="num">' + fmt(n.bn) + '</td></tr>' +
    (n.snr != null ? '<tr><th>median SNR</th><td class="num">' + n.snr + ' dB</td></tr>' : '') +
    '</table>';
  h += '<h2>Sends to (' + n.out + ')</h2>' + peerRows(out, e => e.t);
  h += '<h2>Receives from (' + n.in + ')</h2>' + peerRows(inc, e => e.s);
  side.innerHTML = h; bindPeers(side);
}
function peerRows(es, pick){
  if (!es.length) return '<div class="muted">none heard</div>';
  return '<table>' + es.slice(0, 12).map(e => '<tr><td class="mono">' + kindDot(e.k) + peerSpan(pick(e).id) +
    '</td><td class="num">' + fmt(e.n) + '</td></tr>').join('') +
    (es.length > 12 ? '<tr><td class="muted" colspan=2>+' + (es.length - 12) + ' more</td></tr>' : '') + '</table>';
}
function bindPeers(root){
  root.querySelectorAll('.peer[data-id]').forEach(el =>
    el.addEventListener('click', () => { const t = byId[el.dataset.id]; if (t){ setFocus(t); window.scrollTo({top: 0, behavior: 'smooth'}); } }));
}

// ---- interaction ---------------------------------------------------------
function world(ev){ const r = cv.getBoundingClientRect(); const mx = ev.clientX - r.left, my = ev.clientY - r.top; return {x: (mx - view.x) / view.k, y: (my - view.y) / view.k}; }
function nodeAt(wx, wy){ let best = null, bd = 1e9; for (const n of nodes){ let d = Math.hypot(n.x - wx, n.y - wy); if (d <= n.r + 5 / view.k && d < bd){ bd = d; best = n; } } return best; }
cv.addEventListener('mousedown', ev => { const w = world(ev); moved = false; const n = nodeAt(w.x, w.y); if (n) dragNode = n; else panning = true; last = {x: ev.clientX, y: ev.clientY}; });
window.addEventListener('mousemove', ev => {
  if (dragNode){ const w = world(ev); dragNode.x = w.x; dragNode.y = w.y; dragNode.vx = dragNode.vy = 0; moved = true; needDraw = true; return; }
  if (panning){ view.x += ev.clientX - last.x; view.y += ev.clientY - last.y; last = {x: ev.clientX, y: ev.clientY}; moved = true; needDraw = true; return; }
  const w = world(ev), n = nodeAt(w.x, w.y);
  if (n){ tip.style.display = 'block'; tip.style.left = (ev.clientX + 12) + 'px'; tip.style.top = (ev.clientY + 12) + 'px';
    tip.textContent = n.id + (n === meNode ? ' (receiver)' : '') + '\n' + fmt(n.f) + ' frames · ' + n.deg + ' peers' + (n.snr != null ? ' · ' + n.snr + ' dB' : '') +
      '\n0x' + n.pfx + ' · ' + (ROLE_BY_PFX[n.pfx] || 'unknown role') + ' (~)';
    cv.style.cursor = 'pointer';
  } else { tip.style.display = 'none'; cv.style.cursor = ''; }
});
window.addEventListener('mouseup', () => { if (dragNode && !moved) setFocus(dragNode); else if (panning && !moved) setFocus(null); dragNode = null; panning = false; });
cv.addEventListener('wheel', ev => { ev.preventDefault(); const r = cv.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top; const f = ev.deltaY < 0 ? 1.12 : 1 / 1.12; view.x = mx - (mx - view.x) * f; view.y = my - (my - view.y) * f; view.k *= f; needDraw = true; }, {passive: false});

// ---- controls ------------------------------------------------------------
const bAgg = document.getElementById('bAgg'), bTl = document.getElementById('bTl');
const aggCtl = document.getElementById('aggCtl'), tlCtl = document.getElementById('tlCtl');
const minw = document.getElementById('minw'), minwv = document.getElementById('minwv');
const scrub = document.getElementById('scrub'), scrubv = document.getElementById('scrubv');
const play = document.getElementById('play'), speedEl = document.getElementById('speed');
scrub.max = S.steps - 1; minw.max = Math.min(50, maxEdge);
function setMode(m){
  mode = m; playing = false; play.innerHTML = '&#9654; Play';
  bAgg.classList.toggle('on', m === 'agg'); bTl.classList.toggle('on', m === 'tl');
  aggCtl.style.display = m === 'agg' ? '' : 'none';
  tlCtl.style.display = m === 'tl' ? '' : 'none';
  if (m === 'tl') setStep(step);
  needDraw = true;
}
bAgg.onclick = () => setMode('agg'); bTl.onclick = () => setMode('tl');
minw.oninput = () => { minW = +minw.value; minwv.textContent = minW; needDraw = true; };
scrub.oninput = () => { playing = false; play.innerHTML = '&#9654; Play'; setStep(+scrub.value); };
speedEl.oninput = () => { speed = +speedEl.value; };
play.onclick = () => { playing = !playing; play.innerHTML = playing ? '&#10073;&#10073; Pause' : '&#9654; Play'; };

// ---- static panels -------------------------------------------------------
document.getElementById('meta').textContent =
  fmt(S.ok) + ' CRC-OK frames · ' + S.heard + ' heard transmitting · ' +
  S.nodes + ' nodes (' + S.addressed + ' addressed-only) · ' +
  fmt(S.edges) + ' directed links · ' + (100 * S.recip / Math.max(1, S.edges)).toFixed(1) + '% reciprocal';
document.getElementById('bias').innerHTML =
  '<b>Egocentric capture.</b> One receiver hears nearby meters loudly and distant ones faintly, so size & colour track ' +
  '<b>proximity to the antenna, not network role</b>. Here the loudest node is ' +
  (meNode ? '<span class="peer" data-id="' + S.me + '">' + S.me + '</span>, the author’s own meter (the receiver site)' : 'the receiver site') +
  ' &mdash; proof this is not a routing map. Edges are 0xD5 frames we heard (src→dst); only ' +
  (100 * S.recip / Math.max(1, S.edges)).toFixed(1) + '% are reciprocal. ' +
  'We directly heard just <b>' + S.heard + '</b> meters transmit; the other <b>' + S.addressed +
  '</b> nodes appear only as destinations addressed by frames we received, so absence of an inbound edge means out of earshot, not out of network. ' +
  'Timeline = capture/file order (' + fmt(S.d5frames) + ' directed frames); these logs have no timestamps, so it is sequence, not time.' +
  (S.hasSNR ? ' SNR present — per-node median shown as a proximity proxy.' : '');

// edge-colour legend: message kind -> colour, data-driven so it matches this corpus
const klEl = document.getElementById('kindLegend');
if (KINDS.length){
  klEl.innerHTML = '<span class="muted">edge / message kind:</span>' + KINDS.map(k =>
    '<span class="ksw" title="' + fmt(k.frames) + ' frames over ' + fmt(k.edges) + ' links">' +
    '<i style="background:' + k.color + '"></i>' + k.label + '</span>').join('');
}

// node-shape legend: glyph -> LAN-ID prefix -> inferred role (data-driven)
const slEl = document.getElementById('shapeLegend');
if (PREFIXES.length){
  slEl.innerHTML = '<span class="muted">node shape / prefix (~role):</span>' + PREFIXES.map(p =>
    '<span class="ksw" title="' + fmt(p.n) + ' nodes · ' + fmt(p.tx) + ' heard transmitting">' +
    '<b style="color:#e6edf3;font-size:13px;line-height:1">' + (SHAPE_GLYPH[p.sh] || '●') + '</b> ' +
    p.pfx + ' ' + p.role + '</span>').join('');
}

function table(cols, rows){
  let h = '<table><tr>' + cols.map(c => '<th class="' + (c.num ? 'num' : '') + '">' + c.label + '</th>').join('') + '</tr>';
  h += rows.map(r => '<tr>' + cols.map(c => '<td class="' + (c.mono ? 'mono ' : '') + (c.num ? 'num' : '') + '">' + c.get(r) + '</td>').join('') + '</tr>').join('');
  return h + '</table>';
}
let T = '';
T += '<div><h2>Most-heard meters</h2>' + table([
  {label: 'meter', mono: 1, get: r => peerSpan(r.id) + (r.id === S.me ? ' ◉' : '')},
  {label: 'frames', num: 1, get: r => fmt(r.f)},
  {label: 'peers', num: 1, get: r => r.deg},
  {label: 'tx', num: 1, get: r => fmt(r.tx)},
  {label: 'rx', num: 1, get: r => fmt(r.rx)},
], DATA.mostHeard) + '</div>';
T += '<div><h2>Busiest links (src → dst, as heard)</h2>' + table([
  {label: 'from', mono: 1, get: r => peerSpan(r.s)},
  {label: 'to', mono: 1, get: r => peerSpan(r.t)},
  {label: 'frames', num: 1, get: r => fmt(r.n)},
  {label: 'kind', get: r => '<i class="kd" style="background:' + r.color + '"></i>' + r.kind},
  {label: 'len', num: 1, get: r => r.len},
], DATA.topLinks) + '</div>';
T += '<div><h2>Directed links by message kind (CI)</h2>' + table([
  {label: 'message kind', get: r => '<i class="kd" style="background:' + r.color + '"></i>' + r.label},
  {label: 'CI', mono: 1, get: r => r.ci},
  {label: 'links', num: 1, get: r => fmt(r.edges)},
  {label: 'frames', num: 1, get: r => fmt(r.frames)},
], DATA.kinds) + '</div>';
T += '<div><h2>Frames by family</h2>' + table([
  {label: 'family', get: r => r.name}, {label: 'frames', num: 1, get: r => fmt(r.n)},
], DATA.families);
T += '<h2>Top self-broadcasters (0x55 bubble-up)</h2>' + table([
  {label: 'meter', mono: 1, get: r => peerSpan(r.id)}, {label: 'frames', num: 1, get: r => fmt(r.n)},
], DATA.broadcasters) + '</div>';
T += '<div><h2>0xD5 directed by length</h2>' + table([
  {label: 'bytes', num: 1, get: r => r.len}, {label: 'frames', num: 1, get: r => fmt(r.n)},
], DATA.d5len) + '</div>';
const tablesEl = document.getElementById('tables');
tablesEl.innerHTML = T; bindPeers(tablesEl);

if (meNode) setFocus(meNode); else renderSide();
</script></body></html>
"""


def main(argv):
    args, out, me, steps, corpus = argv[1:], None, "90000000", 240, []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--me" and i + 1 < len(args):
            me = args[i + 1].upper(); i += 2
        elif a == "--steps" and i + 1 < len(args):
            steps = max(1, int(args[i + 1])); i += 2
        elif a.endswith((".html", ".htm")) and out is None:
            out = a; i += 1
        else:
            corpus.append(a); i += 1
    out = out or "visualizations/mesh_topology.html"
    corpus = corpus or ["capture/corpus.log"]
    missing = [p for p in corpus if not os.path.exists(p)]
    if missing:
        print(f"corpus not found: {', '.join(missing)}", file=sys.stderr)
        return 1

    data = build(read_frames(corpus), me, steps)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as fh:
        fh.write(HEAD + json.dumps(data, separators=(",", ":")) + JS)

    s = data["stats"]
    print(f"CRC-OK frames:   {s['ok']}", file=sys.stderr)
    print(f"heard transmit:  {s['heard']} meters  "
          f"({s['nodes']} nodes total, {s['addressed']} addressed-only)", file=sys.stderr)
    print(f"directed links:  {s['edges']}  "
          f"({100 * s['recip'] / max(1, s['edges']):.1f}% reciprocal)", file=sys.stderr)
    print(f"receiver node:   {me}{' (not in graph)' if me not in {n['id'] for n in data['nodes']} else ''}",
          file=sys.stderr)
    print(f"SNR present:     {s['hasSNR']}", file=sys.stderr)
    print(f"-> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
