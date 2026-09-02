/* RadiusPilot visual dashboard — dependency-free SVG renderers.
 * No CDN, no build step: every chart is plain SVG built from the JSON the
 * server embeds in #dashboard-data (and refreshed from /dashboard.json). */
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  var RP = (window.RP = window.RP || {});

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }
  function byId(id) { return document.getElementById(id); }
  function set(el, svg) { if (el) el.innerHTML = svg; }
  function open(w, h, cls) {
    return '<svg viewBox="0 0 ' + w + " " + h + '" class="' + (cls || "") +
      '" preserveAspectRatio="xMidYMid meet" role="img">';
  }
  function niceMax(v) {
    if (v <= 5) return 5;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var n = v / p;
    var step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
    return step * p;
  }

  /* ---- Online-over-time area chart -------------------------------------- */
  function areaChart(el, series) {
    if (!el) return;
    if (!series || !series.length) { set(el, empty("No session data yet")); return; }
    var W = 640, H = 200, pad = 24, base = H - pad;
    var max = niceMax(Math.max(1, series.reduce(function (m, p) { return Math.max(m, p.count); }, 0)));
    var step = (W - pad * 2) / (series.length - 1 || 1);
    var pts = series.map(function (p, i) {
      var x = pad + i * step, y = pad + (base - pad) * (1 - p.count / max);
      return [x, y];
    });
    var line = pts.map(function (p, i) { return (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1); }).join(" ");
    var area = "M" + pts[0][0].toFixed(1) + " " + base + " " + line.replace(/^M/, "L") +
      " L" + pts[pts.length - 1][0].toFixed(1) + " " + base + " Z";
    var svg = open(W, H, "rp-svg");
    // horizontal gridlines
    for (var g = 0; g <= 2; g++) {
      var gy = pad + (base - pad) * (g / 2);
      svg += '<line x1="' + pad + '" y1="' + gy + '" x2="' + (W - pad) + '" y2="' + gy + '" class="rp-grid"/>';
      svg += '<text x="4" y="' + (gy + 3) + '" class="rp-axis">' + Math.round(max * (1 - g / 2)) + "</text>";
    }
    svg += '<defs><linearGradient id="rpArea" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0" stop-color="var(--rp-accent)" stop-opacity="0.35"/>' +
      '<stop offset="1" stop-color="var(--rp-accent)" stop-opacity="0"/></linearGradient></defs>';
    svg += '<path d="' + area + '" fill="url(#rpArea)"/>';
    svg += '<path d="' + line + '" class="rp-line"/>';
    // x labels every ~4h
    series.forEach(function (p, i) {
      if (i % 4 === 0) svg += '<text x="' + (pad + i * step) + '" y="' + (H - 6) + '" class="rp-axis" text-anchor="middle">' + esc(p.hour) + "</text>";
    });
    // last point marker
    var last = pts[pts.length - 1];
    svg += '<circle cx="' + last[0] + '" cy="' + last[1] + '" r="3.5" class="rp-dot"/>';
    set(el, svg + "</svg>");
  }

  /* ---- Vertical bars (hourly starts) ----------------------------------- */
  function bars(el, values, labels, opts) {
    if (!el) return;
    opts = opts || {};
    var W = 640, H = 180, pad = 22, base = H - pad;
    var max = niceMax(Math.max(1, values.reduce(function (m, v) { return Math.max(m, v); }, 0)));
    var n = values.length, gap = 2, bw = (W - pad * 2) / n - gap;
    var svg = open(W, H, "rp-svg");
    svg += '<line x1="' + pad + '" y1="' + base + '" x2="' + (W - pad) + '" y2="' + base + '" class="rp-grid"/>';
    values.forEach(function (v, i) {
      var x = pad + i * (bw + gap), h = (base - pad) * (v / max), y = base - h;
      svg += '<rect x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" width="' + bw.toFixed(1) +
        '" height="' + Math.max(0, h).toFixed(1) + '" rx="1.5" class="rp-bar"/>';
      if (labels && i % (opts.everyLabel || 3) === 0)
        svg += '<text x="' + (x + bw / 2) + '" y="' + (H - 5) + '" class="rp-axis" text-anchor="middle">' + esc(labels[i]) + "</text>";
    });
    set(el, svg + "</svg>");
  }

  /* ---- Horizontal bars (top talkers) ----------------------------------- */
  function hbars(el, items) {
    if (!el) return;
    if (!items || !items.length) { set(el, empty("No usage yet")); return; }
    var rowH = 26, W = 320, H = items.length * rowH + 6, labelW = 108, valW = 52;
    var max = Math.max(1, items.reduce(function (m, it) { return Math.max(m, it.bytes || 0); }, 0));
    var svg = open(W, H, "rp-svg rp-hbars");
    items.forEach(function (it, i) {
      var y = i * rowH + 4, w = (W - labelW - valW) * ((it.bytes || 0) / max);
      svg += '<text x="0" y="' + (y + 13) + '" class="rp-hlabel">' + esc(trim(it.user, 16)) + "</text>";
      svg += '<rect x="' + labelW + '" y="' + y + '" width="' + (W - labelW - valW) + '" height="14" rx="3" class="rp-track"/>';
      svg += '<rect x="' + labelW + '" y="' + y + '" width="' + Math.max(2, w).toFixed(1) + '" height="14" rx="3" class="rp-bar"/>';
      svg += '<text x="' + W + '" y="' + (y + 12) + '" class="rp-hval" text-anchor="end">' + esc(it.usage || "") + "</text>";
    });
    set(el, svg + "</svg>");
  }

  /* ---- Weekday x hour heatmap ------------------------------------------ */
  function heat(el, matrix) {
    if (!el || !matrix || !matrix.length) { set(el, empty("No activity yet")); return; }
    var days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    var cell = 22, gap = 3, left = 34, top = 4, W = left + 24 * cell + 6, H = top + 7 * cell + 18;
    var max = 1;
    matrix.forEach(function (r) { r.forEach(function (v) { if (v > max) max = v; }); });
    var svg = open(W, H, "rp-svg rp-heat");
    for (var d = 0; d < 7; d++) {
      svg += '<text x="0" y="' + (top + d * cell + cell / 2 + 3) + '" class="rp-axis">' + days[d] + "</text>";
      for (var h = 0; h < 24; h++) {
        var v = (matrix[d] && matrix[d][h]) || 0, t = v / max;
        var x = left + h * cell, y = top + d * cell;
        svg += '<rect x="' + x + '" y="' + y + '" width="' + (cell - gap) + '" height="' + (cell - gap) +
          '" rx="3" fill="var(--rp-accent)" fill-opacity="' + (v ? (0.12 + 0.85 * t).toFixed(2) : 0.05) +
          '"><title>' + days[d] + " " + h + ":00 — " + v + " connections</title></rect>";
      }
    }
    for (var hh = 0; hh < 24; hh += 3)
      svg += '<text x="' + (left + hh * cell + (cell - gap) / 2) + '" y="' + (H - 4) + '" class="rp-axis" text-anchor="middle">' + hh + "</text>";
    set(el, svg + "</svg>");
  }

  /* ---- Today session timeline (Gantt) ---------------------------------- */
  function timeline(el, items) {
    if (!el) return;
    if (!items || !items.length) { set(el, empty("No connections today")); return; }
    var rowH = 24, left = 96, W = 640, H = items.length * rowH + 22, span = W - left - 8;
    function x(min) { return left + span * (Math.max(0, Math.min(1440, min)) / 1440); }
    var svg = open(W, H, "rp-svg rp-timeline");
    for (var t = 0; t <= 24; t += 6) {
      var gx = left + span * (t / 24);
      svg += '<line x1="' + gx + '" y1="0" x2="' + gx + '" y2="' + (H - 18) + '" class="rp-grid"/>';
      svg += '<text x="' + gx + '" y="' + (H - 5) + '" class="rp-axis" text-anchor="middle">' + (t < 10 ? "0" + t : t) + ":00</text>";
    }
    items.forEach(function (it, i) {
      var y = i * rowH + 3, x1 = x(it.start_min), x2 = x(it.end_min);
      svg += '<text x="0" y="' + (y + 13) + '" class="rp-hlabel">' + esc(trim(it.user, 15)) + "</text>";
      svg += '<rect x="' + x1.toFixed(1) + '" y="' + y + '" width="' + Math.max(2, x2 - x1).toFixed(1) +
        '" height="16" rx="4" class="rp-span ' + (it.active ? "rp-span-live" : "") + '">' +
        "<title>" + esc(it.user) + " · " + esc(it.usage || "") + (it.active ? " · live" : "") + "</title></rect>";
    });
    set(el, svg + "</svg>");
  }

  /* ---- Live connection map (equirectangular) --------------------------- */
  var CONTINENTS = [
    // rough, stylised land blobs [lon,lat] — the accurate data is the dots
    [[-168, 66], [-150, 60], [-95, 50], [-82, 44], [-80, 26], [-97, 18], [-116, 30], [-125, 40], [-140, 58], [-168, 66]],
    [[-82, 12], [-70, 8], [-56, 6], [-35, -8], [-40, -23], [-58, -50], [-72, -52], [-70, -18], [-80, -4], [-82, 12]],
    [[-11, 36], [10, 37], [30, 32], [43, 12], [51, 12], [40, -5], [35, -20], [20, -35], [10, -18], [-6, 5], [-16, 14], [-11, 36]],
    [[-10, 44], [3, 51], [12, 56], [30, 60], [28, 44], [40, 46], [30, 36], [-2, 36], [-9, 43], [-10, 44]],
    [[40, 68], [90, 72], [140, 70], [160, 62], [150, 45], [122, 40], [120, 24], [100, 8], [78, 8], [66, 24], [44, 40], [40, 68]],
    [[113, -22], [132, -12], [146, -18], [150, -37], [130, -32], [115, -34], [113, -22]]
  ];
  function map(el, geo) {
    if (!el) return;
    geo = geo || {};
    var W = 720, H = 360;
    function px(lon, lat) { return [(lon + 180) / 360 * W, (90 - lat) / 180 * H]; }
    var svg = open(W, H, "rp-svg rp-map");
    svg += '<rect x="0" y="0" width="' + W + '" height="' + H + '" class="rp-ocean"/>';
    // graticule
    for (var lon = -150; lon <= 150; lon += 30) { var gx = px(lon, 0)[0]; svg += '<line x1="' + gx + '" y1="0" x2="' + gx + '" y2="' + H + '" class="rp-gratic"/>'; }
    for (var lat = -60; lat <= 60; lat += 30) { var gy = px(0, lat)[1]; svg += '<line x1="0" y1="' + gy + '" x2="' + W + '" y2="' + gy + '" class="rp-gratic' + (lat === 0 ? " rp-equator" : "") + '"/>'; }
    // continents
    CONTINENTS.forEach(function (poly) {
      var d = poly.map(function (p, i) { var c = px(p[0], p[1]); return (i ? "L" : "M") + c[0].toFixed(1) + " " + c[1].toFixed(1); }).join(" ") + " Z";
      svg += '<path d="' + d + '" class="rp-land"/>';
    });
    var server = geo.server, sp = server ? px(server.lon, server.lat) : null;
    var points = geo.points || [];
    // arcs from each point to the gateway
    if (sp) points.forEach(function (p) {
      var c = px(p.lon, p.lat), mx = (c[0] + sp[0]) / 2, my = (c[1] + sp[1]) / 2 - Math.abs(c[0] - sp[0]) * 0.18 - 12;
      svg += '<path d="M' + c[0].toFixed(1) + " " + c[1].toFixed(1) + " Q" + mx.toFixed(1) + " " + my.toFixed(1) + " " + sp[0].toFixed(1) + " " + sp[1].toFixed(1) + '" class="rp-arc"/>';
    });
    // session points
    points.forEach(function (p) {
      var c = px(p.lon, p.lat), r = 4 + Math.min(6, (p.count - 1) * 2);
      svg += '<g class="rp-point"><circle cx="' + c[0].toFixed(1) + '" cy="' + c[1].toFixed(1) + '" r="' + r + '" class="rp-ping"/>' +
        '<circle cx="' + c[0].toFixed(1) + '" cy="' + c[1].toFixed(1) + '" r="' + r + '" class="rp-core">' +
        "<title>" + esc(p.city || p.country_name || "") + (p.count > 1 ? " · " + p.count + " sessions" : "") +
        (p.users && p.users.length ? " · " + esc(p.users.join(", ")) : "") + "</title></circle>";
      if (p.city) svg += '<text x="' + (c[0] + r + 3).toFixed(1) + '" y="' + (c[1] + 3).toFixed(1) + '" class="rp-place">' + esc(p.city) + (p.count > 1 ? " ×" + p.count : "") + "</text>";
      svg += "</g>";
    });
    // gateway marker
    if (sp) {
      svg += '<g class="rp-hub"><rect x="' + (sp[0] - 4).toFixed(1) + '" y="' + (sp[1] - 4).toFixed(1) + '" width="8" height="8" rx="1.5" class="rp-hub-mark"/>' +
        '<text x="' + (sp[0]).toFixed(1) + '" y="' + (sp[1] - 8).toFixed(1) + '" class="rp-place rp-hub-label" text-anchor="middle">' + esc(server.label || "Gateway") + "</text></g>";
    }
    if (!points.length) svg += '<text x="' + (W / 2) + '" y="' + (H / 2) + '" class="rp-empty-map" text-anchor="middle">No located sessions online</text>';
    set(el, svg + "</svg>");
  }

  /* ---- Live architecture diagram --------------------------------------- */
  function arch(el, health, opts) {
    if (!el) return;
    health = health || {}; opts = opts || {};
    var W = 720, H = 130;
    var nodes = [
      { x: 60, label: "Cisco ISR", sub: "VPN / console", ok: true },
      { x: 240, label: "Duo Proxy", sub: "RADIUS :1812", ok: health.duo_active !== false },
      { x: 430, label: "FreeRADIUS", sub: "auth + hashes", ok: health.active !== false && health.config_valid !== false },
      { x: 620, label: "Duo Cloud", sub: "2nd factor", ok: health.duo_active !== false }
    ];
    var cy = 52, bw = 96, bh = 44;
    var svg = open(W, H, "rp-svg rp-arch");
    for (var i = 0; i < nodes.length - 1; i++) {
      var x1 = nodes[i].x + bw / 2, x2 = nodes[i + 1].x - bw / 2;
      svg += '<line x1="' + x1 + '" y1="' + cy + '" x2="' + x2 + '" y2="' + cy + '" class="rp-link"/>';
      svg += '<line x1="' + x1 + '" y1="' + cy + '" x2="' + x2 + '" y2="' + cy + '" class="rp-link-flow"/>';
    }
    nodes.forEach(function (n) {
      svg += '<g class="rp-node ' + (n.ok ? "ok" : "bad") + '">' +
        '<rect x="' + (n.x - bw / 2) + '" y="' + (cy - bh / 2) + '" width="' + bw + '" height="' + bh + '" rx="8" class="rp-node-box"/>' +
        '<circle cx="' + (n.x - bw / 2 + 12) + '" cy="' + (cy - bh / 2 + 12) + '" r="4" class="rp-node-dot"/>' +
        '<text x="' + n.x + '" y="' + (cy - 2) + '" text-anchor="middle" class="rp-node-label">' + esc(n.label) + "</text>" +
        '<text x="' + n.x + '" y="' + (cy + 13) + '" text-anchor="middle" class="rp-node-sub">' + esc(n.sub) + "</text></g>";
    });
    var tags = [];
    tags.push(opts.accounting ? "accounting live" : "accounting off");
    tags.push(opts.coa ? "CoA ready" : "CoA off");
    svg += '<text x="' + W + '" y="' + (H - 6) + '" text-anchor="end" class="rp-arch-tags">' + esc(tags.join("  ·  ")) + "</text>";
    set(el, svg + "</svg>");
  }

  /* ---- sparkline for metric cards -------------------------------------- */
  function spark(el, values, color) {
    if (!el || !values || !values.length) return;
    var W = 120, H = 32, pad = 2, max = Math.max(1, Math.max.apply(null, values)), n = values.length;
    var step = (W - pad * 2) / (n - 1 || 1);
    var pts = values.map(function (v, i) { return [pad + i * step, pad + (H - pad * 2) * (1 - v / max)]; });
    var line = pts.map(function (p, i) { return (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1); }).join(" ");
    var svg = open(W, H, "rp-spark") +
      '<path d="' + line + '" fill="none" stroke="' + (color || "var(--rp-accent)") + '" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>' +
      '<circle cx="' + pts[pts.length - 1][0].toFixed(1) + '" cy="' + pts[pts.length - 1][1].toFixed(1) + '" r="2" fill="' + (color || "var(--rp-accent)") + '"/></svg>';
    set(el, svg);
  }

  function empty(msg) { return open(320, 60) + '<text x="160" y="34" class="rp-empty" text-anchor="middle">' + esc(msg) + "</text></svg>"; }
  function trim(s, n) { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }
  function trend(el, cur, prev) {
    if (!el) return;
    var diff = (cur || 0) - (prev || 0);
    var pct = prev ? Math.round((diff / prev) * 100) : (cur ? 100 : 0);
    var dir = diff > 0 ? "up" : diff < 0 ? "down" : "flat";
    var arrow = diff > 0 ? "▲" : diff < 0 ? "▼" : "▬";
    el.className = "rp-trend rp-trend-" + dir;
    el.textContent = arrow + " " + Math.abs(pct) + "% vs yesterday";
  }

  RP.charts = { areaChart: areaChart, bars: bars, hbars: hbars, heat: heat, timeline: timeline, map: map, arch: arch, spark: spark };

  RP.renderDashboard = function (d) {
    if (!d) return;
    try {
      map(byId("rp-map"), d.geo);
      areaChart(byId("rp-online"), d.online_series);
      bars(byId("rp-hourly"), d.hourly || [], (d.hourly || []).map(function (_, i) { return i; }), { everyLabel: 3 });
      hbars(byId("rp-top"), d.top_users);
      heat(byId("rp-heatmap"), d.heatmap);
      timeline(byId("rp-timeline"), d.timeline);
      arch(byId("rp-arch"), d.health, { coa: d.coa_enabled, accounting: d.accounting_enabled });
      bars(byId("rp-daily"), (d.daily || []).map(function (x) { return x.sessions; }), (d.daily || []).map(function (x) { return (x.label || "").split(" ")[0]; }), { everyLabel: 2 });
      spark(byId("rp-spark-online"), (d.online_series || []).map(function (p) { return p.count; }));
      spark(byId("rp-spark-daily"), (d.daily || []).map(function (x) { return x.sessions; }));
      var t = d.totals || {};
      setText("rp-total-online", t.online);
      setText("rp-total-sessions", t.sessions_today);
      setText("rp-total-usage", t.usage_today);
      setText("rp-total-users", t.users_today);
      setText("rp-map-online", t.online);
      setText("rp-map-places", (d.geo && d.geo.points ? d.geo.points.length : 0));
      setText("rp-map-unresolved", (d.geo && d.geo.unresolved) || 0);
      trend(byId("rp-trend-sessions"), t.sessions_today, t.sessions_prev);
      trend(byId("rp-trend-usage"), t.bytes_today, t.bytes_prev);
      if (d.generated_at) setText("rp-updated", d.generated_at.replace("T", " "));
      var wl = byId("wall-sessions");
      if (wl) {
        var rows = [];
        ((d.geo && d.geo.points) || []).forEach(function (p) {
          (p.users || []).forEach(function (u) {
            rows.push('<li><span class="who">' + esc(u) + '</span><span class="where">' + esc(p.city || p.country_name || p.country || "") + "</span></li>");
          });
        });
        wl.innerHTML = rows.length ? rows.join("") : '<li class="where">No located sessions online</li>';
      }
    } catch (e) { /* never let one chart break the page */ }
  };
  function setText(id, v) { var el = byId(id); if (el && v != null) el.textContent = v; }

  function geoBadge(e) {
    if (e.blocked) return '<span class="badge bg-red-lt">would block</span>';
    if (e.decision === "allow") return '<span class="badge bg-green-lt">allow</span>';
    return '<span class="badge bg-secondary-lt">' + (e.private ? "LAN — allowed" : "unlocated — allowed") + "</span>";
  }
  function renderGeo(d) {
    if (!d) return;
    var badge = byId("geo-mode-badge");
    if (badge) {
      var mode = d.mode || "off";
      badge.textContent = mode;
      badge.className = "badge " + (mode === "enforce" ? "bg-red-lt" : mode === "monitor" ? "bg-yellow-lt" : "bg-secondary-lt");
    }
    setText("geo-wouldblock", d.would_block_count || 0);
    var note = byId("geo-note");
    if (note) note.textContent = d.geolite_ready ? "Worldwide country database active." : "Worldwide coverage needs a GeoLite2/DB-IP database; without it most public IPs read as unlocated.";
    var feed = byId("geo-feed");
    if (feed) {
      var rows = (d.events || []).slice(0, 25).map(function (e) {
        var loc = esc(e.city || e.country_name || (e.private ? "Private / LAN" : "—"));
        var cc = e.country ? '<span class="text-secondary"> ' + esc(e.country) + "</span>" : "";
        return '<tr class="' + (e.blocked ? "geo-row-block" : "") + '"><td class="text-secondary">' +
          esc((e.timestamp || "").slice(0, 16).replace("T", " ")) + "</td><td>" + esc(e.username) +
          "</td><td>" + loc + cc + "</td><td><code>" + esc(e.client_ip || "") + "</code></td><td>" + geoBadge(e) + "</td></tr>";
      }).join("");
      feed.innerHTML = rows || '<tr><td colspan="5" class="text-secondary py-3">No authentication attempts recorded yet.</td></tr>';
    }
  }
  function fetchGeo() {
    if (!byId("geo-feed")) return;
    fetch("/geo.json", { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { if (d) renderGeo(d); })
      .catch(function () {});
  }
  RP.fetchGeo = fetchGeo;

  function boot() {
    fetchGeo();
    if (byId("geo-feed")) setInterval(fetchGeo, 30000);
    var node = byId("dashboard-data");
    if (!node) return;
    var data;
    try { data = JSON.parse(node.textContent); } catch (e) { return; }
    if (!data || !Object.keys(data).length) return;
    RP.renderDashboard(data);
    var wall = document.body.getAttribute("data-wall") === "1";
    if (byId("rp-map") || wall) {
      setInterval(function () {
        fetch("/dashboard.json", { headers: { Accept: "application/json" }, credentials: "same-origin" })
          .then(function (r) { return r.ok ? r.json() : null; })
          .then(function (d) { if (d) RP.renderDashboard(d); })
          .catch(function () {});
      }, wall ? 10000 : 25000);
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
