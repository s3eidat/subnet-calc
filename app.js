/* Subnet Calc — IPv4 math with unsigned 32-bit numbers, IPv6 with BigInt. Nothing leaves the page. */
(function () {
  "use strict";
  var $ = S3.$, $$ = S3.$$;

  // ================= IPv4 core =================
  function parseV4(s) {
    var m = /^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\s*$/.exec(s || "");
    if (!m) return null;
    var n = 0;
    for (var i = 1; i <= 4; i++) {
      if (m[i].length > 1 && m[i][0] === "0") return null; // no ambiguous octal-looking octets
      var o = +m[i]; if (o > 255) return null;
      n = n * 256 + o;
    }
    return n >>> 0;
  }
  function v4str(n) { return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."); }
  function maskOf(p) { return p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0; }
  function prefixOfMask(m) {
    for (var p = 0; p <= 32; p++) if (maskOf(p) === m) return p;
    return -1;
  }

  // "a.b.c.d/nn", "a.b.c.d/m.m.m.m", "a.b.c.d m.m.m.m", "a.b.c.d" → {ip, prefix|null} or {error}
  function parseV4Input(s) {
    s = (s || "").trim();
    if (!s) return null;
    var parts = s.split(/\s*\/\s*|\s+/);
    if (parts.length > 2) return { error: "Use one address, optionally followed by /prefix or a mask" };
    var ip = parseV4(parts[0]);
    if (ip === null) return { error: "Not a valid IPv4 address" };
    if (parts.length === 1) return { ip: ip, prefix: null };
    var p = parts[1];
    if (/^\d{1,2}$/.test(p) && +p <= 32) return { ip: ip, prefix: +p };
    var m = parseV4(p);
    if (m === null) return { error: "The prefix must be 0–32 or a dotted mask" };
    var pr = prefixOfMask(m);
    if (pr < 0) {
      var wp = prefixOfMask((~m) >>> 0); // a wildcard mask such as 0.0.0.255
      if (wp >= 0 && m !== 0) return { ip: ip, prefix: wp, wildcardGiven: true };
      return { error: "That mask is not contiguous (all ones, then all zeros)" };
    }
    return { ip: ip, prefix: pr };
  }

  var V4_SPECIAL = [
    ["0.0.0.0", 8, "“This network” (RFC 1122)"], ["10.0.0.0", 8, "Private (RFC 1918)"],
    ["100.64.0.0", 10, "Shared / carrier-grade NAT (RFC 6598)"], ["127.0.0.0", 8, "Loopback"],
    ["169.254.0.0", 16, "Link-local (APIPA)"], ["172.16.0.0", 12, "Private (RFC 1918)"],
    ["192.0.0.0", 24, "IETF protocol assignments"], ["192.0.2.0", 24, "Documentation (TEST-NET-1)"],
    ["192.88.99.0", 24, "6to4 relay anycast (deprecated)"], ["192.168.0.0", 16, "Private (RFC 1918)"],
    ["198.18.0.0", 15, "Benchmarking (RFC 2544)"], ["198.51.100.0", 24, "Documentation (TEST-NET-2)"],
    ["203.0.113.0", 24, "Documentation (TEST-NET-3)"], ["224.0.0.0", 4, "Multicast"],
    ["255.255.255.255", 32, "Limited broadcast"], ["240.0.0.0", 4, "Reserved (class E)"]
  ];
  function v4type(ip) {
    for (var i = 0; i < V4_SPECIAL.length; i++) {
      var s = V4_SPECIAL[i], m = maskOf(s[1]);
      if (((ip & m) >>> 0) === parseV4(s[0])) return { label: s[2], pub: false };
    }
    return { label: "Public (globally routable)", pub: true };
  }
  function v4class(ip) {
    var o = ip >>> 24;
    return o < 128 ? "A" : o < 192 ? "B" : o < 224 ? "C" : o < 240 ? "D (multicast)" : "E (reserved)";
  }

  function v4calc(ip, prefix) {
    var mask = maskOf(prefix), wild = (~mask) >>> 0;
    var net = (ip & mask) >>> 0, bc = (net | wild) >>> 0;
    var total = Math.pow(2, 32 - prefix);
    var usable = prefix === 32 ? 1 : prefix === 31 ? 2 : total - 2;
    var first = prefix >= 31 ? net : net + 1, last = prefix >= 31 ? bc : bc - 1;
    return { ip: ip, prefix: prefix, mask: mask, wildcard: wild, network: net, broadcast: bc, first: first >>> 0, last: last >>> 0, total: total, usable: usable };
  }

  // Split into at least n equal subnets.
  function splitN(net, prefix, n) {
    if (!(n >= 1)) return { error: "Enter a number of subnets" };
    var bits = Math.ceil(Math.log2(n) - 1e-9), np = prefix + bits;
    if (np > 32) return { error: "A /" + prefix + " can't be split into " + n + " subnets (max " + Math.pow(2, 32 - prefix) + ")" };
    var count = Math.pow(2, bits), size = Math.pow(2, 32 - np), list = [];
    for (var i = 0; i < count && i < 4096; i++) list.push(v4calc((net + i * size) >>> 0, np));
    return { prefix: np, count: count, list: list, rounded: count !== n };
  }

  // VLSM: biggest first, each block aligned to its own size.
  function parseVlsm(s) {
    var out = [], bad = null;
    (s || "").split(/[,;\n]+/).forEach(function (part, i) {
      part = part.trim(); if (!part) return;
      var m = /^(?:(.*?)\s*[:=]\s*)?(\d+)$/.exec(part);
      if (!m || +m[2] < 1) { bad = part; return; }
      out.push({ name: (m[1] || "").trim() || "Subnet " + (out.length + 1), hosts: +m[2], order: i });
    });
    return bad ? { error: "Can't read “" + bad + "”. Use numbers like 50, 20 or names like Sales:50" } : { list: out };
  }
  function vlsm(net, prefix, reqs) {
    var end = net + Math.pow(2, 32 - prefix), cur = net, rows = [];
    var sorted = reqs.slice().sort(function (a, b) { return b.hosts - a.hosts || a.order - b.order; });
    for (var i = 0; i < sorted.length; i++) {
      var r = sorted[i], bits = Math.ceil(Math.log2(r.hosts + 2) - 1e-9), p = 32 - bits;
      if (p < prefix) return { error: r.name + " needs " + r.hosts + " hosts, more than the whole /" + prefix + " holds" };
      var size = Math.pow(2, bits);
      cur = Math.ceil(cur / size) * size;
      if (cur + size > end) return { error: "Out of space at " + r.name + ": the requests don't fit in /" + prefix };
      var c = v4calc(cur >>> 0, p); c.name = r.name; c.need = r.hosts;
      rows.push(c); cur += size;
    }
    return { list: rows, used: cur - net, free: end - cur };
  }

  function inRange4(ip, range) {
    return ip >= range.start && ip <= range.end;
  }

  // ================= IPv6 core (BigInt) =================
  var B0 = BigInt(0), B1 = BigInt(1), B16 = BigInt(16), BALL = (B1 << BigInt(128)) - B1;
  function parseV6(s) {
    s = (s || "").trim().replace(/^\[|\]$/g, "");
    var zone = "", zi = s.indexOf("%");
    if (zi >= 0) { zone = s.slice(zi + 1); s = s.slice(0, zi); }
    if (!/^[0-9a-fA-F:.]+$/.test(s) || s.indexOf(":") < 0) return null;
    var tail4 = null, m = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
    if (m) { tail4 = parseV4(m[2]); if (tail4 === null) return null; s = m[1] + "0:0"; }
    var halves = s.split("::");
    if (halves.length > 2) return null;
    function groups(h) { return h === "" ? [] : h.split(":"); }
    var a = groups(halves[0]), b = halves.length === 2 ? groups(halves[1]) : [];
    var fill = 8 - a.length - b.length;
    if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
    var all = a.concat(new Array(halves.length === 2 ? fill : 0).fill("0"), b);
    var n = B0;
    for (var i = 0; i < 8; i++) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(all[i])) return null;
      n = (n << B16) | BigInt(parseInt(all[i], 16));
    }
    if (tail4 !== null) n = (n & ~BigInt(0xFFFFFFFF)) | BigInt(tail4);
    return { n: n, zone: zone };
  }
  function v6groups(n) {
    var g = [];
    for (var i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & BigInt(0xFFFF)));
    return g;
  }
  function v6expand(n) { return v6groups(n).map(function (x) { return x.toString(16).padStart(4, "0"); }).join(":"); }
  // RFC 5952: lower case, no leading zeros, longest run (>= 2) of zero groups becomes "::", first one on a tie.
  function v6compress(n) {
    var g = v6groups(n), best = -1, bestLen = 0, i = 0;
    while (i < 8) {
      if (g[i] === 0) {
        var j = i; while (j < 8 && g[j] === 0) j++;
        if (j - i > bestLen) { best = i; bestLen = j - i; }
        i = j;
      } else i++;
    }
    var hex = g.map(function (x) { return x.toString(16); });
    if (bestLen < 2) return hex.join(":");
    return hex.slice(0, best).join(":") + "::" + hex.slice(best + bestLen).join(":");
  }
  function v6mask(p) { return p === 0 ? B0 : (BALL >> BigInt(128 - p)) << BigInt(128 - p); }
  var V6_SPECIAL = [
    ["::", 128, "Unspecified address"], ["::1", 128, "Loopback"], ["::ffff:0:0", 96, "IPv4-mapped"],
    ["64:ff9b::", 96, "IPv4/IPv6 translation (NAT64)"], ["100::", 64, "Discard-only"],
    ["2001:db8::", 32, "Documentation"], ["2001::", 32, "Teredo tunneling"], ["2002::", 16, "6to4"],
    ["fc00::", 7, "Unique local (ULA, private)"], ["fe80::", 10, "Link-local"], ["ff00::", 8, "Multicast"],
    ["2000::", 3, "Global unicast"]
  ];
  function v6type(n) {
    for (var i = 0; i < V6_SPECIAL.length; i++) {
      var s = V6_SPECIAL[i], m = v6mask(s[1]);
      if ((n & m) === parseV6(s[0]).n) return s[2];
    }
    return "Reserved / unassigned";
  }
  function v6calc(n, p) {
    var m = v6mask(p), net = n & m, last = net | (BALL ^ m);
    return {
      n: n, prefix: p, network: net, last: last,
      count: B1 << BigInt(128 - p),
      n64: p <= 64 ? (B1 << BigInt(64 - p)) : null
    };
  }
  function v6reverse(n) {
    return v6expand(n).replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa";
  }
  function bigFmt(b) {
    var s = b.toString();
    return s.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }
  function bigPow2(e) { return e < 1 ? "" : " (2^" + e + ")"; }

  // Range parser for the checker: CIDR, "a - b" or a single IP, either family.
  function parseRange(s) {
    s = (s || "").trim();
    if (!s) return null;
    var dash = s.split(/\s+-\s+|\s*–\s*|(?<=\d)-(?=\d)/);
    if (dash.length === 2) {
      var a4 = parseV4(dash[0]), b4 = parseV4(dash[1]);
      if (a4 !== null && b4 !== null) return { v: 4, start: Math.min(a4, b4), end: Math.max(a4, b4) };
      var a6 = parseV6(dash[0]), b6 = parseV6(dash[1]);
      if (a6 && b6) return { v: 6, start: a6.n < b6.n ? a6.n : b6.n, end: a6.n < b6.n ? b6.n : a6.n };
      return null;
    }
    if (s.indexOf(":") >= 0) {
      var sl = s.split("/"), x = parseV6(sl[0]), p = sl.length > 1 ? +sl[1] : 128;
      if (!x || !(p >= 0 && p <= 128) || sl.length > 2) return null;
      var c = v6calc(x.n, p);
      return { v: 6, start: c.network, end: c.last };
    }
    var r = parseV4Input(s);
    if (!r || r.error) return null;
    var cc = v4calc(r.ip, r.prefix === null ? 32 : r.prefix);
    return { v: 4, start: cc.network, end: cc.broadcast };
  }
  function checkIn(ipText, rangeText) {
    var rg = parseRange(rangeText);
    if (!rg) return { error: "Can't read the range" };
    if (rg.v === 4) {
      var ip = parseV4(ipText);
      if (ip === null) return { error: parseV6(ipText) ? "IPv6 address vs an IPv4 range" : "Not a valid IP address" };
      return { inside: inRange4(ip, rg), rg: rg };
    }
    var x = parseV6(ipText);
    if (!x) return { error: parseV4(ipText) !== null ? "IPv4 address vs an IPv6 range" : "Not a valid IP address" };
    return { inside: x.n >= rg.start && x.n <= rg.end, rg: rg };
  }

  // ================= UI =================
  var ipIn = $("#ip"), maskSel = $("#mask"), res = $("#v4res"), bin = $("#v4bin"), status = $("#v4status");
  var current = null, splitRows = [];

  for (var p = 32; p >= 0; p--) maskSel.appendChild(S3.h("option", { value: p, text: "/" + p + "  " + v4str(maskOf(p)) }));
  maskSel.value = "24";

  function item(label, value, opts) {
    opts = opts || {};
    var b = S3.h("button", { "class": "sn-item" + (opts.wide ? " wide" : ""), type: "button", title: "Click to copy" }, [
      S3.h("span", { "class": "sn-k", text: label }),
      S3.h("span", { "class": "sn-v mono" + (opts.cls ? " " + opts.cls : ""), text: String(value) })
    ]);
    b.addEventListener("click", function () { S3.copy(String(value), label + " copied"); });
    return b;
  }

  function binRow(label, n, prefix) {
    var bits = (n >>> 0).toString(2).padStart(32, "0"), row = S3.h("div", { "class": "sn-binrow" });
    row.appendChild(S3.h("span", { "class": "sn-binlbl", text: label }));
    var code = S3.h("span", { "class": "sn-bits" });
    for (var o = 0; o < 4; o++) {
      var oct = S3.h("span", { "class": "sn-oct" });
      for (var b = 0; b < 8; b++) {
        var idx = o * 8 + b;
        oct.appendChild(S3.h("span", { "class": idx < prefix ? "sn-nb" : "sn-hb", text: bits[idx] }));
      }
      code.appendChild(oct);
    }
    row.appendChild(code);
    row.appendChild(S3.h("span", { "class": "sn-bindec", text: v4str(n) }));
    return row;
  }

  function summaryText(c) {
    return [
      "Address:      " + v4str(c.ip) + "/" + c.prefix,
      "Network:      " + v4str(c.network) + "/" + c.prefix,
      "Netmask:      " + v4str(c.mask),
      "Wildcard:     " + v4str(c.wildcard),
      "Broadcast:    " + (c.prefix >= 31 ? "n/a" : v4str(c.broadcast)),
      "Host range:   " + v4str(c.first) + " - " + v4str(c.last),
      "Usable hosts: " + c.usable.toLocaleString("en-US"),
      "Total:        " + c.total.toLocaleString("en-US"),
      "Type:         " + v4type(c.ip).label
    ].join("\n");
  }

  function renderV4(fromSelect) {
    var raw = ipIn.value, r = parseV4Input(raw);
    res.innerHTML = ""; bin.hidden = true; $("#v4actions").hidden = true; $("#v4note").textContent = "";
    current = null;
    if (!r) { status.className = "chip"; status.textContent = "Type an IPv4 address"; renderSplit(); return; }
    if (r.error) { status.className = "chip bad"; status.textContent = r.error; renderSplit(); return; }
    var prefix = r.prefix;
    if (prefix === null || fromSelect) prefix = +maskSel.value;
    else maskSel.value = String(prefix);
    S3.store("subnet.ip", raw);
    var c = current = v4calc(r.ip, prefix), t = v4type(r.ip);
    status.className = "chip ok"; status.textContent = v4str(c.network) + "/" + prefix;
    if (r.wildcardGiven) $("#v4note").textContent = "Read the second value as a wildcard mask.";
    else if (r.prefix === null) $("#v4note").textContent = "No prefix typed, using the one on the right.";
    else if (fromSelect) $("#v4note").textContent = "Prefix taken from the selector.";
    [
      item("Network", v4str(c.network) + "/" + prefix),
      item("Broadcast", prefix >= 31 ? "none (/" + prefix + ")" : v4str(c.broadcast)),
      item("First host", v4str(c.first)),
      item("Last host", v4str(c.last)),
      item("Usable hosts", c.usable.toLocaleString("en-US"), { cls: "sn-big" }),
      item("Total addresses", c.total.toLocaleString("en-US")),
      item("Subnet mask", v4str(c.mask)),
      item("Wildcard mask", v4str(c.wildcard)),
      item("Class", v4class(r.ip)),
      item("Type", t.label, { cls: t.pub ? "" : "sn-acc" }),
      item("Integer", String(r.ip)),
      item("Hex", "0x" + r.ip.toString(16).toUpperCase().padStart(8, "0"))
    ].forEach(function (el) { res.appendChild(el); });
    if (prefix === 31) $("#v4note").textContent = "/31 is a point-to-point link: both addresses are usable (RFC 3021).";
    bin.innerHTML = "";
    bin.appendChild(binRow("Address", c.ip, prefix));
    bin.appendChild(binRow("Mask", c.mask, prefix));
    bin.appendChild(binRow("Network", c.network, prefix));
    bin.appendChild(binRow("Broadcast", c.broadcast, prefix));
    bin.appendChild(S3.h("div", { "class": "sn-legend" }, [
      S3.h("span", { "class": "sn-nb", text: "■" }), " network bits (" + prefix + ")   ",
      S3.h("span", { "class": "sn-hb", text: "■" }), " host bits (" + (32 - prefix) + ")"
    ]));
    bin.hidden = false; $("#v4actions").hidden = false;
    renderSplit();
  }

  var splitMode = S3.store("subnet.split") || "n";
  function renderSplit() {
    var box = $("#split"), info = $("#splitinfo");
    box.innerHTML = ""; info.textContent = ""; splitRows = []; $("#nnote").textContent = "";
    $("#nrow").hidden = splitMode !== "n"; $("#vrow").hidden = splitMode !== "vlsm";
    if (!current) { box.appendChild(S3.h("div", { "class": "empty" }, [S3.h("b", { text: "Enter a network above" }), "Then split it into equal subnets or by the hosts each one needs."])); return; }
    var c = current, out, vl = splitMode === "vlsm";
    if (vl) {
      var req = parseVlsm($("#vlsm").value);
      out = req.error ? req : vlsm(c.network, c.prefix, req.list);
    } else out = splitN(c.network, c.prefix, Math.floor(+$("#nsub").value));
    if (out.error) { box.appendChild(S3.h("div", { "class": "empty" }, [S3.h("b", { text: "Can't split" }), out.error])); return; }
    if (!vl) {
      $("#nnote").textContent = out.count + " × /" + out.prefix + (out.rounded ? " (rounded up to a power of two)" : "") + ", " + out.list[0].usable.toLocaleString("en-US") + " usable hosts each";
      if (out.count > out.list.length) info.textContent = "Showing the first " + out.list.length + " of " + out.count.toLocaleString("en-US") + ".";
    } else {
      info.textContent = "Used " + out.used.toLocaleString("en-US") + " of " + c.total.toLocaleString("en-US") + " addresses, " + out.free.toLocaleString("en-US") + " left over. Largest requests are placed first.";
    }
    var head = (vl ? ["Name", "Needed"] : ["#"]).concat(["Network", "Host range", "Broadcast", "Usable", "Mask"]);
    var tbl = S3.h("table", { "class": "tbl" }), thead = S3.h("tr");
    head.forEach(function (hd) { thead.appendChild(S3.h("th", { text: hd })); });
    tbl.appendChild(S3.h("thead", null, [thead]));
    var tb = S3.h("tbody");
    out.list.forEach(function (s, i) {
      var row = (vl ? [s.name, String(s.need)] : [String(i + 1)]).concat([
        v4str(s.network) + "/" + s.prefix, v4str(s.first) + " – " + v4str(s.last),
        s.prefix >= 31 ? "—" : v4str(s.broadcast), s.usable.toLocaleString("en-US"), v4str(s.mask)]);
      splitRows.push(row);
      var tr = S3.h("tr");
      row.forEach(function (v, k) { tr.appendChild(S3.h("td", { "class": k === (vl ? 2 : 1) ? "mono sn-strong" : (k > (vl ? 1 : 0) ? "mono" : ""), text: v })); });
      tb.appendChild(tr);
    });
    tbl.appendChild(tb); box.appendChild(tbl);
    splitRows.unshift(head);
  }

  function renderCheck() {
    var r = checkIn($("#chkip").value, $("#chkrange").value), chip = $("#chkres"), note = $("#chknote");
    note.textContent = "";
    if (!$("#chkip").value.trim() || !$("#chkrange").value.trim()) { chip.className = "chip"; chip.textContent = "—"; return; }
    if (r.error) { chip.className = "chip warn"; chip.textContent = r.error; return; }
    chip.className = "chip " + (r.inside ? "ok" : "bad");
    chip.textContent = r.inside ? "✓ Inside the range" : "✗ Outside the range";
    note.textContent = r.rg.v === 4 ? v4str(r.rg.start) + " – " + v4str(r.rg.end) : v6compress(r.rg.start) + " – " + v6compress(r.rg.end);
  }

  function renderV6() {
    var raw = $("#v6").value.trim(), box = $("#v6res"), st = $("#v6status");
    box.innerHTML = "";
    if (!raw) { st.className = "chip"; st.textContent = "Type an IPv6 address"; return; }
    var sl = raw.split("/"), x = parseV6(sl[0]), p = sl.length > 1 ? sl[1].trim() : "128";
    if (!x || sl.length > 2 || !/^\d{1,3}$/.test(p) || +p > 128) { st.className = "chip bad"; st.textContent = "Not a valid IPv6 address" + (sl.length > 1 ? " / prefix" : ""); return; }
    S3.store("subnet.v6", raw);
    var c = v6calc(x.n, +p);
    st.className = "chip ok"; st.textContent = v6type(x.n);
    [
      item("Compressed", v6compress(x.n) + (x.zone ? "%" + x.zone : ""), { wide: true }),
      item("Expanded", v6expand(x.n), { wide: true }),
      item("Network", v6compress(c.network) + "/" + p, { wide: true }),
      item("First address", v6expand(c.network), { wide: true }),
      item("Last address", v6expand(c.last), { wide: true }),
      item("Addresses", bigFmt(c.count) + bigPow2(128 - c.prefix), { wide: true }),
      item("/64 subnets", c.n64 === null ? "less than one /64" : bigFmt(c.n64) + bigPow2(64 - c.prefix), { wide: true }),
      item("Reverse DNS", v6reverse(x.n), { wide: true })
    ].forEach(function (el) { box.appendChild(el); });
  }

  // ---------- wiring ----------
  $$("#splitmode button").forEach(function (b) {
    b.setAttribute("aria-pressed", String(b.dataset.v === splitMode));
    b.addEventListener("click", function () {
      splitMode = b.dataset.v; S3.store("subnet.split", splitMode);
      $$("#splitmode button").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      renderSplit();
    });
  });
  ipIn.addEventListener("input", S3.debounce(function () { renderV4(false); }, 120));
  maskSel.addEventListener("change", function () {
    var r = parseV4Input(ipIn.value);
    if (r && !r.error) { ipIn.value = v4str(r.ip) + "/" + maskSel.value; }
    renderV4(false);
  });
  $("#nsub").addEventListener("input", S3.debounce(renderSplit, 150));
  $("#vlsm").addEventListener("input", S3.debounce(renderSplit, 200));
  $("#chkip").addEventListener("input", renderCheck);
  $("#chkrange").addEventListener("input", renderCheck);
  $("#v6").addEventListener("input", S3.debounce(renderV6, 120));
  $("#v4copy").addEventListener("click", function () { if (current) { S3.copy(summaryText(current), "Summary copied"); S3.done(); } });
  function tableText(sep) {
    return splitRows.map(function (r) {
      return r.map(function (v) { return sep === "," && /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join(sep);
    }).join("\n");
  }
  $("#splitcopy").addEventListener("click", function () { if (splitRows.length) { S3.copy(tableText("\t"), "Table copied"); S3.done(); } else S3.toast("Nothing to copy yet", "error"); });
  $("#splitsave").addEventListener("click", function () {
    if (!splitRows.length) return S3.toast("Nothing to save yet", "error");
    S3.download(tableText(","), "subnets.csv", "text/csv"); S3.done();
  });
  $("#sample").addEventListener("click", function () {
    ipIn.value = "192.168.1.0/24"; renderV4(false);
    $("#v6").value = "2001:db8:abcd::1/48"; renderV6();
  });
  $("#clear").addEventListener("click", function () { ipIn.value = ""; renderV4(false); ipIn.focus(); });

  ipIn.value = S3.store("subnet.ip") || "192.168.1.0/26";
  $("#v6").value = S3.store("subnet.v6") || "2001:db8::1/64";
  renderV4(false); renderV6(); renderCheck();

  window.S3_DEMO = function () {
    ipIn.value = "192.168.10.0/24"; renderV4(false);
    $$("#splitmode button")[1].click();
    $("#v6").value = "2001:db8:abcd::42/48"; renderV6();
    $("#chkip").value = "192.168.10.77"; $("#chkrange").value = "192.168.10.64/27"; renderCheck();
  };

  // ---------- self-test with known answers ----------
  window.S3_SELFTEST = function () {
    var fails = [];
    function eq(name, a, b) { if (a !== b) fails.push(name + ": got " + String(a) + ", want " + String(b)); }
    var r = parseV4Input("192.168.1.0/26"), c = v4calc(r.ip, r.prefix);
    eq("/26 usable", c.usable, 62); eq("/26 broadcast", v4str(c.broadcast), "192.168.1.63");
    eq("/26 first", v4str(c.first), "192.168.1.1"); eq("/26 last", v4str(c.last), "192.168.1.62");
    eq("/26 mask", v4str(c.mask), "255.255.255.192"); eq("/26 wildcard", v4str(c.wildcard), "0.0.0.63");
    var r2 = parseV4Input("10.0.0.5 255.255.255.0"); eq("mask→prefix", r2.prefix, 24); eq("network", v4str(v4calc(r2.ip, 24).network), "10.0.0.0");
    eq("wildcard input", parseV4Input("10.0.0.5 0.0.0.255").prefix, 24);
    eq("/31 usable", v4calc(parseV4("10.0.0.0"), 31).usable, 2); eq("/32 usable", v4calc(parseV4("10.0.0.9"), 32).usable, 1);
    eq("/0 total", v4calc(parseV4("1.2.3.4"), 0).total, 4294967296);
    eq("bad mask", !!parseV4Input("1.1.1.1 255.0.255.0").error, true);
    eq("bad octet", parseV4("256.1.1.1"), null); eq("leading zero", parseV4("01.1.1.1"), null);
    var s = splitN(parseV4("192.168.1.0"), 24, 4);
    eq("split4", s.list.map(function (x) { return v4str(x.network) + "/" + x.prefix; }).join(","), "192.168.1.0/26,192.168.1.64/26,192.168.1.128/26,192.168.1.192/26");
    eq("split3 rounds", splitN(parseV4("10.0.0.0"), 8, 3).count, 4);
    var v = vlsm(parseV4("192.168.1.0"), 24, parseVlsm("2, 50, 10, 20").list);
    eq("vlsm", v.list.map(function (x) { return v4str(x.network) + "/" + x.prefix; }).join(","), "192.168.1.0/26,192.168.1.64/27,192.168.1.96/28,192.168.1.112/30");
    eq("vlsm overflow", !!vlsm(parseV4("10.0.0.0"), 28, parseVlsm("10, 10").list).error, true);
    eq("type private", v4type(parseV4("172.20.1.1")).label, "Private (RFC 1918)");
    eq("type cgnat", v4type(parseV4("100.64.0.1")).label, "Shared / carrier-grade NAT (RFC 6598)");
    eq("type public", v4type(parseV4("8.8.8.8")).pub, true);
    eq("expand", v6expand(parseV6("2001:db8::1").n), "2001:0db8:0000:0000:0000:0000:0000:0001");
    eq("compress tie", v6compress(parseV6("2001:0db8:0000:0000:0001:0000:0000:0001").n), "2001:db8::1:0:0:1");
    eq("compress single 0", v6compress(parseV6("2001:db8:0:1:1:1:1:1").n), "2001:db8:0:1:1:1:1:1");
    eq("compress all", v6compress(parseV6("::").n), "::");
    eq("compress longest", v6compress(parseV6("1:0:0:2:0:0:0:3").n), "1:0:0:2::3");
    eq("v4-mapped", v6compress(parseV6("::ffff:192.0.2.1").n), "::ffff:c000:201");
    eq("bad v6 9 groups", parseV6("1:2:3:4:5:6:7:8:9"), null); eq("bad v6 two ::", parseV6("1::2::3"), null);
    eq("bad v6 hex", parseV6("2001:db8::g"), null);
    eq("/48 /64s", v6calc(parseV6("2001:db8::").n, 48).n64.toString(), "65536");
    eq("/64 last", v6expand(v6calc(parseV6("2001:db8:1:2::9").n, 64).last), "2001:0db8:0001:0002:ffff:ffff:ffff:ffff");
    eq("v6 type doc", v6type(parseV6("2001:db8::1").n), "Documentation"); eq("v6 type ll", v6type(parseV6("fe80::1").n), "Link-local");
    eq("in v4", checkIn("10.1.2.3", "10.0.0.0/8").inside, true); eq("out v4", checkIn("11.0.0.1", "10.0.0.0/8").inside, false);
    eq("dash range", checkIn("192.168.1.50", "192.168.1.10 - 192.168.1.60").inside, true);
    eq("in v6", checkIn("2001:db8::5", "2001:db8::/32").inside, true); eq("out v6", checkIn("2001:db9::5", "2001:db8::/32").inside, false);
    eq("rdns", v6reverse(parseV6("2001:db8::1").n).slice(0, 8), "1.0.0.0.");
    return fails.length ? fails : true;
  };
})();
