// starnix AUR mirror status page.
// All data comes from /status/*.json, which the untrusted build phase can
// write to, so it is rendered with textContent only (never innerHTML).
"use strict";

const LIVE_MS = 10000;
const DATA_MS = 60000;
const PHASES = ["scan", "build", "sign"];

const REASONS = {
  scan: "Review",
  build_error: "Build failed",
  build_timeout: "Timed out",
  trivy: "Trivy",
  no_artifacts: "No packages",
  hash_mismatch: "Recipe changed",
  fetch_error: "Fetch failed",
  publish_error: "Publish failed",
  build_failed: "Known failure",
};

const RESULTS = {
  published: ["published", "ok"],
  unchanged: ["rebuilt, same version", ""],
  stale: ["superseded", ""],
  failed: ["failed", "bad"],
  held: ["held", "warn"],
  backoff: ["backoff", "warn"],
  uptodate: ["up to date", ""],
};

const state = { packages: null, runs: null, live: null, filter: "all", query: "",
                sort: { key: "name", dir: 1 } };

// ---- helpers --------------------------------------------------------------

function el(tag, props, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

function $(id) { return document.getElementById(id); }

function safeHref(url) {
  // Only same-site /status/ links or http(s) upstream URLs are linked.
  if (typeof url !== "string") return null;
  if (url.startsWith("/status/")) return url;
  return /^https?:\/\//i.test(url) ? url : null;
}

function now() { return Math.floor(Date.now() / 1000); }

function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, now() - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function dur(sec) {
  if (sec === null || sec === undefined) return "";
  sec = Math.round(sec);
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

function stamp(ts) { return ts ? new Date(ts * 1000).toLocaleString() : ""; }

function badge(label, tone) { return el("span", { class: `badge ${tone || ""}`.trim(), text: label }); }

function logLink(url, label) {
  const href = safeHref(url);
  return href ? el("a", { class: "log", href, target: "_blank", rel: "noopener", text: label || "log" }) : "";
}

function links(pkg, log) {
  // PKGBUILD (AUR cgit or GitHub) then the build/scan log, in one cell.
  const href = safeHref(pkg && pkg.pkgbuild_url);
  const recipe = href ? el("a", { class: "log", href, target: "_blank", rel: "noopener noreferrer",
                                  title: "Recipe at the commit shown on this row", text: "PKGBUILD" }) : "";
  return el("td", { class: "links" }, recipe, logLink(log));
}

function pkgByName(name) {
  const pkgs = (state.packages && state.packages.packages) || [];
  return pkgs.find((p) => p.name === name);
}

function when(ts) { return el("span", { class: "when", title: stamp(ts), text: ago(ts) }); }

async function fetchJSON(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

function fill(tbody, rows, emptyId) {
  tbody.replaceChildren(...rows);
  if (emptyId) $(emptyId).hidden = rows.length > 0;
}

// ---- live panel -------------------------------------------------------------

function renderLive() {
  const live = state.live;
  const run = state.packages && state.packages.run;
  const dot = $("live-dot");
  const steps = document.querySelectorAll("#live-steps li");
  const running = live && live.phase && live.phase !== "idle" && now() - (live.updated_at || 0) < 12 * 3600;
  steps.forEach((li) => { li.className = ""; li.querySelector("span").textContent = li.dataset.default || li.querySelector("span").textContent; });

  if (!running) {
    dot.className = "dot";
    $("live-title").textContent = "Idle";
    $("live-meta").textContent = run && run.finished_at
      ? `Last run finished ${ago(run.finished_at)}, took ${dur(run.finished_at - run.started_at)}`
      : "No completed run yet";
    $("live-progress").hidden = true;
    return;
  }
  const quiet = now() - live.updated_at;
  dot.className = quiet > 3 * 3600 ? "dot stale" : "dot run";
  const phaseIdx = PHASES.indexOf(live.phase);
  $("live-title").textContent = `Running: ${live.phase}`;
  $("live-meta").textContent = `started ${ago(live.started_at)}`;
  steps.forEach((li, i) => {
    if (i < phaseIdx) li.className = "done";
    if (i === phaseIdx) {
      li.className = "now";
      if (live.package) li.querySelector("span").textContent = live.package;
    }
  });
  const total = live.total || 0;
  const cur = Math.min(live.current || 0, total);
  $("live-progress").hidden = total === 0;
  $("live-fill").style.width = total ? `${(100 * cur) / total}%` : "0";
  const on = live.package ? ` · ${live.package} for ${dur(quiet)}` : "";
  $("live-count").textContent = `${cur} / ${total}${on}`;
}

// ---- tiles ------------------------------------------------------------------

function renderTiles() {
  const c = (state.packages && state.packages.counts) || {};
  const tile = (n, label, tone, filter) => {
    const b = el("button", { type: "button", class: `tile ${tone}`.trim(), "data-filter": filter },
      el("span", { class: "n", text: n === undefined ? "–" : n }), el("span", { class: "l", text: label }));
    b.addEventListener("click", () => { setFilter(filter); $("packages").scrollIntoView({ behavior: "smooth" }); });
    return b;
  };
  $("tiles").replaceChildren(
    tile(c.total, "packages", "", "all"),
    tile(c.ok, "published", "ok", "all"),
    tile(c.held, "held", c.held ? "bad" : "", "held"),
    tile(c.behind, "behind upstream", c.behind ? "warn" : "", "behind"),
  );
}

// ---- held -------------------------------------------------------------------

function reasonBadge(hold) {
  if (!hold) return "";
  const label = REASONS[hold.reason] || hold.reason || "held";
  const tone = hold.reason === "scan" && /high|critical/.test(hold.risk || "") ? "bad" : "warn";
  const extra = hold.reason === "scan" && hold.risk ? ` · ${hold.risk}` : "";
  return badge(label + extra, tone);
}

function renderHeld() {
  const pkgs = ((state.packages && state.packages.packages) || []).filter((p) => p.status === "held");
  pkgs.sort((a, b) => (a.failing_since || 0) - (b.failing_since || 0));
  const rows = pkgs.map((p) => el("tr", {},
    el("td", { class: "name", text: p.name }),
    el("td", {}, reasonBadge(p.hold)),
    el("td", {}, when(p.failing_since)),
    el("td", { class: "num", text: p.streak ? `×${p.streak}` : "" }),
    el("td", { class: "detail", title: (p.hold && p.hold.summary) || "", text: (p.hold && p.hold.summary) || "" }),
    links(p, p.log),
  ));
  fill($("held-table").tBodies[0], rows, "held-empty");
}

// ---- recent builds ------------------------------------------------------------

function renderBuilds() {
  const rows = [];
  for (const run of (state.runs && state.runs.runs) || []) {
    for (const ev of run.events || []) {
      if (ev.owner || ev.result === "uptodate") continue;
      rows.push({ ...ev, ts: run.finished_at });
    }
  }
  const trs = rows.slice(0, 60).map((ev) => {
    const [label, tone] = RESULTS[ev.result] || [ev.result, ""];
    const why = ev.reason ? ` · ${REASONS[ev.reason] || ev.reason}` : "";
    return el("tr", {},
      el("td", { class: "name", text: ev.name }),
      el("td", { title: ev.summary || "" }, badge(label + (ev.result === "failed" || ev.result === "held" ? why : ""), tone)),
      el("td", { class: "mono", text: ev.version || "" }),
      el("td", { class: "num", text: dur(ev.duration) }),
      el("td", {}, when(ev.ts)),
      links(pkgByName(ev.name), ev.log),
    );
  });
  fill($("builds-table").tBodies[0], trs, "builds-empty");
}

// ---- packages table ---------------------------------------------------------------

const STATUS_ORDER = { held: 0, pending: 1, ok: 2 };

function statusCell(p) {
  if (p.status === "held") return reasonBadge(p.hold);
  if (p.status === "pending") return badge("not built yet", "info");
  return badge("published", "ok");
}

function matches(p) {
  if (state.filter === "held" && p.status !== "held") return false;
  if (state.filter === "behind" && !p.behind) return false;
  if (state.filter === "first" && !p.first_party) return false;
  if (!state.query) return true;
  const hay = `${p.name} ${p.pkgbase} ${p.description}`.toLowerCase();
  return hay.includes(state.query);
}

function sortValue(p, key) {
  if (key === "status") return STATUS_ORDER[p.status] ?? 9;
  if (key === "builddate") return p.builddate || 0;
  return (p[key] || "").toString().toLowerCase();
}

function renderPackages() {
  const all = (state.packages && state.packages.packages) || [];
  const { key, dir } = state.sort;
  const list = all.filter(matches).sort((a, b) => {
    const x = sortValue(a, key);
    const y = sortValue(b, key);
    return (x < y ? -1 : x > y ? 1 : 0) * dir || a.name.localeCompare(b.name);
  });
  const rows = list.map((p) => {
    const name = el("td", {},
      el("span", { class: "name", text: p.name }),
      p.first_party ? el("span", { class: "badge info tag", text: "first-party" }) : "",
      el("span", { class: "desc", title: p.description || "", text: p.description || "" }));
    const ver = el("td", {},
      el("span", { class: "mono", text: p.version || "—" }),
      p.behind ? el("span", { class: "behind", text: `upstream ${p.upstream_version}` }) : "");
    return el("tr", {}, name, ver, el("td", {}, statusCell(p)),
      el("td", {}, p.builddate ? when(p.builddate) : el("span", { class: "when", text: "—" })),
      links(p, p.log));
  });
  fill($("pkg-table").tBodies[0], rows, "pkg-empty");
  $("pkg-count").textContent = `${list.length} of ${all.length} shown`;
  document.querySelectorAll("#pkg-table th button").forEach((b) => {
    if (b.dataset.sort === key) b.setAttribute("aria-sort", dir > 0 ? "ascending" : "descending");
    else b.removeAttribute("aria-sort");
  });
}

function setFilter(filter) {
  state.filter = filter;
  document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c.dataset.filter === filter));
  renderPackages();
}

// ---- runs ---------------------------------------------------------------------

function renderRuns() {
  const rows = ((state.runs && state.runs.runs) || []).slice(0, 30).map((r) => {
    const c = r.counts || {};
    const s = r.scan || {};
    return el("tr", {},
      el("td", { title: r.id, text: stamp(r.started_at) }),
      el("td", { class: "num", text: dur((r.finished_at || 0) - (r.started_at || 0)) }),
      el("td", { class: "num", text: s.scanned || 0 }),
      el("td", { class: "num", text: c.published || 0 }),
      el("td", { class: "num", text: c.failed || 0 }),
      el("td", { class: "num", text: (c.held || 0) + (c.backoff || 0) }),
    );
  });
  fill($("runs-table").tBodies[0], rows);
}

// ---- usage snippets -------------------------------------------------------------

function renderUse() {
  const repo = (state.packages && state.packages.repo) || {};
  const server = repo.server || location.origin;
  const name = repo.name || "aur-mirror";
  const key = repo.key_id || "<KEY-ID>";
  $("key-snippet").textContent =
    `curl -fsSL ${server}${repo.key_url || "/status/aur-mirror.asc"} | sudo pacman-key --add -\n` +
    `sudo pacman-key --lsign-key ${key}`;
  $("conf-snippet").textContent = `[${name}]\nSigLevel = Required\nServer = ${server}`;
}

// ---- wiring -------------------------------------------------------------------

function renderAll() {
  renderLive();
  renderTiles();
  renderHeld();
  renderBuilds();
  renderPackages();
  renderRuns();
  renderUse();
  const gen = state.packages && state.packages.generated_at;
  $("updated").textContent = gen ? `Status generated ${stamp(gen)}` : "";
}

async function loadData() {
  const [pkgs, runs] = await Promise.allSettled([
    fetchJSON("/status/packages.json"), fetchJSON("/status/runs.json")]);
  if (pkgs.status === "fulfilled") state.packages = pkgs.value;
  if (runs.status === "fulfilled") state.runs = runs.value;
  renderAll();
}

async function loadLive() {
  try {
    const live = await fetchJSON("/status/live.json");
    const wasRunning = state.live && state.live.phase !== "idle";
    state.live = live;
    if (wasRunning && live.phase === "idle") await loadData();
  } catch (_err) {
    state.live = null;
  }
  renderLive();
}

function init() {
  $("search").addEventListener("input", (e) => { state.query = e.target.value.trim().toLowerCase(); renderPackages(); });
  document.querySelectorAll(".chip").forEach((c) => c.addEventListener("click", () => setFilter(c.dataset.filter)));
  document.querySelectorAll("#pkg-table th button").forEach((b) => b.addEventListener("click", () => {
    const key = b.dataset.sort;
    state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : 1 };
    renderPackages();
  }));
  document.querySelectorAll(".copy").forEach((b) => b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($(b.dataset.copy).textContent);
      b.textContent = "Copied";
      setTimeout(() => { b.textContent = "Copy"; }, 1500);
    } catch (_err) { b.textContent = "Select and copy"; }
  }));
  document.querySelectorAll("#live-steps li").forEach((li) => { li.dataset.default = li.querySelector("span").textContent; });
  loadData().then(loadLive);
  setInterval(loadLive, LIVE_MS);
  setInterval(loadData, DATA_MS);
  setInterval(renderLive, 30000);
}

document.addEventListener("DOMContentLoaded", init);
