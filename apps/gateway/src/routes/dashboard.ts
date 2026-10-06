/**
 * Read-only browser dashboard for the control plane.
 *
 * Threat model / guarantees:
 *
 * - The served shell is STATIC and contains no data, no secrets, and no
 *   server-rendered values. Everything displayed is fetched by the browser
 *   from the existing authenticated `/admin/*` API. This route therefore adds
 *   no new data path and does not weaken the control plane: an unauthenticated
 *   visitor gets a blank shell plus 401/403 responses from the API.
 * - The credential is supplied by the operator in the browser and kept in
 *   `sessionStorage` (cleared when the tab closes). It is never sent to the
 *   server by this route, never logged, and never embedded in the HTML.
 * - Rendering is XSS-safe by construction: every value built from API data is
 *   assigned via `textContent`. There is no `innerHTML` in the payload, so a
 *   hostile policy reason, tool argument, or audit detail is displayed as
 *   literal text rather than markup.
 * - A strict Content-Security-Policy is sent on every dashboard response:
 *   no inline script or style is permitted, so an injected `<script>` cannot
 *   execute even if one were somehow introduced.
 * - Assets are `no-store` so a stale shell never masks a real API failure.
 *
 * Deliberately read-only: approve/deny actions are not exposed here. They
 * remain on the operations CLI and `POST /admin/approvals/:id/{approve,deny}`,
 * where they are audited identically.
 */

import type { FastifyInstance, FastifyReply } from "fastify";

/**
 * `default-src 'none'` denies everything by default; each capability the page
 * genuinely needs is then opened explicitly. `frame-ancestors 'none'` plus
 * `base-uri 'none'` and `form-action 'none'` close the clickjacking/base-tag/
 * form-hijack vectors. No `'unsafe-inline'` anywhere: the shell uses external
 * same-origin assets only.
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

function harden(reply: FastifyReply): void {
  reply.header("content-security-policy", CONTENT_SECURITY_POLICY);
  reply.header("x-content-type-options", "nosniff");
  reply.header("referrer-policy", "no-referrer");
  reply.header("cache-control", "no-store");
}

const HTML = `
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>AegisMCP control plane</title>
<link rel="stylesheet" href="/dashboard/app.css">
</head>
<body>
<header class="masthead">
  <h1>AegisMCP control plane</h1>
  <p class="hint">
    Read-only view. Every value below is fetched from the authenticated
    <code>/admin</code> API using an agent credential you enter here. The
    credential is kept in this browser tab only (<code>sessionStorage</code>),
    is sent to this origin only, and is never stored on the server.
  </p>
</header>

<main>
  <section class="connect">
    <label for="key">Agent API key</label>
    <input id="key" type="password" autocomplete="off" spellcheck="false" placeholder="amcp_…">
    <button id="connect" type="button">Connect</button>
    <button id="refresh" type="button">Refresh</button>
    <button id="forget" type="button">Forget key</button>
    <span id="notice" class="notice" role="status" aria-live="polite"></span>
  </section>

  <div id="panels"></div>
</main>

<script src="/dashboard/app.js"></script>
</body>
</html>
`.trim();

/**
 * Vanilla JS, no dependencies, no build step.
 *
 * Security invariant: this script never uses innerHTML. All dynamic values are
 * written with textContent, so API-supplied strings are treated as text.
 */
const APP_JS = `
(function () {
  "use strict";

  var KEY_STORAGE = "aegis.dashboard.key";
  var apiKey = sessionStorage.getItem(KEY_STORAGE) || "";

  var panelsEl = document.getElementById("panels");
  var noticeEl = document.getElementById("notice");
  var keyInput = document.getElementById("key");

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function display(value) {
    if (value === undefined || value === null) return "\\u2014";
    return String(value);
  }

  function text(value) {
    if (value === undefined || value === null) return "\\u2014";
    if (typeof value === "object") {
      try { return JSON.stringify(value); } catch (err) { return "[unserializable]"; }
    }
    return String(value);
  }

  function table(columns, rows) {
    var wrapper = el("div", "scroll");
    var t = el("table");
    var thead = el("thead");
    var headRow = el("tr");
    for (var i = 0; i < columns.length; i++) headRow.appendChild(el("th", null, columns[i]));
    thead.appendChild(headRow);
    t.appendChild(thead);

    var tbody = el("tbody");
    for (var r = 0; r < rows.length; r++) {
      var tr = el("tr");
      for (var c = 0; c < columns.length; c++) {
        tr.appendChild(el("td", null, text(rows[r][columns[c]])));
      }
      tbody.appendChild(tr);
    }
    t.appendChild(tbody);
    wrapper.appendChild(t);
    return wrapper;
  }

  function keyValues(pairs) {
    var dl = el("dl", "kv");
    for (var i = 0; i < pairs.length; i++) {
      dl.appendChild(el("dt", null, pairs[i][0]));
      dl.appendChild(el("dd", null, display(pairs[i][1])));
    }
    return dl;
  }

  function panel(title, body) {
    var section = el("section", "panel");
    section.appendChild(el("h2", null, title));
    section.appendChild(body);
    return section;
  }

  function note(message, kind) {
    return el("p", kind || "note", message);
  }

  async function fetchJson(path) {
    var headers = {};
    if (apiKey) headers["X-API-Key"] = apiKey;

    var res = await fetch(path, { headers: headers, credentials: "omit" });
    var raw = await res.text();
    var body = null;
    try { body = raw === "" ? null : JSON.parse(raw); } catch (err) { body = null; }

    if (!res.ok) {
      var message = body && body.error && body.error.message
        ? body.error.message
        : "HTTP " + res.status;
      var failure = new Error(message);
      failure.status = res.status;
      throw failure;
    }
    return body;
  }

  function requireKey() {
    if (!apiKey) return note("Enter an agent API key to load this panel.");
    return null;
  }

  /* ------------------------------- status -------------------------------- */

  async function renderStatus() {
    var box = el("div");
    try {
      var health = await fetchJson("/health");
      var ready = await fetchJson("/ready");
      var metrics = await fetchJson("/metrics");

      box.appendChild(keyValues([
        ["Liveness", display(health && health.status)],
        ["Readiness", display(ready && ready.status)],
        ["Persistence", ready && ready.persistence ? "enabled" : "disabled"],
        ["Uptime (s)", metrics && metrics.uptimeSeconds],
        ["Active policies", metrics && metrics.policies ? metrics.policies.active : null],
        ["Pending approvals", metrics && metrics.approvals ? metrics.approvals.pending : null]
      ]));

      var counters = (metrics && metrics.counters) || {};
      var names = Object.keys(counters).sort();
      if (names.length === 0) {
        box.appendChild(note("No counters recorded yet."));
      } else {
        var rows = [];
        for (var i = 0; i < names.length; i++) {
          rows.push({ metric: names[i], value: counters[names[i]] });
        }
        box.appendChild(table(["metric", "value"], rows));
      }

      var audit = metrics && metrics.audit;
      if (audit) {
        box.appendChild(keyValues([
          ["Audit queued", audit.queued],
          ["Audit flushed", audit.flushed],
          ["Audit failed", audit.failed],
          ["Audit dropped", audit.dropped]
        ]));
      }
    } catch (err) {
      box.appendChild(note("Unavailable: " + err.message, "error"));
    }
    return box;
  }

  /* ------------------------------ identity ------------------------------- */

  async function renderIdentity() {
    var missing = requireKey();
    if (missing) return missing;

    try {
      var me = await fetchJson("/admin/me");
      var permissions = (me && me.permissions) || [];
      return keyValues([
        ["Agent id", me && me.agent ? me.agent.id : null],
        ["Agent name", me && me.agent ? me.agent.name : null],
        ["Role", me && me.role],
        ["Permissions", permissions.length === 0 ? "none (data plane only)" : permissions.join(", ")]
      ]);
    } catch (err) {
      return note("Unavailable: " + err.message, "error");
    }
  }

  /* ------------------------------ policies ------------------------------- */

  async function renderPolicies() {
    var missing = requireKey();
    if (missing) return missing;

    try {
      var page = await fetchJson("/admin/policies?limit=100");
      var items = (page && page.items) || [];
      if (items.length === 0) return note("No policies configured.");

      var rows = [];
      for (var i = 0; i < items.length; i++) {
        var p = items[i];
        rows.push({
          id: p.id,
          decision: p.decision,
          priority: p.priority === undefined ? 0 : p.priority,
          enabled: p.enabled === false ? "disabled" : "enabled",
          match: text(p.match),
          reason: p.reason
        });
      }
      var box = el("div");
      box.appendChild(note("Showing " + items.length + " of " + page.total + "."));
      box.appendChild(table(["id", "decision", "priority", "enabled", "match", "reason"], rows));
      return box;
    } catch (err) {
      return note("Unavailable: " + err.message, "error");
    }
  }

  /* ----------------------------- approvals ------------------------------- */

  async function renderApprovals() {
    var missing = requireKey();
    if (missing) return missing;

    var box = el("div");
    var controls = el("div", "controls");
    var select = el("select");
    var options = ["", "PENDING", "APPROVED", "DENIED", "EXPIRED"];
    for (var o = 0; o < options.length; o++) {
      var opt = el("option", null, options[o] === "" ? "All statuses" : options[o]);
      opt.value = options[o];
      select.appendChild(opt);
    }
    select.value = approvalsFilter;
    select.addEventListener("change", function () {
      approvalsFilter = select.value;
      load();
    });
    controls.appendChild(el("label", null, "Status"));
    controls.appendChild(select);
    box.appendChild(controls);

    try {
      var query = "/admin/approvals?limit=50";
      if (approvalsFilter) query += "&status=" + encodeURIComponent(approvalsFilter);
      var page = await fetchJson(query);
      var items = (page && page.items) || [];
      if (items.length === 0) {
        box.appendChild(note("No approvals match."));
        return box;
      }
      var rows = [];
      for (var i = 0; i < items.length; i++) {
        var a = items[i];
        rows.push({
          id: a.id,
          status: a.status,
          agent: a.agentId,
          tool: a.toolName,
          method: a.method,
          approver: a.approverId,
          expires: formatTime(a.expiresAt)
        });
      }
      box.appendChild(note("Showing " + items.length + " of " + page.total + "."));
      box.appendChild(table(["id", "status", "agent", "tool", "method", "approver", "expires"], rows));
    } catch (err) {
      box.appendChild(note("Unavailable: " + err.message, "error"));
    }
    return box;
  }

  /* -------------------------------- audit -------------------------------- */

  async function renderAudit() {
    var missing = requireKey();
    if (missing) return missing;

    try {
      var page = await fetchJson("/admin/audit?limit=50");
      var items = (page && page.items) || [];
      if (items.length === 0) return note("No audit events.");

      var rows = [];
      for (var i = 0; i < items.length; i++) {
        var e = items[i];
        rows.push({
          id: e.id,
          eventType: e.eventType,
          method: e.method,
          decision: e.decision,
          outcome: e.outcome,
          agent: e.agentId,
          latencyMs: e.latencyMs
        });
      }
      var box = el("div");
      box.appendChild(note("Showing " + items.length + " of " + page.total + "."));
      box.appendChild(
        table(["id", "eventType", "method", "decision", "outcome", "agent", "latencyMs"], rows)
      );
      return box;
    } catch (err) {
      return note("Unavailable: " + err.message, "error");
    }
  }

  /* -------------------------------- agents ------------------------------- */

  async function renderAgents() {
    var missing = requireKey();
    if (missing) return missing;

    try {
      var page = await fetchJson("/admin/agents?limit=100");
      var items = (page && page.items) || [];
      if (items.length === 0) return note("No agents registered.");

      var rows = [];
      for (var i = 0; i < items.length; i++) {
        rows.push({ id: items[i].id, name: items[i].name, role: items[i].role || "AGENT" });
      }
      var box = el("div");
      box.appendChild(note("Showing " + items.length + " of " + page.total + "."));
      box.appendChild(table(["id", "name", "role"], rows));
      return box;
    } catch (err) {
      return note("Unavailable: " + err.message, "error");
    }
  }

  /* ------------------------------ plumbing ------------------------------- */

  function formatTime(value) {
    if (value === undefined || value === null) return "\\u2014";
    var d = new Date(value);
    if (isNaN(d.getTime())) return String(value);
    return d.toISOString().replace("T", " ").replace(".000Z", "Z");
  }

  var approvalsFilter = "";

  var PANELS = [
    { title: "Gateway status", render: renderStatus },
    { title: "Your principal", render: renderIdentity },
    { title: "Policies", render: renderPolicies },
    { title: "Approvals", render: renderApprovals },
    { title: "Audit events", render: renderAudit },
    { title: "Agents", render: renderAgents }
  ];

  async function load() {
    noticeEl.textContent = "Loading\\u2026";
    noticeEl.className = "notice";
    panelsEl.replaceChildren();

    var results = await Promise.all(
      PANELS.map(function (config) {
        return config.render().then(
          function (body) { return { config: config, body: body }; },
          function (err) {
            return { config: config, body: note("Failed: " + err.message, "error") };
          }
        );
      })
    );

    for (var i = 0; i < results.length; i++) {
      panelsEl.appendChild(panel(results[i].config.title, results[i].body));
    }

    noticeEl.textContent = apiKey ? "Loaded with the supplied credential." : "Not connected.";
  }

  document.getElementById("connect").addEventListener("click", function () {
    var value = keyInput.value.trim();
    if (value) {
      apiKey = value;
      sessionStorage.setItem(KEY_STORAGE, apiKey);
      keyInput.value = "";
    }
    load();
  });

  document.getElementById("refresh").addEventListener("click", load);

  document.getElementById("forget").addEventListener("click", function () {
    apiKey = "";
    sessionStorage.removeItem(KEY_STORAGE);
    keyInput.value = "";
    load();
  });

  load();
})();
`.trim();

const APP_CSS = `
:root {
  color-scheme: light dark;
  --fg: #1a1a1a;
  --bg: #ffffff;
  --muted: #5b6470;
  --line: #d6dbe1;
  --accent: #1f5fbf;
  --error: #a12622;
  --panel: #f7f8fa;
}

@media (prefers-color-scheme: dark) {
  :root {
    --fg: #e6e8eb;
    --bg: #14171a;
    --muted: #9aa4b0;
    --line: #2c3238;
    --accent: #7aa7f0;
    --error: #f08a84;
    --panel: #1b1f23;
  }
}

* { box-sizing: border-box; }

body {
  margin: 0;
  padding: 1.5rem;
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.5 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
}

.masthead h1 { margin: 0 0 .35rem; font-size: 1.35rem; }
.hint { margin: 0 0 1.25rem; max-width: 78ch; color: var(--muted); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .92em; }

.connect {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: .5rem;
  padding: .85rem 1rem;
  margin-bottom: 1.25rem;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
}

.connect label { color: var(--muted); }
.connect input {
  flex: 1 1 22rem;
  min-width: 12rem;
  padding: .4rem .55rem;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--bg);
  color: var(--fg);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}

button {
  padding: .4rem .8rem;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--bg);
  color: var(--fg);
  cursor: pointer;
}
button:hover { border-color: var(--accent); }

.notice { color: var(--muted); margin-left: auto; }

.panel {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: .85rem 1rem 1rem;
  margin-bottom: 1rem;
  background: var(--panel);
}

.panel h2 { margin: 0 0 .6rem; font-size: 1rem; }

.note { color: var(--muted); margin: .3rem 0 .6rem; }
.error { color: var(--error); margin: .3rem 0 .6rem; }

.controls { display: flex; align-items: center; gap: .5rem; margin-bottom: .6rem; }
.controls label { color: var(--muted); }
.controls select {
  padding: .3rem .45rem;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--bg);
  color: var(--fg);
}

.scroll { overflow-x: auto; }

table { border-collapse: collapse; width: 100%; font-size: .92em; }
th, td {
  text-align: left;
  padding: .35rem .6rem;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
th { color: var(--muted); font-weight: 600; white-space: nowrap; }
td { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-word; }

.kv {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: .25rem 1rem;
  margin: 0 0 .75rem;
}
.kv dt { color: var(--muted); }
.kv dd { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
`.trim();

export async function dashboardRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.get("/dashboard", async (_request, reply) => {
    harden(reply);
    reply.type("text/html; charset=utf-8");
    return HTML;
  });

  fastify.get("/dashboard/app.js", async (_request, reply) => {
    harden(reply);
    reply.type("application/javascript; charset=utf-8");
    return APP_JS;
  });

  fastify.get("/dashboard/app.css", async (_request, reply) => {
    harden(reply);
    reply.type("text/css; charset=utf-8");
    return APP_CSS;
  });
}
