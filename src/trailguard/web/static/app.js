// TrailGuard dashboard. No build step; talks to the FastAPI app in trailguard/web/app.py.
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = async (path, opts = {}) => {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `${r.status} ${r.statusText}`);
  const ct = r.headers.get("content-type") || "";
  return ct.includes("json") ? r.json() : r.text();
};

const LANES = [
  { key: "login-agent", label: "Login" },
  { key: "device-agent", label: "Device" },
  { key: "recovery-agent", label: "Recovery & support" },
  { key: "payments-agent", label: "Payments" },
  { key: "sentinel", label: "Sentinel" },
];
const laneIndex = Object.fromEntries(LANES.map((l, i) => [l.key, i]));
const TTP = { credential_stuffing: "Credential stuffing", sim_swap: "SIM swap", session_hijack: "Session hijack",
  mule_ring: "Mule ring", low_and_slow: "Low and slow" };
const GATE = { transfer: "transfer", payee_add: "new payee", login_success: "new-device login", phone_change: "phone change",
  email_change: "email change", password_reset_complete: "password reset", mfa_device_added: "new 2FA device", card_test: "card test" };
const ACTION = { ALLOW: "Allow", STEP_UP: "Step-up", HOLD: "Hold", BLOCK: "Block" };
const WINDOW = 170;

/* ---------- status & tabs ---------- */
let status = null;
async function loadStatus() {
  try {
    status = await api("/api/status");
    const off = status.backend !== "meko-cloud";
    $("#context").innerHTML = `Context layer <b class="${off ? "offline" : ""}">${esc(status.backend_label)}</b><br>` +
      `Decider <b>${esc(status.decider)}</b>`;
    for (const id of ["#dec-run", "#learn-run", "#audit-run"]) fillRuns($(id));
  } catch (e) {
    $("#context").textContent = `Can't reach the TrailGuard server: ${e.message}`;
  }
}
function fillRuns(sel) {
  const cur = sel.value;
  sel.innerHTML = (status?.runs || []).map((r) => `<option>${esc(r)}</option>`).join("") || "<option value=''>No runs yet</option>";
  if (cur && status.runs.includes(cur)) sel.value = cur;
}
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
function show(view) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.view === view)));
  document.querySelectorAll(".view").forEach((v) => (v.hidden = v.id !== `view-${view}`));
  if (view === "decision") loadDecisionList();
  if (view === "learn") loadLearnings();
  if (view === "results") loadResults();
  if (view === "audit") loadAudit();
}

/* ---------- live run ---------- */
let S = null;
function resetLive() {
  S = { cur: 0, eventIdx: new Map(), sigs: [], threads: [], decisions: [], flags: [], attacks: new Map(),
        counts: { stopped: 0, early: 0, completed: 0, signals: 0, reads: 0, decisions: 0 } };
  $("#feed").innerHTML = "";
  $("#attacks").innerHTML = "";
  updateScore();
  render();
}
$("#runform").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const body = { mode: f.get("mode"), seed: +f.get("seed"), epoch: +f.get("epoch"), events: +f.get("events"), pace: +f.get("pace") };
  const btn = $("#startbtn");
  btn.disabled = true;
  btn.textContent = "Running…";
  resetLive();
  try {
    const { run_id } = await api("/api/runs", { method: "POST", body: JSON.stringify(body) });
    listen(run_id);
  } catch (e) {
    $("#attack-hint").textContent = `Couldn't start the run: ${e.message}`;
    btn.disabled = false;
    btn.textContent = "Start run";
  }
});

function listen(runId) {
  const es = new EventSource(`/api/runs/${encodeURIComponent(runId)}/stream`);
  const on = (k, fn) => es.addEventListener(k, (m) => fn(JSON.parse(m.data)));
  on("meta", (m) => ($("#attack-hint").textContent = `${m.attacks} takeover attempts are planted in ${m.events} events. They appear here as they start.`));
  on("start", (m) => { S.mode = m.mode; S.patterns = m.patterns; });
  on("event", (e) => {
    S.cur = e.idx;
    S.eventIdx.set(e.event_id, e.idx);
    if (e.attack_id) {
      const a = S.attacks.get(e.attack_id) || { id: e.attack_id, ttp: e.ttp, account: e.account, steps: new Set(), state: "live" };
      a.steps.add(e.step);
      if (e.completes) a.completion = e.step;
      S.attacks.set(e.attack_id, a);
      drawAttacks();
    }
    schedule();
  });
  on("signal_written", (s) => {
    S.counts.signals++;
    S.sigs.push({ idx: S.cur, lane: laneIndex[s.agent] ?? 4, high: s.weight >= 30, event_id: s.event_id });
    updateScore(); schedule();
  });
  on("signal_read", (r) => {
    const from = S.eventIdx.get(r.event_id);
    if (from === undefined || laneIndex[r.agent] === undefined) return;
    S.counts.reads++;
    S.threads.push({ from, fromLane: laneIndex[r.agent], to: S.cur, toLane: laneIndex[r.reader] });
    updateScore(); schedule();
  });
  on("decision", (d) => {
    S.counts.decisions++;
    S.decisions.push({ idx: S.cur, decision: d.decision });
    addFeed(d, runId);
    updateScore(); schedule();
  });
  on("interdiction", (i) => {
    const a = S.attacks.get(i.attack_id);
    if (a) { a.state = "stopped"; a.stoppedAt = i.step; if (i.completion_step != null) a.completion = i.completion_step; }
    if (i.completion_step == null || i.step <= i.completion_step) S.counts.stopped++;
    if (i.completion_step != null && i.step < i.completion_step) S.counts.early++;
    drawAttacks(); updateScore();
  });
  on("takeover_completed", (t) => {
    const a = S.attacks.get(t.attack_id);
    if (a) a.state = "done";
    S.counts.completed++;
    S.flags.push({ idx: S.cur });
    drawAttacks(); updateScore(); schedule();
  });
  on("metrics", (m) => {
    S.counts.early = m.prevented_early;
    updateScore();
    $("#attack-hint").textContent = `Run finished: ${m.prevented} of ${m.attacks} takeovers stopped before they completed, ` +
      `${m.fp_hold_block} genuine customers held or blocked, ${m.decisions} decisions.`;
  });
  on("error", (e) => ($("#attack-hint").textContent = `The run stopped with an error: ${e.detail}`));
  on("closed", () => {
    es.close();
    $("#startbtn").disabled = false;
    $("#startbtn").textContent = "Start run";
    loadStatus();
  });
  es.onerror = () => { es.close(); $("#startbtn").disabled = false; $("#startbtn").textContent = "Start run"; };
}

function updateScore() {
  for (const [k, v] of Object.entries(S.counts)) $(`#s-${k}`).textContent = v;
}

function addFeed(d, runId) {
  const li = document.createElement("li");
  const truth = d.truth.attack_id ? `attack: ${TTP[d.truth.ttp] || d.truth.ttp}` : "genuine customer";
  li.innerHTML = `<span class="pill ${d.decision}">${ACTION[d.decision]}</span>` +
    `<span class="what">${esc(GATE[d.gate] || d.gate)} on ${esc(d.account)} · risk ${d.risk}</span>` +
    `<span class="when">${esc(truth)}</span>`;
  li.tabIndex = 0;
  const open = () => { show("decision"); setTimeout(() => openDecision(runId, d.n), 50); };
  li.addEventListener("click", open);
  li.addEventListener("keydown", (e) => e.key === "Enter" && open());
  const feed = $("#feed");
  feed.prepend(li);
  while (feed.children.length > 12) feed.lastChild.remove();
}

function drawAttacks() {
  const rows = [...S.attacks.values()].sort((a, b) => (a.state === "live") - (b.state === "live"));
  $("#attacks").innerHTML = rows.map((a) => {
    const total = Math.max(a.completion ?? 0, ...a.steps) + 1;
    const bars = Array.from({ length: total }, (_, i) => {
      let c = a.steps.has(i) ? "seen" : "";
      if (a.state === "stopped" && i === a.stoppedAt) c = "stopped";
      if (a.state === "done" && i === a.completion) c = "done";
      return `<i class="${c}" title="step ${i + 1}${i === a.completion ? " (takeover completes)" : ""}"></i>`;
    }).join("");
    let label = "in progress";
    if (a.state === "stopped") {
      const early = (a.completion ?? a.stoppedAt) - a.stoppedAt;
      label = a.completion === undefined ? `stopped at step ${a.stoppedAt + 1}`
        : early > 0 ? `stopped ${early} step${early > 1 ? "s" : ""} before takeover` : "stopped at the last moment";
    }
    if (a.state === "done") label = "takeover completed";
    return `<li><span class="who">${esc(TTP[a.ttp] || a.ttp)} on ${esc(a.account)}</span>` +
      `<span class="state ${a.state}">${label}</span><span class="steps">${bars}</span></li>`;
  }).join("");
}

/* ---------- the trail (SVG) ---------- */
let pending = false;
function schedule() { if (!pending) { pending = true; requestAnimationFrame(() => { pending = false; render(); }); } }
function render() {
  const svg = $("#trail");
  const w = svg.clientWidth || 900, h = svg.clientHeight || 330;
  const left = Math.min(150, w * 0.28), right = 16, top = 22, bottom = 22;
  const laneH = (h - top - bottom) / (LANES.length - 1);
  const y = (lane) => top + lane * laneH;
  const lo = Math.max(0, (S?.cur || 0) - WINDOW);
  const x = (idx) => left + ((idx - lo) / WINDOW) * (w - left - right);
  const vis = (idx) => idx >= lo;
  const parts = [];
  LANES.forEach((l, i) => {
    parts.push(`<line class="lane" x1="${left - 6}" x2="${w - right}" y1="${y(i)}" y2="${y(i)}"/>`);
    parts.push(`<text class="lane-label" x="0" y="${y(i) + 4}">${esc(l.label)}</text>`);
  });
  if (S) {
    for (const f of S.flags) if (vis(f.idx)) parts.push(`<line class="done" x1="${x(f.idx)}" x2="${x(f.idx)}" y1="${top - 10}" y2="${h - bottom + 8}"/><circle class="done-head" cx="${x(f.idx)}" cy="${top - 10}" r="4"/>`);
    for (const t of S.threads) {
      if (!vis(t.to)) continue;
      const x1 = x(Math.max(t.from, lo)), x2 = x(t.to), y1 = y(t.fromLane), y2 = y(t.toLane);
      const mx = (x1 + x2) / 2;
      parts.push(`<path class="thread" d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}"/>`);
    }
    for (const s of S.sigs) if (vis(s.idx)) parts.push(`<circle class="sig${s.high ? " high" : ""}" cx="${x(s.idx)}" cy="${y(s.lane)}" r="${s.high ? 4.5 : 3.5}"/>`);
    for (const d of S.decisions) {
      if (!vis(d.idx)) continue;
      const cx = x(d.idx), cy = y(4), r = 7;
      parts.push(`<path class="dia ${d.decision}" d="M${cx},${cy - r} L${cx + r},${cy} L${cx},${cy + r} L${cx - r},${cy} Z"><title>${ACTION[d.decision]}</title></path>`);
    }
    parts.push(`<line class="now" x1="${x(S.cur)}" x2="${x(S.cur)}" y1="${top - 12}" y2="${h - bottom + 10}"/>`);
  }
  svg.innerHTML = parts.join("");
}
window.addEventListener("resize", schedule);

/* ---------- explain a decision ---------- */
async function loadDecisionList() {
  const runSel = $("#dec-run");
  if (!runSel.value) return;
  const list = await api(`/api/runs/${encodeURIComponent(runSel.value)}/decisions`);
  $("#dec-n").innerHTML = list.map((d) => `<option value="${d.n}">#${d.n} ${ACTION[d.decision]} · ${esc(GATE[d.gate] || d.gate)} on ${esc(d.account)} (risk ${d.risk})</option>`).join("");
  if (list.length) openDecision(runSel.value, +$("#dec-n").value);
}
$("#dec-run").addEventListener("change", loadDecisionList);
$("#dec-n").addEventListener("change", () => openDecision($("#dec-run").value, +$("#dec-n").value));

async function openDecision(runId, n) {
  if ($("#dec-run").value !== runId) {
    $("#dec-run").value = runId;
    await loadDecisionList();
  }
  $("#dec-n").value = String(n);
  const { card: c, record: r } = await api(`/api/runs/${encodeURIComponent(runId)}/decisions/${n}`);
  const knew = c.what_agents_knew.map((k) => `<li><div><span class="pts">+${k.points}</span> The <b>${esc(k.agent)}</b> saw ${esc(k.what)}.</div>` +
    `<div class="meta">${esc(k.when)}${k.detail ? ` · ${esc(k.detail)}` : ""}${k.memory_id ? ` · Meko memory ${esc(k.memory_id.slice(0, 8))}` : ""}</div></li>`).join("");
  const refs = c.meko_refs || {};
  $("#story").innerHTML = `
    <div class="verdict"><span class="pill ${c.decision}">${ACTION[c.decision]}</span><span class="risk">risk ${c.risk} out of 100</span></div>
    <h2 class="headline">${esc(c.headline)}</h2>
    <section><h3>What happened</h3><p>${esc(c.what_happened)}</p></section>
    <section><h3>What the agents already knew</h3><ol class="timeline">${knew}</ol></section>
    <section><h3>The rule applied</h3>${c.rule.map((x) => `<p>${esc(x)}</p>`).join("")}</section>
    ${c.pattern ? `<section><h3>Pattern recognised</h3><p>${esc(c.pattern)}</p></section>` : ""}
    ${c.model_explanation ? `<section><h3>In the Sentinel's words</h3><p>${esc(c.model_explanation)}</p></section>` : ""}
    <section><h3>What happened next</h3><p>${esc(c.what_next)}</p></section>
    <p class="reality">${esc(c.reality)} Decided by ${esc(c.decider)}${c.fallback ? " (model reply unusable, written policy applied)" : ""}.
    ${refs.message_id ? `Meko decision trace: conversation ${esc(refs.conversation_id)}, message ${esc(refs.message_id)}.` : ""}</p>
    <details><summary>Raw trace record</summary><pre>${esc(JSON.stringify(r, null, 2))}</pre></details>`;
}

/* ---------- learnings ---------- */
$("#learnbtn").addEventListener("click", async () => {
  const runId = $("#learn-run").value;
  if (!runId) return;
  const b = $("#learnbtn");
  b.disabled = true;
  try { await api("/api/learn", { method: "POST", body: JSON.stringify({ run_id: runId }) }); }
  catch (e) { $("#pending").innerHTML = `<p class="hint">Couldn't create patterns: ${esc(e.message)}</p>`; }
  b.disabled = false;
  loadLearnings();
});
function patternRow(p, actions) {
  const iocs = Object.entries(p.iocs).filter(([, v]) => v.length).map(([k, v]) => `${k.replace("_", " ")}: ${v.slice(0, 4).join(", ")}${v.length > 4 ? "…" : ""}`).join(" · ");
  return `<div class="pattern"><div><b>${esc(TTP[p.ttp] || p.ttp)}</b> <span class="seq">${esc(p.sequence.map((s) => s.replaceAll("_", " ")).join(" → "))}</span>` +
    `<div class="iocs">${esc(iocs)}</div><div class="iocs">${esc(p.action)}</div></div>${actions}</div>`;
}
async function loadLearnings() {
  fillRuns($("#learn-run"));
  const { pending, approved } = await api("/api/learnings");
  $("#pending").innerHTML = pending.length ? pending.map((x) => patternRow(x.pattern,
    `<div class="actions"><button class="primary" data-approve="${esc(x.memory_id)}">Approve</button><button data-reject="${esc(x.memory_id)}">Keep private</button></div>`)).join("") +
    `<p style="margin-top:12px"><button data-approve-all>Approve all ${pending.length}</button></p>`
    : `<p class="hint">No candidates waiting. Pick a finished run above and create candidate patterns.</p>`;
  $("#approved").innerHTML = approved.length ? approved.map((p) => patternRow(p, "")).join("")
    : `<p class="hint">Nothing approved yet. Approved patterns are used by runs in "Meko + approved patterns" mode.</p>`;
}
$("#view-learn").addEventListener("click", async (e) => {
  const t = e.target;
  let body = null, path = "/api/learnings/approve";
  if (t.dataset.approve) body = { ids: [t.dataset.approve] };
  else if (t.dataset.reject) { body = { ids: [t.dataset.reject] }; path = "/api/learnings/reject"; }
  else if ("approveAll" in t.dataset) body = { all: true };
  if (!body) return;
  t.disabled = true;
  await api(path, { method: "POST", body: JSON.stringify(body) });
  loadLearnings();
});

/* ---------- results ---------- */
const MODE_LABEL = { isolated: "Isolated", stuffed: "Paste everything", meko: "Meko", "meko+patterns": "Meko + patterns" };
const MODE_CLASS = { isolated: "base", stuffed: "stuffed", meko: "", "meko+patterns": "learned" };
function bars(rows, key, fmt, title, note) {
  const max = Math.max(...rows.map((r) => r[key]), 1e-9);
  return `<div class="chart"><h3>${title}</h3><p>${note}</p>` + rows.map((r) =>
    `<div class="bar-row"><span class="label">${r.epoch === 2 ? "Epoch 2 · " : ""}${MODE_LABEL[r.mode]}</span>` +
    `<div class="bar ${MODE_CLASS[r.mode]}" style="width:${(100 * r[key]) / max}%"></div><span class="val">${fmt(r[key])}</span></div>`).join("") + "</div>";
}
async function loadResults() {
  const b = await api("/api/bench");
  if (!b.available) return;
  const agg = b.aggregate;
  const e1 = agg.filter((a) => a.epoch === 1), e2 = agg.filter((a) => a.epoch === 2);
  const pct = (v) => `${Math.round(v * 100)}%`;
  const est = agg.some((a) => a.tokens_estimated);
  $("#results").innerHTML =
    `<p class="hint">Context layer: <b>${esc(b.backend === "meko-cloud" ? "Meko Cloud" : "offline stand-in (not Meko)")}</b> · decider ${esc(b.decider)} · seeds ${esc(b.seeds.join(", "))} · ${b.n_events} events per stream</p>` +
    `<ul class="headlines">${(b.headlines || []).map((h) => `<li>${esc(h)}</li>`).join("")}</ul>` +
    bars(e1, "recall", pct, "Takeovers stopped before they completed", "Epoch 1. Higher is better.") +
    bars(e1, "steps_early_mean", (v) => v.toFixed(2), "How early they were stopped", "Average attack steps left before the takeover would have completed.") +
    bars(e1, "tokens_per_decision", (v) => Math.round(v).toLocaleString(), "Model tokens per decision", est ? "Estimated from prompt size (offline decider)." : "Measured from Claude's usage.") +
    bars(e2, "steps_early_mean", (v) => v.toFixed(2), "Learning: new victims, same attackers", "Epoch 2. Meko + patterns uses analyst-approved patterns from epoch 1.") +
    `<div class="tablewrap"><table><thead><tr><th>Epoch</th><th>Context</th><th>Stopped</th><th>Steps early</th><th>Genuine held</th><th>Genuine stepped up</th><th>Decisions</th><th>Tokens / decision</th><th>Meko retrievals</th><th>Cost $</th></tr></thead><tbody>` +
    agg.map((a) => `<tr><td>${a.epoch}</td><td>${MODE_LABEL[a.mode]}</td><td>${pct(a.recall)}</td><td>${a.steps_early_mean.toFixed(2)}</td><td>${a.fp_hold_block.toFixed(1)}</td><td>${a.fp_stepup.toFixed(1)}</td><td>${Math.round(a.decisions)}</td><td>${Math.round(a.tokens_per_decision).toLocaleString()}</td><td>${Math.round(a.meko_retrievals)}</td><td>${a.cost_usd.toFixed(3)}</td></tr>`).join("") +
    `</tbody></table></div>`;
}
$("#benchbtn").addEventListener("click", async () => {
  const b = $("#benchbtn");
  b.disabled = true;
  b.textContent = "Running benchmark…";
  try { await api("/api/bench?seeds=1-2&events=1000", { method: "POST" }); await loadResults(); }
  catch (e) { $("#results").innerHTML = `<p class="hint">${esc(e.message)}</p>`; }
  b.disabled = false;
  b.textContent = "Run a quick offline benchmark";
});

/* ---------- audit ---------- */
async function loadAudit() {
  fillRuns($("#audit-run"));
  const runId = $("#audit-run").value;
  if (!runId) return;
  const md = await api(`/api/runs/${encodeURIComponent(runId)}/audit`);
  $("#report").innerHTML = window.marked ? window.marked.parse(md) : `<pre>${esc(md)}</pre>`;
  const dl = $("#audit-dl");
  dl.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
  dl.download = `audit-${runId}.md`;
}
$("#audit-run").addEventListener("change", loadAudit);

resetLive();
loadStatus();
