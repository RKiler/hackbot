"use strict";

const state = {
  target: "", candidate: null, cursor: null, runId: null, boundPlanId: null,
  csrf: document.querySelector('meta[name="csrf-token"]')?.content || "",
};
const byId = (id) => document.getElementById(id);
const status = (message) => { byId("status").textContent = message; };
const clear = (node) => node.replaceChildren();
const label = (value) => value == null || value === "" ? "—" : String(value);

async function api(path, body) {
  const options = { credentials: "same-origin", headers: { Accept: "application/json" } };
  if (body !== undefined) {
    if (!state.csrf) throw new Error("Protected action unavailable");
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = state.csrf;
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function metric(name, value) {
  const item = document.createElement("div");
  item.className = "metric";
  const count = document.createElement("strong");
  count.textContent = label(value);
  const caption = document.createElement("span");
  caption.textContent = name;
  item.append(count, caption);
  return item;
}

function tableCell(row, value, className) {
  const cell = row.insertCell();
  cell.textContent = label(value);
  if (className) cell.className = className;
  return cell;
}

async function loadTargets() {
  const data = await api("/v1/targets?limit=50");
  const select = byId("target");
  clear(select);
  for (const item of data.items) {
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = item.name || item.primary_domain || item.id;
    select.append(option);
  }
  const requested = new URLSearchParams(location.search).get("target");
  if (requested && data.items.some((item) => item.id === requested)) select.value = requested;
  state.target = select.value;
  if (state.target) await refresh();
}

async function loadMetrics() {
  const data = await api(`/v1/domxss/${encodeURIComponent(state.target)}/metrics`);
  const panel = byId("metrics");
  clear(panel);
  panel.append(metric("Assets analyzed", data.assets_analyzed),
               metric("Candidates", data.candidates),
               metric("Browser actions", data.browser_actions),
               metric("Confirmed", data.confirmed),
               metric("Review", data.manual_review));
}

async function loadCandidates(cursor) {
  const query = cursor ? `?limit=20&cursor=${encodeURIComponent(cursor)}` : "?limit=20";
  const data = await api(`/v1/domxss/${encodeURIComponent(state.target)}/candidates${query}`);
  const rows = byId("candidate-rows");
  clear(rows);
  for (const item of data.items) {
    const row = rows.insertRow();
    if (state.candidate?.id === item.id) row.className = "selected";
    tableCell(row, item.score, "score");
    const cell = row.insertCell();
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `${item.source} → ${item.sink}`;
    button.addEventListener("click", () => showCandidate(item.id).catch(showError));
    cell.append(button);
    tableCell(row, item.status, "status");
    tableCell(row, item.asset_sha256.slice(0, 12), "mono");
  }
  state.cursor = data.next_cursor;
  byId("next-page").disabled = !state.cursor;
}

async function loadAssets() {
  const rows = byId("asset-rows");
  clear(rows);
  let data;
  try { data = await api(`/v1/domxss/${encodeURIComponent(state.target)}/inventory`); }
  catch (error) { byId("asset-total").textContent = error.message; return; }
  byId("asset-total").textContent = `${data.items.length} ranked`;
  for (const asset of data.items) {
    const row = rows.insertRow();
    tableCell(row, asset.score, "score");
    tableCell(row, asset.host);
    tableCell(row, asset.latest_sha256?.slice(0, 16) || "Unknown", "mono");
    tableCell(row, asset.reasons.join(", "));
    const cell = row.insertCell();
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Analyze";
    button.disabled = !state.csrf;
    button.addEventListener("click", () => action(async () => {
      await api(`/v1/domxss/${encodeURIComponent(state.target)}/analyze`,
                { recon_asset_id: asset.recon_asset_id });
      await refresh();
    }));
    cell.append(button);
  }
}

function facts(items) {
  const panel = byId("candidate-facts");
  clear(panel);
  for (const [name, value] of items) {
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = name;
    description.textContent = label(value);
    panel.append(term, description);
  }
}

function updateActions() {
  const item = state.candidate;
  const active = Boolean(state.csrf && item);
  byId("bind-route").disabled = !active;
  byId("prepare").disabled = !active || !item?.route;
  byId("bind-plan").disabled = !active || !item?.links?.hypothesis_id;
  byId("start-run").disabled = !active || !state.boundPlanId || Boolean(state.runId);
  byId("advance-run").disabled = !active || !state.runId;
  byId("validate-run").disabled = !active || !state.runId;
}

async function loadSessions() {
  const data = await api(`/v1/browser/sessions?target=${encodeURIComponent(state.target)}&limit=50`);
  const select = byId("browser-session");
  clear(select);
  for (const item of data.items) {
    if (!item.browser_running) continue;
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = `${item.id.slice(0, 19)} · ${item.status}`;
    select.append(option);
  }
}

async function showCandidate(id) {
  const base = `/v1/domxss/${encodeURIComponent(state.target)}/candidates/${encodeURIComponent(id)}`;
  const [item, runtime] = await Promise.all([api(base), api(`${base}/runtime`)]);
  state.candidate = item;
  state.runId = runtime.links.run_id;
  state.boundPlanId = null;
  if (runtime.links.plan_id) {
    const plan = await api(`/v1/plans/${encodeURIComponent(runtime.links.plan_id)}?target=${encodeURIComponent(state.target)}`);
    if (plan.dom_binding) state.boundPlanId = runtime.links.plan_id;
  }
  byId("candidate-empty").hidden = true;
  byId("candidate-detail").hidden = false;
  byId("candidate-id").textContent = item.id;
  const flow = byId("flow");
  clear(flow);
  for (const [name, value] of [["Source", item.source], ["Check", item.checks.join(" → ")],
                               ["Transform", item.transforms.join(" → ")], ["Sink", item.sink]]) {
    const step = document.createElement("div");
    step.className = "flow-step";
    const caption = document.createElement("span");
    caption.textContent = name;
    const content = document.createElement("strong");
    content.textContent = label(value);
    step.append(caption, content);
    flow.append(step);
  }
  facts([["Status", item.status], ["Priority", item.score], ["Route", item.route],
         ["Asset SHA-256", item.asset_sha256], ["Source line", item.source_line],
         ["Sink line", item.sink_line], ["Mapped source", item.mapped_source],
         ["Source map", item.source_map_sha256], ["Validation", runtime.validation_status]]);
  byId("run-status").textContent = runtime.run_status || "No run";
  const trialPanel = byId("trials");
  clear(trialPanel);
  for (const trial of runtime.trials || []) {
    const row = document.createElement("div");
    row.className = "trial";
    for (const value of [trial.variant, trial.marker_observed ? "Executed" : "No marker",
                         [trial.marker_context, trial.document_origin,
                          trial.csp_present ? "CSP" : null,
                          trial.trusted_types_enforced ? "Trusted Types" : null,
                          trial.sandbox_flags?.length ? "Sandbox" : null,
                          trial.evidence_id].filter(Boolean).join(" · ")]) {
      const cell = document.createElement("span");
      cell.textContent = label(value);
      row.append(cell);
    }
    trialPanel.append(row);
  }
  byId("evidence").textContent = item.evidence_ids.join(" · ") || "No evidence references";
  await loadSessions();
  updateActions();
}

async function action(work) {
  try { status("Working"); await work(); status("Updated"); }
  catch (error) { showError(error); }
}

function showError(error) { status(error?.message || "Request failed"); }

async function refresh() {
  state.candidate = null;
  state.runId = null;
  state.boundPlanId = null;
  byId("candidate-empty").hidden = false;
  byId("candidate-detail").hidden = true;
  byId("candidate-id").textContent = "";
  updateActions();
  await Promise.all([loadMetrics(), loadCandidates(), loadAssets()]);
  status("Ready");
}

document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((other) => {
    const selected = other === tab;
    other.classList.toggle("active", selected);
    other.setAttribute("aria-selected", String(selected));
  });
  byId("candidates-panel").hidden = tab.dataset.tab !== "candidates";
  byId("assets-panel").hidden = tab.dataset.tab !== "assets";
}));

byId("target").addEventListener("change", () => {
  state.target = byId("target").value;
  history.replaceState(null, "", `?target=${encodeURIComponent(state.target)}`);
  refresh().catch(showError);
});
byId("refresh").addEventListener("click", () => refresh().catch(showError));
byId("next-page").addEventListener("click", () => loadCandidates(state.cursor).catch(showError));
byId("input-kind").addEventListener("change", () => {
  byId("input-name").disabled = byId("input-kind").value === "FRAGMENT";
});
byId("bind-route").addEventListener("click", () => action(async () => {
  const id = state.candidate.id;
  await api(`/v1/domxss/${encodeURIComponent(state.target)}/candidates/${encodeURIComponent(id)}/route`,
            { exchange_id: byId("exchange-id").value.trim() });
  await showCandidate(id);
}));
byId("prepare").addEventListener("click", () => action(async () => {
  const id = state.candidate.id;
  await api(`/v1/domxss/${encodeURIComponent(state.target)}/candidates/${encodeURIComponent(id)}/prepare`, {});
  await showCandidate(id);
}));
byId("bind-plan").addEventListener("click", () => action(async () => {
  const id = state.candidate.id;
  await api(`/v1/domxss/${encodeURIComponent(state.target)}/candidates/${encodeURIComponent(id)}/bind-plan`, {
    browser_session_id: byId("browser-session").value,
    input_kind: byId("input-kind").value,
    input_name: byId("input-kind").value === "FRAGMENT" ? null : byId("input-name").value.trim(),
  });
  await showCandidate(id);
}));
byId("start-run").addEventListener("click", () => action(async () => {
  await api(`/v1/plans/${encodeURIComponent(state.boundPlanId)}/runs`, { target: state.target });
  await showCandidate(state.candidate.id);
}));
byId("advance-run").addEventListener("click", () => action(async () => {
  await api(`/v1/runs/${encodeURIComponent(state.runId)}/advance`, { target: state.target });
  await showCandidate(state.candidate.id);
}));
byId("validate-run").addEventListener("click", () => action(async () => {
  await api(`/v1/runs/${encodeURIComponent(state.runId)}/validate`, { target: state.target });
  await showCandidate(state.candidate.id);
}));

loadTargets().catch(showError);
