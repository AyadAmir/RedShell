// ============================================================
// RedShell Advanced Framework — Frontend Application Logic
// ============================================================

const API_BASE = window.location.origin;
const WS_BASE = API_BASE.replace("http", "ws");

let lastScanId = null;
let lastScanContext = {};
let monitorSocket = null;
let monitorAlertCount = 0;

// ---------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------
document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(i => i.classList.remove("active"));
    document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
    item.classList.add("active");
    document.getElementById(`view-${item.dataset.view}`).classList.add("active");
  });
});

// ---------------------------------------------------------------
// Status check (AI configured?)
// ---------------------------------------------------------------
async function checkStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    const data = await res.json();
    const pill = document.getElementById("ai-pill");
    const text = document.getElementById("ai-pill-text");
    if (data.ai_configured) {
      pill.className = "ai-pill on";
      text.textContent = "AI Analyst Online";
    } else {
      pill.className = "ai-pill off";
      text.textContent = "AI Offline (rule-based fallback)";
    }
  } catch (e) {
    document.getElementById("ai-pill-text").textContent = "Backend unreachable";
  }
}
checkStatus();

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
function severityBadgeCounts(counts) {
  return `
    <div class="stat-row">
      <div class="stat-chip crit"><div class="num">${counts.CRITICAL || 0}</div><div class="lbl">Critical</div></div>
      <div class="stat-chip high"><div class="num">${counts.HIGH || 0}</div><div class="lbl">High</div></div>
      <div class="stat-chip med"><div class="num">${counts.MEDIUM || 0}</div><div class="lbl">Medium</div></div>
      <div class="stat-chip low"><div class="num">${counts.LOW || 0}</div><div class="lbl">Low</div></div>
      <div class="stat-chip"><div class="num">${counts.INFO || 0}</div><div class="lbl">Info</div></div>
    </div>`;
}

function renderFindingCard(f) {
  return `
    <div class="finding sev-${f.severity}">
      <div class="finding-top">
        <span class="sev-tag sev-${f.severity}">${f.severity}</span>
        <span class="finding-title">${escapeHtml(f.title)}</span>
        <span class="finding-cat">${escapeHtml(f.category || "")}</span>
      </div>
      <div class="finding-desc">${escapeHtml(f.description || "")}</div>
      ${f.evidence ? `<div class="finding-meta">${escapeHtml(f.evidence)}</div>` : ""}
      ${f.recommendation ? `<div class="finding-rec"><b>Fix:</b> ${escapeHtml(f.recommendation)}</div>` : ""}
    </div>`;
}

function renderCveCard(c) {
  return `
    <div class="finding sev-${c.severity === "UNKNOWN" ? "INFO" : c.severity}">
      <div class="finding-top">
        <span class="sev-tag sev-${c.severity === "UNKNOWN" ? "INFO" : c.severity}">${c.severity}</span>
        <span class="finding-title">${escapeHtml(c.cve_id)}</span>
        <span class="finding-cat">${escapeHtml(c.matched_service)}:${c.matched_port} · ${c.source}</span>
      </div>
      <div class="finding-desc">${escapeHtml(c.summary)}</div>
      <div class="finding-meta">CVSS Score: ${c.score}</div>
    </div>`;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

function emptyState(message) {
  return `
    <div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
      <p>${escapeHtml(message)}</p>
    </div>`;
}

function nowTime() {
  return new Date().toLocaleTimeString();
}

// ---------------------------------------------------------------
// RECON view (standalone)
// ---------------------------------------------------------------
document.getElementById("btn-run-recon").addEventListener("click", async () => {
  const target = document.getElementById("recon-target").value.trim();
  if (!target) return;
  const btn = document.getElementById("btn-run-recon");
  const resultsDiv = document.getElementById("recon-results");
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Scanning…';
  resultsDiv.innerHTML = emptyState("Scanning ports — this can take a few seconds…");

  try {
    const res = await fetch(`${API_BASE}/api/recon`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target})
    });
    const data = await res.json();
    renderReconResults(data, resultsDiv);
  } catch (e) {
    resultsDiv.innerHTML = emptyState("Scan failed: " + e.message);
  }
  btn.disabled = false; btn.innerHTML = "▶ Scan Ports";
});

function renderReconResults(data, container) {
  if (data.error) {
    container.innerHTML = `<div class="panel">${emptyState(data.error)}</div>`;
    return;
  }
  let rows = data.open_ports.map(p => `
    <tr>
      <td><span class="port-pill">${p.port}</span></td>
      <td>${escapeHtml(p.service)}</td>
      <td class="mono">${p.tls ? "TLS" : "plain"}</td>
      <td class="mono" style="color:var(--text-faint); font-size:11px;">${escapeHtml(p.banner || "—")}</td>
      <td class="mono">${p.response_time_ms}ms</td>
    </tr>`).join("");

  container.innerHTML = `
    <div class="stat-row">
      <div class="stat-chip ok"><div class="num">${data.open_ports.length}</div><div class="lbl">Open Ports</div></div>
      <div class="stat-chip"><div class="num">${data.scan_duration_s}s</div><div class="lbl">Duration</div></div>
      <div class="stat-chip"><div class="num" style="font-size:13px; padding-top:4px;">${escapeHtml(data.resolved_ip)}</div><div class="lbl">Resolved IP</div></div>
    </div>
    <div class="panel">
      <div class="panel-title">OS Fingerprint Guess</div>
      <div style="font-family:var(--mono); color:var(--text-dim);">${escapeHtml(data.os_guess)}</div>
    </div>
    <div class="panel">
      <div class="panel-title">Open Ports (${data.open_ports.length})</div>
      ${data.open_ports.length === 0 ? emptyState("No open ports detected in the scanned range.") : `
      <table>
        <thead><tr><th>Port</th><th>Service</th><th>Transport</th><th>Banner</th><th>Latency</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`}
    </div>`;
}

// ---------------------------------------------------------------
// CVE view (standalone)
// ---------------------------------------------------------------
document.getElementById("btn-run-cve").addEventListener("click", async () => {
  const target = document.getElementById("cve-target").value.trim();
  if (!target) return;
  const btn = document.getElementById("btn-run-cve");
  const resultsDiv = document.getElementById("cve-results");
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Correlating…';
  resultsDiv.innerHTML = emptyState("Scanning and querying NVD — this can take 10-30s depending on services found…");

  try {
    const res = await fetch(`${API_BASE}/api/cve-lookup`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target})
    });
    const data = await res.json();
    renderCveResults(data, resultsDiv);
  } catch (e) {
    resultsDiv.innerHTML = emptyState("Lookup failed: " + e.message);
  }
  btn.disabled = false; btn.innerHTML = "▶ Scan &amp; Correlate";
});

function renderCveResults(data, container) {
  if (data.detail) { container.innerHTML = emptyState(data.detail); return; }
  const cves = data.cves || [];
  const cards = cves.map(renderCveCard).join("");
  container.innerHTML = `
    <div class="panel">
      <div class="panel-title">Matched CVEs (${cves.length})</div>
      <div class="finding-grid">${cves.length ? cards : emptyState("No CVEs matched against detected services.")}</div>
    </div>`;
}

// ---------------------------------------------------------------
// WEB view (standalone)
// ---------------------------------------------------------------
document.getElementById("btn-run-web").addEventListener("click", async () => {
  const target = document.getElementById("web-target").value.trim();
  if (!target) return;
  const btn = document.getElementById("btn-run-web");
  const resultsDiv = document.getElementById("web-results");
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Scanning…';
  resultsDiv.innerHTML = emptyState("Running detection checks…");

  try {
    const res = await fetch(`${API_BASE}/api/web-scan`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target_url: target})
    });
    const data = await res.json();
    renderWebResults(data, resultsDiv);
  } catch (e) {
    resultsDiv.innerHTML = emptyState("Scan failed: " + e.message);
  }
  btn.disabled = false; btn.innerHTML = "▶ Scan Application";
});

function renderWebResults(data, container) {
  if (data.error) { container.innerHTML = `<div class="panel">${emptyState(data.error)}</div>`; return; }
  const findings = data.findings || [];
  container.innerHTML = `
    ${severityBadgeCounts(data.severity_counts)}
    <div class="panel">
      <div class="panel-title">Findings (${data.total_findings}) · scanned in ${data.scan_duration_s}s</div>
      <div class="finding-grid">${findings.length ? findings.map(renderFindingCard).join("") : emptyState("No issues detected.")}</div>
    </div>`;
}

// ---------------------------------------------------------------
// OVERVIEW — Full Assessment pipeline via WebSocket
// ---------------------------------------------------------------
const sweepPorts = [21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,8080];

function initSweep() {
  const container = document.getElementById("sweep-ports");
  container.innerHTML = sweepPorts.map(p => `<span class="sweep-port" data-port="${p}">${p}</span>`).join("");
}
initSweep();

function markPortFound(port) {
  const el = document.querySelector(`.sweep-port[data-port="${port}"]`);
  if (el) el.classList.add("found");
}

function logLine(stage, message) {
  const log = document.getElementById("console-log");
  const div = document.createElement("div");
  div.className = `console-line stage-${stage}`;
  div.innerHTML = `<span class="ts">${nowTime()}</span><span class="tag">[${stage.toUpperCase()}]</span><span>${escapeHtml(message)}</span>`;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

document.getElementById("btn-run-assessment").addEventListener("click", () => {
  const target = document.getElementById("input-target").value.trim();
  const targetUrl = document.getElementById("input-target-url").value.trim();
  if (!target) return;

  const includeCve = document.getElementById("chk-cve").checked;
  const includeWeb = document.getElementById("chk-web").checked;
  const includeAi = document.getElementById("chk-ai").checked;

  document.getElementById("topbar-target").innerHTML = `Target: <span>${escapeHtml(target)}</span>`;
  document.getElementById("btn-run-assessment").disabled = true;
  document.getElementById("btn-run-assessment").innerHTML = '<span class="spinner"></span> Running…';
  document.getElementById("progress-panel").classList.remove("hidden");
  document.getElementById("console-log").innerHTML = "";
  document.getElementById("overview-results").innerHTML = "";
  document.getElementById("sweep-stage").classList.add("active");
  initSweep();

  const ws = new WebSocket(`${WS_BASE}/ws/assessment`);
  let reconData = null, cveData = null, webData = null, aiData = null;

  ws.onopen = () => {
    ws.send(JSON.stringify({
      target, target_url: targetUrl,
      include_cve: includeCve, include_web: includeWeb, include_ai: includeAi
    }));
    logLine("recon", `Pipeline started for target: ${target}`);
  };

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);

    if (msg.type === "progress") {
      document.getElementById("progress-fill").style.width = msg.percent + "%";
      document.getElementById("progress-stage").textContent = msg.stage;
      document.getElementById("progress-pct").textContent = msg.percent + "%";
      document.getElementById("sweep-label").textContent = msg.message;
      logLine(msg.stage, msg.message);
    }

    if (msg.type === "recon_complete") {
      reconData = msg.data;
      (reconData.open_ports || []).forEach(p => markPortFound(p.port));
      logLine("recon", `Recon complete: ${reconData.open_ports.length} open ports found.`);
    }

    if (msg.type === "cve_complete") {
      cveData = msg.data;
      logLine("cve", `CVE correlation complete: ${cveData.length} matches found.`);
    }

    if (msg.type === "web_complete") {
      webData = msg.data;
      logLine("web", `Web scan complete: ${webData.total_findings} findings.`);
    }

    if (msg.type === "ai_complete") {
      aiData = msg.data;
      logLine("ai", `AI analysis complete: overall risk = ${aiData.overall_risk}.`);
    }

    if (msg.type === "error") {
      logLine("recon", `ERROR: ${msg.message}`);
      document.getElementById("overview-results").innerHTML = `<div class="panel">${emptyState(msg.message)}</div>`;
    }

    if (msg.type === "done") {
      lastScanId = msg.scan_id;
      lastScanContext = {recon: reconData, cves: cveData, web: webData};
      document.getElementById("sweep-stage").classList.remove("active");
      renderFullAssessmentResults(reconData, cveData, webData, aiData);
      document.getElementById("btn-run-assessment").disabled = false;
      document.getElementById("btn-run-assessment").innerHTML = "▶ Run Full Assessment";
      checkMonitorBadgeRefresh();
    }
  };

  ws.onerror = () => {
    logLine("recon", "WebSocket connection error.");
    document.getElementById("btn-run-assessment").disabled = false;
    document.getElementById("btn-run-assessment").innerHTML = "▶ Run Full Assessment";
  };
});

function renderFullAssessmentResults(recon, cves, web, ai) {
  let html = "";

  if (ai) {
    html += `
      <div class="panel">
        <div class="panel-title">AI Risk Analysis ${ai.ai_powered ? "" : "(rule-based fallback)"}</div>
        <div class="ai-summary-box">
          <div class="risk-badge ${ai.overall_risk}">⬤ ${ai.overall_risk} RISK</div>
          <div style="color:var(--text-dim); font-size:13px; line-height:1.6;">${escapeHtml(ai.executive_summary)}</div>
          ${ai.technical_notes ? `<div style="margin-top:10px; font-size:12px; color:var(--text-faint);"><b>Technical notes:</b> ${escapeHtml(ai.technical_notes)}</div>` : ""}
          <ul class="priority-list">
            ${(ai.top_priorities || []).map((p, i) => `<li><span class="priority-num">${i+1}</span>${escapeHtml(p)}</li>`).join("")}
          </ul>
          ${ai.note ? `<div style="margin-top:10px; font-size:11px; color:var(--text-faint);">${escapeHtml(ai.note)}</div>` : ""}
        </div>
      </div>`;
  }

  if (recon && !recon.error) {
    html += `
      <div class="panel">
        <div class="panel-title">Recon Summary — ${escapeHtml(recon.resolved_ip)}</div>
        <div class="stat-row">
          <div class="stat-chip ok"><div class="num">${recon.open_ports.length}</div><div class="lbl">Open Ports</div></div>
          <div class="stat-chip"><div class="num">${recon.scan_duration_s}s</div><div class="lbl">Scan Time</div></div>
        </div>
        <div style="font-family:var(--mono); font-size:12px; color:var(--text-dim);">OS Guess: ${escapeHtml(recon.os_guess)}</div>
      </div>`;
  }

  if (cves && cves.length) {
    html += `
      <div class="panel">
        <div class="panel-title">CVE Matches (${cves.length})</div>
        <div class="finding-grid">${cves.slice(0, 10).map(renderCveCard).join("")}</div>
      </div>`;
  }

  if (web && !web.error) {
    html += `
      <div class="panel">
        <div class="panel-title">Web Findings (${web.total_findings})</div>
        ${severityBadgeCounts(web.severity_counts)}
        <div class="finding-grid">${(web.findings || []).map(renderFindingCard).join("")}</div>
      </div>`;
  }

  document.getElementById("overview-results").innerHTML = html;
}

// ---------------------------------------------------------------
// AI CHAT
// ---------------------------------------------------------------
document.getElementById("btn-chat-send").addEventListener("click", sendChat);
document.getElementById("chat-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") sendChat();
});

async function sendChat() {
  const input = document.getElementById("chat-input");
  const question = input.value.trim();
  if (!question) return;
  input.value = "";

  const messages = document.getElementById("chat-messages");
  messages.innerHTML += `<div class="chat-msg user">${escapeHtml(question)}</div>`;
  messages.innerHTML += `<div class="chat-msg ai" id="chat-pending"><span class="spinner"></span></div>`;
  messages.scrollTop = messages.scrollHeight;

  try {
    const res = await fetch(`${API_BASE}/api/chat`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({question, scan_id: lastScanId})
    });
    const data = await res.json();
    document.getElementById("chat-pending").outerHTML = `<div class="chat-msg ai">${escapeHtml(data.answer)}</div>`;
  } catch (e) {
    document.getElementById("chat-pending").outerHTML = `<div class="chat-msg ai">Error: ${escapeHtml(e.message)}</div>`;
  }
  messages.scrollTop = messages.scrollHeight;
}

// ---------------------------------------------------------------
// LIVE MONITOR
// ---------------------------------------------------------------
function renderGauges(snap) {
  const gauges = [
    {label: "CPU", value: snap.cpu_percent},
    {label: "Memory", value: snap.memory_percent},
    {label: "Disk", value: snap.disk_percent},
  ];
  document.getElementById("monitor-gauges").innerHTML = gauges.map(g => {
    const circumference = 2 * Math.PI * 34;
    const offset = circumference - (g.value / 100) * circumference;
    return `
      <div class="gauge">
        <div class="gauge-ring">
          <svg width="80" height="80">
            <circle class="bg" cx="40" cy="40" r="34" fill="none" stroke-width="6"/>
            <circle class="fg" cx="40" cy="40" r="34" fill="none" stroke-width="6"
              stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"/>
          </svg>
          <div class="gauge-val">${g.value.toFixed(0)}%</div>
        </div>
        <div class="gauge-lbl">${g.label}</div>
      </div>`;
  }).join("") + `
    <div class="gauge">
      <div style="font-family:var(--mono); font-size:24px; font-weight:700; padding-top:24px;">${snap.established_count}</div>
      <div class="gauge-lbl">Active Connections</div>
    </div>
    <div class="gauge">
      <div style="font-family:var(--mono); font-size:24px; font-weight:700; padding-top:24px;">${snap.listen_ports.length}</div>
      <div class="gauge-lbl">Listening Ports</div>
    </div>`;
}

function renderAlert(a) {
  return `
    <div class="alert-item ${a.severity}">
      <div class="alert-time">${new Date(a.timestamp).toLocaleTimeString()}</div>
      <div class="alert-body"><b>${escapeHtml(a.title)}</b><p>${escapeHtml(a.description)}</p></div>
    </div>`;
}

function checkMonitorBadgeRefresh() {
  const badge = document.getElementById("monitor-badge");
  if (monitorAlertCount > 0) {
    badge.textContent = monitorAlertCount;
    badge.classList.add("show");
  }
}

document.getElementById("btn-start-monitor").addEventListener("click", () => {
  if (monitorSocket) return;
  document.getElementById("btn-start-monitor").disabled = true;
  document.getElementById("btn-stop-monitor").disabled = false;
  document.getElementById("monitor-live-dot").style.display = "inline-block";
  document.getElementById("alert-feed").innerHTML = "";

  monitorSocket = new WebSocket(`${WS_BASE}/ws/monitor`);
  monitorSocket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    renderGauges(data.snapshot);
    if (data.new_alerts && data.new_alerts.length) {
      monitorAlertCount += data.new_alerts.length;
      checkMonitorBadgeRefresh();
    }
    const feed = document.getElementById("alert-feed");
    if (data.recent_alerts && data.recent_alerts.length) {
      feed.innerHTML = data.recent_alerts.map(renderAlert).join("");
    } else if (!feed.querySelector(".alert-item")) {
      feed.innerHTML = emptyState("No alerts yet — monitoring is live and clean.");
    }
  };
  monitorSocket.onclose = () => { monitorSocket = null; };
});

document.getElementById("btn-stop-monitor").addEventListener("click", () => {
  if (monitorSocket) { monitorSocket.close(); monitorSocket = null; }
  document.getElementById("btn-start-monitor").disabled = false;
  document.getElementById("btn-stop-monitor").disabled = true;
  document.getElementById("monitor-live-dot").style.display = "none";
});

document.getElementById("btn-clear-alerts").addEventListener("click", async () => {
  await fetch(`${API_BASE}/api/monitor/clear`, {method: "POST"});
  monitorAlertCount = 0;
  document.getElementById("monitor-badge").classList.remove("show");
  document.getElementById("alert-feed").innerHTML = emptyState("Alerts cleared.");
});

// ---------------------------------------------------------------
// HISTORY
// ---------------------------------------------------------------
async function loadHistory() {
  const list = document.getElementById("history-list");
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    const data = await res.json();
    if (!data.scans.length) {
      list.innerHTML = emptyState("No scans yet. Run a Full Assessment to populate history.");
      return;
    }
    list.innerHTML = data.scans.map(s => `
      <div class="history-item" onclick="viewHistoryItem(${s.id})">
        <div>
          <div class="history-target">${escapeHtml(s.target)}</div>
          <div class="history-meta">${new Date(s.timestamp).toLocaleString()}</div>
        </div>
        <span class="history-type">${escapeHtml(s.scan_type)}</span>
      </div>`).join("");
  } catch (e) {
    list.innerHTML = emptyState("Could not load history: " + e.message);
  }
}

async function viewHistoryItem(id) {
  const res = await fetch(`${API_BASE}/api/history/${id}`);
  const data = await res.json();
  lastScanId = id;
  const r = data.result || {};
  document.querySelectorAll(".nav-item").forEach(i => i.classList.remove("active"));
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  document.querySelector('[data-view="overview"]').classList.add("active");
  document.getElementById("view-overview").classList.add("active");
  document.getElementById("progress-panel").classList.add("hidden");
  renderFullAssessmentResults(r.recon, r.cves, r.web, data.ai_summary);
}

document.querySelector('[data-view="history"]').addEventListener("click", loadHistory);
