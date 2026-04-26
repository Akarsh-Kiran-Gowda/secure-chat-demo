/**
 * security_panel.js – Security Monitor and toggle controls
 *
 * Handles:
 *   - Sending security config updates to the server
 *   - Polling the /api/security/events endpoint
 *   - Rendering events in the Security Monitor pane
 *   - Header badge updates
 */

"use strict";

// ── Security config API ─────────────────────────────────────────

async function updateSecurity(field, value) {
  const body = { [field]: value };
  const r = await fetch("/api/security/update", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok) { console.error("Security update failed", data); return; }

  // Sync client-side E2E flag so chat.js encrypts / passes through accordingly
  if (field === "e2e_enabled") {
    window._state.e2eEnabled = value;
  }

  updateBadges(data);
  pushMonitorEvent({
    type: "CONFIG_CHANGE",
    detail: `${field} → ${value}`,
    ts: new Date().toLocaleTimeString(),
  });
}

function updateBadges(cfg) {
  // TLS
  const tlsBadge = document.getElementById("badge-tls");
  if (cfg.tls_enabled) {
    tlsBadge.textContent = "TLS ON";
    tlsBadge.className   = "badge badge-tls";
  } else {
    tlsBadge.textContent = "TLS OFF";
    tlsBadge.className   = "badge badge-off";
  }

  // E2E
  const e2eBadge = document.getElementById("badge-e2e");
  if (cfg.e2e_enabled) {
    e2eBadge.textContent = "E2E ON";
    e2eBadge.className   = "badge badge-e2e";
  } else {
    e2eBadge.textContent = "E2E OFF";
    e2eBadge.className   = "badge badge-off";
  }

  // Replay protection
  const rpBadge = document.getElementById("badge-rp");
  if (cfg.replay_protection_enabled) {
    rpBadge.textContent = "REPLAY PROT ON";
    rpBadge.className   = "badge badge-e2e";
  } else {
    rpBadge.textContent = "REPLAY PROT OFF";
    rpBadge.className   = "badge badge-off";
  }

  // MITM simulation badge
  const mitmBadge = document.getElementById("badge-mitm");
  mitmBadge.style.display = cfg.simulate_mitm ? "inline-block" : "none";

  // Sync toggles
  document.getElementById("toggle-tls").checked    = !!cfg.tls_enabled;
  document.getElementById("toggle-e2e").checked    = !!cfg.e2e_enabled;
  document.getElementById("toggle-rp").checked     = !!cfg.replay_protection_enabled;
  document.getElementById("toggle-mitm").checked   = !!cfg.simulate_mitm;
  document.getElementById("toggle-replay").checked = !!cfg.simulate_replay;
}

// ── Security Monitor ────────────────────────────────────────────

const EVENT_LABELS = {
  MITM_INTERCEPT:   "MITM intercepted message",
  MITM_MODIFY:      "MITM modified message",
  REPLAY_BLOCKED:   "Replay attack BLOCKED",
  REPLAY_ATTEMPT:   "Replay attack attempted",
  REPLAY_CAPTURE:   "Message captured for replay",
  INTEGRITY_FAILED: "Integrity check FAILED",
  CONFIG_CHANGE:    "Security config changed",
};

const EVENT_ICONS = {
  MITM_INTERCEPT:   "👁",
  MITM_MODIFY:      "✏️",
  REPLAY_BLOCKED:   "🛡",
  REPLAY_ATTEMPT:   "⚡",
  REPLAY_CAPTURE:   "📸",
  INTEGRITY_FAILED: "❌",
  CONFIG_CHANGE:    "⚙",
};

function pushMonitorEvent(ev) {
  const monitor = document.getElementById("security-monitor");
  const div = document.createElement("div");
  div.className = `sec-event ${ev.type || ""}`;

  const icon  = EVENT_ICONS[ev.type]  || "•";
  const label = EVENT_LABELS[ev.type] || ev.type;
  const ts    = ev.ts || new Date().toLocaleTimeString();
  const detail = ev.detail || ev.reason || ev.readable_content || "";

  div.innerHTML = `<b>${icon} ${label}</b> <span style="float:right;color:var(--muted)">${ts}</span>
    ${detail ? `<br><span style="color:var(--muted)">${escapeHtml(String(detail).slice(0, 80))}</span>` : ""}`;

  monitor.prepend(div);

  // Cap at 100 visible events
  while (monitor.children.length > 100) monitor.removeChild(monitor.lastChild);
}

// Exposed so chat.js can push WS error events
window._secPush = pushMonitorEvent;

function clearMonitor() {
  document.getElementById("security-monitor").innerHTML = "";
}

// ── Trigger replay ──────────────────────────────────────────────

async function triggerReplay() {
  const roomId = window._state && window._state.roomId;
  if (!roomId) { alert("Join a room first"); return; }
  const r = await fetch(`/api/security/trigger-replay/${roomId}`, { method: "POST" });
  const d = await r.json();
  pushMonitorEvent({
    type:   "REPLAY_ATTEMPT",
    detail: d.status === "no_captured_messages"
              ? "No captured messages – send a message with Simulate Replay ON first"
              : "Replay triggered – check monitor for block/pass result",
  });
}

// ── Poll security events ────────────────────────────────────────

let _lastEventCount = 0;

async function pollSecurityEvents() {
  try {
    const r = await fetch("/api/security/events?limit=20");
    if (!r.ok) return;
    const { events } = await r.json();
    if (events.length > _lastEventCount) {
      const newEvs = events.slice(_lastEventCount);
      newEvs.forEach(ev => pushMonitorEvent({ ...ev, ts: new Date().toLocaleTimeString() }));
      _lastEventCount = events.length;
    }
  } catch { /* ignore network errors during demo */ }
}

// ── Initialise ──────────────────────────────────────────────────

async function initSecurityPanel() {
  const r = await fetch("/api/security/status");
  if (r.ok) updateBadges(await r.json());
  setInterval(pollSecurityEvents, 2000);
}

function escapeHtml(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

initSecurityPanel();
