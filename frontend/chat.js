/**
 * chat.js – Core chat logic
 *
 * Handles:
 *   - Room creation / joining
 *   - WebSocket connection management
 *   - AES-256-GCM client-side encryption / decryption (via Web Crypto API)
 *   - Message send / receive
 *   - File upload / download
 *
 * Security note:
 *   Client-side encryption mirrors what a real E2EE client would do.
 *   The group key is obtained from the server at join time and held in memory.
 *   When E2E is disabled on the server, messages are sent as plaintext so
 *   the professor can demonstrate what an attacker (or MITM) would observe.
 */

"use strict";

// ── State ──────────────────────────────────────────────────────
const state = {
  username:    "",
  roomId:      null,
  groupKeyB64: null,    // AES-256 key as Base64
  cryptoKey:   null,    // CryptoKey object (imported from groupKeyB64)
  ws:          null,
  e2eEnabled:  true,    // mirrors server toggle
};

// ── Utilities ──────────────────────────────────────────────────

function b64ToUint8(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function uint8ToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function hexFromUint8(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(str) {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return hexFromUint8(buf);
}

function randomHex(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return hexFromUint8(arr);
}

function isoNow() {
  return new Date().toISOString();
}

function randomId(bytes = 12) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return hexFromUint8(arr);
}

// ── Web Crypto AES-256-GCM helpers ─────────────────────────────

async function importGroupKey(b64Key) {
  const raw = b64ToUint8(b64Key);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function encryptMessage(plaintext, cryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, encoded);
  const payload = { iv: uint8ToB64(iv), ct: uint8ToB64(ct) };
  return btoa(JSON.stringify(payload));
}

async function decryptMessage(b64Payload, cryptoKey) {
  try {
    const payload = JSON.parse(atob(b64Payload));
    const iv = b64ToUint8(payload.iv);
    const ct = b64ToUint8(payload.ct);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ct);
    return new TextDecoder().decode(plain);
  } catch {
    return "[decryption failed – message may be tampered]";
  }
}

// ── Room management ────────────────────────────────────────────

function openCreateModal() {
  document.getElementById("create-username").value = state.username || "";
  document.getElementById("token-section").style.display = "none";
  document.getElementById("create-modal").classList.add("open");
}

function openJoinModal() {
  document.getElementById("join-username").value = state.username || "";
  document.getElementById("join-modal").classList.add("open");
}

function closeModal(id) {
  document.getElementById(id).classList.remove("open");
}

async function createRoom() {
  const username = document.getElementById("create-username").value.trim();
  if (!username) { alert("Enter a username"); return; }

  const res = await fetch("/api/rooms/create", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ owner: username }),
  });
  const data = await res.json();
  if (!res.ok) { alert(data.detail || "Error"); return; }

  // Display the invite token (shown once)
  document.getElementById("invite-token-display").textContent = data.invite_token;
  document.getElementById("token-section").style.display = "block";

  // Auto-join as owner
  state.username = username;
  addRoomToList(data.room_id, username);
  await connectToRoom(data.room_id, data.room_id, username);
}

async function joinRoom() {
  const username = document.getElementById("join-username").value.trim();
  const token    = document.getElementById("join-token").value.trim();
  if (!username || !token) { alert("Fill in both fields"); return; }

  const res = await fetch("/api/rooms/join", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ invite_token: token, username }),
  });
  const data = await res.json();
  if (!res.ok) { alert(data.detail || "Invalid token"); return; }

  state.username = username;
  addRoomToList(data.room_id, data.owner);
  closeModal("join-modal");
  await connectToRoom(data.room_id, data.group_key, username);
}

function copyToken() {
  const t = document.getElementById("invite-token-display").textContent;
  navigator.clipboard.writeText(t).then(() => addSystemMsg("Invite token copied to clipboard"));
}

function addRoomToList(roomId, label) {
  const list = document.getElementById("room-list");
  // avoid duplicates
  if (document.getElementById("room-" + roomId)) return;
  const el = document.createElement("div");
  el.id = "room-" + roomId;
  el.className = "room-item";
  el.textContent = "# " + (label || roomId).slice(0, 18);
  el.onclick = () => switchRoom(roomId);
  list.appendChild(el);
}

// ── WebSocket connection ────────────────────────────────────────

async function connectToRoom(roomId, groupKeyB64OrRoomId, username) {
  // If we have a group key (from join), use it; creator needs to fetch it
  let keyB64 = groupKeyB64OrRoomId;
  if (groupKeyB64OrRoomId === roomId) {
    // Creator path: get room info to retrieve group key
    const r = await fetch(`/api/rooms/${roomId}`);
    // Room key is not exposed via GET for security; we need to re-join with token.
    // For the demo, creator stores their key from the create response.
    // We'll fetch the room key via a special helper: re-use the same endpoint via
    // a join with owner token.  For simplicity in the demo, we derive it later.
    // Actually, we stored it in the create; let's grab it from memory via a join GET.
    // Simplest demo approach: expose key on room owner join (server returns group_key on create).
    // The create room response does NOT include group_key – add that now.
    const rd = await r.json();
    // Fallback: owner also gets group_key (server should return it on /create)
    // We'll patch this: fetch key from a /api/rooms/<id>/key endpoint created in main.
    const kr = await fetch(`/api/rooms/${roomId}/key`);
    const kd = await kr.json();
    keyB64 = kd.group_key;
  }

  state.roomId      = roomId;
  state.groupKeyB64 = keyB64;
  state.cryptoKey   = await importGroupKey(keyB64);

  // Close existing WS
  if (state.ws) state.ws.close();

  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/${roomId}/${encodeURIComponent(username)}`);

  ws.onopen    = () => { addSystemMsg(`Connected to room ${roomId}`); };
  ws.onmessage = e  => handleWsMessage(JSON.parse(e.data));
  ws.onclose   = () => addSystemMsg("Disconnected");
  ws.onerror   = () => addSystemMsg("WebSocket error");

  state.ws = ws;

  // Enable input
  document.getElementById("msg-input").disabled  = false;
  document.getElementById("send-btn").disabled   = false;
  document.getElementById("chat-title").textContent = `Room: ${roomId.slice(0, 16)}`;

  // Mark room active
  document.querySelectorAll(".room-item").forEach(e => e.classList.remove("active"));
  const el = document.getElementById("room-" + roomId);
  if (el) el.classList.add("active");

  // Load history
  loadHistory(roomId);
}

function switchRoom(roomId) {
  if (roomId === state.roomId) return;
  addSystemMsg("Switch rooms by rejoining with your token");
}

// ── Message send ───────────────────────────────────────────────

async function sendMessage() {
  const input = document.getElementById("msg-input");
  const text  = input.value.trim();
  if (!text || !state.ws || state.ws.readyState !== WebSocket.OPEN) return;

  const nonce     = randomHex(32);
  const timestamp = isoNow();
  let   ciphertext;

  if (state.e2eEnabled && state.cryptoKey) {
    ciphertext = await encryptMessage(text, state.cryptoKey);
  } else {
    ciphertext = text;   // plaintext – shows attacker what they'd see without E2E
  }

  const msgHash = await sha256Hex(`${state.username}|${ciphertext}|${timestamp}|${nonce}`);

  const payload = {
    type:       "chat",
    message_id: randomId(),
    room_id:    state.roomId,
    sender:     state.username,
    ciphertext,
    timestamp,
    nonce,
    hash:       msgHash,
    is_file:    false,
    filename:   "",
  };

  state.ws.send(JSON.stringify(payload));
  input.value = "";

  // Optimistically show own message
  appendMessage({
    sender:    state.username,
    plaintext: text,
    timestamp,
    is_file:   false,
    own: true,
  });
}

// ── Message receive ────────────────────────────────────────────

async function handleWsMessage(msg) {
  if (msg.type === "system") { addSystemMsg(msg.text); return; }
  if (msg.type === "error")  {
    addErrorMsg(`[${msg.event || "ERROR"}] ${msg.reason}`);
    // Propagate to security monitor
    window._secPush({ type: msg.event || "ERROR", reason: msg.reason });
    return;
  }
  if (msg.type !== "chat")   return;

  // Don't double-render own messages (we showed them optimistically)
  if (msg.sender === state.username) return;

  let plaintext = msg.plaintext || "";
  if (!plaintext && state.cryptoKey && state.e2eEnabled) {
    plaintext = await decryptMessage(msg.ciphertext, state.cryptoKey);
  } else if (!plaintext) {
    plaintext = msg.ciphertext;
  }

  appendMessage({
    sender: msg.sender,
    plaintext,
    timestamp: msg.timestamp,
    is_file:   msg.is_file,
    filename:  msg.filename,
    message_id: msg.message_id,
  });
}

function appendMessage({ sender, plaintext, timestamp, is_file, filename, message_id, own = false }) {
  const container = document.getElementById("messages");
  const div = document.createElement("div");
  div.className = "msg" + (own ? " own" : "");

  const ts = timestamp ? new Date(timestamp).toLocaleTimeString() : "";
  const bodyContent = is_file
    ? `&#128196; <a href="#" style="color:var(--accent)"
          onclick="downloadFile('${escHtml(message_id)}','${escHtml(filename)}');return false;"
        >${escHtml(filename)}</a> <span style="color:var(--muted)">(click to download)</span>`
    : escHtml(plaintext);

  div.innerHTML = `
    <div class="msg-meta">${escHtml(sender)} · ${ts}</div>
    <div class="msg-body">${bodyContent}</div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

function addSystemMsg(text) {
  const div = document.createElement("div");
  div.className = "msg system";
  div.innerHTML = `<div class="msg-body">${escHtml(text)}</div>`;
  document.getElementById("messages").appendChild(div);
  document.getElementById("messages").scrollTop = 9999;
}

function addErrorMsg(text) {
  const div = document.createElement("div");
  div.className = "msg error";
  div.innerHTML = `<div class="msg-body">&#9888; ${escHtml(text)}</div>`;
  document.getElementById("messages").appendChild(div);
  document.getElementById("messages").scrollTop = 9999;
}

// ── History load ───────────────────────────────────────────────

async function loadHistory(roomId) {
  const r = await fetch(`/api/chat/${roomId}/history`);
  if (!r.ok) return;
  const { messages } = await r.json();
  for (const m of messages) {
    if (m.is_file) {
      appendMessage({ sender: m.sender, plaintext: "", timestamp: m.timestamp,
        is_file: true, filename: m.filename, message_id: m.message_id });
      continue;
    }
    let plaintext = m.ciphertext;
    if (state.cryptoKey && state.e2eEnabled) {
      plaintext = await decryptMessage(m.ciphertext, state.cryptoKey);
    }
    appendMessage({ sender: m.sender, plaintext, timestamp: m.timestamp });
  }
}

// ── File download ──────────────────────────────────────────────

async function downloadFile(messageId, filename) {
  if (!state.roomId) { alert("Not in a room"); return; }
  const url = `/api/files/download/${messageId}?room_id=${encodeURIComponent(state.roomId)}`;
  const r = await fetch(url);
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }));
    addErrorMsg(`Download failed: ${err.detail || r.statusText}`);
    return;
  }
  // Trigger browser save-dialog without navigating away
  const blob = await r.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename || "file";
  a.click();
  URL.revokeObjectURL(a.href);
  addSystemMsg(`Downloaded: ${filename}`);
}

// ── File upload ────────────────────────────────────────────────

async function uploadFile() {
  const input = document.getElementById("file-input");
  const file  = input.files[0];
  if (!file || !state.roomId) return;

  const fd = new FormData();
  fd.append("room_id", state.roomId);
  fd.append("sender",  state.username || "anonymous");
  fd.append("file",    file);

  const r = await fetch("/api/files/upload", { method: "POST", body: fd });
  const d = await r.json();
  if (!r.ok) { alert(d.detail || "Upload failed"); return; }
  addSystemMsg(`File uploaded: ${file.name} (sha256: ${d.hash.slice(0, 16)}…)`);
  input.value = "";
}

// ── Misc ───────────────────────────────────────────────────────

function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Expose for security_panel.js
window._state = state;
