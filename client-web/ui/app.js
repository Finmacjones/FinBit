// SPDX-License-Identifier: AGPL-3.0-or-later
// FinBit web UI — wires the static HTML to the WASM crypto module +
// the WebSocket transport (FinBitConnection). Real DMs work end-to-end.

import FinBitModule from "../build/finbit.mjs";
import { FinBitConnection } from "./finbit_conn.js";
import * as Vault from "./identity_vault.js";
import { bootLogin, showLoginOverlay } from "./login_ui.js";
import { seedToPhrase } from "./bip39.js";
import * as ServerBook from "./server_book.js";
import * as Notify from "./notify.js";

const $ = (id) => document.getElementById(id);

// ---------- avatar coloring (matches the desktop client's hue scheme) ----------
function fnv1a(str) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < str.length; i++) {
        h ^= str.charCodeAt(i) & 0xff;
        h = Math.imul(h, 16777619) >>> 0;
    }
    return h;
}
function hueFor(seed) { return fnv1a(seed) % 360; }
function paintAvatars(root = document) {
    for (const el of root.querySelectorAll(".avatar")) {
        const seed = el.dataset.seed || el.textContent;
        el.style.background = `hsl(${hueFor(seed)} 60% 50%)`;
    }
}

// ---------- in-memory message log (per-conversation) -------------------------
// Conversation keys:
//   "dm:<username>"  — DM with a peer (sidebar entries are demo seeds)
//   "chan:<hex32>"   — a real SenderKeys channel; the part after "chan:" is
//                       the 64-char hex of the 32-byte channel id.
const conversations = {
    "dm:alice": [],
    "dm:bob":   [],
};
let currentConv = "dm:alice";
// Map channelHex -> friendly name for the sidebar / chat header.
const channelNames = new Map();

// Tracks the last-rendered conversation + length so we only play the CRT
// glitch-in on a genuinely new message (not on conversation switches or
// unrelated re-renders).
let _crtLastConv = null, _crtLastLen = 0;

function renderMessages() {
    const ul = $("messages");
    ul.innerHTML = "";
    const convo = conversations[currentConv] || [];
    const isNewMsg = currentConv === _crtLastConv && convo.length > _crtLastLen;
    for (const m of convo) {
        const li = document.createElement("li");
        li.className = "message-row";
        const monogram = m.sender.slice(0, 2).toUpperCase();
        const time = new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        li.innerHTML = `
            <span class="avatar" data-seed="${m.sender}">${monogram}</span>
            <div class="message-header">
                <span class="message-sender">${m.sender}</span>
                <span class="message-time">Today at ${time}</span>
            </div>
            <div class="message-body">${escapeHtml(m.body)}</div>`;
        ul.appendChild(li);
    }
    // CRT glitch-in for the newest row (CSS gates it on data-crt / reduced-motion).
    if (isNewMsg && ul.lastElementChild) {
        ul.lastElementChild.classList.add("crt-glitch-in");
    }
    _crtLastConv = currentConv;
    _crtLastLen = convo.length;
    paintAvatars(ul);
    ul.scrollTop = ul.scrollHeight;
}
function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]);
}

function selectConversation(key) {
    currentConv = key;
    document.querySelectorAll(".sidebar-list li").forEach((li) =>
        li.classList.toggle("active", li.dataset.key === key));
    const isChan = key.startsWith("chan:");
    const id = key.split(":")[1];
    const display = isChan ? (channelNames.get(id) || `${id.slice(0, 8)}…`) : id;
    $("chat-header-title").textContent = display;
    document.querySelectorAll(".chat-header-icon").forEach(
        (e) => e.textContent = isChan ? "#" : "@");
    $("chat-header-subtitle").textContent =
        isChan ? "end-to-end encrypted channel (sender-keys)" : "direct message (Double Ratchet)";
    $("compose-input").placeholder = isChan ? `Message #${display}` : `Message @${id}`;
    renderMessages();
}

// Add a channel row to the sidebar (idempotent on cidHex).
function ensureChannelInSidebar(cidHex, name) {
    if (channelNames.get(cidHex) !== name && name) channelNames.set(cidHex, name);
    if (!channelNames.has(cidHex) && name) channelNames.set(cidHex, name);
    const list = $("channel-list");
    const key = `chan:${cidHex}`;
    if (list.querySelector(`li[data-key="${key}"]`)) return;
    const li = document.createElement("li");
    li.dataset.key = key;
    li.textContent = `# ${channelNames.get(cidHex) || cidHex.slice(0, 8) + "…"}`;
    li.addEventListener("click", () => selectConversation(key));
    list.appendChild(li);
}

// ---------- WASM wiring + Connection state ----------
let Module = null;
let Conn = null;
let session = null;             // { seed: Uint8Array(32), username: string, fingerprint: string }
let currentCall = null;         // { peer, cs } — outbound or accepted call
let currentInboundCall = null;  // { peerPub, cs } — pending accept/decline
let activeServerId = null;      // id of the server in the server_book that Conn is bound to

function peerShort(peerPub) {
    return [...peerPub].slice(0, 4)
        .map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Hook a CallSession's events to the active-call UI elements.
function wireCallSession(cs, label) {
    cs.addEventListener("track", (ev) => {
        const { kind, stream } = ev.detail;
        if (kind === "audio") {
            $("remote-audio").srcObject = stream;
        } else if (kind === "video") {
            $("remote-video").hidden = false;
            $("remote-video").srcObject = stream;
        }
    });
    cs.addEventListener("statechange", (ev) => {
        if (ev.detail.state === "live" && cs.localStream) {
            const v = cs.localStream.getVideoTracks();
            if (v.length) {
                $("local-video").hidden = false;
                $("local-video").srcObject = cs.localStream;
            }
        }
    });
}
async function bootWasm() {
    try {
        Module = await FinBitModule();
        $("aes-avail").textContent = Module.aes256gcm_supported() ? "yes" : "no (XChaCha20 only)";
        $("aes-avail").style.color =
            Module.aes256gcm_supported() ? "var(--status-online)" : "var(--warning-amber)";
    } catch (e) {
        $("aes-avail").textContent = `WASM load failed: ${e.message}`;
        $("aes-avail").style.color = "var(--error-red)";
        throw e;
    }
}

// Apply a session to the UI: identity-display, user panel, prefill connect form.
function adoptSession({ seed, username }) {
    const wc = Module.WebClient.from_seed(seed);
    const fp = wc.fingerprint();
    wc.delete();
    session = { seed, username, fingerprint: fp };
    $("conn-user").value = username || "";
    $("identity-display").textContent = `${fp}\n(unlocked locally — connect to go online)`;
    $("user-panel-name").textContent = username || "you";
    $("user-panel-fp").textContent = fp;
    const av = $("user-avatar");
    av.dataset.seed = fp;
    av.textContent = fp.slice(0, 2);
    paintAvatars(av.parentElement);
}

function dropSession() {
    session = null;
    // Hang up any in-flight calls before tearing down the connection so the
    // peer gets a HANGUP signal rather than a silent WS close.
    if (Conn) {
        for (const cs of Conn.calls.values()) {
            try { cs.hangup(); } catch {}
        }
        try { Conn.close(); } catch {}
        Conn = null;
    }
    currentCall = null;
    currentInboundCall = null;
    $("call-banner").hidden = true;
    $("inbound-call-modal").hidden = true;
    $("conn-status").textContent = "disconnected";
    $("identity-display").textContent = "—";
    $("user-panel-name").textContent = "not signed in";
    $("user-panel-fp").textContent = "";
    $("recovery-display").hidden = true;
}

function randBytes(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
}

function uint8ToHex(b, max = 32) {
    const hex = [...b].slice(0, max).map((v) => v.toString(16).padStart(2, "0")).join("");
    return b.length > max ? `${hex}… (${b.length}B)` : hex;
}

// ---------- event wiring ----------
function wire() {
    document.querySelectorAll(".sidebar-list li").forEach((li) => {
        li.addEventListener("click", () => selectConversation(li.dataset.key));
    });

    let connecting = false;
    $("connect-btn").addEventListener("click", async () => {
        if (!Module) {
            $("conn-status").textContent = "WASM not ready";
            return;
        }
        if (!session) {
            $("conn-status").textContent = "sign in first";
            return;
        }
        if (connecting || (Conn && Conn.connected)) {
            // Double-click guard — would otherwise leak a second WebSocket
            // and double-fire all subsequent onText / onCallStateChange.
            return;
        }
        connecting = true;
        $("connect-btn").disabled = true;
        const url = $("conn-url").value;
        const user = $("conn-user").value || session.username;
        $("conn-status").textContent = "connecting…";
        Conn = new FinBitConnection(Module, url, user, { seed: session.seed });
        Conn.on("onLog",  (s)  => { $("conn-status").innerText += "\n" + s; });
        Conn.on("onAuth", (fp) => {
            $("conn-status").innerHTML =
                `<div style="color:var(--status-online)">connected as ${user}</div>
                 <div style="font-family:monospace;font-size:11px">${fp}</div>`;
        });
        Conn.on("onText", ({ senderPub, text }) => {
            const fp_short = [...senderPub].slice(0, 4)
                .map((b) => b.toString(16).padStart(2, "0")).join("");
            const peer = "peer-" + fp_short;
            const convo = conversations["dm:" + peer] || (conversations["dm:" + peer] = []);
            convo.push({ sender: peer, body: text, ts: Date.now() });
            if (currentConv === "dm:" + peer) renderMessages();
            // Background-tab notification — only fires when the tab isn't
            // focused and the user has previously granted permission.
            Notify.showLocal(`Message from ${peer}`,
                text.length > 120 ? text.slice(0, 120) + "…" : text);
        });
        Conn.on("onChannelText", ({ channelHex, senderPub, text }) => {
            const peer_short = [...senderPub].slice(0, 4)
                .map((b) => b.toString(16).padStart(2, "0")).join("");
            const key = "chan:" + channelHex;
            const convo = conversations[key] || (conversations[key] = []);
            convo.push({ sender: "peer-" + peer_short, body: text, ts: Date.now() });
            if (currentConv === key) renderMessages();
            const chanLabel = channelNames.get(channelHex) || channelHex.slice(0, 8) + "…";
            Notify.showLocal(`#${chanLabel}: peer-${peer_short}`,
                text.length > 120 ? text.slice(0, 120) + "…" : text);
        });
        Conn.on("onChannelInvite", ({ channelHex, channelName }) => {
            ensureChannelInSidebar(channelHex, channelName || "(unnamed)");
            paintAvatars();
        });
        Conn.on("onOutboxDrained", ({ sent, failed }) => {
            const msg = failed
                ? `outbox: ${sent} sent, ${failed} still queued (retrying on next reconnect)`
                : `outbox drained: ${sent} queued message(s) delivered`;
            $("conn-status").innerText += "\n" + msg;
        });
        Conn.on("onIncomingCall", ({ peerPub, callSession }) => {
            currentInboundCall = { peerPub, cs: callSession };
            $("inbound-call-from").textContent = `from peer-${peerShort(peerPub)}`;
            $("inbound-call-modal").hidden = false;
            wireCallSession(callSession, peerShort(peerPub));
        });
        Conn.on("onCallStateChange", ({ peerName, state }) => {
            if (state === "closed") {
                $("call-banner").hidden = true;
                $("remote-video").hidden = true;
                $("local-video").hidden = true;
                $("inbound-call-modal").hidden = true;
                currentCall = null;
                currentInboundCall = null;
            } else {
                $("call-banner").hidden = false;
                $("call-banner-text").textContent =
                    `${state === "live" ? "📞 In call" : state} with ${peerName}`;
            }
        });
        try { await Conn.connect(); }
        catch (e) {
            $("conn-status").textContent = "connect failed: " + e.message;
            Conn = null;
        }
        connecting = false;
        $("connect-btn").disabled = false;
    });

    async function startCallFromCurrent(withVideo) {
        if (!Conn || !Conn.connected) {
            alert("connect first");
            return;
        }
        if (!currentConv.startsWith("dm:")) {
            alert("calls only work from a DM conversation (1:1 only for now)");
            return;
        }
        const peer = currentConv.slice(3);
        try {
            const cs = await Conn.startCall(peer, { withVideo });
            currentCall = { peer, cs };
            wireCallSession(cs, peer);
        } catch (e) {
            alert("startCall failed: " + e.message);
        }
    }
    $("call-voice-btn").addEventListener("click", () => startCallFromCurrent(false));
    $("call-video-btn").addEventListener("click", () => startCallFromCurrent(true));

    $("hangup-btn").addEventListener("click", async () => {
        const cs = (currentCall && currentCall.cs) ||
                   (currentInboundCall && currentInboundCall.cs);
        if (cs) await cs.hangup();
    });

    $("accept-voice-btn").addEventListener("click", async () => {
        if (!currentInboundCall) return;
        $("inbound-call-modal").hidden = true;
        try { await Conn.acceptIncomingCall(currentInboundCall.peerPub, { withVideo: false }); }
        catch (e) { alert("accept failed: " + e.message); }
    });
    $("accept-video-btn").addEventListener("click", async () => {
        if (!currentInboundCall) return;
        $("inbound-call-modal").hidden = true;
        try { await Conn.acceptIncomingCall(currentInboundCall.peerPub, { withVideo: true }); }
        catch (e) { alert("accept failed: " + e.message); }
    });
    $("decline-call-btn").addEventListener("click", async () => {
        if (!currentInboundCall) return;
        $("inbound-call-modal").hidden = true;
        try { await Conn.declineIncomingCall(currentInboundCall.peerPub); } catch {}
        currentInboundCall = null;
    });

    $("show-recovery-btn").addEventListener("click", async () => {
        if (!session) {
            alert("sign in first");
            return;
        }
        const rec = $("recovery-display");
        if (!rec.hidden) { rec.hidden = true; return; }
        if (!confirm("Reveal the recovery code? Anyone with this code can impersonate you. Write it down offline.")) return;
        const hex    = Vault.seedToRecoveryHex(session.seed);
        const phrase = await seedToPhrase(session.seed);
        rec.innerHTML =
            `<div style="color:var(--text-muted);font-size:11px;margin-bottom:4px;">` +
              `Recovery phrase (24 words, BIP39 — friendlier to write down):` +
            `</div>` +
            `<div style="font-family:monospace;font-size:12px;` +
              `background:var(--bg-floating);padding:8px;border-radius:4px;` +
              `word-spacing:6px;line-height:1.6;">${phrase}</div>` +
            `<div style="color:var(--text-muted);font-size:11px;margin:10px 0 4px;">` +
              `Or as 64 hex characters:` +
            `</div>` +
            `<div style="font-family:monospace;font-size:11px;` +
              `background:var(--bg-floating);padding:8px;border-radius:4px;` +
              `word-break:break-all;">${hex}</div>`;
        rec.hidden = false;
    });

    $("signout-btn").addEventListener("click", async () => {
        if (!confirm("Sign out? You'll be returned to the login screen — your vault stays on this device.")) return;
        dropSession();
        showLoginOverlay();
        // Re-run the login flow against the still-existing vault.
        bootLogin(Module).then(adoptSession);
    });

    $("wipe-vault-btn").addEventListener("click", async () => {
        if (!confirm("Wipe the local vault from this device? This is destructive — without a recovery code your identity is gone.")) return;
        await Vault.signOut();
        dropSession();
        location.reload();
    });

    $("add-channel-btn").addEventListener("click", async () => {
        if (!Conn || !Conn.connected) {
            alert("connect first, then create a channel");
            return;
        }
        const name = prompt("Channel name (e.g. general):");
        if (!name) return;
        const inviteesStr = prompt(
            `Invite which usernames to "${name}"?  (comma-separated, blank for none — they must already be registered)`,
            "");
        const invitees = (inviteesStr || "")
            .split(",").map((s) => s.trim()).filter(Boolean);
        try {
            const { channelHex } = await Conn.createChannel(name, invitees);
            ensureChannelInSidebar(channelHex, name);
            selectConversation("chan:" + channelHex);
        } catch (e) {
            alert("createChannel failed: " + e.message);
        }
    });

    $("aead-btn").addEventListener("click", () => {
        if (!Module) return;
        const text = $("aead-input").value || "hello from the web client";
        const key = randBytes(32);
        const nonce = randBytes(24);
        const pt = new TextEncoder().encode(text);
        const aad = new TextEncoder().encode("settings-self-test");
        try {
            const ct = Module.xchacha20_encrypt(key, nonce, pt, aad);
            const rt = Module.xchacha20_decrypt(key, nonce, ct, aad);
            const ok = rt && [...rt].every((v, i) => v === pt[i]) && rt.length === pt.length;
            $("aead-display").innerHTML =
                `<div>ct (${ct.length}B): ${uint8ToHex(ct)}</div>
                 <div>rt: <span style="color:${ok ? "var(--status-online)" : "var(--error-red)"}">${
                    ok ? "OK — round-trip matched" : "MISMATCH"
                 }</span></div>`;
        } catch (e) {
            $("aead-display").textContent = `error: ${e.message}`;
        }
    });

    // Send button: if connected, real WS DM/channel; offline DMs queue
    // to IndexedDB via Outbox + drain on next connect.
    $("send-btn").addEventListener("click", async () => {
        const v = $("compose-input").value.trim();
        if (!v) return;
        let queued = false;
        try {
            if (currentConv.startsWith("dm:")) {
                if (Conn) {
                    const res = await Conn.sendDm(currentConv.slice(3), v);
                    queued = res?.queued ?? false;
                } else {
                    // No Conn at all — queue via Outbox so it survives a
                    // tab close. (The user hasn't yet hit Connect once.)
                    const Outbox = await import("./outbox.js");
                    await Outbox.enqueue({ recipient: currentConv.slice(3), plaintext: v });
                    queued = true;
                }
            } else if (currentConv.startsWith("chan:") && Conn) {
                const cidHex = currentConv.slice(5);
                const cid = new Uint8Array(cidHex.match(/.{2}/g).map((h) => parseInt(h, 16)));
                await Conn.sendChannelMessage(cid, v);
            }
        } catch (e) {
            $("aead-display").textContent = `send error: ${e.message}`;
        }
        const convo = conversations[currentConv] || (conversations[currentConv] = []);
        convo.push({
            sender: "you",
            body: queued ? `${v}  [queued — will send on reconnect]` : v,
            ts: Date.now(),
        });
        $("compose-input").value = "";
        renderMessages();
    });
    $("compose-input").addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            $("send-btn").click();
        }
    });

    // ---- placeholder chrome ------------------------------------------------
    // The settings panel is statically rendered; this button toggles its
    // visibility so the chat area can use the full width.
    const settingsToggle = $("settings-toggle-btn");
    settingsToggle.addEventListener("click", () => {
        const p = $("settings-panel");
        p.hidden = !p.hidden;
        document.getElementById("app").style.gridTemplateColumns =
            p.hidden ? "72px 240px 1fr" : "72px 240px 1fr 320px";
    });

    // The user-panel gear is currently a quick access for the recovery /
    // sign-out controls in the settings panel — focus & flash them.
    $("settings-btn").addEventListener("click", () => {
        if ($("settings-panel").hidden) settingsToggle.click();
        const r = $("show-recovery-btn");
        r.scrollIntoView({ behavior: "smooth", block: "center" });
        r.style.outline = "2px solid var(--brand-blurple)";
        setTimeout(() => { r.style.outline = ""; }, 1200);
    });

    // (No "home" button anymore — the server rail's per-relay icons act
    // as the navigation between known relays. Click a server icon to
    // switch to it.)

    // Notifications: status + permission button.
    function refreshNotifyStatus() {
        const el = $("notifications-status");
        if (typeof Notification === "undefined") {
            el.textContent = "not supported in this browser";
            return;
        }
        switch (Notification.permission) {
            case "granted": el.textContent = "enabled"; break;
            case "denied":  el.textContent = "blocked (change in browser settings)"; break;
            default:        el.textContent = "click the button to allow"; break;
        }
    }
    refreshNotifyStatus();
    $("enable-notifications-btn").addEventListener("click", async () => {
        const ok = await Notify.requestPermission();
        refreshNotifyStatus();
        if (ok) {
            await Notify.registerSw();
            $("notifications-status").textContent = "enabled — service worker registered";
        }
    });

    // Pre-fill TURN settings from localStorage on boot.
    try {
        $("turn-url").value  = localStorage.getItem("FB_TURN_URL")  || "";
        $("turn-user").value = localStorage.getItem("FB_TURN_USER") || "";
        $("turn-pass").value = localStorage.getItem("FB_TURN_PASS") || "";
        if (localStorage.getItem("FB_TURN_URL")) {
            $("turn-status").textContent = "configured";
        }
    } catch {}
    $("turn-save-btn").addEventListener("click", () => {
        try {
            const url = $("turn-url").value.trim();
            if (url) {
                localStorage.setItem("FB_TURN_URL",  url);
                localStorage.setItem("FB_TURN_USER", $("turn-user").value);
                localStorage.setItem("FB_TURN_PASS", $("turn-pass").value);
                $("turn-status").textContent = "saved — applies to NEW calls";
            } else {
                localStorage.removeItem("FB_TURN_URL");
                localStorage.removeItem("FB_TURN_USER");
                localStorage.removeItem("FB_TURN_PASS");
                $("turn-status").textContent = "cleared";
            }
        } catch (e) { $("turn-status").textContent = "save failed: " + e.message; }
    });
}

// ---------- federation: server rail + add-server modal ----------

// Render one icon per known relay in the rail, plus highlight the active.
async function renderServerRail() {
    const list = await ServerBook.list();
    const railList = document.getElementById("server-list");
    if (!railList) return;
    railList.replaceChildren();
    for (const s of list) {
        const btn = document.createElement("button");
        btn.className = "server-rail-icon";
        btn.dataset.url = s.url;
        btn.textContent = (s.label || "?").slice(0, 2).toUpperCase();
        if (s.id === activeServerId) btn.classList.add("active");
        btn.addEventListener("click", () => {
            void switchToServer(s);
        });
        railList.appendChild(btn);
    }
}

// Tear down the existing connection (if any) and connect to `s`.
async function switchToServer(s) {
    if (!session) {
        alert("sign in first, then add servers");
        return;
    }
    if (Conn) {
        try { Conn.close(); } catch {}
        Conn = null;
    }
    activeServerId = s.id;
    document.getElementById("conn-url").value = s.url;
    document.getElementById("conn-user").value = s.username;
    await renderServerRail();
    // Trigger the existing connect flow by clicking the connect button.
    document.getElementById("connect-btn").click();
}

// Wire the add-server modal once during boot.
function wireAddServer() {
    const modal = $("add-server-modal");
    const open  = () => { modal.hidden = false; $("add-server-url").focus(); };
    const close = () => {
        modal.hidden = true;
        $("add-server-error").hidden = true;
        $("add-server-url").value = "";
        $("add-server-username").value = "";
        $("add-server-label").value = "";
    };
    $("add-server-btn").addEventListener("click", open);
    $("add-server-cancel").addEventListener("click", close);
    $("add-server-form").addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const url   = $("add-server-url").value.trim();
        const user  = $("add-server-username").value.trim();
        const label = $("add-server-label").value.trim();
        if (!url) { showAddServerError("URL required"); return; }
        if (!/^wss?:\/\//.test(url)) { showAddServerError("URL must start with ws:// or wss://"); return; }
        if (!user) { showAddServerError("username required"); return; }
        try {
            await ServerBook.add({ url, username: user, label });
            close();
            await renderServerRail();
        } catch (e) {
            showAddServerError(e.message);
        }
    });
}
function showAddServerError(msg) {
    const el = $("add-server-error");
    el.textContent = msg;
    el.hidden = false;
}

// On boot, if no servers are known, seed one for 127.0.0.1:8766 so the
// rail isn't empty in the obvious local-dev case.
async function ensureSeedServer() {
    const list = await ServerBook.list();
    if (list.length > 0) return;
    if (!session) return;
    try {
        await ServerBook.add({
            url: "ws://127.0.0.1:8766",
            username: session.username,
            label: "local",
        });
    } catch {}
}

// ---------- boot ----------
paintAvatars();
renderMessages();
wire();
wireAddServer();
(async () => {
    await bootWasm();
    if (!Module) return;
    const sess = await bootLogin(Module);
    adoptSession(sess);
    await ensureSeedServer();
    await renderServerRail();
    // Auto-pick the default relay (so the URL field is preset to the right
    // value) but don't auto-connect — that's still the user's choice.
    const def = await ServerBook.getDefault();
    if (def) {
        activeServerId = def.id;
        $("conn-url").value  = def.url;
        $("conn-user").value = def.username;
        await renderServerRail();
    }
})();
