// SPDX-License-Identifier: AGPL-3.0-or-later
// Login overlay controller. Drives index.html's #login-overlay until the
// user signs in (or creates / restores) an identity. Resolves with
// { seed: Uint8Array(32), username: string }.
//
// State machine:
//   absent  → show "create" pane
//   locked  → show "signin" pane (passphrase prompt)
//   legacy  → show "signin" pane with a one-click no-passphrase confirm
//             (and a hint to set a passphrase from settings later)
//   recover → show "recover" pane (entered from any other pane)
//
// All async crypto work runs inside try/catch + a "working…" spinner so
// the UI doesn't freeze silently during the ~0.5s Argon2id step.

'use strict';

import * as Vault from "./identity_vault.js";
import { phraseToSeed } from "./bip39.js";

// Recover-from-code accepts both formats:
//   * 64-char lowercase hex (the v0 format — exact bytes of the seed)
//   * 24-word BIP39 English phrase (the friendlier UX, with a built-in
//     checksum that catches typos before the KDF burns CPU on garbage).
// We auto-detect: if the input contains whitespace it's treated as BIP39,
// otherwise hex.
async function decodeRecoveryInput(s) {
    if (/\s/.test(s.trim())) {
        return phraseToSeed(s);    // throws on unknown word / bad checksum
    }
    return Vault.recoveryHexToSeed(s);
}

const $ = (id) => document.getElementById(id);

function show(paneId) {
    for (const p of ["login-create-pane", "login-signin-pane", "login-recover-pane"]) {
        $(p).hidden = (p !== paneId);
    }
    for (const e of ["login-create-error", "login-signin-error", "login-recover-error"]) {
        $(e).hidden = true;
    }
}

function setError(paneSlug, msg) {
    const el = $(`login-${paneSlug}-error`);
    el.textContent = msg;
    el.hidden = false;
}

function setSpinner(on, label) {
    const el = $("login-spinner");
    el.hidden = !on;
    if (on && label) el.textContent = label;
}

// NFC-normalize the passphrase so a user typing "café" via different IMEs
// (decomposed vs precomposed) gets the same KDF input on both ends. Without
// this, cross-device unlocks via recovery code would silently fail despite
// identical-looking text.
function normPass(s) { return (s || "").normalize("NFC"); }

// Boot the login flow. Returns Promise<{ seed, username }>. The overlay is
// hidden once the user has unlocked. Safe to call multiple times — each
// invocation replaces the form elements (so listeners from earlier calls
// don't double-fire).
export async function bootLogin(Module) {
    // Reset form state (also strips any listeners from a previous bootLogin).
    for (const id of ["login-create-pane", "login-signin-pane", "login-recover-pane"]) {
        const old = $(id);
        if (!old) continue;
        const fresh = old.cloneNode(true);
        old.parentNode.replaceChild(fresh, old);
    }
    $("login-overlay").hidden = false;
    document.body.style.overflow = "hidden";

    const status = await Vault.vaultStatus();
    let mode = status;   // "absent" | "locked" | "legacy" | "error"
    if (mode === "error") {
        // IndexedDB unreadable. Don't proceed to create-vault — that would
        // overwrite a vault we couldn't read. Show the create form anyway
        // so the user can recover via "use recovery code", but lead with
        // a loud error and keep the username field empty.
        const why = await Vault.vaultErrorMessage();
        $("login-sub").innerHTML =
            `<span style="color:var(--error-red)">storage unreadable: ${
                why || "unknown"}</span><br>` +
            `<span style="font-size:11px">create new identity, or use ` +
            `recovery code to restore</span>`;
        show("login-create-pane");
    } else if (mode === "absent") {
        show("login-create-pane");
        $("login-sub").textContent = "create your local identity";
    } else {
        const meta = await Vault.getMetadata();
        $("login-signin-username").textContent = meta?.username || "(unknown)";
        if (mode === "legacy") {
            // Hide the passphrase field; the legacy vault unlocks with no input.
            $("login-signin-passlabel").hidden = true;
            $("login-signin-btn").textContent = "Continue (no passphrase)";
            $("login-sub").textContent = "unencrypted vault — sign in";
        } else {
            $("login-signin-passlabel").hidden = false;
            $("login-signin-btn").textContent = "Sign in";
            $("login-sub").textContent = "enter your passphrase";
        }
        show("login-signin-pane");
        $("login-signin-pass").focus();
    }

    return new Promise((resolve, reject) => {
        // ---------- create pane ----------
        $("login-create-pane").addEventListener("submit", async (ev) => {
            ev.preventDefault();
            const username = $("login-create-username").value.trim();
            const pass     = normPass($("login-create-pass").value);
            const pass2    = normPass($("login-create-pass2").value);
            if (!username) { setError("create", "username required"); return; }
            if (pass !== pass2) { setError("create", "passphrases don't match"); return; }
            if (!pass && !confirm(
                "Create the vault WITHOUT a passphrase?\n\n" +
                "The seed will be stored in IndexedDB unencrypted. Anyone " +
                "with access to this browser profile (or a JS-injecting " +
                "extension) could read it.\n\nProceed anyway?")) {
                return;
            }
            try {
                setSpinner(!!pass, "deriving key (Argon2id)…");
                // Generate a fresh identity in WASM, then read back the seed.
                const wc = new Module.WebClient();
                const seed = new Uint8Array(wc.identity_seed());
                wc.delete();
                await Vault.createVault({ Module, username, passphrase: pass, seed });
                setSpinner(false);
                hideOverlay();
                resolve({ seed, username });
            } catch (e) {
                setSpinner(false);
                setError("create", e.message);
            }
        });

        // ---------- signin pane ----------
        $("login-signin-pane").addEventListener("submit", async (ev) => {
            ev.preventDefault();
            try {
                setSpinner(true, "verifying passphrase (Argon2id)…");
                const passphrase = normPass($("login-signin-pass").value);
                const seed = await Vault.unlock({ Module, passphrase });
                setSpinner(false);
                if (!seed) {
                    setError("signin", "wrong passphrase or corrupted vault");
                    return;
                }
                const meta = await Vault.getMetadata();
                hideOverlay();
                resolve({ seed, username: meta?.username || "" });
            } catch (e) {
                setSpinner(false);
                setError("signin", e.message);
            }
        });

        $("login-wipe-link").addEventListener("click", async (ev) => {
            ev.preventDefault();
            if (!confirm("Wipe the local vault? Your identity (and access to existing channels) will be lost unless you have a recovery code.")) return;
            await Vault.signOut();
            // Restart the login flow from scratch.
            location.reload();
        });

        // ---------- recover pane ----------
        const goRecover = (ev) => {
            ev.preventDefault();
            // Pre-fill username if we have one.
            Vault.getMetadata().then((m) => {
                if (m?.username) $("login-recover-username").value = m.username;
            });
            $("login-sub").textContent = "restore from recovery code";
            show("login-recover-pane");
            $("login-recover-hex").focus();
        };
        $("login-recover-link").addEventListener("click", goRecover);
        $("login-recover-link-2").addEventListener("click", goRecover);

        $("login-recover-back-btn").addEventListener("click", () => {
            // Return to whichever pane we came from.
            if (mode === "absent") show("login-create-pane");
            else                   show("login-signin-pane");
        });

        $("login-recover-pane").addEventListener("submit", async (ev) => {
            ev.preventDefault();
            try {
                const username = $("login-recover-username").value.trim();
                const hex      = $("login-recover-hex").value;
                const pass     = normPass($("login-recover-pass").value);
                if (!username) { setError("recover", "username required"); return; }
                let seed;
                try { seed = await decodeRecoveryInput(hex); }
                catch (e) { setError("recover", e.message); return; }
                if (!pass && !confirm(
                    "Restore without a passphrase? The seed will be stored " +
                    "in IndexedDB unencrypted. Anyone with access to this " +
                    "browser profile could read it.")) {
                    return;
                }
                setSpinner(!!pass, "deriving key (Argon2id)…");
                await Vault.createVault({ Module, username, passphrase: pass, seed });
                setSpinner(false);
                hideOverlay();
                resolve({ seed, username });
            } catch (e) {
                setSpinner(false);
                setError("recover", e.message);
            }
        });
    });
}

function hideOverlay() {
    $("login-overlay").hidden = true;
    document.body.style.overflow = "";
}

// Re-show the overlay after sign-out. Used by the settings panel.
export function showLoginOverlay() {
    $("login-overlay").hidden = false;
    document.body.style.overflow = "hidden";
}
