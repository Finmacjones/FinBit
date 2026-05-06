// SPDX-License-Identifier: AGPL-3.0-or-later
// Verify the server refuses a second client claiming a username already
// bound to a different identity.
//
//   1. alice (identity A) connects → succeeds.
//   2. impostor (identity B, fresh keypair) connects with username "alice"
//      → server sends ControlMessage(USERNAME_TAKEN, code=7) and closes.
//
// Without the fix the impostor would silently authenticate as identity B
// while believing they were "alice".

import FinBitModule from "../build/finbit.mjs";
import { FinBitConnection } from "../ui/finbit_conn.js";

const URL = process.env.WS_URL || "ws://127.0.0.1:8766";
// Generate one stable username per test run so reruns don't collide with
// the persistent server directory.
const NAME = process.env.NAME ||
             ("alice-takeover-" + Math.random().toString(36).slice(2, 8));

const M = await FinBitModule();

// Real alice connects first and registers the name.
const alice = new FinBitConnection(M, URL, NAME);
alice.on("onLog", (s) => console.error(`[alice] ${s}`));
await alice.connect();
console.error(`[alice] connected as ${NAME}`);

// Impostor: fresh WebClient → different identity → tries to claim NAME.
const impostor = new FinBitConnection(M, URL, NAME);

let gotControl = null;
impostor.on("onLog",     (s) => console.error(`[impostor] ${s}`));
impostor.on("onControl", (c) => { gotControl = c; });

try {
    await impostor.connect();
    // The control message arrives shortly after HelloAck. Wait briefly.
    await new Promise((r) => setTimeout(r, 400));
} catch (e) {
    // OK if connect throws — the WS may have been torn down mid-handshake.
    console.error(`[impostor] connect threw: ${e.message}`);
}

if (!gotControl) {
    console.error("FAIL: impostor did not receive ControlMessage");
    process.exit(1);
}
if (gotControl.code !== 7) {
    console.error(`FAIL: expected USERNAME_TAKEN (7), got code=${gotControl.code} detail=${gotControl.detail}`);
    process.exit(1);
}
console.log(`OK: impostor rejected with USERNAME_TAKEN: "${gotControl.detail}"`);

alice.close();
impostor.close();
console.log("PASS: username takeover rejection.");
