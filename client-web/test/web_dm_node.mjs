// SPDX-License-Identifier: AGPL-3.0-or-later
// End-to-end Node.js script: act as the FinBit web client (WebSocket
// transport, JS protobuf encoding, WASM crypto) and DM a peer who is
// listening over the existing TCP path via fb-cli.

import FinBitModule from "../build/finbit.mjs";
import { FinBitConnection } from "../ui/finbit_conn.js";

const url = process.env.WS_URL || "ws://127.0.0.1:8766";
const username = process.env.WEB_USER || "alice";
const peer = process.env.PEER || "bob";
const text = process.env.MARKER || "hello-from-web";

const M = await FinBitModule();
const conn = new FinBitConnection(M, url, username);
conn.on("onLog",  (s)  => console.error(`[web] ${s}`));
conn.on("onAuth", (fp) => console.error(`[web] AUTHED as ${username} (${fp})`));
conn.on("onText", ({ text: t }) => console.log(`MSG: ${t}`));

await conn.connect();
await new Promise((r) => setTimeout(r, 200));
await conn.sendDm(peer, text);
await new Promise((r) => setTimeout(r, 800));
conn.close();
