// SPDX-License-Identifier: AGPL-3.0-or-later
// End-to-end: two web-style clients (alice + bob) over the WebSocket
// transport. Alice creates a channel, invites bob via DM, sends a channel
// message; bob installs the chain from the invite and decrypts the message.
//
// Use:
//   ./build/system/server/fb_server --port 8765 --ws-port 8766
//   cd client-web && node test/web_channel_node.mjs
//
// Exit 0 on success; non-zero with stderr trace on failure.

import FinBitModule from "../build/finbit.mjs";
import { FinBitConnection } from "../ui/finbit_conn.js";

const URL  = process.env.WS_URL || "ws://127.0.0.1:8766";
const A    = process.env.A || "alice-ch";
const B    = process.env.B || "bob-ch";
const TEXT = process.env.MARKER || "secret-channel-msg-from-alice";

const M = await FinBitModule();
const aliceConn = new FinBitConnection(M, URL, A);
const bobConn   = new FinBitConnection(M, URL, B);

let bobGotInvite = null;
let bobGotText   = null;

aliceConn.on("onLog",  (s) => console.error(`[A] ${s}`));
bobConn.on("onLog",    (s) => console.error(`[B] ${s}`));
bobConn.on("onChannelInvite", (i) => { bobGotInvite = i; });
bobConn.on("onChannelText",   (m) => { bobGotText   = m; });

await aliceConn.connect();
await bobConn.connect();

// Bob has to be subscribed before alice creates+sends, otherwise the server
// will fan out the channel envelope before bob's chan_subscribe arrives.
// The flow handles this naturally: alice DMs bob the invite, bob subscribes
// inside its onChannelInvite path. We just need to wait for the invite to
// land before alice sends to the channel.

console.error("[*] alice creates channel + invites bob…");
const { channelId, channelHex } = await aliceConn.createChannel("test-ch", [B]);
console.error(`[*] channel id ${channelHex}`);

await waitFor(() => bobGotInvite !== null, 3000, "bob never received invite");
console.error(`[*] bob got invite for "${bobGotInvite.channelName}"`);

// Brief pause so the server records bob's chan_subscribe before the message
// is fanned out. (Without it the message can arrive before subscribe lands
// and the server skips bob.)
await sleep(150);

console.error("[*] alice sends channel message…");
await aliceConn.sendChannelMessage(channelId, TEXT);

await waitFor(() => bobGotText !== null, 3000, "bob never received channel msg");
if (bobGotText.text !== TEXT) {
    throw new Error(`PLAINTEXT MISMATCH: got "${bobGotText.text}" wanted "${TEXT}"`);
}
console.log(`PASS: bob decrypted "${bobGotText.text}"`);

aliceConn.close();
bobConn.close();
process.exit(0);

function sleep(ms)   { return new Promise((r) => setTimeout(r, ms)); }
async function waitFor(pred, ms, msg) {
    const t0 = Date.now();
    while (!pred()) {
        if (Date.now() - t0 > ms) throw new Error("timeout: " + msg);
        await sleep(20);
    }
}
