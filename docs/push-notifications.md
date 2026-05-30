# Push notification privacy spec

Mobile clients (iOS, Android) will need to wake on a push notification from
Apple Push Notification service (APNs) or Firebase Cloud Messaging (FCM) so
they can fetch new messages without holding a persistent socket. Both push
intermediaries are **honest-but-curious at best** — Apple and Google can
read the push payload, are subject to subpoena, can be compromised, and
have visible histories of cooperating with intelligence agencies. Sending a
sender name or message preview in the push payload is equivalent to
publishing it to Apple/Google.

This document pre-locks the design so when the mobile clients land they
have nothing to figure out at the protocol layer. **No mobile client
exists yet** — this is a design contract, not an implementation report.

## Threat model

A passive observer of the push stream:

| Adversary | Sees today (if we ship naively) |
|---|---|
| Apple/Google push infra | full notification payload (sender, recipient, preview) |
| Compelled disclosure | full APNs/FCM log going back the service's retention window |
| Insider at the push provider | live feed of who's messaging whom, when, what about |
| Network attacker on Apple/Google's wire | TLS-protected — Apple/Google's content, not ours, so HTTPS is theirs |

What we want them to see:

| Layer | What's visible |
|---|---|
| Push payload bytes | `wake_token` (16 random bytes) + a constant trigger flag. Nothing else. |
| Push timing | per-recipient cadence (residual leak — see "Cover pushes" below) |
| Recipient device token | Apple/Google necessarily know which device they're delivering to (the addressing is theirs) — same as for any push-based app |

## Wake-push payload (the only thing we ship to APNs/FCM)

```json
{
  "wake_token": "<16-byte hex>",
  "trigger":    "fb_envelope"
}
```

- **wake_token** — a random 16-byte token the relay generates per
  envelope-pending-for-this-recipient. The client reads it, then HTTP-GETs
  `https://relay/envelopes/by-token/<wake_token>` over TLS to fetch the
  actual Envelope, then decrypts via the recipient's local Double Ratchet.
  The token is single-use; the relay deletes it on successful fetch.
- **trigger** — a constant string identifying FinBit's push kind so the
  mobile client can route in `didReceiveRemoteNotification` /
  `onMessageReceived` without parsing. Single value today
  (`"fb_envelope"`); could grow if other in-band wakes are needed.
- **Nothing else.** No sender pubkey, no recipient pubkey, no message
  type, no count, no preview. The relay must not include identifiable
  metadata in the push payload regardless of what an operator's mobile
  PM thinks would improve UX.

### Why not just include the encrypted envelope bytes?

APNs caps a single notification payload at 4 KB; one of our envelopes after
Tier-7 PQ-hybrid and the Tier-11 PQ-sig sealed-sender headers can reach
several KB. The wake-token + fetch indirection sidesteps the cap and lets
the client decrypt large attachments too. It also keeps the push payload
constant-size, defeating size-side-channel inferences about message
content.

## Receive flow — iOS

1. The app installs an APNs token at first launch; it registers the token
   with the relay over the existing TLS channel.
2. A new envelope arrives at the relay for this user → relay POSTs
   `{wake_token, trigger}` to APNs with `apns-push-type: alert` and
   `mutable-content: 1`.
3. iOS wakes the app's **Notification Service Extension** (NSE). Apple
   guarantees the NSE 30 seconds before the OS shows the OS-supplied
   notification body.
4. Inside the NSE: TLS-fetch `envelope/by-token/<wake_token>` from the
   relay; the existing PQ-hybrid ratchet decrypts it locally; the NSE
   mutates the notification's `title`/`body` to the real (decrypted)
   sender + preview.
5. The OS displays the mutated notification. The user taps it; the main
   app activates and the envelope is already in the local store.

Reliability notes:

- iOS throttles silent (`content-available: 1`) pushes aggressively when
  the app isn't in the foreground. **Always** send the visible-alert
  variant with the mutable-content flag; rely on the NSE to fill in the
  body.
- If the NSE can't reach the relay (offline), it leaves the notification
  as the OS-supplied generic "You have a new message" — the user knows
  something arrived but the content stays opaque on the lock screen.
- The NSE has 30 s; a slow TLS handshake + fetch + decrypt should fit but
  doesn't have headroom. Keep TLS session resumption enabled.

## Receive flow — Android

1. App registers an FCM token at install; pushes the token to the relay
   on connect.
2. Relay sends FCM **data message** (NOT a notification message) with
   `{wake_token, trigger}`. The OS does NOT auto-display anything.
3. FCM delivers to the app's `FirebaseMessagingService.onMessageReceived`.
4. The service enqueues a WorkManager job for the actual fetch (so it
   survives Doze/App Standby). The job: TLS-fetch the envelope from the
   relay, decrypt locally, write to the local store, and only THEN call
   `NotificationManager.notify(...)` with the decrypted content. The
   notification is posted by the APP, not the platform — so FCM never
   sees the plaintext.
5. If WorkManager is delayed by Doze (~minutes on a phone that's been
   idle), the user sees the notification with a delay; the message
   itself is correct.

## What goes in the displayed notification

Defaults — overridable per-conversation in settings, all conservative:

- **Title:** the peer's user-set display name OR their `Identity::fingerprint()`
  (10-char base32). Never the full pubkey.
- **Body:** the first 100 characters of the decrypted text, OR a generic
  "📷 Image" / "🎤 Voice" / "📎 Attachment" for non-text payloads. Sealed-
  sender envelopes (post-handshake) reveal the sender via the safety-
  number-verified peer record; pre-bootstrap envelopes (with the
  plaintext sender_pubkey on the wire) get the same name resolution.
- **Lock-screen preview:** OFF by default. The OS exposes a per-app
  "show preview only when unlocked" toggle on both iOS and Android;
  honor it.
- **Group notification by conversation,** not by sender — so the iOS
  "Notification Group" view doesn't leak the pattern of who-talks-to-
  whom even when the user has lock-screen previews off.

## Residual leaks (honest list)

1. **Frequency / timing.** Apple/Google see how often this device is being
   pushed to, which leaks "user is online" + "user just got a message."
   Mitigation: **cover pushes** — at the relay, schedule periodic dummy
   pushes (random wake tokens that the client recognizes as no-ops on
   fetch). Bandwidth-hostile; opt-in. Matches the Tier-9 wire-level
   cover-traffic mode.
2. **Device token = device fingerprint.** Apple/Google know which physical
   device is registered for our app. Tied to the platform's app-install
   identity. Defense: re-register the token periodically (e.g. monthly)
   to break long-term correlation. Limited because the platform's
   underlying device token also rotates on its own schedule.
3. **WHO has the device token.** The relay's per-user mapping
   `pubkey → push_token` is sensitive. Mitigation: store ONLY the
   wrapped form (push_token AEAD-encrypted under a per-user key the
   relay only uses when DELIVERING). Listed in the
   [warrant-canary](warrant-canary.md) defensible-claims set.
4. **Backend dependency.** Push relies on Apple/Google operating
   correctly. A user on a degoogled Android (no Play Services) can't
   receive FCM pushes. **For that user we fall back to a long-lived
   WebSocket**, accepting the battery cost. The app surfaces this
   choice as a settings toggle ("Use FCM" default-on; off → persistent
   socket).

## Relay-side changes (when mobile lands)

The relay needs:

1. **Push-token table:** `{user_pubkey, platform (apns/fcm), token,
   registered_at}`. AEAD-wrapped per-user as noted above. Honor `--amnesia`
   — when amnesia mode is on, the table is in-RAM only.
2. **Wake-token issuance:** per envelope-pending, generate 16 random bytes,
   store `(wake_token → envelope_id)` for fetch lookup, post to APNs/FCM
   with the wake_token in the payload.
3. **Wake-token fetch endpoint:** `GET /envelopes/by-token/<wake_token>` —
   returns the matching Envelope, deletes the wake-token record. TLS-only,
   the existing fb_server TLS port serves it.
4. **APNs HTTP/2 client + FCM HTTP/1.1 client:** vendor or use existing
   libraries (libpushd / libfcm) — both are well-trodden.

## Implementation acceptance criteria

When the mobile client lands, the test plan must include:

- [ ] Capture a push payload via mitmproxy against APNs/FCM — payload
      contains ONLY `wake_token` + `trigger`. No sender, no preview.
- [ ] Notification displayed on iOS lock screen with previews OFF shows
      generic "New message" — never the sender name or body text.
- [ ] App restart while offline still receives queued pushes once
      network returns (FCM/APNs queue + relay re-issues wake tokens
      that survive restart).
- [ ] Degoogled Android falls back to WebSocket without FCM and message
      delivery still works.
- [ ] On a fresh install the push registration round trip happens over
      TLS to the relay (no plaintext push token sent in HTTP clear).

## Out of scope for this spec

- The actual mobile app codebases (iOS / Android) — separate workstreams
  per `docs/ROADMAP.md`.
- The push-relay infrastructure scaling (HTTP/2 connection pooling, FCM
  rate limits) — operational concern when traffic exists.
- Cross-device sync for users with multiple devices — design depends on
  how the multi-device identity story lands.
