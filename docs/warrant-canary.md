# Warrant canary template

A warrant canary is a published statement asserting the operator has NOT
received certain compelled-disclosure orders. If the canary stops being
published — or is published without re-asserting the same statements — the
operator is signalling under duress that they CAN no longer truthfully make
those claims, without violating any specific gag order on the disclosure
itself.

This document is the template a FinBit relay operator publishes (signed,
under the operator's long-term Ed25519 identity, ideally also notarized in a
public log like a Merkle-tree transparency log or an OpenTimestamps proof).

Pair with `--amnesia` mode on `fb_server` to back the assertions
operationally: an operator in amnesia mode (no disk persistence) can
truthfully assert that no message bodies, message metadata, prekeys, or
directory records exist on disk for any third party to seize.

---

## When to publish

* **Initial.** When the relay is first stood up.
* **Monthly.** First day of every month, no exceptions. If the operator
  has been compelled and cannot truthfully republish, they DO NOT publish
  (the absence is the signal).
* **On request.** Auditors or peers may ask for a fresh canary at any time;
  the operator either republishes or explicitly declines.

## Format

A signed text file. Sign with the operator's identity key:

```
fb-cli sign-file --identity ~/.finbit/operator.seed warrant-canary.txt
```

The output is `warrant-canary.txt.sig` (64-byte Ed25519 detached signature
over the file bytes). Publish both. Verifiers fetch both, recompute the
signature against the operator's published identity_pubkey, and compare.

For Tier-11 PQ-sig parity, also sign with the operator's PQ-sig identity
(ML-DSA-65) — verifiers require both to pass, defeating a future-CRQC
adversary forging the canary.

```
fb-cli sign-file --identity ~/.finbit/operator.seed --pq-also warrant-canary.txt
```

(produces `warrant-canary.txt.sig` AND `warrant-canary.txt.pqsig`)

---

## Template (copy + customize)

```
# FinBit Relay Warrant Canary

Relay name:          <your-relay-name>
Relay identity (fp): <10-char base32 fingerprint from fb-cli --whoami>
Relay onion (if any): <56-char.onion>
Operator (handle):   <pseudonymous or legal name; up to operator>
Issued:              YYYY-MM-DD (UTC)
Valid through:       YYYY-MM-{DD+31} (UTC) — next canary REPLACES this one
Headline news (UTC): <one-line news headline from the past 24h — pins this
                       canary to a date no earlier than its issue>

Affirmations (true as of the issue date):

  1. This relay runs `fb_server --amnesia`. No message bodies, no
     message metadata (sender pubkey, recipient pubkey, timestamps),
     no prekey bundles, no directory records, and no connection logs
     are written to disk. Power-off erases all state.

  2. The operator has received NO legally-compelled disclosure requests
     of any kind (subpoena, NSL, court order, intelligence-agency
     request, or equivalent in any jurisdiction) targeting any FinBit
     user, message, or identity.

  3. The operator has not voluntarily disclosed any user data to any
     third party, government or private.

  4. The operator has not added, removed, or modified the relay binary
     beyond the published reproducible-build hashes (see Tier-8 +
     .github/workflows/reproducible.yml).

  5. The operator has not been instructed to add, remove, or modify any
     of the above behaviors.

  6. No part of this document was authored under coercion. The operator
     has not been instructed to suppress, alter, or pre-date this canary.

Signature: see warrant-canary.txt.sig (Ed25519)
PQ sig:    see warrant-canary.txt.pqsig (ML-DSA-65)
Operator identity pubkey (base64url): <pub bytes>
Operator PQ-sig pubkey (base64url):   <pq pub bytes>
```

---

## How peers verify

```
# 1. Fetch the canary + sigs from the operator's published location.
curl -O https://relay.example.com/warrant-canary.txt
curl -O https://relay.example.com/warrant-canary.txt.sig
curl -O https://relay.example.com/warrant-canary.txt.pqsig

# 2. Verify with fb-cli (TODO: ship sign-file/verify-file commands).
fb-cli verify-file --pubkey <relay-operator-pub> \
                    --pq-pubkey <relay-operator-pq-pub> \
                    warrant-canary.txt

# 3. Confirm the headline news matches some real news source from the
#    issue date — proves the document was authored no earlier than that
#    date (defeats pre-signing many canaries in advance).

# 4. Confirm the issue date is within the previous canary's valid-through
#    window. A gap means the operator could not truthfully republish.
```

## What a missing canary means

* **Late by one day:** probably the operator was busy. Wait 24h, ping them.
* **Late by 3+ days:** treat as silently compromised. Stop trusting the
  relay for new sessions. Existing sessions are E2E so message content
  stays confidential — but metadata gathered after the canary lapses is
  unprotected by the assertions above.
* **The canary returns but DROPS one of the affirmations:** the operator
  has been compelled on the specific axis that was dropped. The remaining
  affirmations are still true.

---

## Recommended publishing channels

* HTTPS at a stable path on the relay's own domain.
* `.onion` mirror of the same path.
* A signed git commit to a public canary repo (one tagged commit per
  monthly canary; users follow the repo).
* OpenTimestamps proof for the file hash — anchors the document to the
  Bitcoin blockchain, preventing post-hoc backdating.

## Operational hygiene

* **Don't pre-sign multiple canaries in advance** — defeats the entire
  point. The "pin to today's news" affirmation is the canary's only
  defence against an attacker who has compelled the operator AND has
  access to the signing key (e.g. a key-disclosure order).
* **Don't trust the canary as more than a deadline-based signal** — an
  attacker with the signing key can publish ONE more canary after
  compelling the operator. The next canary is the one that won't appear.
* **Document any change of operator** — if the relay changes hands,
  publish a final canary under the OLD identity announcing the
  transition, then start a fresh canary thread under the new identity.
