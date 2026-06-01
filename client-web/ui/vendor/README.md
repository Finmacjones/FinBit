# Vendored bundles

Third-party JavaScript that's **deliberately not auto-fetched** by the build
or by any agent — sourcing, verifying, and committing the bytes here is a
supply-chain decision that belongs to a human reviewer.

## `noble-mlkem.mjs` — post-quantum ML-KEM-768 for the web client

`finbit_pq.js` enables Tier-7 post-quantum hybrid key exchange iff this file
is present and exports an `ml_kem768` object matching the
[@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) API:

```js
ml_kem768.keygen(seed64?: Uint8Array)                       // → {publicKey, secretKey}
ml_kem768.encapsulate(publicKey, randomness?: Uint8Array)   // → {cipherText, sharedSecret}
ml_kem768.decapsulate(cipherText, secretKey)                // → sharedSecret
```

Sizes (FIPS-203 ML-KEM-768): seed=64, publicKey=1184, secretKey=2400,
cipherText=1088, sharedSecret=32.

### Recommended workflow

1. **Pick a release.** **Selected vendor: `paulmillr/noble-post-quantum`**
   (MIT; pure-JS; exact drop-in for the `finbit_pq.js` seam; supports the
   64-byte deterministic seeded keygen FinBit requires; sits on the
   Cure53-audited `@noble/hashes` SHA3/SHAKE base). Current tag at decision
   time: **`v0.6.1`** (Apr 2026) — pin a specific tag (never `latest`) and
   read its CHANGELOG for security-relevant notes.

2. **Decide on bundling.** The upstream library is published as ESM with
   external imports (`@noble/hashes/sha3.js`, `@noble/hashes/utils.js`, and
   internal `./_crystals.js` + `./utils.js`). Two options:

   **A. Vendor the source + bundle locally** (most auditable). Clone the tag,
   run `npm install`, then bundle to a single file with esbuild/rollup:
   ```
   npx esbuild src/ml-kem.ts --bundle --format=esm \
     --outfile=client-web/ui/vendor/noble-mlkem.mjs
   ```
   The output is a self-contained ESM module re-exporting `ml_kem512`,
   `ml_kem768`, `ml_kem1024`. Review the bundle before committing.

   **B. Fetch a pre-bundled file from a CDN you trust** (faster, requires
   you to trust the CDN's bundling integrity). esm.sh, jsdelivr, and unpkg
   all serve `@noble/post-quantum`; only esm.sh bundles dependencies inline
   (`?bundle` query). Always pin to a specific version, never `latest`.

3. **Verify.**
   - Compute SHA-256: `sha256sum client-web/ui/vendor/noble-mlkem.mjs`
   - Record the hash in this README under "Current vendored version" below.
   - Run the **FinBit acceptance gate** — export shape, FIPS-203 sizes,
     encap/decap round-trip, **deterministic seeded keygen** (mandatory:
     FinBit derives the PQ keypair from the identity seed), and FIPS-203
     implicit rejection (a distinctive behaviour a stub/tampered bundle
     won't reproduce):
     ```
     node client-web/test/pq_vendor_verify.mjs
     ```
     It skips cleanly when no vendor file is present, so it's safe in CI.
   - Run the upstream's own test vectors against the local bundle if
     feasible (noble exports `__tests` for that purpose).
   - For FIPS-203 conformance, cross-check with the NIST CAVP test vectors
     (also reproduced inside noble's test suite).

4. **Commit.** Add `client-web/ui/vendor/noble-mlkem.mjs` and update the
   "Current vendored version" section below with: tag, source URL, SHA-256,
   date, reviewer initials.

### Current vendored version

**VENDORED — PQ is now ACTIVE on the web client** (`finbit_pq.pqEnabled()`
returns true; `KeyBundleUpload` ships a real 1184 B `pq_pubkey`, envelopes
carry `pq_ct`, and web↔desktop/fb-cli sessions are PQ-hybrid).

```
- package:   @noble/post-quantum  (npm)
- tag:       v0.6.1
- source:    https://www.npmjs.com/package/@noble/post-quantum/v/0.6.1
- deps:      @noble/hashes 2.2.0  (SHA3/SHAKE; the Cure53-audited base)
- file:      bundled locally with esbuild 0.24.2 from the published
             node_modules/@noble/post-quantum/ml-kem.js, flags:
             --bundle --format=esm --legal-comments=inline
- sha256:    753aeb6117d88009ab12b6f8d9bcc53153eafbb1a7da6d652a72fb434d18ed7a
- size:      29555 bytes
- date:      2026-06-02
- reviewer:  FM — authorized + verified by the acceptance gate
             (client-web/test/pq_vendor_verify.mjs, 5/5: export shape,
             FIPS-203 sizes, encap/decap round-trip, deterministic seeded
             keygen, FIPS-203 implicit rejection) plus pq_wire_shape's live
             hybrid round-trip (10/10, incl. symmetric Alice↔Bob combiner)
```

Re-bundling with the same package + esbuild versions and flags reproduces
this exact sha256 (esbuild output is deterministic) — re-run the runbook
above and `sha256sum` to confirm before trusting any future re-vendor.

To re-verify the in-tree bytes at any time:
`node client-web/test/pq_vendor_verify.mjs` (now passes, no longer skips).

### What lights up automatically once vendored

- The web client's `KeyBundleUpload` ships a real `pq_pubkey` (1184 B) +
  Ed25519 binding signature.
- Every outbound DM `Envelope` from a hybrid session ships `pq_ct`
  (1088 B) on the first send.
- Inbound envelopes with `pq_ct` are decapsulated + HKDF-combined with
  the X25519 ECDH to derive an identical hybrid root on both sides.
- Web↔desktop / web↔fb-cli sessions become PQ-hybrid bit-for-bit
  compatible (same FinBit-PQ-seed-v1 HKDF for identity derivation,
  same FinBit-hybrid-v1 HKDF for the combiner).

No code changes needed at the call sites — `finbit_pq.pqEnabled()` flips
to true the moment the vendor file resolves.

### What does NOT change

- The pre-vendor wire format. Empty `pq_pubkey` / `pq_ct` (the default
  when this file is absent) cleanly trigger the X25519 fallback path on
  every desktop / fb-cli peer; pre-PQ peers see no difference.
- The `finbit_pq.js` API surface. Vendoring is a single-file drop-in.
