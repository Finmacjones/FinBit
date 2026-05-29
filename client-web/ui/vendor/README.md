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

1. **Pick a release.** The current upstream is
   [`paulmillr/noble-post-quantum`](https://github.com/paulmillr/noble-post-quantum).
   Choose a tag (e.g. `v0.3.0`) and read its CHANGELOG for any
   security-relevant notes.

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
   - Run the upstream's own test vectors against the local bundle if
     feasible (noble exports `__tests` for that purpose).
   - For FIPS-203 conformance, cross-check with the NIST CAVP test vectors
     (also reproduced inside noble's test suite).

4. **Commit.** Add `client-web/ui/vendor/noble-mlkem.mjs` and update the
   "Current vendored version" section below with: tag, source URL, SHA-256,
   date, reviewer initials.

### Current vendored version

> _Not yet vendored. Web client falls back to X25519-only handshakes; PQ
> interop is structurally wired but inactive. See finbit_pq.js — the
> dynamic import at the top tries `./vendor/noble-mlkem.mjs` and silently
> degrades to no-op stubs when the file is absent._

After vendoring, replace this block with something like:

```
- tag:       v0.3.0
- source:    https://github.com/paulmillr/noble-post-quantum/releases/tag/v0.3.0
- file:      bundled locally via esbuild from src/ml-kem.ts at the tagged commit
- sha256:    <64-hex-digest>
- date:      YYYY-MM-DD
- reviewer:  <initials>
```

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
