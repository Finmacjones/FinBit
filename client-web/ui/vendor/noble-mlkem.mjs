// node_modules/@noble/hashes/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;

// node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
function anumber(n, title = "") {
  if (typeof n !== "number") {
    const prefix = title && `"${title}" `;
    throw new TypeError(`${prefix}expected number, got ${typeof n}`);
  }
  if (!Number.isSafeInteger(n) || n < 0) {
    const prefix = title && `"${title}" `;
    throw new RangeError(`${prefix}expected integer >= 0, got ${n}`);
  }
}
function abytes(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    const message = prefix + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  return value;
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "digestInto() output");
  const min = instance.outputLen;
  if (out.length < min) {
    throw new RangeError('"digestInto() output" expected to be of length >=' + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function createHasher(hashCons, info = {}) {
  const hashC = (msg, opts2) => hashCons(opts2).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts2) => hashCons(opts2);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
function randomBytes(bytesLength = 32) {
  anumber(bytesLength, "bytesLength");
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.getRandomValues !== "function")
    throw new Error("crypto.getRandomValues must be defined");
  if (bytesLength > 65536)
    throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
  return cr.getRandomValues(new Uint8Array(bytesLength));
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// node_modules/@noble/hashes/sha3.js
var _0n = BigInt(0);
var _1n = BigInt(1);
var _2n = BigInt(2);
var _7n = BigInt(7);
var _256n = BigInt(256);
var _0x71n = BigInt(113);
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n)
      t ^= _1n << (_1n << BigInt(j)) - _1n;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
function keccakP(s, rounds = 24) {
  anumber(rounds, "rounds");
  if (rounds < 1 || rounds > 24)
    throw new Error('"rounds" expected integer 1..24');
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x = 0; x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
      s[y] ^= ~s[y + 2] & s[y + 4];
      s[y + 1] ^= ~s[y + 3] & s[y + 5];
      s[y + 2] ^= ~s[y + 4] & s[y + 6];
      s[y + 3] ^= ~s[y + 5] & s[y + 7];
      s[y + 4] ^= ~s[y + 6] & s[y + 8];
      s[y + 5] ^= ~s[y + 7] & s[y + 9];
      s[y + 6] ^= ~s[y + 8] & b0;
      s[y + 7] ^= ~s[y + 9] & b1;
      s[y + 8] ^= ~b0 & b2;
      s[y + 9] ^= ~b1 & b3;
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}
var Keccak = class _Keccak {
  state;
  pos = 0;
  posOut = 0;
  finished = false;
  state32;
  destroyed = false;
  blockLen;
  suffix;
  outputLen;
  canXOF;
  enableXOF = false;
  rounds;
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.canXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen, "outputLen");
    if (!(0 < blockLen && blockLen < 200))
      throw new Error("only keccak-f1600 function is supported");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone() {
    return this._cloneInto();
  }
  keccak() {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { blockLen, state } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out.subarray(0, this.outputLen));
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.outputLen);
    this.digestInto(out);
    return out;
  }
  destroy() {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.blockLen = blockLen;
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.canXOF = this.canXOF;
    to.destroyed = this.destroyed;
    return to;
  }
};
var genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
var sha3_256 = /* @__PURE__ */ genKeccak(
  6,
  136,
  32,
  /* @__PURE__ */ oidNist(8)
);
var sha3_512 = /* @__PURE__ */ genKeccak(
  6,
  72,
  64,
  /* @__PURE__ */ oidNist(10)
);
var genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts2 = {}) => new Keccak(blockLen, suffix, opts2.dkLen === void 0 ? outputLen : opts2.dkLen, true), info);
var shake128 = /* @__PURE__ */ genShake(31, 168, 16, /* @__PURE__ */ oidNist(11));
var shake256 = /* @__PURE__ */ genShake(31, 136, 32, /* @__PURE__ */ oidNist(12));

// node_modules/@noble/curves/abstract/fft.js
function checkU32(n) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 4294967295)
    throw new Error("wrong u32 integer:" + n);
  return n;
}
function isPowerOfTwo(x) {
  checkU32(x);
  return (x & x - 1) === 0 && x !== 0;
}
function reverseBits(n, bits) {
  checkU32(n);
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32)
    throw new Error(`expected integer 0 <= bits <= 32, got ${bits}`);
  let reversed = 0;
  for (let i = 0; i < bits; i++, n >>>= 1)
    reversed = reversed << 1 | n & 1;
  return reversed >>> 0;
}
function log2(n) {
  checkU32(n);
  return 31 - Math.clz32(n);
}
function bitReversalInplace(values) {
  const n = values.length;
  if (!isPowerOfTwo(n))
    throw new Error("expected positive power-of-two length, got " + n);
  const bits = log2(n);
  for (let i = 0; i < n; i++) {
    const j = reverseBits(i, bits);
    if (i < j) {
      const tmp = values[i];
      values[i] = values[j];
      values[j] = tmp;
    }
  }
  return values;
}
var FFTCore = (F2, coreOpts) => {
  const { N: N2, roots, dit, invertButterflies = false, skipStages = 0, brp = true } = coreOpts;
  const bits = log2(N2);
  if (!isPowerOfTwo(N2))
    throw new Error("FFT: Polynomial size should be power of two");
  if (roots.length !== N2)
    throw new Error(`FFT: wrong roots length: expected ${N2}, got ${roots.length}`);
  const isDit = dit !== invertButterflies;
  isDit;
  return (values) => {
    if (values.length !== N2)
      throw new Error("FFT: wrong Polynomial length");
    if (dit && brp)
      bitReversalInplace(values);
    for (let i = 0, g = 1; i < bits - skipStages; i++) {
      const s = dit ? i + 1 + skipStages : bits - i;
      const m = 1 << s;
      const m2 = m >> 1;
      const stride = N2 >> s;
      for (let k = 0; k < N2; k += m) {
        for (let j = 0, grp = g++; j < m2; j++) {
          const rootPos = invertButterflies ? dit ? N2 - grp : grp : j * stride;
          const i0 = k + j;
          const i1 = k + j + m2;
          const omega = roots[rootPos];
          const b = values[i1];
          const a = values[i0];
          if (isDit) {
            const t = F2.mul(b, omega);
            values[i0] = F2.add(a, t);
            values[i1] = F2.sub(a, t);
          } else if (invertButterflies) {
            values[i0] = F2.add(b, a);
            values[i1] = F2.mul(F2.sub(b, a), omega);
          } else {
            values[i0] = F2.add(a, b);
            values[i1] = F2.mul(F2.sub(a, b), omega);
          }
        }
      }
    }
    if (!dit && brp)
      bitReversalInplace(values);
    return values;
  };
};

// node_modules/@noble/post-quantum/utils.js
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
var abytesDoc = abytes;
var randomBytes2 = randomBytes;
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes(bytes));
}
function splitCoder(label, ...lengths) {
  const getLength = (c) => typeof c === "number" ? c : c.bytesLen;
  const bytesLen = lengths.reduce((sum, a) => sum + getLength(a), 0);
  return {
    bytesLen,
    encode: (bufs) => {
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < lengths.length; i++) {
        const c = lengths[i];
        const l = getLength(c);
        const b = typeof c === "number" ? bufs[i] : c.encode(bufs[i]);
        abytes(b, l, label);
        res.set(b, pos);
        if (typeof c !== "number")
          b.fill(0);
        pos += l;
      }
      return res;
    },
    decode: (buf) => {
      abytes(buf, bytesLen, label);
      const res = [];
      for (const c of lengths) {
        const l = getLength(c);
        const b = buf.subarray(0, l);
        res.push(typeof c === "number" ? b : c.decode(b));
        buf = buf.subarray(l);
      }
      return res;
    }
  };
}
function vecCoder(c, vecLen) {
  const coder = c;
  const bytesLen = vecLen * coder.bytesLen;
  return {
    bytesLen,
    encode: (u) => {
      if (u.length !== vecLen)
        throw new RangeError(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < u.length; i++) {
        const b = coder.encode(u[i]);
        res.set(b, pos);
        b.fill(0);
        pos += b.length;
      }
      return res;
    },
    decode: (a) => {
      abytes(a, bytesLen);
      const r = [];
      for (let i = 0; i < a.length; i += coder.bytesLen)
        r.push(coder.decode(a.subarray(i, i + coder.bytesLen)));
      return r;
    }
  };
}
function cleanBytes(...list) {
  for (const t of list) {
    if (Array.isArray(t))
      for (const b of t)
        b.fill(0);
    else
      t.fill(0);
  }
}
function getMask(bits) {
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32)
    throw new RangeError(`expected bits in [0..32], got ${bits}`);
  return bits === 32 ? 4294967295 : ~(-1 << bits) >>> 0;
}

// node_modules/@noble/post-quantum/_crystals.js
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
var genCrystals = (opts2) => {
  const { newPoly, N: N2, Q: Q2, F: F2, ROOT_OF_UNITY: ROOT_OF_UNITY2, brvBits, isKyber } = opts2;
  const mod = (a, modulo = Q2) => {
    const result = a % modulo | 0;
    return (result >= 0 ? result | 0 : modulo + result | 0) | 0;
  };
  const smod = (a, modulo = Q2) => {
    const r = mod(a, modulo) | 0;
    return (r > modulo >> 1 ? r - modulo | 0 : r) | 0;
  };
  function getZettas() {
    const out = newPoly(N2);
    for (let i = 0; i < N2; i++) {
      const b = reverseBits(i, brvBits);
      const p = BigInt(ROOT_OF_UNITY2) ** BigInt(b) % BigInt(Q2);
      out[i] = Number(p) | 0;
    }
    return out;
  }
  const nttZetas = getZettas();
  const field = {
    add: (a, b) => mod((a | 0) + (b | 0)) | 0,
    sub: (a, b) => mod((a | 0) - (b | 0)) | 0,
    mul: (a, b) => mod((a | 0) * (b | 0)) | 0,
    inv: (_a) => {
      throw new Error("not implemented");
    }
  };
  const nttOpts = {
    N: N2,
    roots: nttZetas,
    invertButterflies: true,
    skipStages: isKyber ? 1 : 0,
    brp: false
  };
  const dif = FFTCore(field, { dit: false, ...nttOpts });
  const dit = FFTCore(field, { dit: true, ...nttOpts });
  const NTT = {
    encode: (r) => {
      return dif(r);
    },
    decode: (r) => {
      dit(r);
      for (let i = 0; i < r.length; i++)
        r[i] = mod(F2 * r[i]);
      return r;
    }
  };
  const bitsCoder = (d, c) => {
    const mask = getMask(d);
    const bytesLen = d * (N2 / 8);
    return {
      bytesLen,
      encode: (poly_) => {
        const poly = poly_;
        const r = new Uint8Array(bytesLen);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
          buf |= (c.encode(poly[i]) & mask) << bufLen;
          bufLen += d;
          for (; bufLen >= 8; bufLen -= 8, buf >>= 8)
            r[pos++] = buf & getMask(bufLen);
        }
        return r;
      },
      decode: (bytes) => {
        const r = newPoly(N2);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
          buf |= bytes[i] << bufLen;
          bufLen += 8;
          for (; bufLen >= d; bufLen -= d, buf >>= d)
            r[pos++] = c.decode(buf & mask);
        }
        return r;
      }
    };
  };
  return {
    mod,
    smod,
    nttZetas,
    NTT: {
      encode: (r) => NTT.encode(r),
      decode: (r) => NTT.decode(r)
    },
    bitsCoder
  };
};
var createXofShake = (shake) => (seed, blockLen) => {
  if (!blockLen)
    blockLen = shake.blockLen;
  const _seed = new Uint8Array(seed.length + 2);
  _seed.set(seed);
  const seedLen = seed.length;
  const buf = new Uint8Array(blockLen);
  let h = shake.create({});
  let calls = 0;
  let xofs = 0;
  return {
    stats: () => ({ calls, xofs }),
    get: (x, y) => {
      _seed[seedLen + 0] = x;
      _seed[seedLen + 1] = y;
      h.destroy();
      h = shake.create({}).update(_seed);
      calls++;
      return () => {
        xofs++;
        return h.xofInto(buf);
      };
    },
    clean: () => {
      h.destroy();
      cleanBytes(buf, _seed);
    }
  };
};
var XOF128 = /* @__PURE__ */ createXofShake(shake128);

// node_modules/@noble/post-quantum/ml-kem.js
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
var N = 256;
var Q = 3329;
var F = 3303;
var ROOT_OF_UNITY = 17;
var crystals = /* @__PURE__ */ genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly: (n) => new Uint16Array(n),
  brvBits: 7,
  isKyber: true
});
var PARAMS = /* @__PURE__ */ (() => Object.freeze({
  512: Object.freeze({ N, Q, K: 2, ETA1: 3, ETA2: 2, du: 10, dv: 4, RBGstrength: 128 }),
  768: Object.freeze({ N, Q, K: 3, ETA1: 2, ETA2: 2, du: 10, dv: 4, RBGstrength: 192 }),
  1024: Object.freeze({ N, Q, K: 4, ETA1: 2, ETA2: 2, du: 11, dv: 5, RBGstrength: 256 })
}))();
var compress = (d) => {
  if (d >= 12)
    return { encode: (i) => i, decode: (i) => i >= Q ? i - Q : i };
  const a = 2 ** (d - 1);
  return {
    // This only matches standalone Compress_d after bitsCoder masks the result into Z_(2^d).
    encode: (i) => ((i << d) + Q / 2) / Q,
    // const decompress = (i: number) => round((Q / 2 ** d) * i);
    decode: (i) => i * Q + a >>> d
  };
};
var byteCoder = (d) => crystals.bitsCoder(d, d === 12 ? { encode: (i) => i, decode: (i) => i >= Q ? i - Q : i } : { encode: (i) => i, decode: (i) => i });
var polyCoder = (d) => d === 12 ? byteCoder(12) : crystals.bitsCoder(d, compress(d));
function polyAdd(a_, b_) {
  const a = a_;
  const b = b_;
  for (let i = 0; i < N; i++)
    a[i] = crystals.mod(a[i] + b[i]);
}
function polySub(a_, b_) {
  const a = a_;
  const b = b_;
  for (let i = 0; i < N; i++)
    a[i] = crystals.mod(a[i] - b[i]);
}
function BaseCaseMultiply(a0, a1, b0, b1, zeta) {
  const c0 = crystals.mod(a1 * b1 * zeta + a0 * b0);
  const c1 = crystals.mod(a0 * b1 + a1 * b0);
  return { c0, c1 };
}
function MultiplyNTTs(f_, g_) {
  const f = f_;
  const g = g_;
  for (let i = 0; i < N / 2; i++) {
    let z = crystals.nttZetas[64 + (i >> 1)];
    if (i & 1)
      z = -z;
    const { c0, c1 } = BaseCaseMultiply(f[2 * i + 0], f[2 * i + 1], g[2 * i + 0], g[2 * i + 1], z);
    f[2 * i + 0] = c0;
    f[2 * i + 1] = c1;
  }
  return f;
}
function SampleNTT(xof_) {
  const xof = xof_;
  const r = new Uint16Array(N);
  for (let j = 0; j < N; ) {
    const b = xof();
    if (b.length % 3)
      throw new Error("SampleNTT: unaligned block");
    for (let i = 0; j < N && i + 3 <= b.length; i += 3) {
      const d1 = (b[i + 0] >> 0 | b[i + 1] << 8) & 4095;
      const d2 = (b[i + 1] >> 4 | b[i + 2] << 4) & 4095;
      if (d1 < Q)
        r[j++] = d1;
      if (j < N && d2 < Q)
        r[j++] = d2;
    }
  }
  return r;
}
var sampleCBDBytes = (buf, eta) => {
  const r = new Uint16Array(N);
  const b32 = u32(buf);
  swap32IfBE(b32);
  let len = 0;
  for (let i = 0, p = 0, bb = 0, t0 = 0; i < b32.length; i++) {
    let b = b32[i];
    for (let j = 0; j < 32; j++) {
      bb += b & 1;
      b >>= 1;
      len += 1;
      if (len === eta) {
        t0 = bb;
        bb = 0;
      } else if (len === 2 * eta) {
        r[p++] = crystals.mod(t0 - bb);
        bb = 0;
        len = 0;
      }
    }
  }
  swap32IfBE(b32);
  if (len)
    throw new Error(`sampleCBD: leftover bits: ${len}`);
  return r;
};
function sampleCBD(PRF_, seed, nonce, eta) {
  const PRF = PRF_;
  return sampleCBDBytes(PRF(eta * N / 4, seed, nonce), eta);
}
var genKPKE = (opts_) => {
  const opts2 = opts_;
  const { K, PRF, XOF, HASH512, ETA1, ETA2, du, dv } = opts2;
  const poly1 = polyCoder(1);
  const polyV = polyCoder(dv);
  const polyU = polyCoder(du);
  const publicCoder = splitCoder("publicKey", vecCoder(polyCoder(12), K), 32);
  const secretCoder = vecCoder(polyCoder(12), K);
  const cipherCoder = splitCoder("ciphertext", vecCoder(polyU, K), polyV);
  const seedCoder = splitCoder("seed", 32, 32);
  return {
    secretCoder,
    lengths: {
      secretKey: secretCoder.bytesLen,
      publicKey: publicCoder.bytesLen,
      cipherText: cipherCoder.bytesLen
    },
    keygen: (seed) => {
      abytesDoc(seed, 32, "seed");
      const seedDst = new Uint8Array(33);
      seedDst.set(seed);
      seedDst[32] = K;
      const seedHash = HASH512(seedDst);
      const [rho, sigma] = seedCoder.decode(seedHash);
      const sHat = [];
      const tHat = [];
      for (let i = 0; i < K; i++)
        sHat.push(crystals.NTT.encode(sampleCBD(PRF, sigma, i, ETA1)));
      const x = XOF(rho);
      for (let i = 0; i < K; i++) {
        const e = crystals.NTT.encode(sampleCBD(PRF, sigma, K + i, ETA1));
        for (let j = 0; j < K; j++) {
          const aji = SampleNTT(x.get(j, i));
          polyAdd(e, MultiplyNTTs(aji, sHat[j]));
        }
        tHat.push(e);
      }
      x.clean();
      const res = {
        publicKey: publicCoder.encode([tHat, rho]),
        secretKey: secretCoder.encode(sHat)
      };
      cleanBytes(rho, sigma, sHat, tHat, seedDst, seedHash);
      return res;
    },
    encrypt: (publicKey, msg, seed) => {
      const [tHat, rho] = publicCoder.decode(publicKey);
      const rHat = [];
      for (let i = 0; i < K; i++)
        rHat.push(crystals.NTT.encode(sampleCBD(PRF, seed, i, ETA1)));
      const x = XOF(rho);
      const tmp2 = new Uint16Array(N);
      const u = [];
      for (let i = 0; i < K; i++) {
        const e1 = sampleCBD(PRF, seed, K + i, ETA2);
        const tmp = new Uint16Array(N);
        for (let j = 0; j < K; j++) {
          const aij = SampleNTT(x.get(i, j));
          polyAdd(tmp, MultiplyNTTs(aij, rHat[j]));
        }
        polyAdd(e1, crystals.NTT.decode(tmp));
        u.push(e1);
        polyAdd(tmp2, MultiplyNTTs(tHat[i], rHat[i]));
        cleanBytes(tmp);
      }
      x.clean();
      const e2 = sampleCBD(PRF, seed, 2 * K, ETA2);
      polyAdd(e2, crystals.NTT.decode(tmp2));
      const v = poly1.decode(msg);
      polyAdd(v, e2);
      cleanBytes(tHat, rHat, tmp2, e2);
      return cipherCoder.encode([u, v]);
    },
    decrypt: (cipherText, privateKey) => {
      const [u, v] = cipherCoder.decode(cipherText);
      const sk = secretCoder.decode(privateKey);
      const tmp = new Uint16Array(N);
      for (let i = 0; i < K; i++)
        polyAdd(tmp, MultiplyNTTs(sk[i], crystals.NTT.encode(u[i])));
      polySub(v, crystals.NTT.decode(tmp));
      cleanBytes(tmp, sk, u);
      return poly1.encode(v);
    }
  };
};
function createKyber(opts2) {
  const rawOpts = opts2;
  const KPKE = genKPKE(rawOpts);
  const { HASH256, HASH512, KDF } = rawOpts;
  const { secretCoder: KPKESecretCoder, lengths } = KPKE;
  const secretCoder = splitCoder("secretKey", lengths.secretKey, lengths.publicKey, 32, 32);
  const msgLen = 32;
  const seedLen = 64;
  const kemLengths = Object.freeze({
    ...lengths,
    seed: 64,
    msg: msgLen,
    msgRand: msgLen,
    secretKey: secretCoder.bytesLen
  });
  return Object.freeze({
    info: Object.freeze({ type: "ml-kem" }),
    lengths: kemLengths,
    keygen: (seed = randomBytes2(seedLen)) => {
      abytesDoc(seed, seedLen, "seed");
      const { publicKey, secretKey: sk } = KPKE.keygen(seed.subarray(0, 32));
      const publicKeyHash = HASH256(publicKey);
      const secretKey = secretCoder.encode([sk, publicKey, publicKeyHash, seed.subarray(32)]);
      cleanBytes(sk, publicKeyHash);
      return {
        publicKey,
        secretKey
      };
    },
    getPublicKey: (secretKey) => {
      const [_sk, publicKey, _publicKeyHash, _z] = secretCoder.decode(secretKey);
      return Uint8Array.from(publicKey);
    },
    encapsulate: (publicKey, msg = randomBytes2(msgLen)) => {
      abytesDoc(publicKey, lengths.publicKey, "publicKey");
      abytesDoc(msg, msgLen, "message");
      const eke = publicKey.subarray(0, 384 * opts2.K);
      const ek = KPKESecretCoder.encode(KPKESecretCoder.decode(copyBytes(eke)));
      if (!equalBytes(ek, eke)) {
        cleanBytes(ek);
        throw new Error("ML-KEM.encapsulate: wrong publicKey modulus");
      }
      cleanBytes(ek);
      const kr = HASH512.create().update(msg).update(HASH256(publicKey)).digest();
      const cipherText = KPKE.encrypt(publicKey, msg, kr.subarray(32, 64));
      cleanBytes(kr.subarray(32));
      return {
        cipherText,
        sharedSecret: kr.subarray(0, 32)
      };
    },
    decapsulate: (cipherText, secretKey) => {
      abytesDoc(secretKey, secretCoder.bytesLen, "secretKey");
      abytesDoc(cipherText, lengths.cipherText, "cipherText");
      const k768 = secretCoder.bytesLen - 96;
      const start = k768 + 32;
      const test = HASH256(secretKey.subarray(k768 / 2, start));
      if (!equalBytes(test, secretKey.subarray(start, start + 32)))
        throw new Error("invalid secretKey: hash check failed");
      const [sk, publicKey, publicKeyHash, z] = secretCoder.decode(secretKey);
      const msg = KPKE.decrypt(cipherText, sk);
      const kr = HASH512.create().update(msg).update(publicKeyHash).digest();
      const Khat = kr.subarray(0, 32);
      const cipherText2 = KPKE.encrypt(publicKey, msg, kr.subarray(32, 64));
      const isValid = equalBytes(cipherText, cipherText2);
      const Kbar = KDF.create({ dkLen: 32 }).update(z).update(cipherText).digest();
      cleanBytes(msg, cipherText2, !isValid ? Khat : Kbar);
      return isValid ? Khat : Kbar;
    }
  });
}
function shakePRF(dkLen, key, nonce) {
  return shake256.create({ dkLen }).update(key).update(new Uint8Array([nonce])).digest();
}
var opts = /* @__PURE__ */ (() => ({
  HASH256: sha3_256,
  HASH512: sha3_512,
  KDF: shake256,
  XOF: XOF128,
  PRF: shakePRF
}))();
var mk = (params) => createKyber({
  ...opts,
  ...params
});
var ml_kem512 = /* @__PURE__ */ (() => mk(PARAMS[512]))();
var ml_kem768 = /* @__PURE__ */ (() => mk(PARAMS[768]))();
var ml_kem1024 = /* @__PURE__ */ (() => mk(PARAMS[1024]))();
var __tests = /* @__PURE__ */ (() => Object.freeze({
  Compress_d: (x, d) => {
    if (d < 1 || d > 11)
      throw new Error(`Compress_d: expected d in [1..11], got ${d}`);
    return compress(d).encode(x) & getMask(d);
  },
  Decompress_d: (y, d) => {
    if (d < 1 || d > 11)
      throw new Error(`Decompress_d: expected d in [1..11], got ${d}`);
    return compress(d).decode(y);
  },
  ByteEncode_d: (F2, d) => {
    if (d < 1 || d > 12)
      throw new Error(`ByteEncode_d: expected d in [1..12], got ${d}`);
    return byteCoder(d).encode(F2);
  },
  ByteDecode_d: (B, d) => {
    if (d < 1 || d > 12)
      throw new Error(`ByteDecode_d: expected d in [1..12], got ${d}`);
    return byteCoder(d).decode(B);
  },
  NTT: (f) => crystals.NTT.encode(Uint16Array.from(f)),
  NTT_inv: (fHat) => crystals.NTT.decode(Uint16Array.from(fHat)),
  MultiplyNTTs: (fHat, gHat) => MultiplyNTTs(Uint16Array.from(fHat), Uint16Array.from(gHat)),
  SamplePolyCBD: (B, eta) => {
    abytesDoc(B, 64 * eta, "B");
    return sampleCBDBytes(B, eta);
  },
  SampleNTT: (B) => {
    abytesDoc(B, 34, "B");
    const xof = XOF128(B.subarray(0, 32));
    try {
      return SampleNTT(xof.get(B[32], B[33]));
    } finally {
      xof.clean();
    }
  }
}))();
export {
  PARAMS,
  __tests,
  ml_kem1024,
  ml_kem512,
  ml_kem768
};
