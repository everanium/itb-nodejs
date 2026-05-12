# ITB Node.js / TypeScript Binding

`koffi`-based runtime FFI wrapper over the libitb shared library
(`cmd/cshared`). No C compiler at install time, no compile-time
link against libitb; the `.so` / `.dll` / `.dylib` is resolved and
dispatched at first use through `koffi.load`. Targets Node.js 22+
ESM with `[Symbol.dispose]` / `using` declarations for
deterministic resource lifetime.

**Path placeholder.** `<itb>` denotes the path to the local ITB
repository checkout (or this binding's mirror clone) — for example,
`/home/you/go/src/itb` or `~/projects/itb-nodejs`. Substitute the
literal token in the recipes below.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go go-tools nodejs npm
```

## Build the shared library

The convenience driver `bindings/nodejs/build.sh` builds
`libitb.so` plus the Node.js / TypeScript binding's compiled
output in one step. Run it from anywhere:

```bash
./bindings/nodejs/build.sh
```

The driver expands to three underlying steps — building libitb
from the repo root, running `npm install` if `node_modules/` is
missing, then `npm run build` (TypeScript compile to `dist/`) on
the binding side. Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/nodejs && npm install && npm run build
```

(macOS produces `libitb.dylib` under `dist/darwin-<arch>/`,
Windows produces `libitb.dll` under `dist/windows-<arch>/`.)

## Add to a Node.js project

The library is published as `itb` targeting Node.js 22+. As a
local file dependency from inside this repository:

```json
{
  "dependencies": {
    "itb": "file:../bindings/nodejs"
  }
}
```

Build the TypeScript surface once before consuming:

```bash
cd bindings/nodejs
npm install
npm run build
```

Project metadata: `name = "itb"`, `version = 0.1.0`,
`type = "module"`, `engines.node = ">=22"`,
`license = Apache-2.0`. The runtime dependency is `koffi` (modern
runtime FFI, cross-runtime Node / Deno / Bun, no native compile);
dev dependencies are `typescript` and `@types/node`.

## Library lookup order

1. `ITB_LIBRARY_PATH` environment variable (absolute path).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up
   from this module's directory until a matching `dist/` folder is
   found (raw sources via Node's type stripping or compiled
   `dist/` / `dist-test/` / `dist-bench/` layouts all resolve).
3. System loader path (`ld.so.cache`, `DYLD_LIBRARY_PATH`, `PATH`).

## Memory

Two process-wide knobs constrain Go runtime arena pacing. Both readable at libitb load time via env vars:

- `ITB_GOMEMLIMIT=512MiB` — soft memory limit in bytes; supports `B` / `KiB` / `MiB` / `GiB` / `TiB` suffixes.
- `ITB_GOGC=20` — GC trigger percentage; default `100`, lower triggers GC more aggressively.

Programmatic setters override env-set values at any time. Pass `-1` to either setter to query the current value without changing it.

```typescript
itb.setMemoryLimit(512n * 1024n * 1024n);
itb.setGcPercent(20);
```

## Tests

```bash
./bindings/nodejs/run_tests.sh
```

The harness verifies `libitb.so` is present plus `node_modules/`
exists, exports `LD_LIBRARY_PATH`, and invokes `npm test`.
Positional arguments are forwarded straight to the npm test script
(e.g. `./run_tests.sh dist-test/test/easy/test_blake3.test.js` to
scope the run to one file). The integration test suite under
`bindings/nodejs/test/` mirrors the cross-binding coverage:
Single + Triple Ouroboros, mixed primitives, authenticated paths,
blob round-trip, streaming chunked I/O, error paths, lockSeed
lifecycle. `npm test` compiles the source + tests through
`tsconfig.test.json` to `dist-test/`, then runs
`node --test 'dist-test/test/**/*.test.js'`.

## Benchmarks

A custom Go-bench-style harness lives under `bench/` and covers
the four ops (`encrypt`, `decrypt`, `encrypt_auth`, `decrypt_auth`)
across the nine PRF-grade primitives plus one mixed-primitive
variant for both Single and Triple Ouroboros at 1024-bit ITB key
width and 16 MiB payload. See [`bench/README.md`](bench/README.md)
for invocation / environment variables / output format and
[`bench/BENCH.md`](bench/BENCH.md) for recorded throughput results
across the canonical pass matrix.

The four-pass canonical sweep (Single + Triple × ±LockSeed) that
fills `bench/BENCH.md` is driven by the wrapper script in the
binding root:

```bash
./bindings/nodejs/run_bench.sh                  # full 4-pass canonical sweep
./bindings/nodejs/run_bench.sh --lockseed-only  # pass 3 + pass 4 only
```

The harness sets `LD_LIBRARY_PATH` to `dist/linux-amd64/`,
manages `ITB_LOCKSEED` per pass, and forwards `ITB_NONCE_BITS` /
`ITB_BENCH_FILTER` / `ITB_BENCH_MIN_SEC` straight through to the
underlying `npm run bench:single` / `npm run bench:triple`
invocations.

## Streaming AEAD

**Streaming AEAD** authenticates a chunked stream end-to-end while
preserving the deniability of the per-chunk MAC-Inside-Encrypt
container. Each chunk's MAC binds the encrypted payload to a 32-byte
CSPRNG stream anchor (written as a once-per-stream wire prefix), the
cumulative pixel offset of preceding chunks, and a final-flag bit —
defending against chunk reorder, replay within or across streams
sharing the PRF / MAC key, silent mid-stream drop, and truncate-tail.
The wire format adds 32 bytes of stream prefix plus one byte of
encrypted trailing flag per chunk; no externally visible MAC tag.

The two examples below encrypt a 64 MiB random source file in 16 MiB
chunks and verify a sha256 round-trip on the decrypted output.
Production deployments typically encrypt files at 1 GiB+ scale through
the same loop pattern; the chunk size selection (16 MiB here) controls
per-iteration memory residency.

**Easy Mode:**

`Encryptor.encryptStreamAuth` accepts any
`Readable` source and any `Writable` sink; `fs.createReadStream` /
`fs.createWriteStream` are the typical production-scale choices. Both
stream-auth methods return a Promise that settles when the per-chunk
loop completes. The MAC key is allocated CSPRNG-fresh inside the
encryptor at constructor time.

```javascript
import { createReadStream, createWriteStream, existsSync, statSync, writeFileSync } from 'node:fs';
import { PassThrough } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createHash, randomBytes } from 'node:crypto';
import {
  Cipher,
  Encryptor,
  UnwrapStreamReader,
  WrapStreamWriter,
  wrapperGenerateKey,
  wrapperNonceSize,
} from 'itb';

const SRC_PATH = '/tmp/64mb.src';
const ENC_PATH = '/tmp/64mb.enc';
const DST_PATH = '/tmp/64mb.dst';
const CHUNK_SIZE = 16 * 1024 * 1024;

async function sha256Of(path) {
  const h = createHash('sha256');
  for await (const chunk of createReadStream(path, { highWaterMark: 1 << 20 })) {
    h.update(chunk);
  }
  return h.digest('hex');
}

// Materialise a 64 MiB random source file once.
if (!existsSync(SRC_PATH) || statSync(SRC_PATH).size !== 64 * 1024 * 1024) {
  writeFileSync(SRC_PATH, randomBytes(64 * 1024 * 1024));
}

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);

const enc = new Encryptor('areion512', 1024, 'hmac-blake3', 1);
try {
  // Sender — buffer the inner ITB transcript, then pump it through one
  // wrap-stream session so the on-wire bytes carry no ITB framing.
  const innerOut = new PassThrough();
  await enc.encryptStreamAuth(
    createReadStream(SRC_PATH, { highWaterMark: CHUNK_SIZE }),
    innerOut,
    CHUNK_SIZE,
  );
  innerOut.end();
  const innerChunks = [];
  for await (const c of innerOut) innerChunks.push(c);
  const innerBytes = Buffer.concat(innerChunks);

  // Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
  const ww = new WrapStreamWriter(Cipher.Aes128Ctr, outerKey);
  let wire;
  try {
    wire = Buffer.concat([ww.nonce, ww.update(innerBytes)]);
  } finally {
    ww.close();
  }
  await pipeline(
    async function* () { yield wire; },
    createWriteStream(ENC_PATH),
  );

  // Receiver — strip the leading nonce, unwrap the body, decrypt.
  const wireBuf = Buffer.alloc(wire.length);
  let off = 0;
  for await (const c of createReadStream(ENC_PATH, { highWaterMark: CHUNK_SIZE })) {
    c.copy(wireBuf, off);
    off += c.length;
  }
  const nlen = wrapperNonceSize(Cipher.Aes128Ctr);
  const ur = new UnwrapStreamReader(Cipher.Aes128Ctr, outerKey, wireBuf.subarray(0, nlen));
  let innerWire;
  try {
    innerWire = ur.update(wireBuf.subarray(nlen));
  } finally {
    ur.close();
  }
  const innerSrc = new PassThrough();
  innerSrc.end(innerWire);
  await enc.decryptStreamAuth(
    innerSrc,
    createWriteStream(DST_PATH),
  );
} finally {
  enc.close();
}

const srcHash = await sha256Of(SRC_PATH);
const dstHash = await sha256Of(DST_PATH);
console.log(`Easy Mode src sha256: ${srcHash}`);
console.log(`Easy Mode dst sha256: ${dstHash}`);
if (srcHash !== dstHash) throw new Error('Easy Mode: sha256 mismatch');
console.log('[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified');
```

**Build + run:**

The example project's `package.json` declares a single local-file
dependency on the binding:

```json
{
  "name": "itb-stream-aead-example",
  "version": "0.1.0",
  "type": "module",
  "dependencies": {
    "itb": "file:<itb>/bindings/nodejs"
  }
}
```

Place the source above in `<itb>/nodejs_example/main.mjs`, then:

```sh
cd <itb>/nodejs_example && npm install && node main.mjs
```

The binding's `koffi.load` resolver locates
`<itb>/dist/<os>-<arch>/libitb.so` automatically once `npm install`
materialises `node_modules/itb` — no `ITB_LIBRARY_PATH` export is
required when the shared library lives under the repository's
canonical `dist/` tree. Override with `ITB_LIBRARY_PATH=/abs/path` to
point at a non-canonical build.

**Output (verified):**

```
Easy Mode src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Easy Mode dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Easy Mode: 64 MiB roundtrip via stream-auth verified
```

---

**Low-Level Mode:**

Module-level free functions
`encryptStreamAuth` / `decryptStreamAuth` take three explicit `Seed`
handles plus a `MAC` instance (32-byte key drawn via
`crypto.randomBytes(32)`) and stream through the same chunked-AEAD
construction. Seed and MAC handles are explicitly freed at the end of
the loop.

```javascript
import { createReadStream, createWriteStream } from 'node:fs';
import { PassThrough } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createHash, randomBytes } from 'node:crypto';
import {
  Cipher,
  MAC,
  Seed,
  UnwrapStreamReader,
  WrapStreamWriter,
  decryptStreamAuth,
  encryptStreamAuth,
  wrapperGenerateKey,
  wrapperNonceSize,
} from 'itb';

const SRC_PATH = '/tmp/64mb.src';
const ENC_PATH = '/tmp/64mb.enc';
const DST_PATH = '/tmp/64mb.dst';
const CHUNK_SIZE = 16 * 1024 * 1024;

async function sha256Of(path) {
  const h = createHash('sha256');
  for await (const chunk of createReadStream(path, { highWaterMark: 1 << 20 })) {
    h.update(chunk);
  }
  return h.digest('hex');
}

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);

const noise = new Seed('areion512', 1024);
const data  = new Seed('areion512', 1024);
const start = new Seed('areion512', 1024);
const macKey = randomBytes(32);
const mac = new MAC('hmac-blake3', macKey);
try {
  // Sender — buffer the inner ITB transcript, then pump it through one
  // wrap-stream session so the on-wire bytes carry no ITB framing.
  const innerOut = new PassThrough();
  await encryptStreamAuth(
    noise, data, start, mac,
    createReadStream(SRC_PATH, { highWaterMark: CHUNK_SIZE }),
    innerOut,
    CHUNK_SIZE,
  );
  innerOut.end();
  const innerChunks = [];
  for await (const c of innerOut) innerChunks.push(c);
  const innerBytes = Buffer.concat(innerChunks);

  // Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
  const ww = new WrapStreamWriter(Cipher.Aes128Ctr, outerKey);
  let wire;
  try {
    wire = Buffer.concat([ww.nonce, ww.update(innerBytes)]);
  } finally {
    ww.close();
  }
  await pipeline(
    async function* () { yield wire; },
    createWriteStream(ENC_PATH),
  );

  // Receiver — strip the leading nonce, unwrap the body, decrypt.
  const wireBuf = Buffer.alloc(wire.length);
  let off = 0;
  for await (const c of createReadStream(ENC_PATH, { highWaterMark: CHUNK_SIZE })) {
    c.copy(wireBuf, off);
    off += c.length;
  }
  const nlen = wrapperNonceSize(Cipher.Aes128Ctr);
  const ur = new UnwrapStreamReader(Cipher.Aes128Ctr, outerKey, wireBuf.subarray(0, nlen));
  let innerWire;
  try {
    innerWire = ur.update(wireBuf.subarray(nlen));
  } finally {
    ur.close();
  }
  const innerSrc = new PassThrough();
  innerSrc.end(innerWire);
  await decryptStreamAuth(
    noise, data, start, mac,
    innerSrc,
    createWriteStream(DST_PATH),
  );
} finally {
  mac.free();
  noise.free(); data.free(); start.free();
}

const srcHash = await sha256Of(SRC_PATH);
const dstHash = await sha256Of(DST_PATH);
console.log(`Low-Level src sha256: ${srcHash}`);
console.log(`Low-Level dst sha256: ${dstHash}`);
if (srcHash !== dstHash) throw new Error('Low-Level: sha256 mismatch');
console.log('[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified');
```

**Build + run:**

```sh
cd <itb>/nodejs_example && node main.mjs
```

**Output (verified):**

```
Low-Level src sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
Low-Level dst sha256: 7adc82f9bebf205db2a6c8033d7c1fe43d3bf8b3ecb0fbfd6c4c2dff71672425
[OK] Low-Level Mode: 64 MiB roundtrip via stream-auth verified
```

The Node.js binding's stream-auth methods are async and return
Promises; every consumer must `await` the call (or chain `.then`) to
drive the per-chunk loop to completion. Backpressure flows through
Node.js's standard `Readable.pipe` buffering — the binding does not
pull faster than the sink can absorb. Easy Mode mode parameter is the
integer `1` for Single Ouroboros (`3` for Triple Ouroboros).
Low-Level Mode does not carry a top-level mode parameter — Single vs
Triple is selected by the seed-handle count passed in.

## Quick Start — `Encryptor` + HMAC-BLAKE3 (MAC Authenticated)

The high-level `Encryptor` (mirroring the
`github.com/everanium/itb/easy` Go sub-package) replaces the
seven-line setup ceremony of the lower-level
`Seed` / `encrypt` / `decrypt` path with one constructor call: the
encryptor allocates its own three (Single) or seven (Triple) seeds
plus MAC closure, snapshots the global configuration into a
per-instance Config, and exposes setters that mutate only its own
state without touching the process-wide `Library` accessors. Two
encryptors with different settings can run concurrently without
cross-contamination.

The MAC primitive is bound at construction time — the `macName`
parameter selects one of the registry names (`hmac-blake3` —
recommended default, `hmac-sha256`, `kmac256`). The encryptor
allocates a fresh 32-byte CSPRNG MAC key alongside the per-seed
PRF keys; `enc.exportState()` carries all of them in a single
JSON blob. On the receiver side, `dec.importState(blob)` restores
the MAC key together with the seeds, so the encrypt-today /
decrypt-tomorrow flow is one method call per side.

When the `macName` argument is omitted (or `null`) the binding
picks `"hmac-blake3"` rather than forwarding `null` through to
libitb's own default — HMAC-BLAKE3 measures the lightest
authenticated-mode overhead across the Easy Mode bench surface
(~9% over plain encrypt vs HMAC-SHA256's ~15% vs KMAC-256's
~44%).

```typescript
// Sender

import {
  Cipher,
  Encryptor,
  ITBError,
  Status,
  setMaxWorkers,
  unwrapInPlace,
  wrapInPlace,
  wrapperGenerateKey,
  wrapperNonceSize,
} from 'itb';

// Per-instance configuration — mutates only this encryptor's
// Config. Two encryptors built side-by-side carry independent
// settings; process-wide Library accessors are NOT consulted
// after construction. mode: 1 = Single Ouroboros (3 seeds);
// mode: 3 = Triple Ouroboros (7 seeds).
using enc = new Encryptor('areion512', 2048, 'hmac-blake3', 1);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);

enc.setNonceBits(512);    // 512-bit nonce (default: 128-bit)
enc.setBarrierFill(4);    // CSPRNG fill margin (default: 1, valid: 1, 2, 4, 8, 16, 32)
enc.setBitSoup(1);        // optional bit-level split ("bit-soup"; default: 0 = byte-level)
                          // auto-enabled for Single Ouroboros if setLockSoup(1) is on
enc.setLockSoup(1);       // optional Insane Interlocked Mode: per-chunk PRF-keyed
                          // bit-permutation overlay on top of bit-soup;
                          // auto-enabled for Single Ouroboros if setBitSoup(1) is on

// enc.setLockSeed(1);    // optional dedicated lockSeed for the bit-permutation
                          // derivation channel — separates that PRF's keying
                          // material from the noiseSeed-driven noise-injection
                          // channel; auto-couples setLockSoup(1) +
                          // setBitSoup(1). Adds one extra seed slot
                          // (3 → 4 for Single, 7 → 8 for Triple). Must be
                          // called BEFORE the first encryptAuth — switching
                          // mid-session raises ITBError with code
                          // Status.EasyLockSeedAfterEncrypt.

// Persistence blob — carries seeds + PRF keys + MAC key (and the
// dedicated lockSeed material when setLockSeed(1) is active).
const blob = enc.exportState();
console.log(`state blob: ${blob.length} bytes`);
console.log(`primitive: ${enc.primitive}, key_bits: ${enc.keyBits}, mode: ${enc.mode}, mac: ${enc.macName}`);

const plaintext = new TextEncoder().encode('any text or binary data - including 0x00 bytes');
// const chunkSize = 4 * 1024 * 1024;  // 4 MiB - bulk local crypto, not small-frame network streaming

// Authenticated encrypt — 32-byte tag is computed across the
// entire decrypted capacity and embedded inside the RGBWYOPA
// container, preserving oracle-free deniability.
const encrypted = Buffer.from(enc.encryptAuth(plaintext));
console.log(`encrypted: ${encrypted.length} bytes`);

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
const nonce = wrapInPlace(Cipher.Aes128Ctr, outerKey, encrypted);
const wire = Buffer.concat([nonce, encrypted]);
console.log(`wire: ${wire.length} bytes`);

// Send `wire` payload + state blob; Symbol.dispose at scope
// end (via using) releases the handle and zeroes the
// per-encryptor output buffer. enc.close() is the explicit
// zeroisation entry point that does not release the handle.


// Receiver

// Receive `wire` payload + state blob
// const wire = ...;
// const blob = ...;

setMaxWorkers(8);   // limit to 8 CPU cores (default: 0 = all CPUs)

// Optional: peek at the blob's metadata before constructing a
// matching encryptor. Useful when the receiver multiplexes blobs
// of different shapes (different primitive / mode / MAC choices).
const cfg = Encryptor.peekConfig(blob);
console.log(`peek: primitive=${cfg.primitive}, key_bits=${cfg.keyBits}, mode=${cfg.mode}, mac=${cfg.macName}`);

using dec = new Encryptor(cfg.primitive, cfg.keyBits, cfg.macName, cfg.mode);

// dec.importState(blob) below automatically restores the full
// per-instance configuration (NonceBits, BarrierFill, BitSoup,
// LockSoup, and the dedicated lockSeed material when sender's
// setLockSeed(1) was active). The set*() lines below are kept
// for documentation — they show the knobs available for explicit
// pre-import override. BarrierFill is asymmetric: a receiver-set
// value > 1 takes priority over the blob's BarrierFill (the
// receiver's heavier CSPRNG margin is preserved across import).
dec.setNonceBits(512);
dec.setBarrierFill(4);
dec.setBitSoup(1);
dec.setLockSoup(1);

// Restore PRF keys, seed components, MAC key, and the per-instance
// configuration overrides (NonceBits / BarrierFill / BitSoup /
// LockSoup / LockSeed) from the saved blob.
dec.importState(blob);

// Strip the per-stream nonce, recover the inner ITB ciphertext.
const wireBuf = Buffer.from(wire);
const recovered = unwrapInPlace(Cipher.Aes128Ctr, outerKey, wireBuf);

// Authenticated decrypt — any single-bit tamper triggers MAC
// failure (no oracle leak about which byte was tampered).
// Mismatch surfaces as ITBError with code Status.MacFailure,
// not a corrupted plaintext.
try {
  const decrypted = dec.decryptAuth(recovered);
  console.log(`decrypted: ${new TextDecoder().decode(decrypted)}`);
} catch (e) {
  if (e instanceof ITBError && e.code === Status.MacFailure) {
    console.log('MAC verification failed — tampered or wrong key');
  } else {
    throw e;
  }
}
```

## Quick Start — Mixed primitives (Different PRF per seed slot)

`Encryptor.mixedSingle` and `Encryptor.mixedTriple` accept
per-slot primitive names — the noise / data / start (and optional
dedicated lockSeed) seed slots can use different PRF primitives
within the same native hash width. The mix-and-match-PRF freedom
of the lower-level path, surfaced through the high-level
`Encryptor` without forcing the caller off the Easy Mode
constructor. The state blob carries per-slot primitives + per-slot
PRF keys; the receiver constructs a matching encryptor with the
same arguments and calls `importState` to restore.

```typescript
// Sender

import {
  Cipher,
  Encryptor,
  unwrapInPlace,
  wrapInPlace,
  wrapperGenerateKey,
} from 'itb';

// Per-slot primitive selection (Single Ouroboros, 3 + 1 slots).
// Every name must share the same native hash width — mixing widths
// raises ITBError at construction time.
// Triple Ouroboros mirror — Encryptor.mixedTriple takes seven
// per-slot names (noise + 3 data + 3 start) plus the optional
// primL lockSeed.
using enc = Encryptor.mixedSingle(
  'blake3',         // primN: noiseSeed   BLAKE3
  'blake2s',        // primD: dataSeed    BLAKE2s
  'areion256',      // primS: startSeed   Areion-SoEM-256
  'blake2b256',     // primL: dedicated lockSeed (null for no lockSeed slot)
  1024,             // keyBits
  'hmac-blake3',    // macName
);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);

// Per-instance configuration applies as for the new Encryptor(...)
// case shown above.
enc.setNonceBits(512);
enc.setBarrierFill(4);
// BitSoup + LockSoup are auto-coupled on the on-direction by primL
// above; explicit calls below are unnecessary but harmless if added.
// enc.setBitSoup(1);
// enc.setLockSoup(1);

// Per-slot introspection — enc.primitive returns the first slot's
// name, enc.primitiveAt(slot) returns each slot's name, enc.isMixed
// is the typed predicate. Slot ordering is canonical: 0 = noiseSeed,
// 1 = dataSeed, 2 = startSeed, 3 = lockSeed (Single); Triple grows
// the middle range to 7 slots + lockSeed.
console.log(`mixed=${enc.isMixed} primitive=${enc.primitive}`);
for (let i = 0; i < 4; i++) {
  console.log(`  slot ${i}: ${enc.primitiveAt(i)}`);
}

const blob = enc.exportState();
const plaintext = new TextEncoder().encode('mixed-primitive Easy Mode payload');
const encrypted = Buffer.from(enc.encryptAuth(plaintext));

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
const nonce = wrapInPlace(Cipher.Aes128Ctr, outerKey, encrypted);
const wire = Buffer.concat([nonce, encrypted]);


// Receiver

// Receive `wire` payload + state blob
// const wire = ...;
// const blob = ...;

// Receiver constructs a matching mixed encryptor — every per-slot
// primitive name plus keyBits and mac must agree with the sender.
// importState validates each per-slot primitive against the receiver's
// bound spec; mismatches raise ITBEasyMismatchError with the
// "primitive" field tag.
using dec = Encryptor.mixedSingle(
  'blake3',
  'blake2s',
  'areion256',
  'blake2b256',
  1024,
  'hmac-blake3',
);

dec.importState(blob);

const wireBuf = Buffer.from(wire);
const recovered = unwrapInPlace(Cipher.Aes128Ctr, outerKey, wireBuf);
const decrypted = dec.decryptAuth(recovered);
console.log(`decrypted: ${new TextDecoder().decode(decrypted)}`);
```

## Quick Start — Triple Ouroboros

Triple Ouroboros (3× security: P × 2^(3×key_bits)) takes seven
seeds (one shared `noiseSeed` plus three `dataSeed` and three
`startSeed`) on the low-level path, all wrapped behind a single
`Encryptor` call when `mode === 3` is passed to the constructor.

```typescript
import {
  Cipher,
  Encryptor,
  unwrapInPlace,
  wrapInPlace,
  wrapperGenerateKey,
} from 'itb';

// mode = 3 selects Triple Ouroboros. All other constructor
// arguments behave identically to the Single (mode = 1) case
// shown above.
using enc = new Encryptor('areion512', 2048, 'hmac-blake3', 3);

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);

const plaintext = new TextEncoder().encode('Triple Ouroboros payload');
const encrypted = Buffer.from(enc.encryptAuth(plaintext));

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
const nonce = wrapInPlace(Cipher.Aes128Ctr, outerKey, encrypted);
const wire = Buffer.concat([nonce, encrypted]);

const wireBuf = Buffer.from(wire);
const recovered = unwrapInPlace(Cipher.Aes128Ctr, outerKey, wireBuf);
const decrypted = enc.decryptAuth(recovered);
```

`Encryptor.mixedTriple` is the per-slot mixed-primitive
counterpart for Triple Ouroboros (7 + optional lockSeed slots).

## Quick Start — Areion-SoEM-512 + HMAC-BLAKE3 (Low-Level, MAC Authenticated)

The lower-level path is for callers who prefer to manage the seven
`Seed` handles (Triple) or three (Single) plus the MAC handle
manually. `encryptAuth` / `decryptAuth` (Single) and
`encryptAuthTriple` / `decryptAuthTriple` (Triple) take the seed
handles and a `MAC` instance directly, so a non-Easy caller can
share the underlying seeds across multiple encrypt sessions or
expose the seed-introspection surface (`seed.components`,
`seed.hashKey`, `Seed.fromComponents`) for cross-process
persistence at the seed layer.

```typescript
import {
  Cipher,
  encryptAuth,
  decryptAuth,
  MAC,
  Seed,
  setBitSoup,
  setLockSoup,
  unwrapInPlace,
  wrapInPlace,
  wrapperGenerateKey,
} from 'itb';
import { randomBytes } from 'node:crypto';

// Optional: process-wide bit-permutation overlay. The setBitSoup /
// setLockSoup pair flips the on-wire bit layout from byte-level to
// bit-level + per-chunk PRF-keyed bit-permutation. Encryptor
// instances in the same process inherit the active state at
// construction time; the lower-level path consults the global
// flags on every encrypt / decrypt call.
setBitSoup(1);
setLockSoup(1);

// Three Single-Ouroboros seeds and one MAC handle. Seeds are
// CSPRNG-keyed; persistence-restore would use Seed.fromComponents.
using noise = new Seed('areion512', 2048);
using data = new Seed('areion512', 2048);
using start = new Seed('areion512', 2048);
using mac = new MAC('hmac-blake3', randomBytes(32));

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);

const plaintext = new TextEncoder().encode('low-level authenticated payload');
const encrypted = Buffer.from(encryptAuth(noise, data, start, mac, plaintext));

// Format-deniability ITB masking through outer cipher AES-128-CTR with ~0% overhead over ITB Encrypt / Decrypt (Recommended in every case).
const nonce = wrapInPlace(Cipher.Aes128Ctr, outerKey, encrypted);
const wire = Buffer.concat([nonce, encrypted]);

const wireBuf = Buffer.from(wire);
const recovered = unwrapInPlace(Cipher.Aes128Ctr, outerKey, wireBuf);
const decrypted = decryptAuth(noise, data, start, mac, recovered);
console.log(`decrypted: ${new TextDecoder().decode(decrypted)}`);
```

The Triple Ouroboros counterparts `encryptAuthTriple` /
`decryptAuthTriple` take seven seed handles
(`noise`, `data1`, `data2`, `data3`, `start1`, `start2`, `start3`)
plus the MAC handle. Plain (non-authenticated) variants are
`encrypt` / `decrypt` (Single) and `encryptTriple` / `decryptTriple`
(Triple) — same shape minus the MAC argument.

## Streams — chunked I/O over Node streams

The `streams` module wraps `node:stream`'s `Readable` /
`Writable` / `PassThrough` for files, sockets, and HTTP bodies. The
binding owns the chunking — every fixed-size plaintext slice
becomes one self-framed ITB chunk, and the wire format consists of
those chunks concatenated end-to-end. Two convenience helpers,
`encryptStream` and `decryptStream`, drive the pipe end-to-end;
the underlying `StreamEncryptor` / `StreamDecryptor` classes are
exposed for callers who want to control chunk timing or interleave
encryption with other writes. Triple-Ouroboros mirrors —
`encryptStreamTriple`, `decryptStreamTriple`, `StreamEncryptorTriple`,
`StreamDecryptorTriple` — preserve the same shape, swapping in the
seven-seed split.

```typescript
import { createReadStream, createWriteStream } from 'node:fs';
import { PassThrough } from 'node:stream';
import {
  Cipher,
  Seed,
  UnwrapStreamReader,
  WrapStreamWriter,
  decryptStream,
  encryptStream,
  wrapperGenerateKey,
  wrapperNonceSize,
} from 'itb';

// Outer cipher key - preferred surface for HKDF / ML-KEM / key-rotation policy in user-side application. ITB Inner seeds + PRF key keep as CSPRNG derived.
const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);

// Encrypt: read plaintext from disk, drive the ITB chunked
// transcript through one wrap-stream session, write the wrapped
// bytes to disk.
async function encryptFile(): Promise<void> {
  using noise = new Seed('areion512', 2048);
  using data = new Seed('areion512', 2048);
  using start = new Seed('areion512', 2048);

  const input = createReadStream('plaintext.bin');
  const output = createWriteStream('ciphertext.bin');

  // Format-deniability ITB masking via outer-cipher streaming wrapper (AES-128-CTR) - same ~0% overhead in stream mode (Recommended in every case).
  const ww = new WrapStreamWriter(Cipher.Aes128Ctr, outerKey);
  output.write(ww.nonce);

  const innerOut = new PassThrough();
  innerOut.on('data', (chunk: Buffer) => output.write(ww.update(chunk)));
  // chunk_size: 4 MiB — bulk local crypto, not small-frame
  // network streaming. Each plaintext slice becomes one ITB
  // chunk on the wire.
  await encryptStream(noise, data, start, input, innerOut, 4 * 1024 * 1024);
  innerOut.end();
  ww.close();
  output.end();
}

// Decrypt: stream wrapped bytes from disk, strip the leading
// nonce, unwrap each block, hand the inner ITB transcript to
// StreamDecryptor (which probes each chunk's header via
// parseChunkLen to learn the on-wire chunk length).
async function decryptFile(): Promise<void> {
  using noise = new Seed('areion512', 2048);
  using data = new Seed('areion512', 2048);
  using start = new Seed('areion512', 2048);

  const input = createReadStream('ciphertext.bin');
  const output = createWriteStream('decrypted.bin');

  const nlen = wrapperNonceSize(Cipher.Aes128Ctr);
  const nonceBuf = Buffer.alloc(nlen);
  let read = 0;
  for await (const c of input) {
    const take = Math.min(c.length, nlen - read);
    (c as Buffer).copy(nonceBuf, read, 0, take);
    read += take;
    if (read === nlen) {
      const tail = (c as Buffer).subarray(take);
      const ur = new UnwrapStreamReader(Cipher.Aes128Ctr, outerKey, nonceBuf);
      const innerIn = new PassThrough();
      if (tail.length > 0) innerIn.write(ur.update(tail));
      input.on('data', (chunk: Buffer) => innerIn.write(ur.update(chunk)));
      input.on('end', () => { ur.close(); innerIn.end(); });
      await decryptStream(noise, data, start, innerIn, output);
      break;
    }
  }
  output.end();
}
```

The wrapped `Writable` is **NOT** auto-ended by the helper or by
`StreamEncryptor.close()` / `StreamDecryptor.close()` — the caller
owns the end-of-write contract. Tests using `PassThrough` pipes
must call `output.end()` after the stream operation completes;
otherwise downstream `for-await ... of output` consumers hang on
an open writer.

For class-based callers, `new StreamEncryptor(noise, data, start, output, chunkSize)`
exposes `.write(chunk)` / `.close()` for explicit chunk-timing
control; `new StreamDecryptor(noise, data, start, output)` exposes
`.feed(chunk)` / `.close()`. The Triple variants mirror the same
shape with seven seed arguments.

## Native Blob — low-level state persistence

Native `Blob128` / `Blob256` / `Blob512` objects carry the raw
seed components, PRF keys, MAC key, and MAC name across processes
without going through the Easy Mode JSON envelope. Useful for
binary-protocol persistence backends (KMS, vault, on-wire blob)
where the `Encryptor.exportState()` JSON format is heavier than
needed.

```typescript
import {
  Blob512,
  BlobSlot,
  BlobExportOpts,
  Seed,
  encrypt,
  decrypt,
} from 'itb';

// Sender — pack three seeds into a Blob512.
function pack(): Uint8Array {
  using noise = Seed.fromComponents('areion512', noiseComponents, noiseHashKey);
  using data = Seed.fromComponents('areion512', dataComponents, dataHashKey);
  using start = Seed.fromComponents('areion512', startComponents, startHashKey);

  using src = new Blob512();
  src.setComponents(BlobSlot.N, noise.components);
  src.setComponents(BlobSlot.D, data.components);
  src.setComponents(BlobSlot.S, start.components);
  src.setKey(BlobSlot.N, noise.hashKey);
  src.setKey(BlobSlot.D, data.hashKey);
  src.setKey(BlobSlot.S, start.hashKey);
  // Optional: include MAC key + MAC name for authenticated paths.
  // src.setMacKey(macKey);
  // src.setMacName('hmac-blake3');
  return src.export(BlobExportOpts.None);
}

// Receiver — unpack a Blob512 back into three seeds.
function unpack(blob: Uint8Array, plaintext: Uint8Array): Uint8Array {
  using dst = new Blob512();
  dst.import(blob);

  using noise = Seed.fromComponents('areion512', dst.getComponents(BlobSlot.N), dst.getKey(BlobSlot.N));
  using data = Seed.fromComponents('areion512', dst.getComponents(BlobSlot.D), dst.getKey(BlobSlot.D));
  using start = Seed.fromComponents('areion512', dst.getComponents(BlobSlot.S), dst.getKey(BlobSlot.S));

  return encrypt(noise, data, start, plaintext);
}
```

Triple-Ouroboros blobs use `exportTriple` / `importTriple`
on the same `Blob512` (or 256 / 128) handle; the mode is recorded
in the blob and a Single-mode blob fed to a Triple-mode
`importTriple` raises `ITBBlobModeMismatchError`.

`BlobSlot` enumerates the slot index used by `setKey` / `setComponents`:
`N=0, D=1, S=2, L=3, D1=4, D2=5, D3=6, S1=7, S2=8, S3=9`.
`BlobExportOpts` is a bitmask: `None=0`, `LockSeed=1` (include the
dedicated lockSeed slot), `Mac=2` (include the MAC key + name).

## Hash primitives (Single / Triple)

Names match the canonical `hashes/` registry: `areion256`,
`areion512`, `siphash24`, `aescmac`, `blake2b256`, `blake2b512`,
`blake2s`, `blake3`, `chacha20`. Triple Ouroboros (3× security)
takes seven seeds (one shared `noiseSeed` plus three `dataSeed`
and three `startSeed`) via `encryptTriple` / `decryptTriple` and
the authenticated counterparts `encryptAuthTriple` /
`decryptAuthTriple`. Streaming counterparts: `StreamEncryptorTriple` /
`StreamDecryptorTriple` / `encryptStreamTriple` /
`decryptStreamTriple`.

All seeds passed to one `encrypt` / `decrypt` call must share the
same native hash width. Mixing widths raises
`ITBError(Status.SeedWidthMix)`.

## MAC primitives

Names match the libitb MAC registry; ordering matches that registry's declaration order.

| MAC | Key bytes | Tag bytes | Underlying primitive |
|---|---|---|---|
| `kmac256` | 32 | 32 | KMAC256 (Keccak-derived) |
| `hmac-sha256` | 32 | 32 | HMAC over SHA-256 |
| `hmac-blake3` | 32 | 32 | HMAC over BLAKE3 |

`kmac256` and `hmac-sha256` accept keys 16 bytes and longer; the binding fleet's tests and examples use 32 bytes uniformly across primitives for cross-binding consistency. `hmac-blake3` requires exactly 32 bytes by construction.

## Process-wide configuration

Every setter takes effect for all subsequent encrypt / decrypt
calls in the process. Out-of-range values raise
`ITBError(Status.BadInput)` rather than crashing. Per-encryptor
overrides via `enc.setX(...)` mutate only that handle's Config and
do not consult these globals after construction.

| Function | Accepted values | Default |
|---|---|---|
| `setMaxWorkers(n)` | non-negative int | 0 (auto) |
| `setNonceBits(n)` | 128, 256, 512 | 128 |
| `setBarrierFill(n)` | 1, 2, 4, 8, 16, 32 | 1 |
| `setBitSoup(mode)` | 0 (off), non-zero (on) | 0 |
| `setLockSoup(mode)` | 0 (off), non-zero (on) | 0 |

Read-only accessors: `maxKeyBits()`, `channels()`, `headerSize()`,
`version()`.

For low-level chunk parsing (e.g. when implementing custom file
formats around ITB chunks): `parseChunkLen(header)` inspects the
fixed-size chunk header and returns the chunk's total
on-the-wire length; `headerSize()` returns the active header byte
count (20 / 36 / 68 for nonce sizes 128 / 256 / 512 bits).

## Concurrency

`Seed` / `MAC` / `Encryptor` / `Blob128` / `Blob256` / `Blob512` /
`StreamEncryptor` / `StreamDecryptor` (+ Triple variants) wrap
mutex-protected libitb cgo handles, so concurrent read-only
accessor calls against the same handle are sound at the libitb
layer. The wrapper objects themselves are NOT `MessagePort`-cloneable
(structured-clone strips the prototype chain and per-instance
private fields including the output-buffer cache), so worker-thread
sharing must go through the state-blob serialisation path:
`enc.exportState()` → `MessageChannel` of the resulting `Uint8Array`
→ `worker.importState(blob)` reconstructing a fresh wrapper on the
recipient. `Encryptor` cipher methods write into a per-instance
output-buffer cache; sharing one `Encryptor` across worker threads
without external synchronisation corrupts that cache. Distinct
`Encryptor` handles, each owned by one worker thread, run
independently against the libitb worker pool.

By contrast, the low-level cipher free functions (`encrypt` /
`decrypt` / `encryptAuth` / `decryptAuth` plus the Triple
counterparts) allocate output per call and are **thread-safe** under
concurrent invocation on the same `Seed` handles — libitb's worker
pool dispatches them independently. Two exceptions:
`seed.attachLockSeed` mutates the noise Seed and must not race
against an in-flight cipher call on it, and the process-wide setters
above stay process-global.

`koffi`'s synchronous `lib.func()` blocks the V8 main thread for
the duration of the FFI call, so `FinalizationRegistry` callbacks
(which queue on the JS event loop) cannot fire while libitb is
in flight on the calling thread — the binding's wrapper objects
remain reachable past every static-FFI call without explicit
keep-alive guards. The same property does not hold for
`koffi.func.async`; this binding ships sync FFI only.

## Error model

Every failure surfaces as `ITBError` (or one of its typed
subclasses) with two fields:

```typescript
import { ITBError, ITBEasyMismatchError, MAC, Status } from 'itb';
import { randomBytes } from 'node:crypto';

try {
  new MAC('nonsense', randomBytes(32));
} catch (e) {
  if (e instanceof ITBError) {
    console.log(`status=${e.code} (${e.message})`); // e.code === Status.BadMac
  }
}

try {
  enc.importState(blob);
} catch (e) {
  if (e instanceof ITBEasyMismatchError) {
    console.log(`mismatch on field '${e.field}'`); // e.code === Status.EasyMismatch
  }
}
```

Status codes are documented in
`cmd/cshared/internal/capi/errors.go` and mirrored in `Status.*`
exported constants. Typed subclasses provided for the most common
selective-catch patterns:

| Subclass | Status code | Raised on |
|---|---|---|
| `ITBEasyMismatchError` | `Status.EasyMismatch` | `Encryptor.importState` / `peekConfig` field disagreement; `.field` carries the JSON key |
| `ITBBlobModeMismatchError` | `Status.BlobModeMismatch` | `Blob.import` Single-vs-Triple mode mismatch |
| `ITBBlobMalformedError` | `Status.BlobMalformed` | `Blob.import` framing / length / magic-byte validation failure |
| `ITBBlobVersionTooNewError` | `Status.BlobVersionTooNew` | `Blob.import` version field newer than the binding can decode |

Type / value-input errors raise plain JavaScript `TypeError` /
`RangeError` (e.g. `plaintext` not a `Uint8Array`, `mode` not in
`{1, 3}`, `chunkSize ≤ 0`).

**Note:** empty plaintext / ciphertext is rejected by libitb itself
with `ITBError(Status.EncryptFailed)` ("itb: empty data") on every
cipher entry point. Pass at least one byte.

### Status codes

| Code | Name | Description |
|---|---|---|
| 0 | `Status.Ok` | Success — the only non-failure return value |
| 1 | `Status.BadHash` | Unknown hash primitive name |
| 2 | `Status.BadKeyBits` | ITB key width invalid for the chosen primitive |
| 3 | `Status.BadHandle` | FFI handle invalid or already freed |
| 4 | `Status.BadInput` | Generic shape / range / domain violation on a call argument |
| 5 | `Status.BufferTooSmall` | Output buffer cap below required size; probe-then-allocate idiom |
| 6 | `Status.EncryptFailed` | Encrypt path raised on the Go side (rare; structural / OOM) |
| 7 | `Status.DecryptFailed` | Decrypt path raised on the Go side (corrupt ciphertext shape) |
| 8 | `Status.SeedWidthMix` | Seeds passed to one call do not share the same native hash width |
| 9 | `Status.BadMac` | Unknown MAC name or key-length violates the primitive's `minKeyBytes` |
| 10 | `Status.MacFailure` | MAC verification failed — tampered ciphertext or wrong MAC key |
| 11 | `Status.EasyClosed` | Easy Mode encryptor call after `close()` |
| 12 | `Status.EasyMalformed` | Easy Mode `importState` blob fails JSON parse / structural check |
| 13 | `Status.EasyVersionTooNew` | Easy Mode blob version field higher than this build supports |
| 14 | `Status.EasyUnknownPrimitive` | Easy Mode blob references a primitive this build does not know |
| 15 | `Status.EasyUnknownMac` | Easy Mode blob references a MAC this build does not know |
| 16 | `Status.EasyBadKeyBits` | Easy Mode blob's `key_bits` invalid for its primitive |
| 17 | `Status.EasyMismatch` | Easy Mode blob disagrees with the receiver on `primitive` / `key_bits` / `mode` / `mac`; field name on `ITBEasyMismatchError.field` |
| 18 | `Status.EasyLockSeedAfterEncrypt` | `setLockSeed(1)` called after the first encrypt — must precede the first ciphertext |
| 19 | `Status.BlobModeMismatch` | Native Blob importer received a Single blob into a Triple receiver (or vice versa) |
| 20 | `Status.BlobMalformed` | Native Blob payload fails JSON parse / magic / structural check |
| 21 | `Status.BlobVersionTooNew` | Native Blob version field higher than this libitb build supports |
| 22 | `Status.BlobTooManyOpts` | Native Blob export opts mask carries unsupported bits |
| 23 | `Status.StreamTruncated` | Streaming AEAD transcript truncated before the terminator chunk; raised as `ITBStreamTruncatedError` |
| 24 | `Status.StreamAfterFinal` | Streaming AEAD transcript carries chunk bytes after the terminator; raised as `ITBStreamAfterFinalError` |
| 99 | `Status.Internal` | Generic "internal" sentinel for paths the caller cannot recover from at the binding layer |

## Constraints

- **Node.js 22 minimum.** The package's `package.json` declares
  `"engines": { "node": ">=22" }`. Earlier runtimes lack the ABI /
  loader features koffi depends on for the FFI substrate.
- **TypeScript 6 toolchain.** The build invokes `typescript ^6.0.3`
  in strict mode; consumers compile their own TypeScript against the
  bundled `.d.ts` declarations, or import the compiled JavaScript
  directly from Node.js.
- **Single distribution.** All consumer-visible declarations live
  under `src/`; the FFI substrate (`src/sys.ts`) is kept separate so
  audits can read it independently.
- **libitb.so required at runtime.** The package loads
  `dist/<os>-<arch>/libitb.<ext>` via koffi at module import; the
  shared library must be built first and reachable through the
  loader's search path.
- **External runtime deps.** The single non-stdlib runtime dependency
  is `koffi ^2.16.1`. The test runner uses Node's built-in
  `node:test` plus `@types/node`.
- **Frozen C ABI.** The `ITB_*` exports declared by the koffi-parsed
  signatures (synced from `dist/<os>-<arch>/libitb.h`) are the
  contract; the binding does not extend or reshape them.

## API Overview

Every public symbol re-exports through the package entry point
(`@everanium/itb`). TypeScript callers receive the bundled `.d.ts`;
JavaScript callers see the same identifiers on the imported module.

### Library metadata

| Symbol | Purpose |
|---|---|
| `version(): string` | Library version `"<major>.<minor>.<patch>"` |
| `maxKeyBits(): number` | Max supported ITB key width in bits |
| `channels(): number` | Number of native channel slots |
| `headerSize(): number` | Current chunk header size in bytes |
| `parseChunkLen(header: Uint8Array): number` | Parse chunk header, return total on-wire chunk length |
| `listHashes(): HashEntry[]` / `listMacs(): MacEntry[]` | Catalogue accessors |
| `lastError(): string` | Per-thread last-error message |
| `libraryPath(): string` | Resolved `libitb` library path |

### Process-wide configuration

| Symbol | Purpose |
|---|---|
| `setBitSoup(mode: number)` / `getBitSoup(): number` | Bit Soup mode toggle |
| `setLockSoup(mode: number)` / `getLockSoup(): number` | Lock Soup mode toggle |
| `setMaxWorkers(n: number)` / `getMaxWorkers(): number` | Worker pool cap |
| `setNonceBits(n: number)` / `getNonceBits(): number` | Nonce width (128 / 256 / 512) |
| `setBarrierFill(n: number)` / `getBarrierFill(): number` | Barrier-fill factor |
| `setMemoryLimit(limit: bigint \| number): bigint` | Go runtime heap soft limit in bytes; negative argument = query only |
| `setGcPercent(pct: number): number` | Go GC trigger percentage; negative argument = query only |

### Seeds and MAC

| Symbol | Purpose |
|---|---|
| `new Seed(hashName: string, keyBits: number)` | CSPRNG-fresh seed |
| `Seed.fromComponents(hashName, keyBits, components)` | Reconstruct from explicit components |
| `seed.width / seed.hashName / seed.hashKey() / seed.components() / seed.attachLockSeed(lock)` | Introspection + lock-seed attachment |
| `new MAC(macName: string, key: Uint8Array)` | Construct MAC handle (32-byte keys across the shipped catalogue) |

### Low-level cipher (free functions)

| Symbol | Purpose |
|---|---|
| `encrypt(noise, data, start, plaintext): Uint8Array` / `decrypt(...)` | Single Message |
| `encryptAuth(noise, data, start, mac, plaintext)` / `decryptAuth(...)` | MAC-authenticated counterparts |
| `encryptTriple(noise, d1, d2, d3, s1, s2, s3, plaintext)` / `decryptTriple(...)` | Triple Ouroboros |
| `encryptAuthTriple(...)` / `decryptAuthTriple(...)` | Triple Ouroboros MAC-authenticated |

### Easy Mode encryptor

| Symbol | Purpose |
|---|---|
| `new Encryptor(primitive, keyBits, opts?)` | Single-primitive constructor |
| `Encryptor.mixed(primitives, keyBits, opts?)` / `Encryptor.mixed3(primitives, keyBits, opts?)` | Mixed-primitive Single / Triple |
| `enc.encrypt(pt)` / `enc.decrypt(ct)` | Cipher entry points |
| `enc.encryptAuth(pt)` / `enc.decryptAuth(ct)` | MAC-authenticated cipher entry points |
| `enc.setNonceBits / setBarrierFill / setBitSoup / setLockSoup / setLockSeed / setChunkSize` | Per-instance setters |
| `enc.primitive / macName / keyBits / mode / nonceBits / headerSize / hasPRFKeys / isMixed / seedCount` | Accessors |
| `enc.prfKey(slot)` / `enc.macKey()` / `enc.seedComponents(slot)` | Key-material accessors |
| `enc.export()` / `enc.importState(blob)` | State-blob persistence |
| `peekConfig(blob): PeekedConfig` / `lastMismatchField(): string` | Pre-import discriminator + mismatch-field accessor |
| `enc.close()` | Release encryptor |

### Streaming AEAD

| Symbol | Purpose |
|---|---|
| `encryptStream(read, write, noise, data, start, opts?)` / `decryptStream(...)` | Single Low-Level streams |
| `encryptStreamTriple(...)` / `decryptStreamTriple(...)` | Triple Low-Level streams |
| `encryptStreamAuth(read, write, noise, data, start, mac, opts?)` / `decryptStreamAuth(...)` | Single Low-Level Streaming AEAD |
| `encryptStreamAuthTriple(...)` / `decryptStreamAuthTriple(...)` | Triple Low-Level Streaming AEAD |
| `StreamEncryptor / StreamDecryptor / StreamEncryptorTriple / StreamDecryptorTriple` | Push-style Low-Level streamers |
| `StreamEncryptorAuth / StreamDecryptorAuth / StreamEncryptorAuthTriple / StreamDecryptorAuthTriple` | Push-style Streaming AEAD streamers |
| `DEFAULT_CHUNK_SIZE` / `STREAM_ID_LEN` | Streaming chunk size + stream-id length |

### Native Blob

| Symbol | Purpose |
|---|---|
| `new Blob128() / new Blob256() / new Blob512()` | Width-specific Native Blob handles |
| `blob.setKey / setComponents / setMacKey / setMacName(...)` | Field setters |
| `blob.getKey / getComponents / getMacKey / getMacName(...)` | Field getters |
| `blob.export(opts?) / exportTriple(opts?) / import(payload) / importTriple(payload)` | Serialisation |
| `BlobSlot.N / D / S / L / D1 / D2 / D3 / S1 / S2 / S3` | Slot enum |
| `BlobExportOpts.None / LockSeed / Mac` | Export opt-in flag bits |

### Wrapper (format-deniability outer cipher)

| Symbol | Purpose |
|---|---|
| `Cipher.Aes128Ctr / ChaCha20 / SipHash24` | Cipher enum |
| `CIPHER_NAMES: readonly CipherName[]` | Canonical name list |
| `wrapperKeySize(cipher): number` / `wrapperNonceSize(cipher): number` | Cipher dimension accessors |
| `wrapperGenerateKey(cipher): Uint8Array` | CSPRNG-fresh wrapper key |
| `wrap(cipher, key, blob): Uint8Array` / `unwrap(cipher, key, wire): Uint8Array` | Single Message Wrap / Unwrap |
| `wrapInPlace(cipher, key, buf): Uint8Array` / `unwrapInPlace(cipher, key, wire): Uint8Array` | In-place Wrap / Unwrap |
| `new WrapStreamWriter(cipher, key)` / `new UnwrapStreamReader(cipher, key, wireNonce)` | Streaming wrap writer / unwrap reader |
| `InvalidCipherError / InvalidKeyError / InvalidNonceError / WrapperError / WrapperHandleClosedError` | Typed exceptions |

### Error model

| Symbol | Purpose |
|---|---|
| `ITBError` | Base error class; `.code` carries the numeric status |
| `ITBEasyMismatchError / ITBBlobModeMismatchError / ITBBlobMalformedError / ITBBlobVersionTooNewError` | Typed subclasses for cold-path discriminators |
| `ITBStreamTruncatedError / ITBStreamAfterFinalError` | Streaming AEAD transcript-shape exceptions |
| `Status` (enum) / `StatusCode` (type alias) | Status-code surface |
