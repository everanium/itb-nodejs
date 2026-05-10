# ITB Node.js Binding — Format-Deniability Wrapper

TypeScript-idiomatic surface over the format-deniability wrapper exposed by libitb. Mirrors `github.com/everanium/itb/wrapper` structurally; the wire bytes produced by the Node.js helpers are byte-identical to the Go-native helpers under the same `(cipher, key, nonce)` tuple.

The runtime module lives at `itb/wrapper`; this directory carries the wrapper-side documentation (`README.md` + `BENCH.md`). The example utility lives at `bindings/nodejs/eitb/eitb.ts` and the benchmark binary at `bindings/nodejs/bench/bench-wrapper.ts`.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte streamID prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte streamID prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher: AES-128-CTR, ChaCha20 (RFC 8439), or SipHash-2-4 in CTR mode. After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Wrapper API

The Node.js module exposes Single Message helpers (immutable + in-place mutation) and a streaming class pair:

| Helper | Wire format | Use case |
|---|---|---|
| `wrap` / `unwrap` | `nonce \|\| keystream-XOR(blob)` | Single Message Encrypt / EncryptAuth output, immutable plaintext path. |
| `wrapInPlace` / `unwrapInPlace` | same as `wrap` / `unwrap` | Single Message, zero-allocation steady state. Mutates the caller's `Buffer`. |
| `WrapStreamWriter` / `UnwrapStreamReader` | `nonce` + keystream-XOR(continuous bytestream) | streaming use — Streaming AEAD wraps the entire bytestream end-to-end; User-Driven Loop emits per-chunk caller-side framing (`u32_LE` length prefix) through the wrap-writer so the framing bytes also pass through the keystream XOR. |

The single keystream advances monotonically across all bytes within one wrap session. A fresh CSPRNG nonce is generated per session; emitted once at stream start; never reused across sessions. This is standard CTR mode usage — within one stream, one nonce + counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop emits length prefixes through the wrap-writer so they get XORed into the keystream alongside the chunk bodies.

The streaming classes implement `Disposable` — using a `using` declaration releases the underlying libitb stream handle deterministically. A `FinalizationRegistry` backstop runs the same release on GC if `close` / `[Symbol.dispose]` is not called explicitly. `close()` is the explicit release path that surfaces release-time errors to the caller.

### Binding asymmetry

The Node.js binding exposes Streaming AEAD as a `Readable` / `Writable` pair (`Encryptor.encryptStreamAuth` / `decryptStreamAuth`, plus the free functions `encryptStreamAuth` / `decryptStreamAuth`). The Streaming No MAC path has **no** equivalent stream adapter pair on top of the wrap surface for Non-AEAD streaming. This asymmetry is intentional. The Non-AEAD streaming arm in the Node.js wrapper covers the **User-Driven Loop** variant only — caller produces an ITB ciphertext per chunk via `enc.encrypt(chunk)` (or `encrypt(...)`), frames `u32_LE_len || ct`, and pushes through the streaming wrap handle. See CLAUDE.md.

## Outer ciphers

| Cipher | Constant | Key | Nonce | Notes |
|---|---|---|---|---|
| AES-128-CTR | `Cipher.Aes128Ctr` (`"aes"`) | 16 B | 16 B | libitb-side stdlib path with AES-NI. |
| ChaCha20 (RFC 8439) | `Cipher.ChaCha20` (`"chacha"`) | 32 B | 12 B | `golang.org/x/crypto/chacha20`. No AES-NI dependency. |
| SipHash-2-4 in CTR mode | `Cipher.SipHash24` (`"siphash"`) | 16 B | 16 B | `github.com/dchest/siphash` PRF. Custom CTR construction; sound under standard PRF assumption. |

The SipHash-CTR construction:
- 16-byte SipHash key = wrapper key.
- 16-byte nonce split into `(nonce_hi, nonce_lo)` 64-bit halves.
- Each keystream block: `siphash.Hash(key, nonce_hi || (nonce_lo XOR counter_LE))` — 8-byte output, XORed with plaintext.
- Counter increments per block; nonce stays fixed for the stream.

## Quick Start

Code paths under `bindings/nodejs/eitb/eitb.ts`. Run the matrix:

```sh
cd bindings/nodejs
npx tsc -p tsconfig.eitb.json
node dist-eitb/eitb/eitb.js
node dist-eitb/eitb/eitb.js --help
```

### 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)

ITB Call: `Encryptor.encryptStreamAuth` / `decryptStreamAuth`. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` over the continuous bytestream ITB emits.

```ts
import { PassThrough } from 'node:stream';
import {
  Encryptor, UnwrapStreamReader, WrapStreamWriter,
  wrapperGenerateKey, wrapperNonceSize, Cipher,
} from 'itb';

using enc = new Encryptor('areion512', 1024, 'hmac-blake3', 1);
enc.setNonceBits(512); enc.setBarrierFill(4);
enc.setBitSoup(1); enc.setLockSoup(1);

const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);

// Sender — encrypt the bytestream into an in-memory PassThrough,
// then wrap the entire bytestream in one keystream session.
const innerOut = new PassThrough();
const innerIn = new PassThrough();
innerIn.end(plaintext);
await enc.encryptStreamAuth(innerIn, innerOut, 16 * 1024);
innerOut.end();
const innerBytes = await drain(innerOut);

using ww = new WrapStreamWriter(Cipher.Aes128Ctr, outerKey);
const wire = Buffer.concat([ww.nonce, ww.update(innerBytes)]);

// Receiver — strip the leading nonce, unwrap the body, decrypt.
const nlen = wrapperNonceSize(Cipher.Aes128Ctr);
using ur = new UnwrapStreamReader(Cipher.Aes128Ctr, outerKey, wire.subarray(0, nlen));
const innerWire = ur.update(wire.subarray(nlen));

const ptIn = new PassThrough();
ptIn.end(innerWire);
const ptOut = new PassThrough();
await enc.decryptStreamAuth(ptIn, ptOut);
ptOut.end();
const recovered = await drain(ptOut);
```

### 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)

ITB Call: `encryptStreamAuth(noise, data, start, mac, ...)` / `decryptStreamAuth(...)` with three explicit `Seed` handles plus a `MAC` keyed on `hmac-blake3`. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`.

```ts
import { Seed, MAC, encryptStreamAuth, decryptStreamAuth } from 'itb';

using mac = new MAC('hmac-blake3', macKey32);
const seeds = [new Seed('areion512', 1024), new Seed('areion512', 1024), new Seed('areion512', 1024)];
const [s0, s1, s2] = seeds as [Seed, Seed, Seed];

const innerOut = new PassThrough();
const innerIn = new PassThrough();
innerIn.end(plaintext);
await encryptStreamAuth(s0, s1, s2, mac, innerIn, innerOut, 16 * 1024);
innerOut.end();
const innerBytes = await drain(innerOut);

using ww = new WrapStreamWriter(Cipher.Aes128Ctr, outerKey);
const wire = Buffer.concat([ww.nonce, ww.update(innerBytes)]);
// Receiver mirrors example 1.
```

### 3. Streaming Easy (No MAC, User-Driven Loop)

The "Alternative — User-Driven Loop" pattern: each chunk is one independent `enc.encrypt(chunk)` call. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` driven by a caller loop that emits `u32_LE_len || ct` per chunk through the wrapped writer. Length prefix and chunk body both pass through the keystream XOR — no length appears in cleartext on the wire.

```ts
using enc = new Encryptor('areion512', 1024, null, 1);
enc.setNonceBits(512); enc.setBarrierFill(4);
enc.setBitSoup(1); enc.setLockSoup(1);

const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);
using ww = new WrapStreamWriter(Cipher.Aes128Ctr, outerKey);
const parts: Buffer[] = [ww.nonce];
let off = 0;
while (off < plaintext.length) {
  const take = Math.min(16 * 1024, plaintext.length - off);
  const ct = enc.encrypt(plaintext.subarray(off, off + take));
  const lenLe = Buffer.alloc(4);
  lenLe.writeUInt32LE(ct.length, 0);
  parts.push(ww.update(lenLe));
  parts.push(ww.update(Buffer.from(ct)));
  off += take;
}
const wire = Buffer.concat(parts);

// Receiver — pull the entire decrypted bytestream then walk
// u32_LE-prefixed chunks.
const nlen = wrapperNonceSize(Cipher.Aes128Ctr);
using ur = new UnwrapStreamReader(Cipher.Aes128Ctr, outerKey, wire.subarray(0, nlen));
const decrypted = ur.update(wire.subarray(nlen));

let pos = 0;
const out: Buffer[] = [];
while (pos < decrypted.length) {
  const clen = decrypted.readUInt32LE(pos);
  pos += 4;
  out.push(Buffer.from(enc.decrypt(decrypted.subarray(pos, pos + clen))));
  pos += clen;
}
```

### 4. Streaming Low-Level (No MAC, User-Driven Loop)

Per-chunk `encrypt` / `decrypt` with caller-side framing. Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader`. Each chunk is emitted as `u32_LE_len || ct` through the wrap-writer; the length and the body both pass through the keystream XOR.

```ts
import { encrypt as itbEncrypt, decrypt as itbDecrypt } from 'itb';

const seeds = [new Seed('areion512', 1024), new Seed('areion512', 1024), new Seed('areion512', 1024)];
const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);
using ww = new WrapStreamWriter(Cipher.Aes128Ctr, outerKey);
const parts: Buffer[] = [ww.nonce];
let off = 0;
while (off < plaintext.length) {
  const take = Math.min(16 * 1024, plaintext.length - off);
  const ct = itbEncrypt(s0, s1, s2, plaintext.subarray(off, off + take));
  const lenLe = Buffer.alloc(4);
  lenLe.writeUInt32LE(ct.length, 0);
  parts.push(ww.update(lenLe));
  parts.push(ww.update(Buffer.from(ct)));
  off += take;
}
const wire = Buffer.concat(parts);

// Receiver mirrors example 3 with itbDecrypt(s0, s1, s2, ct).
```

### 5. Easy: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `enc.encrypt(plaintext)` returns one ITB blob. Wrap shape: `wrap` — `nonce || ks-XOR(blob)`. The `wrapInPlace` / `unwrapInPlace` variant is shown — mutates the caller's `Buffer` in place to skip the steady-state allocation.

```ts
using enc = new Encryptor('areion512', 2048, null, 1);
enc.setNonceBits(512); enc.setBarrierFill(4);
enc.setBitSoup(1); enc.setLockSoup(1);

const encrypted = Buffer.from(enc.encrypt(plaintext));

const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);
// wrap respects immutability of `encrypted` (allocates a fresh wire buffer):
// const wire = wrap(Cipher.Aes128Ctr, outerKey, encrypted);
const nonce = wrapInPlace(Cipher.Aes128Ctr, outerKey, encrypted);
const wire = Buffer.concat([nonce, encrypted]);

// Receiver — unwrap respects immutability of `wire` (allocates a fresh recovered buffer):
// const recovered = unwrap(Cipher.Aes128Ctr, outerKey, wire);
const wireBuf = Buffer.from(wire);
const recovered = unwrapInPlace(Cipher.Aes128Ctr, outerKey, wireBuf);
const pt = enc.decrypt(recovered);
```

### 6. Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `enc.encryptAuth` / `enc.decryptAuth`. Wrap shape: `wrap` (or `wrapInPlace`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```ts
using enc = new Encryptor('areion512', 2048, 'hmac-blake3', 1);
enc.setNonceBits(512); enc.setBarrierFill(4);
enc.setBitSoup(1); enc.setLockSoup(1);

const encrypted = Buffer.from(enc.encryptAuth(plaintext));

const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);
const nonce = wrapInPlace(Cipher.Aes128Ctr, outerKey, encrypted);
const wire = Buffer.concat([nonce, encrypted]);

// Receiver
const wireBuf = Buffer.from(wire);
const recovered = unwrapInPlace(Cipher.Aes128Ctr, outerKey, wireBuf);
const pt = enc.decryptAuth(recovered);
```

### 7. Low-Level: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `encrypt(s0, s1, s2, plaintext)` / `decrypt(...)` with three explicit `Seed` handles. Wrap shape: `wrap` (or `wrapInPlace`). Wire shape matches example 5; the difference is that the seed material is held by caller-side `Seed` handles rather than by an `Encryptor` instance.

```ts
const seeds = [new Seed('areion512', 2048), new Seed('areion512', 2048), new Seed('areion512', 2048)];
const [s0, s1, s2] = seeds as [Seed, Seed, Seed];

const encrypted = Buffer.from(itbEncrypt(s0, s1, s2, plaintext));

const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);
const nonce = wrapInPlace(Cipher.Aes128Ctr, outerKey, encrypted);
const wire = Buffer.concat([nonce, encrypted]);

// Receiver
const wireBuf = Buffer.from(wire);
const recovered = unwrapInPlace(Cipher.Aes128Ctr, outerKey, wireBuf);
const pt = itbDecrypt(s0, s1, s2, recovered);
```

### 8. Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `encryptAuth(s0, s1, s2, mac, plaintext)` / `decryptAuth(...)`. Wrap shape: `wrap` (or `wrapInPlace`). The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```ts
import { encryptAuth, decryptAuth } from 'itb';

const seeds = [new Seed('areion512', 2048), new Seed('areion512', 2048), new Seed('areion512', 2048)];
const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
using mac = new MAC('hmac-blake3', macKey32);

const encrypted = Buffer.from(encryptAuth(s0, s1, s2, mac, plaintext));

const outerKey = wrapperGenerateKey(Cipher.Aes128Ctr);
const nonce = wrapInPlace(Cipher.Aes128Ctr, outerKey, encrypted);
const wire = Buffer.concat([nonce, encrypted]);

// Receiver
const wireBuf = Buffer.from(wire);
const recovered = unwrapInPlace(Cipher.Aes128Ctr, outerKey, wireBuf);
const pt = decryptAuth(s0, s1, s2, mac, recovered);
```

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with sha256 byte-equality. Sample run:

```
[PASS] aead-easy-io               + aes        pt=65536 wire=90208
[PASS] aead-easy-io               + chacha     pt=65536 wire=90204
[PASS] aead-easy-io               + siphash    pt=65536 wire=90208
[PASS] aead-lowlevel-io           + aes        pt=65536 wire=90208
[PASS] aead-lowlevel-io           + chacha     pt=65536 wire=90204
[PASS] aead-lowlevel-io           + siphash    pt=65536 wire=90208
[PASS] noaead-easy-userloop       + aes        pt=65536 wire=90192
[PASS] noaead-easy-userloop       + chacha     pt=65536 wire=90188
[PASS] noaead-easy-userloop       + siphash    pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + aes        pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop   + chacha     pt=65536 wire=90188
[PASS] noaead-lowlevel-userloop   + siphash    pt=65536 wire=90192
[PASS] message-easy-nomac         + aes        pt=1024 wire=4316
[PASS] message-easy-nomac         + chacha     pt=1024 wire=4312
[PASS] message-easy-nomac         + siphash    pt=1024 wire=4316
[PASS] message-easy-auth          + aes        pt=1024 wire=8276
[PASS] message-easy-auth          + chacha     pt=1024 wire=8272
[PASS] message-easy-auth          + siphash    pt=1024 wire=8276
[PASS] message-lowlevel-nomac     + aes        pt=1024 wire=4316
[PASS] message-lowlevel-nomac     + chacha     pt=1024 wire=4312
[PASS] message-lowlevel-nomac     + siphash    pt=1024 wire=4316
[PASS] message-lowlevel-auth      + aes        pt=1024 wire=8276
[PASS] message-lowlevel-auth      + chacha     pt=1024 wire=8272
[PASS] message-lowlevel-auth      + siphash    pt=1024 wire=8276

=== Summary: 24 PASS, 0 FAIL ===
```

The wire-byte difference between cipher columns is exactly the per-stream nonce-size delta (16 vs 12 vs 16 bytes); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk. The wire byte counts match the Python / Rust / C# bindings' matrices exactly under the same plaintext sizes.

## Performance

Bench numbers across Single Ouroboros and Triple Ouroboros, message and streaming, encrypt and decrypt (split sub-benches) are tracked in [BENCH.md](BENCH.md).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the example utility generates a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
