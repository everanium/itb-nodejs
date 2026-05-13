// Node.js eitb — runs every wrapper × ITB example end-to-end.
//
// Mirrors `tools/eitb/main.go` adapted to the Node.js binding asymmetry:
// the binding has no `stream.Readable` / `stream.Writable` wrap-layer
// adapter pair for Non-AEAD streaming. Streaming AEAD wraps the
// entire bytestream end-to-end via the `WrapStreamWriter` /
// `UnwrapStreamReader` byte pump after the inner ITB transcript is
// materialised in a `Buffer`. The Non-AEAD streaming arm covers the
// User-Driven Loop variant only — caller produces an ITB ciphertext
// per chunk via `Encryptor.encrypt(chunk)` (or the low-level free
// function `encrypt(...)`), frames `u32_LE_len || ct`, and pushes
// through the wrap-stream writer.
//
// Matrix: 8 examples × 3 outer ciphers (aes / chacha / siphash) =
// 24 PASS/FAIL cells.
//
// Examples covered:
//
//   - aead-easy-io               Streaming AEAD Easy        (MAC Authenticated, IO-Driven)
//   - aead-lowlevel-io           Streaming AEAD Low-Level   (MAC Authenticated, IO-Driven)
//   - noaead-easy-userloop       Streaming Easy             (No MAC, User-Driven Loop)
//   - noaead-lowlevel-userloop   Streaming Low-Level        (No MAC, User-Driven Loop)
//   - message-easy-nomac         Easy Single Message           (No MAC)
//   - message-easy-auth          Easy Single Message           (MAC Authenticated)
//   - message-lowlevel-nomac     Low-Level Single Message      (No MAC)
//   - message-lowlevel-auth      Low-Level Single Message      (MAC Authenticated)
//
// Single-message examples encrypt 1024 bytes; streaming examples
// encrypt 64 KiB through 16 KiB chunks. Each example runs sender +
// receiver in the same process, wraps the ITB ciphertext under the
// chosen outer cipher, hands the wrapped bytes to the receiver path,
// and verifies sha256 byte-equality of the recovered plaintext
// against the original.
//
// Usage:
//
//     node dist-eitb/eitb/eitb.js
//     node dist-eitb/eitb/eitb.js --example aead
//     node dist-eitb/eitb/eitb.js --cipher aes -v

/* eslint-disable no-console */

import { createHash, randomBytes } from 'node:crypto';
import { PassThrough } from 'node:stream';

import {
  CIPHER_NAMES,
  Encryptor,
  MAC,
  Seed,
  decryptAuth,
  decryptStreamAuth,
  decrypt as itbDecrypt,
  encryptAuth,
  encryptStreamAuth,
  encrypt as itbEncrypt,
  setBarrierFill,
  setBitSoup,
  setLockSoup,
  setMaxWorkers,
  setNonceBits,
  unwrapInPlace,
  UnwrapStreamReader,
  wrapInPlace,
  WrapStreamWriter,
  wrapperGenerateKey,
  wrapperNonceSize,
} from '../src/index.js';
import type { CipherName } from '../src/index.js';

const SINGLE_MESSAGE_BYTES = 1024;
const STREAM_BYTES = 64 * 1024;
const STREAM_CHUNK_SIZE = 16 * 1024;

// ────────────────────────────────────────────────────────────────────
// Helpers — random fill, sha256 fingerprint, drain a PassThrough.
// ────────────────────────────────────────────────────────────────────

function sha256Short(b: Buffer): string {
  return createHash('sha256').update(b).digest('hex').slice(0, 16);
}

function sha256Hex(b: Buffer): string {
  return createHash('sha256').update(b).digest('hex');
}

async function drain(stream: PassThrough): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

// ────────────────────────────────────────────────────────────────────
// Builders — parity with `tools/eitb/main.go`'s build_easy /
// build_three_seeds / apply_lowlevel_config helpers.
// ────────────────────────────────────────────────────────────────────

function buildEasy(macName: string | null, keyBits: number): Encryptor {
  const enc = new Encryptor('areion512', keyBits, macName, 1);
  enc.setNonceBits(512);
  enc.setBarrierFill(4);
  enc.setBitSoup(1);
  enc.setLockSoup(1);
  return enc;
}

function buildThreeSeeds(keyBits: number): [Seed, Seed, Seed] {
  return [
    new Seed('areion512', keyBits),
    new Seed('areion512', keyBits),
    new Seed('areion512', keyBits),
  ];
}

function applyLowLevelConfig(): void {
  setNonceBits(512);
  setBarrierFill(4);
  setBitSoup(1);
  setLockSoup(1);
}

function disposeSeeds(seeds: Seed[]): void {
  for (const s of seeds) s.free();
}

// ────────────────────────────────────────────────────────────────────
// Streaming AEAD Easy (MAC Authenticated, IO-Driven)
//
// ITB Call: `Encryptor.encryptStreamAuth` / `decryptStreamAuth`.
// Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` over the
// continuous bytestream ITB emits. The inner transcript is
// materialised in a single `Buffer` between the ITB AEAD pipeline
// and the wrap layer — Node's binding has no Reader/Writer adapter
// over the wrap surface, so the bridge is buffered.
// ────────────────────────────────────────────────────────────────────

async function runAeadEasyIo(
  cipher: CipherName,
  plaintext: Buffer,
): Promise<{ recovered: Buffer; wireBytes: number }> {
  const enc = buildEasy('hmac-blake3', 1024);
  try {
    const outerKey = wrapperGenerateKey(cipher);

    // Sender — encrypt the bytestream into an in-memory PassThrough,
    // then wrap the entire bytestream in one keystream session.
    const innerOut = new PassThrough();
    const innerIn = new PassThrough();
    innerIn.end(plaintext);
    await enc.encryptStreamAuth(innerIn, innerOut, STREAM_CHUNK_SIZE);
    innerOut.end();
    const innerBytes = await drain(innerOut);

    const ww = new WrapStreamWriter(cipher, outerKey);
    let wire: Buffer;
    try {
      const body = ww.update(innerBytes);
      wire = Buffer.concat([ww.nonce, body]);
    } finally {
      ww.close();
    }
    const wireBytes = wire.length;

    // Receiver — strip the leading nonce, unwrap the body, decrypt.
    const nlen = wrapperNonceSize(cipher);
    const ur = new UnwrapStreamReader(cipher, outerKey, wire.subarray(0, nlen));
    let innerWire: Buffer;
    try {
      innerWire = ur.update(wire.subarray(nlen));
    } finally {
      ur.close();
    }

    const ptIn = new PassThrough();
    ptIn.end(innerWire);
    const ptOut = new PassThrough();
    await enc.decryptStreamAuth(ptIn, ptOut);
    ptOut.end();
    const recovered = await drain(ptOut);
    return { recovered, wireBytes };
  } finally {
    enc.free();
  }
}

// ────────────────────────────────────────────────────────────────────
// Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)
//
// ITB Call: `encryptStreamAuth(noise, data, start, mac, ...)` /
// `decryptStreamAuth(...)` with three explicit `Seed` handles plus
// `MAC` keyed on hmac-blake3. Wrap shape mirrors example 1 — buffer
// the inner transcript, wrap the entire bytestream end-to-end.
// ────────────────────────────────────────────────────────────────────

async function runAeadLowLevelIo(
  cipher: CipherName,
  plaintext: Buffer,
): Promise<{ recovered: Buffer; wireBytes: number }> {
  applyLowLevelConfig();
  const seeds = buildThreeSeeds(1024);
  const [s0, s1, s2] = seeds;
  try {
    const macKey = randomBytes(32);
    using mac = new MAC('hmac-blake3', macKey);
    const outerKey = wrapperGenerateKey(cipher);

    const innerOut = new PassThrough();
    const innerIn = new PassThrough();
    innerIn.end(plaintext);
    await encryptStreamAuth(s0, s1, s2, mac, innerIn, innerOut, STREAM_CHUNK_SIZE);
    innerOut.end();
    const innerBytes = await drain(innerOut);

    const ww = new WrapStreamWriter(cipher, outerKey);
    let wire: Buffer;
    try {
      const body = ww.update(innerBytes);
      wire = Buffer.concat([ww.nonce, body]);
    } finally {
      ww.close();
    }
    const wireBytes = wire.length;

    const nlen = wrapperNonceSize(cipher);
    const ur = new UnwrapStreamReader(cipher, outerKey, wire.subarray(0, nlen));
    let innerWire: Buffer;
    try {
      innerWire = ur.update(wire.subarray(nlen));
    } finally {
      ur.close();
    }

    const ptIn = new PassThrough();
    ptIn.end(innerWire);
    const ptOut = new PassThrough();
    await decryptStreamAuth(s0, s1, s2, mac, ptIn, ptOut);
    ptOut.end();
    const recovered = await drain(ptOut);
    return { recovered, wireBytes };
  } finally {
    disposeSeeds(seeds);
  }
}

// ────────────────────────────────────────────────────────────────────
// Streaming Easy (No MAC, User-Driven Loop)
//
// Per-chunk encrypt + caller-side u32_LE framing emitted through one
// wrap-stream session — both the length prefix and each chunk body
// pass through the same keystream so neither shows in cleartext.
// ────────────────────────────────────────────────────────────────────

function runNoaeadEasyUserloop(
  cipher: CipherName,
  plaintext: Buffer,
): { recovered: Buffer; wireBytes: number } {
  const enc = buildEasy(null, 1024);
  try {
    const outerKey = wrapperGenerateKey(cipher);

    // Sender
    const ww = new WrapStreamWriter(cipher, outerKey);
    const wireParts: Buffer[] = [ww.nonce];
    try {
      let off = 0;
      while (off < plaintext.length) {
        const take = Math.min(STREAM_CHUNK_SIZE, plaintext.length - off);
        const ct = enc.encrypt(plaintext.subarray(off, off + take));
        const lenLe = Buffer.alloc(4);
        lenLe.writeUInt32LE(ct.length, 0);
        wireParts.push(ww.update(lenLe));
        wireParts.push(ww.update(Buffer.from(ct)));
        off += take;
      }
    } finally {
      ww.close();
    }
    const wire = Buffer.concat(wireParts);
    const wireBytes = wire.length;

    // Receiver
    const nlen = wrapperNonceSize(cipher);
    const ur = new UnwrapStreamReader(cipher, outerKey, wire.subarray(0, nlen));
    let decrypted: Buffer;
    try {
      decrypted = ur.update(wire.subarray(nlen));
    } finally {
      ur.close();
    }

    const outParts: Buffer[] = [];
    let pos = 0;
    while (pos < decrypted.length) {
      if (pos + 4 > decrypted.length) {
        throw new Error(`truncated length prefix at pos ${pos}`);
      }
      const clen = decrypted.readUInt32LE(pos);
      pos += 4;
      if (pos + clen > decrypted.length) {
        throw new Error(`truncated body at pos ${pos}: need ${clen}`);
      }
      const pt = enc.decrypt(decrypted.subarray(pos, pos + clen));
      outParts.push(Buffer.from(pt));
      pos += clen;
    }
    return { recovered: Buffer.concat(outParts), wireBytes };
  } finally {
    enc.free();
  }
}

// ────────────────────────────────────────────────────────────────────
// Streaming Low-Level (No MAC, User-Driven Loop)
//
// Per-chunk `itbEncrypt` / `itbDecrypt` with caller-side framing.
// Wrap shape: `WrapStreamWriter` / `UnwrapStreamReader` with
// per-chunk `u32_LE_len || ct` emitted through the writer.
// ────────────────────────────────────────────────────────────────────

function runNoaeadLowLevelUserloop(
  cipher: CipherName,
  plaintext: Buffer,
): { recovered: Buffer; wireBytes: number } {
  applyLowLevelConfig();
  const seeds = buildThreeSeeds(1024);
  const [s0, s1, s2] = seeds;
  try {
    const outerKey = wrapperGenerateKey(cipher);

    const ww = new WrapStreamWriter(cipher, outerKey);
    const wireParts: Buffer[] = [ww.nonce];
    try {
      let off = 0;
      while (off < plaintext.length) {
        const take = Math.min(STREAM_CHUNK_SIZE, plaintext.length - off);
        const ct = itbEncrypt(s0, s1, s2, plaintext.subarray(off, off + take));
        const lenLe = Buffer.alloc(4);
        lenLe.writeUInt32LE(ct.length, 0);
        wireParts.push(ww.update(lenLe));
        wireParts.push(ww.update(Buffer.from(ct)));
        off += take;
      }
    } finally {
      ww.close();
    }
    const wire = Buffer.concat(wireParts);
    const wireBytes = wire.length;

    const nlen = wrapperNonceSize(cipher);
    const ur = new UnwrapStreamReader(cipher, outerKey, wire.subarray(0, nlen));
    let decrypted: Buffer;
    try {
      decrypted = ur.update(wire.subarray(nlen));
    } finally {
      ur.close();
    }

    const outParts: Buffer[] = [];
    let pos = 0;
    while (pos < decrypted.length) {
      if (pos + 4 > decrypted.length) {
        throw new Error(`truncated length prefix at pos ${pos}`);
      }
      const clen = decrypted.readUInt32LE(pos);
      pos += 4;
      if (pos + clen > decrypted.length) {
        throw new Error(`truncated body at pos ${pos}: need ${clen}`);
      }
      const pt = itbDecrypt(s0, s1, s2, decrypted.subarray(pos, pos + clen));
      outParts.push(Buffer.from(pt));
      pos += clen;
    }
    return { recovered: Buffer.concat(outParts), wireBytes };
  } finally {
    disposeSeeds(seeds);
  }
}

// ────────────────────────────────────────────────────────────────────
// Single Message — Easy: Areion-SoEM-512 (No MAC)
//
// One enc.encrypt() call → one ITB blob. wrapInPlace mutates the
// blob and returns the per-stream nonce; the caller composes
// nonce || mutated-blob to produce the wire. unwrapInPlace mutates
// the wire and returns a Buffer aliasing the recovered blob.
// ────────────────────────────────────────────────────────────────────

function runMessageEasyNomac(
  cipher: CipherName,
  plaintext: Buffer,
): { recovered: Buffer; wireBytes: number } {
  const enc = buildEasy(null, 2048);
  try {
    const outerKey = wrapperGenerateKey(cipher);

    const encrypted = Buffer.from(enc.encrypt(plaintext));
    // wrap respects immutability of `encrypted` (allocates a fresh
    // wire buffer):
    // const wire = wrap(cipher, outerKey, encrypted);
    const nonce = wrapInPlace(cipher, outerKey, encrypted);
    const wire = Buffer.concat([nonce, encrypted]);
    const wireBytes = wire.length;

    // Receiver — unwrap respects immutability of `wire` (allocates a
    // fresh recovered buffer):
    // const recovered = unwrap(cipher, outerKey, wire);
    const wireBuf = Buffer.from(wire);
    const recovered = unwrapInPlace(cipher, outerKey, wireBuf);
    const pt = Buffer.from(enc.decrypt(recovered));
    return { recovered: pt, wireBytes };
  } finally {
    enc.free();
  }
}

// ────────────────────────────────────────────────────────────────────
// Single Message — Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC
// Authenticated)
// ────────────────────────────────────────────────────────────────────

function runMessageEasyAuth(
  cipher: CipherName,
  plaintext: Buffer,
): { recovered: Buffer; wireBytes: number } {
  const enc = buildEasy('hmac-blake3', 2048);
  try {
    const outerKey = wrapperGenerateKey(cipher);

    const encrypted = Buffer.from(enc.encryptAuth(plaintext));
    // wrap respects immutability of `encrypted` (allocates a fresh
    // wire buffer):
    // const wire = wrap(cipher, outerKey, encrypted);
    const nonce = wrapInPlace(cipher, outerKey, encrypted);
    const wire = Buffer.concat([nonce, encrypted]);
    const wireBytes = wire.length;

    // Unwrap respects immutability of `wire` (allocates a fresh
    // recovered buffer):
    // const recovered = unwrap(cipher, outerKey, wire);
    const wireBuf = Buffer.from(wire);
    const recovered = unwrapInPlace(cipher, outerKey, wireBuf);
    const pt = Buffer.from(enc.decryptAuth(recovered));
    return { recovered: pt, wireBytes };
  } finally {
    enc.free();
  }
}

// ────────────────────────────────────────────────────────────────────
// Single Message — Low-Level: Areion-SoEM-512 (No MAC)
// ────────────────────────────────────────────────────────────────────

function runMessageLowLevelNomac(
  cipher: CipherName,
  plaintext: Buffer,
): { recovered: Buffer; wireBytes: number } {
  applyLowLevelConfig();
  const seeds = buildThreeSeeds(2048);
  const [s0, s1, s2] = seeds;
  try {
    const outerKey = wrapperGenerateKey(cipher);

    const encrypted = Buffer.from(itbEncrypt(s0, s1, s2, plaintext));
    // wrap respects immutability of `encrypted` (allocates a fresh
    // wire buffer):
    // const wire = wrap(cipher, outerKey, encrypted);
    const nonce = wrapInPlace(cipher, outerKey, encrypted);
    const wire = Buffer.concat([nonce, encrypted]);
    const wireBytes = wire.length;

    // Unwrap respects immutability of `wire` (allocates a fresh
    // recovered buffer):
    // const recovered = unwrap(cipher, outerKey, wire);
    const wireBuf = Buffer.from(wire);
    const recovered = unwrapInPlace(cipher, outerKey, wireBuf);
    const pt = Buffer.from(itbDecrypt(s0, s1, s2, recovered));
    return { recovered: pt, wireBytes };
  } finally {
    disposeSeeds(seeds);
  }
}

// ────────────────────────────────────────────────────────────────────
// Single Message — Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC
// Authenticated)
// ────────────────────────────────────────────────────────────────────

function runMessageLowLevelAuth(
  cipher: CipherName,
  plaintext: Buffer,
): { recovered: Buffer; wireBytes: number } {
  applyLowLevelConfig();
  const seeds = buildThreeSeeds(2048);
  const [s0, s1, s2] = seeds;
  try {
    const macKey = randomBytes(32);
    using mac = new MAC('hmac-blake3', macKey);
    const outerKey = wrapperGenerateKey(cipher);

    const encrypted = Buffer.from(encryptAuth(s0, s1, s2, mac, plaintext));
    // wrap respects immutability of `encrypted` (allocates a fresh
    // wire buffer):
    // const wire = wrap(cipher, outerKey, encrypted);
    const nonce = wrapInPlace(cipher, outerKey, encrypted);
    const wire = Buffer.concat([nonce, encrypted]);
    const wireBytes = wire.length;

    // Unwrap respects immutability of `wire` (allocates a fresh
    // recovered buffer):
    // const recovered = unwrap(cipher, outerKey, wire);
    const wireBuf = Buffer.from(wire);
    const recovered = unwrapInPlace(cipher, outerKey, wireBuf);
    const pt = Buffer.from(decryptAuth(s0, s1, s2, mac, recovered));
    return { recovered: pt, wireBytes };
  } finally {
    disposeSeeds(seeds);
  }
}

// ────────────────────────────────────────────────────────────────────
// Matrix runner
// ────────────────────────────────────────────────────────────────────

interface Example {
  readonly name: string;
  readonly description: string;
  readonly plaintextN: number;
  readonly run: (
    cipher: CipherName,
    pt: Buffer,
  ) =>
    | Promise<{ recovered: Buffer; wireBytes: number }>
    | { recovered: Buffer; wireBytes: number };
}

const EXAMPLES: Example[] = [
  {
    name: 'aead-easy-io',
    description: 'Streaming AEAD Easy (MAC Authenticated, IO-Driven)',
    plaintextN: STREAM_BYTES,
    run: runAeadEasyIo,
  },
  {
    name: 'aead-lowlevel-io',
    description: 'Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)',
    plaintextN: STREAM_BYTES,
    run: runAeadLowLevelIo,
  },
  {
    name: 'noaead-easy-userloop',
    description: 'Streaming Easy (No MAC, User-Driven Loop)',
    plaintextN: STREAM_BYTES,
    run: runNoaeadEasyUserloop,
  },
  {
    name: 'noaead-lowlevel-userloop',
    description: 'Streaming Low-Level (No MAC, User-Driven Loop)',
    plaintextN: STREAM_BYTES,
    run: runNoaeadLowLevelUserloop,
  },
  {
    name: 'message-easy-nomac',
    description: 'Easy: Areion-SoEM-512 (No MAC, Single Message)',
    plaintextN: SINGLE_MESSAGE_BYTES,
    run: runMessageEasyNomac,
  },
  {
    name: 'message-easy-auth',
    description:
      'Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)',
    plaintextN: SINGLE_MESSAGE_BYTES,
    run: runMessageEasyAuth,
  },
  {
    name: 'message-lowlevel-nomac',
    description: 'Low-Level: Areion-SoEM-512 (No MAC, Single Message)',
    plaintextN: SINGLE_MESSAGE_BYTES,
    run: runMessageLowLevelNomac,
  },
  {
    name: 'message-lowlevel-auth',
    description:
      'Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)',
    plaintextN: SINGLE_MESSAGE_BYTES,
    run: runMessageLowLevelAuth,
  },
];

interface Result {
  readonly example: string;
  readonly cipher: CipherName;
  readonly ok: boolean;
  readonly err: string | null;
  readonly wireN: number;
  readonly ptN: number;
  readonly ptHash: string;
  readonly recHash: string;
}

function parseArgs(argv: string[]): {
  exampleFilter: string;
  cipherFilter: string;
  verbose: boolean;
  help: boolean;
} {
  let exampleFilter = '';
  let cipherFilter = '';
  let verbose = false;
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--example':
        exampleFilter = argv[++i] ?? '';
        break;
      case '--cipher':
        cipherFilter = argv[++i] ?? '';
        break;
      case '-v':
      case '--verbose':
        verbose = true;
        break;
      case '-h':
      case '--help':
        help = true;
        break;
      default:
        if (a !== undefined && a.length > 0) {
          throw new Error(`unknown argument: ${a}`);
        }
        break;
    }
  }
  return { exampleFilter, cipherFilter, verbose, help };
}

function printHelp(): void {
  console.log(
    [
      'eitb — runs every wrapper × ITB example end-to-end.',
      '',
      'Usage:',
      '  node dist-eitb/eitb/eitb.js [--example <substr>] [--cipher <aes|chacha|siphash>] [-v]',
      '',
      'Without flags runs the full 8 × 3 = 24 example × cipher matrix.',
    ].join('\n'),
  );
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const { exampleFilter, cipherFilter, verbose, help } = parseArgs(argv);
  if (help) {
    printHelp();
    return 0;
  }

  setMaxWorkers(0);

  const results: Result[] = [];
  let pass = 0;
  let fail = 0;

  for (const ex of EXAMPLES) {
    if (exampleFilter !== '' && !ex.name.includes(exampleFilter)) continue;
    for (const cn of CIPHER_NAMES) {
      if (cipherFilter !== '' && cn !== cipherFilter) continue;
      const plaintext = randomBytes(ex.plaintextN);
      const ptHash = sha256Hex(plaintext);
      let recovered: Buffer = Buffer.alloc(0);
      let wireN = 0;
      let ok = false;
      let errStr: string | null = null;
      try {
        const out = await ex.run(cn, plaintext);
        recovered = out.recovered;
        wireN = out.wireBytes;
        ok = recovered.length === plaintext.length && plaintext.equals(recovered);
        if (!ok) {
          errStr = `plaintext hash mismatch: pt=${sha256Short(plaintext)} rcv=${sha256Short(recovered)}`;
        }
      } catch (e) {
        errStr = (e as Error).message;
      }
      const recHash = sha256Hex(recovered);
      const r: Result = {
        example: ex.name,
        cipher: cn,
        ok,
        err: errStr,
        wireN,
        ptN: ex.plaintextN,
        ptHash,
        recHash,
      };
      results.push(r);
      if (ok) pass++;
      else fail++;
      const tag = ok ? 'PASS' : 'FAIL';
      const exName = padRight(ex.name, 26);
      const cnPad = padRight(cn, 8);
      let line = `[${tag}] ${exName} + ${cnPad}   pt=${r.ptN} wire=${r.wireN}`;
      if (!ok && errStr !== null) {
        line += `  err: ${errStr}`;
      }
      console.log(line);
      if (verbose && ok) {
        console.log(`       pt sha256:  ${ptHash}`);
        console.log(`       rcv sha256: ${recHash}`);
      }
    }
  }

  console.log('');
  console.log(`=== Summary: ${pass} PASS, ${fail} FAIL ===`);
  return fail > 0 ? 1 : 0;
}

function padRight(s: string, w: number): string {
  if (s.length >= w) return s;
  return s + ' '.repeat(w - s.length);
}

main()
  .then((rc) => process.exit(rc))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
