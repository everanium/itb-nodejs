// Plaintext content: the payload modes, the seeded per-worker
// generator, and the buffer fill from the operating-system CSPRNG.

import { randomFillSync } from 'node:crypto';

/*
 * Payload mode selectors for the --payload-mode flag.
 *
 *   - fixed: one CSPRNG-generated buffer per worker, held unchanged
 *     for the whole run (the default).
 *   - rotating: the buffer is regenerated before every iteration, so
 *     no two encrypt calls see the same plaintext.
 *   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
 *     all 0xFF) probing minimum-entropy plaintext handling.
 *   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
 *     structured text.
 */
export const PAYLOAD_FIXED = 0;
export const PAYLOAD_ROTATING = 1;
export const PAYLOAD_PATTERN_ZERO = 2;
export const PAYLOAD_PATTERN_FF = 3;
export const PAYLOAD_PATTERN_ASCII = 4;

export const PAYLOAD_NAMES: readonly string[] = [
  'fixed',
  'rotating',
  'pattern-zero',
  'pattern-ff',
  'pattern-ascii',
];

export function payloadModeName(mode: number): string {
  return PAYLOAD_NAMES[mode]!;
}

export function parsePayloadMode(s: string): number | null {
  const i = PAYLOAD_NAMES.indexOf(s);
  return i < 0 ? null : i;
}

const MASK64 = (1n << 64n) - 1n;

/**
 * Seeded plaintext. The seed makes plaintext content reproducible so a
 * failing iteration can be replayed with the same bytes; it governs
 * nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
 * so a seeded run is a reproduction aid and never a security test.
 * Each worker's stream is domain-separated by its id so seeded workers
 * still hold pairwise-distinct buffers under the fixed and rotating
 * modes. The generator is splitmix64: a few lines in any language,
 * which is why it is the one every binding uses.
 */
export function seedWorker(seed: bigint, workerId: number): bigint {
  return (seed + BigInt(workerId) + 1n) & MASK64;
}

/**
 * One splitmix64 draw; returns the advanced state and the output.
 *
 * TypeScript-specific. A double carries 53 bits exactly, so the whole
 * generator runs in BigInt and every step that would wrap in a 64-bit
 * register is masked explicitly; without the masks the generator still
 * produces bytes and still reproduces itself, but it is not
 * splitmix64.
 */
function splitmix64(state: bigint): [bigint, bigint] {
  const s = (state + 0x9e3779b97f4a7c15n) & MASK64;
  let z = s;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
  return [s, z ^ (z >> 31n)];
}

/** Draws n bytes from the operating-system CSPRNG. */
export function fillRandom(buf: Buffer): void {
  // randomFillSync draws at most 65536 bytes per call, so a
  // payload-sized buffer is filled in windows of that size.
  const step = 65536;
  for (let off = 0; off < buf.length; off += step) {
    randomFillSync(buf, off, Math.min(step, buf.length - off));
  }
}

/**
 * Fills buf according to the payload mode and returns the advanced
 * generator state. The fixed and rotating modes draw from the seeded
 * generator when the run is seeded and from the OS CSPRNG otherwise;
 * the pattern modes are deterministic regardless of the seed.
 */
export function fillPayload(
  buf: Buffer,
  mode: number,
  seeded: boolean,
  rng: bigint,
): bigint {
  if (mode === PAYLOAD_FIXED || mode === PAYLOAD_ROTATING) {
    if (!seeded) {
      fillRandom(buf);
      return rng;
    }
    let state = rng;
    const word = Buffer.allocUnsafe(8);
    for (let i = 0; i < buf.length; i += 8) {
      let value: bigint;
      [state, value] = splitmix64(state);
      word.writeBigUInt64LE(value, 0);
      word.copy(buf, i, 0, Math.min(8, buf.length - i));
    }
    return state;
  }
  if (mode === PAYLOAD_PATTERN_ZERO) {
    buf.fill(0x00);
    return rng;
  }
  if (mode === PAYLOAD_PATTERN_FF) {
    buf.fill(0xff);
    return rng;
  }
  const ramp = Buffer.allocUnsafe(26);
  for (let i = 0; i < 26; i++) {
    ramp[i] = 0x41 + i;
  }
  for (let off = 0; off < buf.length; off += 26) {
    ramp.copy(buf, off, 0, Math.min(26, buf.length - off));
  }
  return rng;
}
