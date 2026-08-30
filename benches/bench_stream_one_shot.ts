// Stream one-shot throughput vs plaintext size. Times the
// whole-buffer path (a single FFI round trip through the Pipeline's
// stream chain).
//
// Env-var overrides identical to bench_message.ts, with the stream
// profile default:
//
//   | env var            | default                    |
//   |--------------------|----------------------------|
//   | ITB_PROFILE        | streaming-noaead-triple-v1 |
//   | ITB_INNER_HASH     | (profile default)          |
//   | ITB_NONCE_BITS     | 512                        |
//   | ITB_KEY_BITS       | 1024                       |
//   | ITB_WITH_PARALLAX  | false                      |
//   | ITB_WITH_WRAPPER   | false                      |
//   | ITB_BENCH_MIN_SEC  | 5                          |

import { randomFillSync } from 'node:crypto';
import { performance } from 'node:perf_hooks';

import { Opts, Pipeline, setGCPercent, setMemoryLimit } from '../src/index.js';

function buildOpts(): Opts {
  const env = process.env;
  const opts = new Opts()
    .withNonceBits(Number(env['ITB_NONCE_BITS'] ?? 512))
    .withKeyBits(Number(env['ITB_KEY_BITS'] ?? 1024))
    .withParallax(env['ITB_WITH_PARALLAX'] === 'true' || env['ITB_WITH_PARALLAX'] === '1')
    .withWrapper(env['ITB_WITH_WRAPPER'] === 'true' || env['ITB_WITH_WRAPPER'] === '1');
  const innerHash = env['ITB_INNER_HASH'];
  if (innerHash) {
    opts.withInnerHash(innerHash);
  }
  const macName = env['ITB_MAC_NAME'];
  if (macName) {
    opts.withMacName(macName);
  }
  return opts;
}

const MIN_SEC = Number(process.env['ITB_BENCH_MIN_SEC'] ?? 5);

/** Warm-up once, then loop until the wall-clock budget elapses. */
function measure(label: string, sizeBytes: number, iter: () => void): void {
  iter(); // warm-up, excluded from timing
  const budgetMs = MIN_SEC * 1000;
  const start = performance.now();
  let iters = 0;
  let elapsed = 0;
  do {
    iter();
    iters++;
    elapsed = performance.now() - start;
  } while (elapsed < budgetMs);
  const mbps = sizeBytes / (1 << 20) / (elapsed / 1000 / iters);
  console.log(
    `${label}  ${iters} iters  ${(elapsed / iters).toFixed(1)} ms/op  ${mbps.toFixed(1)} MB/s`,
  );
}

setMemoryLimit(512n * 1024n * 1024n);
setGCPercent(20);

const profile = process.env['ITB_PROFILE'] ?? 'streaming-noaead-triple-v1';
const pipe = Pipeline.init(profile, buildOpts());
console.log(`encrypt_stream_one_shot  profile=${profile}  min_sec=${MIN_SEC}`);
for (const size of [1 << 20, 16 << 20, 64 << 20]) {
  const plain = Buffer.alloc(size);
  // CSPRNG-fill so plaintext content matches the root Go bench
  // (crypto/rand). Not in the timing loop.
  randomFillSync(plain);
  measure(`  ${size >> 20} MiB`, size, () => {
    const wire = pipe.encryptStreamOneShot(plain);
    if (wire.length === 0) {
      throw new Error('empty wire');
    }
  });
  // Pre-encrypt one wire outside the decrypt timing loop.
  const decWire = pipe.encryptStreamOneShot(plain);
  measure(`  ${size >> 20} MiB dec`, size, () => {
    const out = pipe.decryptStreamOneShot(decWire);
    if (out.length === 0) {
      throw new Error('empty plain');
    }
  });
}
pipe.free();
