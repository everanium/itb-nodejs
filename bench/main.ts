// Entry point for the Node.js Easy Mode bench harness.
//
// `argv[2]` selects the pass:
//   * `single` — runs the Single-Ouroboros 9-primitive + 1-mixed grid.
//   * `triple` — runs the Triple-Ouroboros 9-primitive + 1-mixed grid.
//
// Each pass walks the canonical 10-row matrix four ops per row (encrypt /
// decrypt / encrypt + MAC / decrypt + MAC). Pair the two passes with
// `ITB_LOCKSEED=1` for the LockSeed-mode arms — four passes total
// produce the BENCH.md table set.

/* eslint-disable no-console */

import { runSingle } from './bench-single.js';
import { runTriple } from './bench-triple.js';

async function main(): Promise<void> {
  const arg = process.argv[2];
  if (arg === 'single') {
    await runSingle();
  } else if (arg === 'triple') {
    await runTriple();
  } else {
    console.error(`Usage: node ${process.argv[1]} <single|triple>`);
    process.exit(2);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
