// Long-run stress harness. The loop utility holds one Pipeline handle
// per exercised cipher surface for minutes, hammers it with concurrent
// encrypt -> decrypt -> compare round-trips from N worker threads,
// rotates the outer masters and reopens the handle from its session
// blob on a schedule, and reports whether the process survived with
// every byte intact. It is the Node.js binding's counterpart of the Go
// harness under tools/loop: the same flags, the same round structure,
// the same summary in both renderings.
//
// The default shape is full production: the Streaming AEAD profile with
// parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
// 1024-bit keys, and the compile-in 512-bit nonce width, driven through
// a stream session by three workers for five minutes on 16 MiB
// plaintexts. Every worker owns a distinct CSPRNG-generated plaintext
// held for the whole run, so any cross-call state leakage inside the
// Pipeline surfaces as a data mismatch between workers rather than
// cancelling out.
//
// A failure is one of two things. A cipher, rekey or load call that
// returns a non-OK status is a worker error: the run stops, the summary
// lists it, the verdict is FAIL and the exit code 1. A round-trip that
// returns without error but with different bytes is a data mismatch:
// the process terminates on the spot with exit code 3, printing the
// worker, the iteration and the first differing offset, and no summary
// — the state that produced the wrong bytes is the evidence. A crash
// inside the shared library or the host runtime has no exit code of its
// own here; surfacing it is what the utility is for.
//
// Usage:
//
//   node dist-loop/loop/main.js --duration 5m --goroutines 3 \
//       --shape stream --hash areion512 --mac hmac-blake3 \
//       --payload-size 16MB --memlimit auto --parallax on --wrapper on
//
// Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
// then the partial summary prints.

import { Worker } from 'node:worker_threads';
import {
  Opts,
  Pipeline,
  hashNames,
  inspect,
  lookup,
  setGCPercent,
  setGOMAXPROCS,
  setMemoryLimit,
  writeHeapProfile,
  type Profile,
} from '../src/index.js';
import {
  PAYLOAD_NAMES,
  parsePayloadMode,
  payloadModeName,
} from './payload.js';
import {
  humanBytes,
  humanDuration,
  nowNs,
  parseDuration,
  parseSize,
  roundNs,
  u64Dec,
} from './size.js';
import {
  CONCURRENCY,
  MAX_WORKERS,
  SHAPE_BOTH,
  SHAPE_MESSAGE,
  SHAPE_STREAM,
  SHAPE_STREAM_ONE_SHOT,
  Shared,
  errLine,
  errRaw,
  errorSentence,
  hardExit,
  logLine,
  newConfig,
  onOff,
  parseShape,
  policyLabel,
  restoreSigpipe,
  shapeName,
  statusDetail,
  type Config,
  type WorkerMsg,
  type WorkerReport,
} from './state.js';
import { finalSummary, poolSnapshot, readRss } from './summary.js';

/** Profiles the shape-based pair is built against when --profile is empty. */
const DEFAULT_STREAM_PROFILE = 'streaming-aead-triple-mac-v1';
const DEFAULT_MESSAGE_PROFILE = 'singlemsg-triple-mac-v1';

/**
 * The primitive supplied for the parallax palette and the outer cipher
 * when a profile leaves them unnamed. AES-CMAC is PRF-grade, so it is
 * sound outside the Interlocked Barrier, and it is the closest relative
 * of the AES-based inner primitive whose profiles need this fill.
 */
const KEYSTREAM_FILL_CIPHER = 'aescmac';

// ─── Flags ─────────────────────────────────────────────────────────

const enum Kind {
  Int,
  Int64,
  Uint64,
  Str,
  Bool,
}

type FlagRow = readonly [string, string, Kind, number | bigint | string | boolean, string];

/**
 * One command-line flag: its name, the type label the usage prints, its
 * kind, its default, and its help text. Values are validated after the
 * whole line is parsed. The table is in alphabetical order, which is
 * the order the usage prints.
 */
const FLAGS: readonly FlagRow[] = [
  ['barrier-fill', 'int', Kind.Int, 0,
    'DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)'],
  ['blob-cycle-every', 'int', Kind.Int64, 0,
    'reopen each pipeline from its session blob every N iterations per worker; 0 = never'],
  ['blob-mode', 'int', Kind.Int, 1,
    'container floor sizing mode: 1 (per-region, default) | 2 (per-container)'],
  ['chunk-size', 'string', Kind.Str, '0',
    'streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape'],
  ['drbg', 'string', Kind.Str, '',
    'DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)'],
  ['duration', 'duration', Kind.Str, '5m',
    'run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0'],
  ['gogc', 'int', Kind.Int, 0,
    'GC trigger percentage; 0 = leave the runtime default'],
  ['gomaxprocs', 'int', Kind.Int, 0,
    'Go runtime GOMAXPROCS override; 0 = inherit from the environment'],
  ['goroutines', 'int', Kind.Int, 3,
    'concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1'],
  ['hash', 'string', Kind.Str, 'areion512',
    'inner ITB hash primitive name'],
  ['iterations', 'int', Kind.Int64, 0,
    'fixed per-worker iteration count; 0 = duration-based'],
  ['json-output', '', Kind.Bool, false,
    'print the final summary as one compact JSON object instead of log lines'],
  ['key-bits', 'int', Kind.Int, 0,
    'per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)'],
  ['mac', 'string', Kind.Str, 'hmac-blake3',
    'MAC primitive name'],
  ['memlimit', 'string', Kind.Str, 'auto',
    'Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the ' +
    'runtime has no limit) or a size (e.g. 512MB)'],
  ['memprofile', 'string', Kind.Str, '',
    'write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none'],
  ['nonce-bits', 'int', Kind.Int, 0,
    'on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)'],
  ['parallax', 'string', Kind.Str, 'on',
    'parallax layer: on | off'],
  ['payload-mode', 'string', Kind.Str, 'fixed',
    'plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii'],
  ['payload-size', 'string', Kind.Str, '16MB',
    'per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)'],
  ['profile', 'string', Kind.Str, '',
    'exercise this single registered triple profile (overrides --shape with the profile\'s ' +
    'surface); empty = shape-based profile pair'],
  ['rekey-every', 'int', Kind.Int64, 0,
    'rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never'],
  ['seed', 'uint', Kind.Uint64, 0n,
    'deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline ' +
    'keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts'],
  ['shape', 'string', Kind.Str, 'stream',
    'cipher surface to exercise: stream | message | stream_one_shot | both'],
  ['wrapper', 'string', Kind.Str, 'on',
    'wrapper layer: on | off'],
];

const INT32_MAX = 2147483647;
const UINT64_MAX = (1n << 64n) - 1n;

function usage(): void {
  let out = 'Usage of loop:\n';
  for (const [name, label, kind, def, help] of FLAGS) {
    out += `  -${name}${label === '' ? '' : ' ' + label}\n`;
    let line = `    \t${help}`;
    // The default-value suffix follows the shape a Go flag set prints:
    // an integer default only when it is non-zero, a string default
    // only when it is non-empty.
    if (kind === Kind.Int && def !== 0) {
      line += ` (default ${def})`;
    } else if (kind === Kind.Str && def !== '') {
      line += ` (default "${def}")`;
    }
    out += line + '\n';
  }
  errRaw(out);
}

type RawValue = number | bigint | string | boolean;

/** Parses one value into its flag slot; null on a malformed value. */
function assignValue(kind: Kind, value: string): RawValue | null {
  if (kind === Kind.Int || kind === Kind.Int64) {
    const sign = value.slice(0, 1);
    const body = sign === '+' || sign === '-' ? value.slice(1) : value;
    if (!/^[0-9]+$/.test(body)) {
      return null;
    }
    // The sign is applied after the digits are converted: the BigInt
    // constructor accepts a leading minus but rejects a leading plus,
    // which the reference's integer parser takes.
    const n = sign === '-' ? -BigInt(body) : BigInt(body);
    if (kind === Kind.Int && (n > BigInt(INT32_MAX) || n < BigInt(-INT32_MAX))) {
      return null;
    }
    if (n > BigInt(Number.MAX_SAFE_INTEGER) || n < BigInt(-Number.MAX_SAFE_INTEGER)) {
      return null;
    }
    return Number(n);
  }
  if (kind === Kind.Uint64) {
    const body = value.slice(0, 1) === '+' ? value.slice(1) : value;
    if (!/^[0-9]+$/.test(body)) {
      return null;
    }
    const n = BigInt(body);
    return n <= UINT64_MAX ? n : null;
  }
  if (kind === Kind.Str) {
    return value;
  }
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }
  return null;
}

/**
 * Parses argv into the raw flag values. Accepts -name value,
 * --name value, -name=value and --name=value; a boolean flag takes no
 * value unless given as -name=true / -name=false. Returns [0, values],
 * [1, {}] for -h / --help (usage printed), or [-1, {}] after printing
 * the error.
 */
function parseArgv(argv: string[]): [number, Map<string, RawValue>] {
  const raw = new Map<string, RawValue>();
  const byName = new Map<string, Kind>();
  for (const [name, , kind, def] of FLAGS) {
    raw.set(name, def);
    byName.set(name, kind);
  }
  const empty = new Map<string, RawValue>();
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i]!;
    if (!arg.startsWith('-') || arg === '-') {
      errLine(`unexpected positional arguments: [${arg}]`);
      return [-1, empty];
    }
    let name = arg.startsWith('--') ? arg.slice(2) : arg.slice(1);
    if (name === 'h' || name === 'help') {
      usage();
      return [1, empty];
    }
    const eq = name.indexOf('=');
    let value: string | null = null;
    if (eq >= 0) {
      value = name.slice(eq + 1);
      name = name.slice(0, eq);
    }
    const kind = byName.get(name);
    if (kind === undefined) {
      errLine(`flag provided but not defined: -${name}`);
      usage();
      return [-1, empty];
    }
    if (value === null) {
      if (kind === Kind.Bool) {
        value = 'true';
      } else if (i + 1 < argv.length) {
        i++;
        value = argv[i]!;
      } else {
        errLine(`flag needs an argument: -${name}`);
        return [-1, empty];
      }
    }
    const parsed = assignValue(kind, value);
    if (parsed === null) {
      errLine(`invalid value "${value}" for flag -${name}`);
      return [-1, empty];
    }
    raw.set(name, parsed);
    i++;
  }
  return [0, raw];
}

function parseOnOff(v: string): boolean | null {
  if (v === 'on') {
    return true;
  }
  if (v === 'off') {
    return false;
  }
  return null;
}

/** Whether name is in the shipped hash registry the binding enumerates. */
function hashRegistered(name: string): boolean {
  try {
    return hashNames().includes(name);
  } catch {
    return false;
  }
}

/**
 * Resolves a registered profile to the shape family its record's mode
 * exposes by reading the record through the binding's lookup: a mode
 * beginning with "streaming" exposes the stream surfaces, one beginning
 * with "singlemsg" the message surface, "blob-only" none. Prints the
 * validation message and returns null on rejection.
 */
function profileSurface(name: string): number | null {
  let record: Profile;
  try {
    record = lookup(name);
  } catch {
    errLine(`--profile "${name}" is not a registered triple profile`);
    return null;
  }
  const mode = record.mode ?? '';
  if (mode.startsWith('streaming')) {
    return SHAPE_STREAM;
  }
  if (mode.startsWith('singlemsg')) {
    return SHAPE_MESSAGE;
  }
  errLine(`--profile "${name}" carries no cipher surface (blob-only mode)`);
  return null;
}

/**
 * Applies a --profile's surface to the requested shape: a
 * message-surface profile forces message; a stream-surface profile
 * keeps stream or stream_one_shot as requested and turns message or
 * both into stream.
 */
function narrowShape(requested: number, surface: number): number {
  if (surface === SHAPE_MESSAGE) {
    return SHAPE_MESSAGE;
  }
  return requested === SHAPE_STREAM_ONE_SHOT ? SHAPE_STREAM_ONE_SHOT : SHAPE_STREAM;
}

/**
 * Builds the resolved config from argv. Returns [0, cfg], [1, cfg] for
 * help, or [-1, cfg] after printing "loop: <message>" for the first
 * failing rule.
 */
function parseFlags(argv: string[]): [number, Config] {
  const cfg = newConfig();
  const [rc, raw] = parseArgv(argv);
  if (rc !== 0) {
    return [rc, cfg];
  }
  const str = (k: string): string => String(raw.get(k));
  const num = (k: string): number => Number(raw.get(k));

  const durationNs = parseDuration(str('duration'));
  if (durationNs === null || durationNs <= 0) {
    errLine(`--duration must be positive, got ${str('duration')}`);
    return [-1, cfg];
  }
  cfg.durationNs = durationNs;
  cfg.iterations = num('iterations');
  if (cfg.iterations < 0) {
    errLine(`--iterations must be >= 0, got ${cfg.iterations}`);
    return [-1, cfg];
  }
  const goroutines = num('goroutines');
  if (goroutines < 1 || goroutines > MAX_WORKERS) {
    errLine(`--goroutines must be in 1..${MAX_WORKERS}, got ${goroutines}`);
    return [-1, cfg];
  }
  // Concurrency mode. This binding runs independent-handles: a worker
  // thread holds its own isolate and its own instance of the FFI addon,
  // and the binding's public surface offers no entry that adopts an
  // existing native handle, so every worker opens its own from the Init
  // blob. --goroutines is the thread count verbatim, never clamped.
  cfg.workersRequested = goroutines;
  cfg.workers = goroutines;
  const shape = parseShape(str('shape'));
  if (shape === null) {
    errLine(
      `--shape must be stream | message | stream_one_shot | both, got "${str('shape')}"`,
    );
    return [-1, cfg];
  }
  cfg.shape = shape;
  if (!hashRegistered(str('hash'))) {
    errLine(`--hash "${str('hash')}" is not a registered hash primitive`);
    return [-1, cfg];
  }
  cfg.hash = str('hash');
  // Validated by Init: the C ABI enumerates no MAC names.
  cfg.mac = str('mac');
  const payload = parseSize(str('payload-size'));
  if (payload === null) {
    errLine(`--payload-size: invalid size "${str('payload-size')}"`);
    return [-1, cfg];
  }
  cfg.payload = payload;
  if (cfg.payload < 1) {
    errLine('--payload-size must be at least 1 byte');
    return [-1, cfg];
  }
  if (str('memlimit') === 'auto') {
    cfg.memlimitAuto = true;
    cfg.memlimit = cfg.workers <= 3 ? 1073741824 : 268435456;
  } else {
    const memlimit = parseSize(str('memlimit'));
    if (memlimit === null) {
      errLine(`--memlimit: invalid size "${str('memlimit')}"`);
      return [-1, cfg];
    }
    cfg.memlimit = memlimit;
  }
  cfg.gogc = num('gogc');
  if (cfg.gogc < 0) {
    errLine(`--gogc must be >= 0, got ${cfg.gogc}`);
    return [-1, cfg];
  }
  const parallax = parseOnOff(str('parallax'));
  if (parallax === null) {
    errLine(`--parallax must be on | off, got "${str('parallax')}"`);
    return [-1, cfg];
  }
  cfg.parallax = parallax;
  const wrapper = parseOnOff(str('wrapper'));
  if (wrapper === null) {
    errLine(`--wrapper must be on | off, got "${str('wrapper')}"`);
    return [-1, cfg];
  }
  cfg.wrapper = wrapper;
  cfg.profile = str('profile');
  if (cfg.profile !== '') {
    const surface = profileSurface(cfg.profile);
    if (surface === null) {
      return [-1, cfg];
    }
    cfg.shape = narrowShape(cfg.shape, surface);
  }
  cfg.keyBits = num('key-bits');
  if (![0, 512, 1024, 2048].includes(cfg.keyBits)) {
    errLine(
      `--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got ${cfg.keyBits}`,
    );
    return [-1, cfg];
  }
  cfg.nonceBits = num('nonce-bits');
  if (![0, 128, 256, 512].includes(cfg.nonceBits)) {
    errLine(
      `--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got ${cfg.nonceBits}`,
    );
    return [-1, cfg];
  }
  cfg.blobMode = num('blob-mode');
  if (![1, 2].includes(cfg.blobMode)) {
    errLine(`--blob-mode must be 1 (per-region) | 2 (per-container), got ${cfg.blobMode}`);
    return [-1, cfg];
  }
  cfg.barrierFill = num('barrier-fill');
  if (![0, 1, 2, 4, 8, 16, 32].includes(cfg.barrierFill)) {
    errLine(
      '--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got ' +
        `${cfg.barrierFill}`,
    );
    return [-1, cfg];
  }
  // Validated by Init: the C ABI enumerates no DRBG names.
  cfg.drbg = str('drbg');
  const chunkSize = parseSize(str('chunk-size'));
  if (chunkSize === null) {
    errLine(`--chunk-size: invalid size "${str('chunk-size')}"`);
    return [-1, cfg];
  }
  cfg.chunkSize = chunkSize;
  cfg.gomaxprocs = num('gomaxprocs');
  if (cfg.gomaxprocs < 0) {
    errLine(`--gomaxprocs must be > 0 when specified, got ${cfg.gomaxprocs}`);
    return [-1, cfg];
  }
  cfg.rekeyEvery = num('rekey-every');
  if (cfg.rekeyEvery < 0) {
    errLine(`--rekey-every must be >= 0, got ${cfg.rekeyEvery}`);
    return [-1, cfg];
  }
  cfg.blobCycleEvery = num('blob-cycle-every');
  if (cfg.blobCycleEvery < 0) {
    errLine(`--blob-cycle-every must be >= 0, got ${cfg.blobCycleEvery}`);
    return [-1, cfg];
  }
  const payloadMode = parsePayloadMode(str('payload-mode'));
  if (payloadMode === null) {
    errLine(
      `--payload-mode must be ${PAYLOAD_NAMES.join(' | ')}, got "${str('payload-mode')}"`,
    );
    return [-1, cfg];
  }
  cfg.payloadMode = payloadMode;
  cfg.seed = raw.get('seed') as bigint;
  cfg.jsonOutput = raw.get('json-output') === true;
  cfg.memprofile = str('memprofile');
  return [0, cfg];
}

// ─── Pipelines ─────────────────────────────────────────────────────

/**
 * String value of key in a profile record, or "-" when absent or
 * empty.
 */
function recordStr(value: string | undefined): string {
  return value === undefined || value === '' ? '-' : value;
}

/**
 * Prints the construction line with the recipe read back from the blob
 * the Pipeline handed out, not echoed from the flags: every
 * construction override is proven to have reached the library by the
 * value the receiver would see. Record values that are empty (a No MAC
 * profile's MAC, a mixed profile's single hash) print as "-".
 */
function logPipelineInitialised(profile: string, blob: Uint8Array): void {
  let record: Profile;
  try {
    record = inspect(blob);
  } catch (e) {
    logLine(
      `pipeline initialised: profile=${profile} blob=${blob.length} bytes ` +
        `(inspect: ${errorSentence(e)})`,
    );
    return;
  }
  logLine(
    `pipeline initialised: profile=${profile} blob=${blob.length} bytes ` +
      `hash=${recordStr(record.hash)} ` +
      `key-bits=${record.keybits ?? 0} ` +
      `nonce-bits=${record.nonce_bits ?? 0} ` +
      `barrier-fill=${record.barrier_fill ?? 0} ` +
      `chunk-size=${record.chunk ?? 0} ` +
      `mac=${recordStr(record.mac)} ` +
      `parallax=${onOff(record.parallax === true)} ` +
      `wrapper=${onOff(record.wrapper === true)}` +
      (record.container_mode === 2 ? ` container-mode=${record.container_mode}` : '') +
      (record.drbg !== undefined && record.drbg !== '' ? ` drbg=${record.drbg}` : ''),
  );
}

/**
 * Sets the inner blob's "mode" field of a wrap-layer session blob to
 * targetMode (1 = per-region, 2 = per-container) and returns the
 * re-encoded blob. The wrap layer's profile record carries its own
 * "mode" (a string), so only the inner blob ("ib") is touched; every
 * other value survives the round trip unchanged (integers stay
 * integers, strings stay byte-identical) and no key is added.
 */
function editInnerBlobMode(blob: Uint8Array, targetMode: number): Uint8Array {
  const wrap: unknown = JSON.parse(new TextDecoder().decode(blob));
  if (typeof wrap !== 'object' || wrap === null || Array.isArray(wrap)) {
    throw new Error('wrap blob is not a JSON object');
  }
  const inner = (wrap as Record<string, unknown>)['ib'];
  if (typeof inner !== 'object' || inner === null || Array.isArray(inner)) {
    throw new Error('inner blob not found');
  }
  if (!('mode' in inner)) {
    throw new Error('inner blob mode field not found');
  }
  (inner as Record<string, unknown>)['mode'] = targetMode;
  return new TextEncoder().encode(JSON.stringify(wrap));
}

/**
 * Folds a keystream primitive into opts for any layer the named profile
 * leaves unfilled but the operator asked for.
 *
 * A profile built around a primitive that is safe only inside the
 * Interlocked Barrier ships with no parallax palette and no outer
 * cipher: both layers run outside the barrier, where that primitive
 * would stand bare, so the recipe leaves them unnamed rather than
 * naming a primitive that must not key them. Engaging either layer
 * therefore needs a keystream-capable primitive supplied from outside
 * the recipe; without it construction fails on a palette below its
 * minimum or an unnamed outer cipher, and the primitive that most
 * deserves stressing becomes the one that cannot be stressed with those
 * layers engaged.
 *
 * Overrides fold into the resolved record the blob carries, so the
 * receiver rebuilds the same shape from the blob alone.
 *
 * Returns 1 when a layer was filled, 0 when none needed it, -1 on a
 * lookup failure (message already printed).
 */
function fillKeystreamLayers(
  name: string,
  opts: Opts,
  wantParallax: boolean,
  wantWrapper: boolean,
): number {
  let record: Profile;
  try {
    record = lookup(name);
  } catch {
    errLine(`--profile "${name}" is not a registered triple profile`);
    return -1;
  }
  let filled = 0;
  if (wantParallax && record.palette === undefined) {
    opts.withParallaxPalette([
      KEYSTREAM_FILL_CIPHER,
      KEYSTREAM_FILL_CIPHER,
      KEYSTREAM_FILL_CIPHER,
    ]);
    if (record.segment === undefined) {
      // A recipe that never carried a palette never carried a segment
      // size either, and the schedule rejects zero.
      opts.withParallaxSegmentSize(4093);
    }
    filled = 1;
  }
  if (wantWrapper && record.outer === undefined) {
    opts.withOuterCipher(KEYSTREAM_FILL_CIPHER);
    filled = 1;
  }
  return filled;
}

/**
 * Constructs one Pipeline against profile with every flag-carried
 * override in the opts string (zero values included — the shared
 * library treats zero as "profile default"), then obtains the Init blob
 * once through save: the binding's init entry does not hand the blob
 * back, and the bytes are the ones Init produced. Later blob reopens
 * use the retained blob; save is never called again.
 */
function buildPipeline(
  cfg: Config,
  profile: string,
): { pipe: Pipeline; blob: Uint8Array } | null {
  const opts = new Opts()
    .withInnerHash(cfg.hash)
    .withMacName(cfg.mac)
    .withParallax(cfg.parallax)
    .withWrapper(cfg.wrapper)
    .withKeyBits(cfg.keyBits)
    .withNonceBits(cfg.nonceBits)
    .withBarrierFill(cfg.barrierFill)
    .withDrbg(cfg.drbg)
    .withChunkSize(cfg.chunkSize);
  if (cfg.profile !== '') {
    const filled = fillKeystreamLayers(cfg.profile, opts, cfg.parallax, cfg.wrapper);
    if (filled < 0) {
      return null;
    }
    if (filled > 0) {
      errLine(
        `${cfg.profile} leaves the requested keystream layers unnamed; ` +
          `${KEYSTREAM_FILL_CIPHER} supplied for them`,
      );
    }
  }
  let pipe: Pipeline;
  try {
    pipe = Pipeline.init(profile, opts);
  } catch (e) {
    errLine(`Init(${profile}): ${statusDetail(e)}`);
    return null;
  }
  let blob: Uint8Array;
  try {
    blob = pipe.save();
  } catch (e) {
    errLine(`Save(${profile}): ${statusDetail(e)}`);
    pipe.free();
    return null;
  }
  if (cfg.blobMode === 2) {
    // The sizing mode is not an Opts knob: the Init blob is edited and
    // the pipeline reopened from it, so the retained blob (the one
    // blob-cycle reopens from) carries the edited mode.
    try {
      blob = editInnerBlobMode(blob, 2);
    } catch (e) {
      errLine(`rewrite blob mode: ${errorSentence(e)}`);
      pipe.free();
      return null;
    }
    pipe.free();
    try {
      pipe = Pipeline.load(blob);
    } catch (e) {
      errLine(`reload Mode 2 blob: ${statusDetail(e)}`);
      return null;
    }
  }
  logPipelineInitialised(profile, blob);
  return { pipe, blob };
}

// ─── Run ───────────────────────────────────────────────────────────

interface Slot {
  worker: Worker;
  warmupSeen: boolean;
  report: WorkerReport | null;
  failure: string;
}

async function run(argv: string[]): Promise<number> {
  const [rc, cfg] = parseFlags(argv);
  if (rc === 1) {
    return 0;
  }
  if (rc !== 0) {
    return 2;
  }

  // Runtime shaping. A long run under allocation churn grows the Go
  // heap inside the shared library without bound unless a soft limit
  // paces the collector, so a limit is always in force: an explicit
  // --memlimit is set as given, and auto caps the heap only when the
  // runtime reports no limit at all (a limit already installed from the
  // environment is left standing). The GC percentage and GOMAXPROCS are
  // set only when their flag is non-zero — a zero flag skips the setter
  // rather than calling it with zero, because zero is a real value to
  // the GC-percent setter, and a call would clobber whatever the
  // environment installed. All of it lands before any Pipeline exists
  // so the baselines are taken under the shaped runtime, in the order
  // heap limit, GC percent, GOMAXPROCS.
  if (cfg.memlimitAuto) {
    if (setMemoryLimit(-1) === (1n << 63n) - 1n) {
      setMemoryLimit(cfg.memlimit);
    }
  } else {
    setMemoryLimit(cfg.memlimit);
  }
  cfg.memlimit = Number(setMemoryLimit(-1));
  if (cfg.gogc > 0) {
    setGCPercent(cfg.gogc);
  }
  if (cfg.gomaxprocs > 0) {
    setGOMAXPROCS(cfg.gomaxprocs);
  }

  logLine(
    `start: duration=${humanDuration(BigInt(cfg.durationNs))} ` +
      `iterations=${cfg.iterations} goroutines=${cfg.workersRequested} ` +
      `workers=${cfg.workers} concurrency=${CONCURRENCY} ` +
      `shape=${shapeName(cfg.shape)} hash=${cfg.hash} mac=${cfg.mac} ` +
      `payload=${humanBytes(cfg.payload)} memlimit=${humanBytes(cfg.memlimit)} ` +
      `parallax=${onOff(cfg.parallax)} wrapper=${onOff(cfg.wrapper)}`,
  );
  logLine(
    `overrides: profile="${cfg.profile}" key-bits=${cfg.keyBits} ` +
      `nonce-bits=${cfg.nonceBits} chunk-size=${humanBytes(cfg.chunkSize)} ` +
      `barrier-fill=${cfg.barrierFill} gomaxprocs=${cfg.gomaxprocs} ` +
      `rekey-every=${cfg.rekeyEvery} blob-cycle-every=${cfg.blobCycleEvery} ` +
      `payload-mode=${payloadModeName(cfg.payloadMode)} seed=${u64Dec(cfg.seed)} ` +
      `json-output=${cfg.jsonOutput ? 'true' : 'false'}` +
      (cfg.blobMode !== 1 ? ` blob-mode=${cfg.blobMode}` : '') +
      (cfg.drbg !== '' ? ` drbg=${cfg.drbg}` : ''),
  );
  logLine(
    'policy: microbatch-tiers=' +
      `${policyLabel(process.env['ITB_MICROBATCH_TIERS'])} ` +
      `hashpool-starters=${policyLabel(process.env['ITB_HASHPOOL_STARTERS'])}`,
  );

  // Pipeline construction — one Init per exercised shape, from which
  // every worker opens its own handle. stream and stream_one_shot share
  // the streaming recipe.
  const streamProfile = cfg.profile !== '' ? cfg.profile : DEFAULT_STREAM_PROFILE;
  const msgProfile = cfg.profile !== '' ? cfg.profile : DEFAULT_MESSAGE_PROFILE;
  let streamInit: { pipe: Pipeline; blob: Uint8Array } | null = null;
  let msgInit: { pipe: Pipeline; blob: Uint8Array } | null = null;
  if (
    cfg.shape === SHAPE_STREAM ||
    cfg.shape === SHAPE_STREAM_ONE_SHOT ||
    cfg.shape === SHAPE_BOTH
  ) {
    streamInit = buildPipeline(cfg, streamProfile);
    if (streamInit === null) {
      return 1;
    }
  }
  if (cfg.shape === SHAPE_MESSAGE || cfg.shape === SHAPE_BOTH) {
    msgInit = buildPipeline(cfg, msgProfile);
    if (msgInit === null) {
      return 1;
    }
  }

  const shared = Shared.create();
  let poolWarmup = poolSnapshot();
  let poolSteady = poolWarmup;
  if (poolWarmup.length === 0) {
    errLine('pool snapshot alloc failed');
    return 1;
  }

  // Graceful stop. SIGINT / SIGTERM set the run's stop request, which
  // every worker checks before starting an iteration, so a signal
  // interrupts nothing mid-call — the in-flight encrypt / decrypt /
  // compare completes, the worker returns, and the partial summary
  // prints with the verdict the completed iterations earned.
  process.on('SIGINT', () => shared.requestStop());
  process.on('SIGTERM', () => shared.requestStop());

  const slots: Slot[] = [];
  let warmupPending = cfg.workers;
  let donePending = cfg.workers;
  let onWarmupComplete: () => void = () => undefined;
  const warmupComplete = new Promise<void>((resolve) => {
    onWarmupComplete = resolve;
  });
  let onAllExited: () => void = () => undefined;
  const allExited = new Promise<void>((resolve) => {
    onAllExited = resolve;
  });

  const workerUrl = new URL('./worker.js', import.meta.url);
  const warmupStart = nowNs();
  for (let i = 0; i < cfg.workers; i++) {
    const slot: Slot = {
      worker: new Worker(workerUrl, {
        workerData: {
          id: i,
          cfg,
          cells: shared.cells,
          streamProfile,
          msgProfile,
          streamBlob: streamInit === null ? null : streamInit.blob,
          msgBlob: msgInit === null ? null : msgInit.blob,
        },
      }),
      warmupSeen: false,
      report: null,
      failure: '',
    };
    const arrive = (): void => {
      if (slot.warmupSeen) {
        return;
      }
      slot.warmupSeen = true;
      warmupPending--;
      if (warmupPending === 0) {
        onWarmupComplete();
      }
    };
    slot.worker.on('message', (m: WorkerMsg) => {
      if (m.t === 'warmup') {
        arrive();
      } else if (m.t === 'fatal') {
        // The mismatch path could not leave the process from inside the
        // worker thread; it is left from here, with nothing printed.
        hardExit(m.code);
        process.exit(m.code);
      } else {
        slot.report = m.report;
      }
    });
    slot.worker.on('error', (e: Error) => {
      slot.failure = `g${i}: worker thread: ${e.message}`;
      shared.requestStop();
    });
    slot.worker.on('exit', (code: number) => {
      if (slot.report === null && slot.failure === '') {
        slot.failure = `g${i}: worker thread exited with code ${code} before reporting`;
        shared.requestStop();
      }
      arrive();
      donePending--;
      if (donePending === 0) {
        onAllExited();
      }
    });
    slots.push(slot);
  }

  // Warmup barrier. Every worker runs one iteration and reports; the
  // clock starts only once all of them have paid their first-call costs
  // (pool warm-up, lazy kernel dispatch, page faults on the payload
  // buffers), and the RSS and pool baselines taken here describe a
  // process that has already run the whole cipher path once per worker.
  await warmupComplete;
  let [rssWarmup, rssPeak] = readRss();
  poolWarmup = poolSnapshot();
  const warmupNs = nowNs() - warmupStart;
  logLine(
    `warmup: ${cfg.workers} workers x 1 iter completed in ` +
      `${humanDuration(roundNs(warmupNs, 100000000n))} ` +
      `(baseline rss=${humanBytes(rssWarmup)})`,
  );

  // Open the gate; the deadline below asks the workers to stop in
  // duration mode.
  const startNs = nowNs();
  shared.release();
  let deadline: NodeJS.Timeout | null = null;
  if (cfg.iterations === 0) {
    deadline = setTimeout(() => shared.requestStop(), cfg.durationNs / 1e6);
  }
  await allExited;
  if (deadline !== null) {
    clearTimeout(deadline);
  }

  let finishNs = startNs;
  const reports: WorkerReport[] = [];
  for (let i = 0; i < slots.length; i++) {
    const slot = slots[i]!;
    const r = slot.report;
    if (r === null) {
      reports.push({
        id: i,
        iters: 0,
        bytesEnc: 0,
        bytesDec: 0,
        nanosEnc: 0n,
        nanosDec: 0n,
        finishNs: startNs,
        failed: true,
        error: slot.failure === '' ? `g${i}: worker thread produced no report` : slot.failure,
      });
      continue;
    }
    if (slot.failure !== '' && !r.failed) {
      reports.push({ ...r, failed: true, error: slot.failure });
    } else {
      reports.push(r);
    }
    if (r.finishNs > finishNs) {
      finishNs = r.finishNs;
    }
  }
  const elapsedNs = finishNs - startNs;

  const [rssFinal, peak] = readRss();
  if (peak > rssPeak) {
    rssPeak = peak;
  }
  poolSteady = poolSnapshot();

  if (cfg.memprofile !== '') {
    try {
      writeHeapProfile(cfg.memprofile);
      logLine(`memprofile: heap profile written to ${cfg.memprofile}`);
    } catch (e) {
      errLine(`memprofile: ${errorSentence(e)}`);
    }
  }

  const code = finalSummary({
    cfg,
    reports,
    rekeys: shared.rekeys(),
    blobCycles: shared.blobCycles(),
    streamProfile: streamInit === null ? '' : streamProfile,
    msgProfile: msgInit === null ? '' : msgProfile,
    rssWarmup,
    rssPeak,
    rssFinal,
    poolWarmup,
    poolSteady,
    gomaxprocs: setGOMAXPROCS(0),
    elapsedNs,
  });

  if (streamInit !== null) {
    streamInit.pipe.free();
  }
  if (msgInit !== null) {
    msgInit.pipe.free();
  }
  return code;
}

restoreSigpipe();
run(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e: unknown) => {
    errLine(String(e));
    process.exit(1);
  },
);
