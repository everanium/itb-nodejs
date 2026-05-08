// Exception hierarchy for libitb FFI failures.
//
// Every fallible libitb call returns a non-zero status code on
// failure; the higher-level wrappers translate the code into one of
// the typed exceptions below via `check(status)` or
// `errorFromStatus(status)`.
//
// The hierarchy uses typed subclasses so selective `instanceof`
// matching can distinguish the structurally-distinct failure modes
// (`ITBError` base + `ITBEasyMismatchError` with `.field` +
// `ITBBlobModeMismatchError` + `ITBBlobMalformedError` +
// `ITBBlobVersionTooNewError`). The numeric `.code` on every
// exception preserves the "match by code" idiom alongside the
// type-based catch hierarchy.
//
// Threading caveat. The textual `.message` is read from a
// process-wide atomic inside libitb that follows the C `errno`
// discipline: the most recent non-OK Status across the whole
// process wins, and a sibling thread that calls into libitb between
// the failing call and the diagnostic read overwrites the message.
// The structural `.code` on the failing call is unaffected — only
// the textual message is racy.

import { ITB_Easy_LastMismatchField, ITB_LastError } from './native.js';
import { readString } from './read-string.js';
import { Status } from './status.js';

export class ITBError extends Error {
  readonly code: number;

  constructor(code: number, message?: string) {
    super(formatMessage(code, message));
    this.code = code;
    this.name = 'ITBError';
    // Restore prototype chain after `super()` (Error's constructor
    // resets the prototype to Error.prototype on some V8 paths).
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised by `Encryptor.importState` / `Encryptor.peekConfig` when
 * the supplied state blob disagrees with the live encryptor's
 * configuration on at least one field. `.field` carries the
 * offending JSON field name (e.g. `"primitive"`, `"key_bits"`,
 * `"mode"`, `"mac"`).
 *
 * Field-attribution race. The `.field` value is read from
 * `ITB_Easy_LastMismatchField` at exception construction time — a
 * process-wide atomic that follows the same C `errno` discipline as
 * `ITB_LastError`. Two concurrent failing imports across separate
 * worker threads can cross the field-name strings; callers that
 * need reliable field attribution under concurrent imports must
 * serialise the import calls externally.
 */
export class ITBEasyMismatchError extends ITBError {
  readonly field: string;

  constructor(code: number, message: string | undefined, field: string | null) {
    const normalisedField = field ?? '';
    super(code, formatWithField(message, normalisedField));
    this.field = normalisedField;
    this.name = 'ITBEasyMismatchError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Raised by `Blob.import` when a Single-mode blob is fed into a
 * Triple-mode handle (or vice-versa). */
export class ITBBlobModeMismatchError extends ITBError {
  constructor(code: number, message?: string) {
    super(code, message);
    this.name = 'ITBBlobModeMismatchError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Raised by `Blob.import` when the blob's framing / length /
 * magic-byte shape fails validation. */
export class ITBBlobMalformedError extends ITBError {
  constructor(code: number, message?: string) {
    super(code, message);
    this.name = 'ITBBlobMalformedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Raised by `Blob.import` when the blob's version field is newer
 * than the running binding can decode. */
export class ITBBlobVersionTooNewError extends ITBError {
  constructor(code: number, message?: string) {
    super(code, message);
    this.name = 'ITBBlobVersionTooNewError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised by the authenticated streaming decrypt path when the input
 * transcript exhausts without a chunk whose recovered `final_flag`
 * is `1`. Carries `Status.StreamTruncated` (numeric value `23`).
 */
export class ITBStreamTruncatedError extends ITBError {
  constructor(code: number, message?: string) {
    super(code, message);
    this.name = 'ITBStreamTruncatedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised by the authenticated streaming decrypt path when extra
 * chunk bytes follow the terminating chunk on the wire transcript.
 * Carries `Status.StreamAfterFinal` (numeric value `24`).
 */
export class ITBStreamAfterFinalError extends ITBError {
  constructor(code: number, message?: string) {
    super(code, message);
    this.name = 'ITBStreamAfterFinalError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

function formatMessage(code: number, message: string | undefined): string {
  if (!message || message.length === 0) {
    return `itb: status=${code}`;
  }
  return `itb: status=${code} (${message})`;
}

function formatWithField(message: string | undefined, field: string): string | undefined {
  if (field.length === 0) {
    return message;
  }
  if (!message || message.length === 0) {
    return `mismatch on field '${field}'`;
  }
  return `${message} (field '${field}')`;
}

export function lastError(): string {
  try {
    const { rc, value } = readString((out, cap, outLen) =>
      ITB_LastError(out, cap, outLen),
    );
    if (rc !== Status.Ok) {
      return '';
    }
    return value;
  } catch {
    return '';
  }
}

/**
 * Reads `ITB_Easy_LastMismatchField` for the most recent
 * `STATUS_EASY_MISMATCH` returned on this thread. Returns the empty
 * string when the most recent failure was not a mismatch or libitb
 * recorded no field.
 *
 * `Encryptor.import` already attaches this name to the returned
 * `ITBEasyMismatchError.field` property; the free-function form is
 * exposed for callers that need to read the field independently of
 * the error path.
 */
export function lastMismatchField(): string {
  try {
    const { rc, value } = readString((out, cap, outLen) =>
      ITB_Easy_LastMismatchField(out, cap, outLen),
    );
    if (rc !== Status.Ok) {
      return '';
    }
    return value;
  } catch {
    return '';
  }
}

export function errorFromStatus(code: number): ITBError {
  const msg = lastError();
  switch (code) {
    case Status.EasyMismatch:
      return new ITBEasyMismatchError(code, msg, lastMismatchField());
    case Status.BlobModeMismatch:
      return new ITBBlobModeMismatchError(code, msg);
    case Status.BlobMalformed:
      return new ITBBlobMalformedError(code, msg);
    case Status.BlobVersionTooNew:
      return new ITBBlobVersionTooNewError(code, msg);
    case Status.StreamTruncated:
      return new ITBStreamTruncatedError(code, msg);
    case Status.StreamAfterFinal:
      return new ITBStreamAfterFinalError(code, msg);
    default:
      return new ITBError(code, msg);
  }
}

export function check(status: number): void {
  if (status === Status.Ok) {
    return;
  }
  throw errorFromStatus(status);
}
