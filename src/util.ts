// Small shared helpers: hashing, base64, ids and a deterministic clock.
// Everything here is dependency-free Node standard library.

import { createHash, randomBytes } from 'node:crypto';

export const ZERO_OID = '0'.repeat(40);

/** SHA-1 hex of a buffer. */
export function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

/** Standard base64 of bytes (no line wrapping). */
export function b64encode(data: Buffer | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return buf.toString('base64');
}

/** Base64 that tolerates whitespace/newlines, as the contents API returns. */
export function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

/** URL-safe base64 without padding, for opaque global ids and cursors. */
export function b64url(data: string): string {
  return Buffer.from(data, 'utf8').toString('base64url');
}

export function b64urlDecode(text: string): string {
  return Buffer.from(text, 'base64url').toString('utf8');
}

/** A short random hex string for request ids. */
export function randomHex(bytes = 8): string {
  return randomBytes(bytes).toString('hex');
}

/**
 * A deterministic clock: the forge never reads the wall clock for anything a
 * check can observe, so two runs on the same inputs produce the same state.
 * Starts at 2025-01-01T00:00:00Z and advances one second per tick.
 */
export class Clock {
  private seconds: number;
  constructor(startSeconds = 1735689600) {
    this.seconds = startSeconds;
  }
  /** Next timestamp in epoch seconds. */
  tick(): number {
    this.seconds += 1;
    return this.seconds;
  }
  /** Current timestamp without advancing. */
  now(): number {
    return this.seconds;
  }
  iso(seconds?: number): string {
    return new Date((seconds ?? this.seconds) * 1000).toISOString();
  }
}

/** Split a path into segments, dropping empty ones. */
export function splitPath(path: string): string[] {
  return path.split('/').filter((segment) => segment !== '');
}

/** Escape a string for safe inclusion in a JSON error message. */
export function clip(text: string, max = 400): string {
  return text.length <= max ? text : `${text.slice(0, max)}…`;
}

/** True when a value is a plain JSON object (not null, not an array). */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
