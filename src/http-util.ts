// Low-level HTTP replies shared by every surface: JSON bodies, raw buffers,
// request ids and body reading. Every JSON reply carries a non-empty
// X-GitHub-Request-Id, as the wire contract requires.

import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomHex } from './util.ts';

const JSON_TYPE = 'application/json; charset=utf-8';

let requestCounter = 0;
const processSuffix = randomHex(4);

export function nextRequestId(): string {
  requestCounter += 1;
  return `req-${processSuffix}-${requestCounter.toString(16)}`;
}

/** Send a JSON body with the given status and extra headers. */
export function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...headers,
  });
  res.end(text);
}

/** Send a raw buffer with an explicit content type. */
export function sendBuffer(
  res: ServerResponse,
  status: number,
  body: Buffer,
  contentType: string,
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': nextRequestId(),
    ...headers,
  });
  res.end(body);
}

/** A JSON error body: {"message": "..."}. */
export function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

/** Read a whole request body (with a generous cap for packs). */
export function readBody(req: IncomingMessage, maxBytes = 256 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Parse a JSON body; returns null on malformed input. */
export function parseJsonBody(body: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (body.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(body.toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}
