// Git smart HTTP: info/refs advertisements, protocol v2 upload-pack
// (ls-refs, fetch) and v0 upload-pack, and v0 receive-pack (push). The wire
// is pkt-lines over HTTP, packs are read and written with src/gitobj.ts, and
// every object the server stores is verified by its SHA-1.

import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  collectReachable,
  hashObject,
  isAncestor,
  parseCommit,
  peelObject,
  readPack,
  writePack,
  type GitObject,
} from './gitobj.ts';
import { sendBuffer, sendError } from './http-util.ts';
import { Store, VIEWER_LOGIN } from './store.ts';
import { ZERO_OID } from './util.ts';

const AGENT = 'forge/1.0';
const UPLOAD_AD = 'application/x-git-upload-pack-advertisement';
const UPLOAD_RESULT = 'application/x-git-upload-pack-result';
const RECEIVE_AD = 'application/x-git-receive-pack-advertisement';
const RECEIVE_RESULT = 'application/x-git-receive-pack-result';

// --------------------------------------------------------------------------------------------
// pkt-lines
// --------------------------------------------------------------------------------------------

export type PacketKind = 'data' | 'flush' | 'delim' | 'end';

export interface Packet {
  kind: PacketKind;
  payload: Buffer;
}

export function pktLine(payload: Buffer | string): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const length = data.length + 4;
  const header = Buffer.allocUnsafe(4);
  header.write(length.toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

export const FLUSH = Buffer.from('0000', 'ascii');
export const DELIM = Buffer.from('0001', 'ascii');

/** Decode a buffer of pkt-lines. Throws on a malformed length. */
export function decodePktLines(buffer: Buffer): { packets: Packet[]; rest: Buffer } {
  const packets: Packet[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) throw new Error('truncated pkt-line header');
    const head = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`not a pkt-line: ${JSON.stringify(head)}`);
    const length = Number.parseInt(head, 16);
    if (length === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (length === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push({ kind: 'end', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (length < 4 || offset + length > buffer.length) throw new Error('pkt-line length out of range');
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return { packets, rest: Buffer.alloc(0) };
}

/** Split a sideband payload (band byte + data) into its band. */
export function sidebandPacket(band: 1 | 2 | 3, data: Buffer): Buffer {
  return pktLine(Buffer.concat([Buffer.from([band]), data]));
}

// --------------------------------------------------------------------------------------------
// advertisements
// --------------------------------------------------------------------------------------------

interface RefLine {
  oid: string;
  name: string;
  peeled?: string;
  symrefTarget?: string;
}

/** All refs of a repo, HEAD first, then heads, then tags (each sorted). */
function listRefs(store: Store, repo: { refs: Map<string, string>; objects: Map<string, GitObject> }, headTarget: string): RefLine[] {
  const out: RefLine[] = [];
  const headOid = repo.refs.get(headTarget);
  if (headOid !== undefined) {
    out.push({ oid: headOid, name: 'HEAD', symrefTarget: headTarget });
  }
  const heads = [...repo.refs.entries()].filter(([name]) => name.startsWith('refs/heads/')).sort(([a], [b]) => (a < b ? -1 : 1));
  const tags = [...repo.refs.entries()].filter(([name]) => name.startsWith('refs/tags/')).sort(([a], [b]) => (a < b ? -1 : 1));
  for (const [name, oid] of heads) out.push({ oid, name });
  for (const [name, oid] of tags) {
    const object = repo.objects.get(oid);
    const entry: RefLine = { oid, name };
    if (object?.type === 'tag') {
      const peeled = peelObject((id) => repo.objects.get(id), oid);
      if (peeled !== null) entry.peeled = peeled;
    }
    out.push(entry);
  }
  return out;
}

function v2Advertisement(): Buffer {
  const lines = [
    'version 2\n',
    `agent=${AGENT}\n`,
    'ls-refs\n',
    'fetch=shallow filter\n',
    'object-format=sha1\n',
  ];
  return Buffer.concat([...lines.map((line) => pktLine(line)), FLUSH]);
}

function v0Advertisement(
  service: 'git-upload-pack' | 'git-receive-pack',
  store: Store,
  repo: Parameters<typeof listRefs>[1] & { defaultBranch: string },
  capabilities: string,
): Buffer {
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), FLUSH];
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const refs = listRefs(store, repo, headTarget);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${capabilities}\n`));
  } else {
    let first = true;
    for (const ref of refs) {
      const suffix = first ? `\0${capabilities}` : '';
      first = false;
      parts.push(pktLine(`${ref.oid} ${ref.name}${suffix}\n`));
      if (ref.peeled !== undefined) {
        parts.push(pktLine(`${ref.peeled} ${ref.name}^{}\n`));
      }
    }
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}

const UPLOAD_V0_CAPS = `symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta multi_ack agent=${AGENT}`;
const RECEIVE_CAPS = `report-status side-band-64k delete-refs thin-pack ofs-delta agent=${AGENT} symref=HEAD:refs/heads/main`;

// --------------------------------------------------------------------------------------------
// entry points
// --------------------------------------------------------------------------------------------

export interface GitRequest {
  owner: string;
  repo: string;
  service: 'git-upload-pack' | 'git-receive-pack';
  suffix: string; // 'info/refs' | 'git-upload-pack' | 'git-receive-pack'
}

function findRepo(store: Store, owner: string, name: string) {
  if (owner !== VIEWER_LOGIN) return undefined;
  return store.getRepo(owner, name);
}

/** GET /{owner}/{repo}.git/info/refs?service=... */
export function handleInfoRefs(
  req: IncomingMessage,
  res: ServerResponse,
  store: Store,
  git: GitRequest,
  service: string | null,
): void {
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
    sendError(res, 404, 'Not Found');
    return;
  }
  const repo = findRepo(store, git.owner, git.repo);
  if (!repo) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const wantsV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
  if (wantsV2) {
    sendBuffer(res, 200, v2Advertisement(), UPLOAD_AD);
    return;
  }
  const body =
    service === 'git-upload-pack'
      ? v0Advertisement(service, store, repo, UPLOAD_V0_CAPS)
      : v0Advertisement(service, store, repo, RECEIVE_CAPS);
  sendBuffer(res, 200, body, service === 'git-upload-pack' ? UPLOAD_AD : RECEIVE_AD);
}

// --------------------------------------------------------------------------------------------
// upload-pack
// --------------------------------------------------------------------------------------------

interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
  filter: string | null;
}

/** The shallow boundary computation for a depth-limited fetch. */
function shallowPlan(
  store: Store,
  repo: { objects: Map<string, GitObject> },
  wants: readonly string[],
  depth: number,
  oldShallow: readonly string[],
): { included: string[]; boundary: string[]; unshallow: string[] } {
  const lookup = (oid: string) => repo.objects.get(oid);
  // BFS over commits from the wants, tracking distance in generations.
  const distance = new Map<string, number>();
  const queue: Array<{ oid: string; depth: number }> = wants.map((oid) => ({ oid, depth: 0 }));
  const included: string[] = [];
  while (queue.length > 0) {
    const { oid, depth: d } = queue.shift() as { oid: string; depth: number };
    if (distance.has(oid) || oid === ZERO_OID) continue;
    const object = lookup(oid);
    if (!object || object.type !== 'commit') continue;
    distance.set(oid, d);
    if (d >= depth) continue;
    included.push(oid);
    for (const parent of parseCommit(object.data).parents) {
      if (!distance.has(parent)) queue.push({ oid: parent, depth: d + 1 });
    }
  }
  const boundary: string[] = [];
  for (const oid of included) {
    const object = lookup(oid);
    if (!object || object.type !== 'commit') continue;
    const parents = parseCommit(object.data).parents;
    if (parents.some((parent) => !distance.has(parent) || (distance.get(parent) as number) >= depth)) {
      boundary.push(oid);
    }
  }
  const boundarySet = new Set(boundary);
  const unshallow = oldShallow.filter((oid) => distance.has(oid) && !boundarySet.has(oid));
  return { included, boundary: [...boundary].sort(), unshallow: [...unshallow].sort() };
}

function handleLsRefsV2(
  store: Store,
  repo: { refs: Map<string, string>; objects: Map<string, GitObject>; defaultBranch: string },
  args: string[],
): Buffer {
  const peel = args.includes('peel');
  const symrefs = args.includes('symrefs');
  const prefixes = args.filter((arg) => arg.startsWith('ref-prefix ')).map((arg) => arg.slice('ref-prefix '.length));
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const all = listRefs(store, repo, headTarget);
  const lines: Buffer[] = [];
  for (const ref of all) {
    if (prefixes.length > 0 && !prefixes.some((prefix) => ref.name.startsWith(prefix))) continue;
    let line = `${ref.oid} ${ref.name}`;
    if (ref.name === 'HEAD' && symrefs && ref.symrefTarget) line += ` symref-target:${ref.symrefTarget}`;
    if (peel && ref.peeled !== undefined) line += ` peeled:${ref.peeled}`;
    lines.push(pktLine(`${line}\n`));
  }
  lines.push(FLUSH);
  return Buffer.concat(lines);
}

function handleFetchV2(store: Store, repo: NonNullable<ReturnType<Store['getRepo']>>, args: FetchArgs): Buffer {
  const parts: Buffer[] = [];
  // acknowledgments
  if (args.haves.length > 0) {
    parts.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), DELIM);
  }
  // shallow-info + object selection
  const plan = fetchPlan(store, repo, args);
  if (args.depth !== null) {
    const lines: string[] = [];
    for (const oid of plan.boundary) lines.push(`shallow ${oid}\n`);
    for (const oid of plan.unshallow) lines.push(`unshallow ${oid}\n`);
    if (lines.length > 0) {
      parts.push(pktLine('shallow-info\n'));
      for (const line of lines) parts.push(pktLine(line));
      parts.push(DELIM);
    }
  }
  // packfile section, sideband band 1
  const pack = cachedPackBytes(repo, args, plan.objects);
  parts.push(pktLine('packfile\n'));
  const CHUNK = 32768;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    parts.push(sidebandPacket(1, pack.subarray(offset, Math.min(pack.length, offset + CHUNK))));
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}

function handleFetchV0(store: Store, repo: NonNullable<ReturnType<Store['getRepo']>>, args: FetchArgs): Buffer {
  const parts: Buffer[] = [];
  const plan = fetchPlan(store, repo, args);
  if (args.depth !== null) {
    for (const oid of plan.boundary) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  }
  parts.push(pktLine('NAK\n'));
  const pack = cachedPackBytes(repo, args, plan.objects);
  const CHUNK = 32768;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    parts.push(sidebandPacket(1, pack.subarray(offset, Math.min(pack.length, offset + CHUNK))));
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}

/** The objects a fetch must send, plus its shallow/unshallow lines. */
function fetchPlan(
  store: Store,
  repo: NonNullable<ReturnType<Store['getRepo']>>,
  args: FetchArgs,
): { objects: Map<string, GitObject>; boundary: string[]; unshallow: string[] } {
  const lookup = (oid: string) => repo.objects.get(oid);
  const subtract = (
    wants: readonly string[],
    haves: readonly string[],
    wantCutAt: ReadonlySet<string>,
    haveCutAt: ReadonlySet<string>,
  ): Map<string, GitObject> => {
    const haveClosure = collectReachable(haves, lookup, { allowMissing: true, cutAt: haveCutAt });
    const wantClosure = collectReachable(wants, lookup, { allowMissing: true, cutAt: wantCutAt });
    const objects = new Map<string, GitObject>();
    for (const oid of wantClosure) {
      if (haveClosure.has(oid)) continue;
      const object = repo.objects.get(oid);
      if (object) objects.set(oid, object);
    }
    return objects;
  };
  if (args.depth !== null) {
    const plan = shallowPlan(store, repo, args.wants, args.depth, args.shallow);
    // Haves are cut at the request's old shallow boundaries; wants at the new ones.
    const objects = subtract(plan.included, args.haves, new Set(plan.boundary), new Set(args.shallow));
    return { objects, boundary: plan.boundary, unshallow: plan.unshallow };
  }
  return { objects: subtract(args.wants, args.haves, new Set(), new Set()), boundary: [], unshallow: [] };
}

// --------------------------------------------------------------------------------------------
// fetch pack cache
// --------------------------------------------------------------------------------------------

/**
 * Built fetch packs, keyed by the exact request plus the repo's revision:
 * the 50 concurrent clones of one tip all ask for the same bytes, so the
 * pack is deflated once and reused. The revision bump on any object or ref
 * mutation keeps the cache honest.
 */
const packCache = new Map<string, Buffer>();
const PACK_CACHE_MAX = 64;

function cachedPackBytes(
  repo: NonNullable<ReturnType<Store['getRepo']>>,
  args: FetchArgs,
  objects: Map<string, GitObject>,
): Buffer {
  const key = JSON.stringify([repo.id, repo.rev, args.wants, args.haves, args.shallow, args.depth, args.filter]);
  const hit = packCache.get(key);
  if (hit !== undefined) return hit;
  const pack = writePack([...objects.values()]);
  if (packCache.size >= PACK_CACHE_MAX) {
    const first = packCache.keys().next().value;
    if (first !== undefined) packCache.delete(first);
  }
  packCache.set(key, pack);
  return pack;
}

/** Parse the v2 command request body into (command, args). */
function parseV2Request(body: Buffer): { command: string; args: string[] } {
  const { packets } = decodePktLines(body);
  let command = '';
  const args: string[] = [];
  let seenDelim = false;
  for (const packet of packets) {
    if (packet.kind === 'flush') break;
    if (packet.kind === 'delim') {
      seenDelim = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8').replace(/\n$/, '');
    if (!seenDelim) {
      if (text.startsWith('command=')) command = text.slice('command='.length);
      continue;
    }
    args.push(text);
  }
  return { command, args };
}

/** Parse the v0 upload-pack request body into fetch args. */
function parseV0FetchRequest(body: Buffer): FetchArgs {
  const { packets } = decodePktLines(body);
  const args: FetchArgs = { wants: [], haves: [], shallow: [], depth: null, filter: null };
  let section = 0;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      section += 1;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const text = packet.payload.toString('utf8').replace(/\n$/, '');
    const [head, ...rest] = text.split(' ');
    if (head === 'want') args.wants.push(rest[0] ?? '');
    else if (head === 'have') args.haves.push(rest[0] ?? '');
    else if (head === 'shallow') args.shallow.push(rest[0] ?? '');
    else if (head === 'deepen') args.depth = Number.parseInt(rest[0] ?? '0', 10);
    else if (head === 'deepen-since') args.depth = args.depth ?? 0;
    else if (head === 'done') void 0;
    void section;
  }
  return args;
}

/** POST /{owner}/{repo}.git/git-upload-pack */
export function handleUploadPack(
  req: IncomingMessage,
  res: ServerResponse,
  store: Store,
  git: GitRequest,
  body: Buffer,
): void {
  const repo = findRepo(store, git.owner, git.repo);
  if (!repo) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  try {
    if (isV2) {
      const { command, args } = parseV2Request(body);
      if (command === 'ls-refs') {
        sendBuffer(res, 200, handleLsRefsV2(store, repo, args), UPLOAD_RESULT);
        return;
      }
      if (command === 'fetch') {
        const fetchArgs: FetchArgs = { wants: [], haves: [], shallow: [], depth: null, filter: null };
        for (const arg of args) {
          if (arg.startsWith('want ')) fetchArgs.wants.push(arg.slice(5));
          else if (arg.startsWith('have ')) fetchArgs.haves.push(arg.slice(5));
          else if (arg.startsWith('shallow ')) fetchArgs.shallow.push(arg.slice(8));
          else if (arg.startsWith('deepen ')) fetchArgs.depth = Number.parseInt(arg.slice(7), 10);
          else if (arg.startsWith('filter ')) fetchArgs.filter = arg.slice(7);
        }
        sendBuffer(res, 200, handleFetchV2(store, repo, fetchArgs), UPLOAD_RESULT);
        return;
      }
      sendError(res, 400, `unknown command ${command}`);
      return;
    }
    const fetchArgs = parseV0FetchRequest(body);
    sendBuffer(res, 200, handleFetchV0(store, repo, fetchArgs), UPLOAD_RESULT);
  } catch (err) {
    sendError(res, 400, err instanceof Error ? err.message : 'bad request');
  }
}

// --------------------------------------------------------------------------------------------
// receive-pack
// --------------------------------------------------------------------------------------------

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

/** POST /{owner}/{repo}.git/git-receive-pack */
export function handleReceivePack(
  _req: IncomingMessage,
  res: ServerResponse,
  store: Store,
  git: GitRequest,
  body: Buffer,
): void {
  const repo = findRepo(store, git.owner, git.repo);
  if (!repo) {
    sendError(res, 404, 'Not Found');
    return;
  }
  let commands: PushCommand[] = [];
  let packBytes: Buffer = Buffer.alloc(0);
  try {
    // Walk the command section pkt-line by pkt-line until its flush; the
    // bytes after the flush are the pack, not pkt-lines.
    let offset = 0;
    let sawFlush = false;
    while (offset < body.length) {
      const head = body.subarray(offset, offset + 4).toString('ascii');
      if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`not a pkt-line: ${JSON.stringify(head)}`);
      const length = Number.parseInt(head, 16);
      if (length === 0) {
        offset += 4;
        sawFlush = true;
        break;
      }
      if (length === 1 || length === 2) {
        offset += 4;
        continue;
      }
      if (length < 4 || offset + length > body.length) throw new Error('pkt-line length out of range');
      offset += length;
    }
    if (!sawFlush) throw new Error('command list has no flush');
    packBytes = body.subarray(offset);
    // Re-decode the command section for the lines.
    const { packets: commandPackets } = decodePktLines(body.subarray(0, offset));
    for (const packet of commandPackets) {
      if (packet.kind !== 'data') continue;
      let text = packet.payload.toString('utf8');
      const nul = text.indexOf('\0');
      if (nul >= 0) text = text.slice(0, nul);
      text = text.replace(/\n$/, '');
      const [oldOid, newOid, ref] = text.split(' ');
      if (!oldOid || !newOid || !ref) throw new Error(`bad command line ${JSON.stringify(text)}`);
      commands.push({ oldOid, newOid, ref });
    }
  } catch (err) {
    sendError(res, 400, err instanceof Error ? err.message : 'bad request');
    return;
  }
  if (commands.length === 0) {
    sendError(res, 400, 'no commands');
    return;
  }

  // Unpack: store every object the pack carries, verifying the trailer.
  let unpackError: string | null = null;
  if (packBytes.length > 0) {
    try {
      const pack = readPack(packBytes);
      if (!pack.checksumOk) throw new Error('pack trailer checksum mismatch');
      for (const entry of pack.entries) {
        const oid = hashObject(entry.type, entry.data);
        if (!repo.objects.has(oid)) repo.objects.set(oid, { type: entry.type, data: entry.data });
      }
      repo.rev += 1;
    } catch (err) {
      unpackError = err instanceof Error ? err.message : 'unpack failed';
    }
  }

  // Validate and apply each command; report-status is per ref.
  const lines: string[] = [];
  if (unpackError !== null) {
    lines.push(`unpack ${unpackError}\n`);
    for (const command of commands) lines.push(`ng ${command.ref} unpack error\n`);
  } else {
    // Every new tip must exist now (from the pack or already on the server).
    const missing = commands.filter(
      (command) => command.newOid !== ZERO_OID && !repo.objects.has(command.newOid),
    );
    if (missing.length > 0) {
      lines.push(`unpack object ${missing[0]?.newOid} not found\n`);
      for (const command of commands) lines.push(`ng ${command.ref} unpack error\n`);
    } else {
      lines.push('unpack ok\n');
      for (const command of commands) {
        const current = repo.refs.get(command.ref);
        if (command.newOid === ZERO_OID) {
          // Delete.
          if (current === undefined) lines.push(`ng ${command.ref} no such ref\n`);
          else if (command.oldOid !== current) lines.push(`ng ${command.ref} non-fast-forward\n`);
          else {
            repo.refs.delete(command.ref);
            lines.push(`ok ${command.ref}\n`);
          }
          continue;
        }
        if (command.oldOid === ZERO_OID) {
          // Create.
          if (current !== undefined) lines.push(`ng ${command.ref} already exists\n`);
          else {
            repo.refs.set(command.ref, command.newOid);
            lines.push(`ok ${command.ref}\n`);
          }
          continue;
        }
        // Update.
        if (current === undefined) {
          lines.push(`ng ${command.ref} no such ref\n`);
        } else if (command.oldOid !== current) {
          lines.push(`ng ${command.ref} non-fast-forward\n`);
        } else if (command.oldOid === command.newOid) {
          lines.push(`ok ${command.ref}\n`);
        } else if (command.ref.startsWith('refs/tags/')) {
          repo.refs.set(command.ref, command.newOid);
          lines.push(`ok ${command.ref}\n`);
        } else if (isAncestor((oid) => repo.objects.get(oid), command.oldOid, command.newOid)) {
          repo.refs.set(command.ref, command.newOid);
          lines.push(`ok ${command.ref}\n`);
        } else {
          lines.push(`ng ${command.ref} non-fast-forward\n`);
        }
      }
    }
  }

  // Ref changes invalidate the fetch pack cache.
  repo.rev += 1;

  // The report is pkt-lined inside band 1 and ends with a flush pkt-line
  // inside band 1 (the parent reads the demuxed stream as pkt-lines and
  // waits for that flush); the outer flush then closes the sideband stream.
  const inner = Buffer.concat([...lines.map((line) => pktLine(line)), FLUSH]);
  const parts: Buffer[] = [];
  const CHUNK = 32768;
  for (let offset = 0; offset < inner.length; offset += CHUNK) {
    parts.push(sidebandPacket(1, inner.subarray(offset, Math.min(inner.length, offset + CHUNK))));
  }
  parts.push(FLUSH);
  // A 200 with the report even when refs were refused: the refusal is in the report.
  sendBuffer(res, 200, Buffer.concat(parts), RECEIVE_RESULT);
}
