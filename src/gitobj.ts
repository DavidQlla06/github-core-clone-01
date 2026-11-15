// Git objects and packfiles, implemented from the format itself: object ids,
// trees, commits, tags, pack reading (plain objects plus OFS/REF deltas) and
// pack writing (plain objects, zlib-deflated). No git binary is involved.

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { sha1Hex, ZERO_OID } from './util.ts';

export type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';

export interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

export interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

export interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

export interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

const TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

/** The id of an object: sha1("<type> <size>\0" + data). */
export function hashObject(type: GitObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'ascii');
  return sha1Hex(Buffer.concat([header, data]));
}

/** Compare two tree names the way git sorts tree entries (dirs sort as name + '/'). */
function compareTreeNames(a: { name: string; mode: string }, b: { name: string; mode: string }): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

/** Serialize tree entries in git's canonical order. */
export function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

/** Parse a tree object into its entries. */
export function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) break;
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0) break;
    const mode = data.subarray(offset, space).toString('ascii');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

/** Parse a commit object. */
export function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const headerText = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  const parents: string[] = [];
  let tree = '';
  let author = '';
  let committer = '';
  for (const line of headerText.split('\n')) {
    const space = line.indexOf(' ');
    if (space < 0) continue;
    const key = line.slice(0, space);
    const value = line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

/** Build a commit object from its fields. */
export function buildCommit(fields: {
  tree: string;
  parents: readonly string[];
  author: string;
  committer: string;
  message: string;
}): Buffer {
  const lines = [`tree ${fields.tree}`];
  for (const parent of fields.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${fields.author}`);
  lines.push(`committer ${fields.committer}`);
  lines.push('');
  lines.push(fields.message);
  return Buffer.from(lines.join('\n'), 'utf8');
}

/** Parse an annotated tag object. */
export function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const headerText = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of headerText.split('\n')) {
    const space = line.indexOf(' ');
    if (space < 0) continue;
    const key = line.slice(0, space);
    const value = line.slice(space + 1);
    if (key === 'object') object = value;
    else if (key === 'type') type = value;
    else if (key === 'tag') tag = value;
    else if (key === 'tagger') tagger = value;
  }
  return { object, type, tag, tagger, message };
}

/** Build an annotated tag object. */
export function buildTag(fields: {
  object: string;
  type: GitObjectType;
  tag: string;
  tagger: string;
  message: string;
}): Buffer {
  const lines = [
    `object ${fields.object}`,
    `type ${fields.type}`,
    `tag ${fields.tag}`,
    `tagger ${fields.tagger}`,
    '',
    fields.message,
  ];
  return Buffer.from(lines.join('\n'), 'utf8');
}

/** Peel an annotated tag to the commit it points at (following tag chains). */
export function peelObject(
  lookup: (oid: string) => GitObject | undefined,
  oid: string,
): string | null {
  let current = oid;
  for (let hops = 0; hops < 16; hops += 1) {
    const object = lookup(current);
    if (!object) return null;
    if (object.type !== 'tag') return current;
    current = parseTag(object.data).object;
  }
  return null;
}

// --------------------------------------------------------------------------------------------
// Packs
// --------------------------------------------------------------------------------------------

/** One pack entry after parsing (deltas already resolved). */
export interface PackEntry {
  offset: number;
  type: GitObjectType;
  data: Buffer;
  oid: string;
}

export interface PackRead {
  version: number;
  declaredCount: number;
  entries: PackEntry[];
  objects: Map<string, GitObject>;
  trailer: string;
  checksumOk: boolean;
}

function readPackObjectHeader(buffer: Buffer, start: number): { typeCode: number; size: number; next: number } {
  let offset = start;
  const first = buffer[offset] ?? 0;
  offset += 1;
  const typeCode = (first >> 4) & 0x07;
  let size = first & 0x0f;
  let shift = 4;
  let byte = first;
  while ((byte & 0x80) !== 0) {
    byte = buffer[offset] ?? 0;
    offset += 1;
    size |= (byte & 0x7f) << shift;
    shift += 7;
  }
  return { typeCode, size, next: offset };
}

function readOfsDeltaOffset(buffer: Buffer, start: number): { offset: number; next: number } {
  let offset = start;
  let byte = buffer[offset] ?? 0;
  offset += 1;
  let result = byte & 0x7f;
  while ((byte & 0x80) !== 0) {
    byte = buffer[offset] ?? 0;
    offset += 1;
    result = ((result + 1) << 7) | (byte & 0x7f);
  }
  return { offset: result, next: offset };
}

/** Apply a git delta to a base buffer. */
export function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readVarint = (): number => {
    let result = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset] ?? 0;
      offset += 1;
      result |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return result;
  };
  const baseSize = readVarint();
  const resultSize = readVarint();
  if (baseSize !== base.length) throw new Error(`delta base size ${baseSize} does not match ${base.length}`);
  const parts: Buffer[] = [];
  let produced = 0;
  while (offset < delta.length) {
    const opcode = delta[offset] ?? 0;
    offset += 1;
    if ((opcode & 0x80) !== 0) {
      let copyOffset = 0;
      let copySize = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if ((opcode & (1 << bit)) !== 0) {
          copyOffset |= (delta[offset] ?? 0) << (8 * bit);
          offset += 1;
        }
      }
      for (let bit = 0; bit < 3; bit += 1) {
        if ((opcode & (0x10 << bit)) !== 0) {
          copySize |= (delta[offset] ?? 0) << (8 * bit);
          offset += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      parts.push(base.subarray(copyOffset, copyOffset + copySize));
      produced += copySize;
    } else if (opcode !== 0) {
      parts.push(delta.subarray(offset, offset + opcode));
      produced += opcode;
      offset += opcode;
    } else {
      throw new Error('delta opcode 0 is invalid');
    }
  }
  if (produced !== resultSize) throw new Error(`delta produced ${produced} bytes, expected ${resultSize}`);
  return Buffer.concat(parts);
}

/**
 * Parse a packfile. Resolves OFS and REF deltas against objects in the same
 * pack (or a caller-supplied resolver for thin packs).
 */
export function readPack(
  pack: Buffer,
  options: { resolveBase?: (oid: string) => GitObject | undefined } = {},
): PackRead {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = pack.readUInt32BE(4);
  const declaredCount = pack.readUInt32BE(8);
  const trailer = pack.subarray(pack.length - 20).toString('hex');
  const expectedTrailer = sha1Hex(pack.subarray(0, pack.length - 20));
  const checksumOk = trailer === expectedTrailer;

  interface RawEntry {
    offset: number;
    typeCode: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
  }
  const raw: RawEntry[] = [];
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const entryOffset = offset;
    const header = readPackObjectHeader(pack, offset);
    offset = header.next;
    let typeCode = header.typeCode;
    let baseOffset: number | undefined;
    let baseOid: string | undefined;
    if (typeCode === 6) {
      const ofs = readOfsDeltaOffset(pack, offset);
      offset = ofs.next;
      baseOffset = entryOffset - ofs.offset;
    } else if (typeCode === 7) {
      baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    }
    const inflated = inflateSync(pack.subarray(offset), { info: true }) as unknown as {
      buffer: Buffer;
      engine: { bytesWritten: number };
    };
    // inflateSync ignores trailing bytes; the engine's bytesWritten is exactly
    // how much of the input the zlib stream consumed.
    const consumed = inflated.engine.bytesWritten;
    offset += consumed;
    raw.push({ offset: entryOffset, typeCode, data: inflated.buffer, baseOffset, baseOid });
  }

  const byOffset = new Map<number, RawEntry>();
  for (const entry of raw) byOffset.set(entry.offset, entry);
  const resolved = new Map<number, { type: GitObjectType; data: Buffer; oid: string }>();
  const resolvedByOid = new Map<string, { type: GitObjectType; data: Buffer; oid: string }>();
  const resolving = new Set<number>();

  const resolve = (entry: RawEntry): { type: GitObjectType; data: Buffer; oid: string } => {
    const cached = resolved.get(entry.offset);
    if (cached) return cached;
    if (resolving.has(entry.offset)) throw new Error(`delta cycle at pack offset ${entry.offset}`);
    resolving.add(entry.offset);
    let type: GitObjectType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset ?? -1);
      if (!baseEntry) throw new Error(`ofs-delta base at offset ${entry.baseOffset} is not in the pack`);
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid ?? '';
      const baseEntry = resolvedByOid.get(wanted);
      if (baseEntry) {
        type = baseEntry.type;
        data = applyDelta(baseEntry.data, entry.data);
      } else {
        const external = options.resolveBase?.(wanted);
        if (!external) throw new Error(`ref-delta base ${wanted} is not in the pack`);
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode] as GitObjectType;
      if (!type) throw new Error(`unknown pack object type ${entry.typeCode}`);
      data = entry.data;
    }
    const oid = hashObject(type, data);
    const out = { type, data, oid };
    resolved.set(entry.offset, out);
    resolvedByOid.set(oid, out);
    resolving.delete(entry.offset);
    return out;
  };

  const entries: PackEntry[] = [];
  const objects = new Map<string, GitObject>();
  for (const entry of raw) {
    const done = resolve(entry);
    entries.push({ offset: entry.offset, type: done.type, data: done.data, oid: done.oid });
    if (!objects.has(done.oid)) objects.set(done.oid, { type: done.type, data: done.data });
  }
  return { version, declaredCount, entries, objects, trailer, checksumOk };
}

/** Encode one object's pack header (type/size varint). */
function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas), version 2, with trailer. */
export function writePack(objects: Iterable<GitObject>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    // Level 1: packs are built on the hot path (clones, fetches); it is ~3x
    // faster than the default level at the same size for these small objects.
    parts.push(deflateSync(object.data, { level: 1 }));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

/** Verify a pack's trailer checksum. */
export function verifyPackChecksum(pack: Buffer): { ok: boolean; expected: string; actual: string } {
  const actual = pack.subarray(pack.length - 20).toString('hex');
  const expected = sha1Hex(pack.subarray(0, pack.length - 20));
  return { ok: actual === expected, expected, actual };
}

// --------------------------------------------------------------------------------------------
// Reachability
// --------------------------------------------------------------------------------------------

export type ObjectLookup = (oid: string) => GitObject | undefined;

/**
 * All objects reachable from `tips`: commits walk parents, trees and tags
 * walk their entries/targets. Throws when an object is missing, unless
 * `allowMissing` is set (then the walk stops at the gap).
 * `cutAt` names commits whose parents are not followed (shallow boundaries).
 */
export function collectReachable(
  tips: Iterable<string>,
  lookup: ObjectLookup,
  options: { allowMissing?: boolean; cutAt?: ReadonlySet<string> } = {},
): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...tips];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid) || oid === ZERO_OID) continue;
    const object = lookup(oid);
    if (!object) {
      if (options.allowMissing) continue;
      throw new Error(`missing object ${oid}`);
    }
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      // A shallow boundary still contributes its own tree; only its parents
      // are cut off.
      if (options.cutAt?.has(oid)) continue;
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) queue.push(entry.oid);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    }
  }
  return seen;
}

/** The commits reachable from `tips`, newest first by timestamp then by discovery order. */
export function collectCommits(tips: Iterable<string>, lookup: ObjectLookup): CommitView[] {
  const seen = new Set<string>();
  const queue: string[] = [...tips];
  const commits: Array<{ oid: string; view: CommitView; stamp: number }> = [];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid) || oid === ZERO_OID) continue;
    const object = lookup(oid);
    if (!object || object.type !== 'commit') continue;
    seen.add(oid);
    const view = parseCommit(object.data);
    const stamp = parseStamp(view.committer) ?? parseStamp(view.author) ?? 0;
    commits.push({ oid, view, stamp });
    for (const parent of view.parents) queue.push(parent);
  }
  commits.sort((a, b) => b.stamp - a.stamp);
  return commits.map((entry) => entry.view);
}

function parseStamp(identity: string): number | null {
  const match = / (\d+) [+-]\d{4}$/.exec(identity);
  return match ? Number(match[1]) : null;
}

/** Is `ancestor` an ancestor of (or equal to) `descendant`? */
export function isAncestor(lookup: ObjectLookup, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const queue: string[] = [descendant];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid) || oid === ZERO_OID) continue;
    seen.add(oid);
    const object = lookup(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return false;
}

/** Find a merge base of two commits: the first common ancestor found walking both sides. */
export function mergeBase(lookup: ObjectLookup, a: string, b: string): string | null {
  if (a === b) return a;
  const fromA = new Set<string>();
  const queueA: string[] = [a];
  while (queueA.length > 0) {
    const oid = queueA.pop() as string;
    if (fromA.has(oid) || oid === ZERO_OID) continue;
    fromA.add(oid);
    const object = lookup(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queueA.push(parent);
  }
  const queueB: string[] = [b];
  const seenB = new Set<string>();
  while (queueB.length > 0) {
    const oid = queueB.pop() as string;
    if (fromA.has(oid)) return oid;
    if (seenB.has(oid) || oid === ZERO_OID) continue;
    seenB.add(oid);
    const object = lookup(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queueB.push(parent);
  }
  return null;
}

/** Flatten a tree object into path -> {mode, oid} (files and subtrees' files). */
export function flattenTree(lookup: ObjectLookup, treeOid: string, prefix = ''): Map<string, { mode: string; oid: string }> {
  const out = new Map<string, { mode: string; oid: string }>();
  const walk = (oid: string, pathPrefix: string): void => {
    const object = lookup(oid);
    if (!object || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      const path = pathPrefix === '' ? entry.name : `${pathPrefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, { mode: entry.mode, oid: entry.oid });
    }
  };
  walk(treeOid, prefix);
  return out;
}

/** Build a tree object (and its subtrees) from a flat path map; returns the root tree oid. */
export function buildTreeFromPaths(
  put: (type: GitObjectType, data: Buffer) => string,
  files: ReadonlyMap<string, { mode: string; oid: string }>,
): string {
  interface Node {
    files: Map<string, { mode: string; oid: string }>;
    dirs: Map<string, Node>;
  }
  const makeNode = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = makeNode();
  for (const [path, entry] of files) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const name = segments[i] as string;
      if (!node.dirs.has(name)) node.dirs.set(name, makeNode());
      node = node.dirs.get(name) as Node;
    }
    node.files.set(segments[segments.length - 1] as string, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return put('tree', buildTree(entries));
  };
  return build(root);
}
