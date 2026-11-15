// The forge's store: every repository, issue, pull request, label and git
// object lives in memory, in one process, with no outside service. The store
// also owns the git-level operations the REST and GraphQL surfaces need:
// creating commits from file changes, diffing trees, and three-way merges.

import {
  buildCommit,
  buildTag,
  buildTreeFromPaths,
  collectReachable,
  flattenTree,
  hashObject,
  isAncestor,
  mergeBase,
  parseCommit,
  parseTag,
  peelObject,
  type GitObject,
  type GitObjectType,
} from './gitobj.ts';
import { Clock, ZERO_OID, b64encode } from './util.ts';

/** The login the trial's bearer token names (the seeded scenario's viewer). */
export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';

export interface Label {
  name: string;
  color: string;
  description: string;
}

export interface Comment {
  id: number;
  body: string;
  user: string;
  createdAt: string;
}

export interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
  comments: Comment[];
}

export interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  createdSeq: number;
  createdAt: string;
}

export interface Repo {
  id: number;
  owner: string;
  name: string;
  fullName: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdSeq: number;
  createdAt: string;
  /** Bumped on every object or ref mutation; caches key on it. */
  rev: number;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  nextIssueNumber: number;
  nextPullNumber: number;
}

export interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
  changes: number;
}

export class Store {
  readonly clock = new Clock();
  private repos = new Map<string, Repo>();
  private repoOrder: Repo[] = [];
  private nextRepoId = 1;
  private nextObjectId = 1; // global ids for issues/comments (REST `id`)
  private seq = 0;

  private nextSeq(): number {
    this.seq += 1;
    return this.seq;
  }

  private nextGlobalId(): number {
    const id = this.nextObjectId;
    this.nextObjectId += 1;
    return id;
  }

  // ---------------------------------------------------------------- repos

  getRepo(owner: string, name: string): Repo | undefined {
    return this.repos.get(`${owner}/${name}`);
  }

  listViewerRepos(): Repo[] {
    return [...this.repoOrder];
  }

  createRepo(owner: string, name: string, description: string, isPrivate: boolean): Repo {
    const stamp = this.clock.tick();
    const repo: Repo = {
      id: this.nextRepoId,
      owner,
      name,
      fullName: `${owner}/${name}`,
      description,
      isPrivate,
      defaultBranch: 'main',
      createdSeq: this.nextSeq(),
      createdAt: this.clock.iso(stamp),
      rev: 0,
      objects: new Map(),
      refs: new Map(),
      labels: new Map(),
      issues: new Map(),
      pulls: new Map(),
      nextIssueNumber: 1,
      nextPullNumber: 1,
    };
    this.nextRepoId += 1;
    this.repos.set(repo.fullName, repo);
    this.repoOrder.push(repo);
    return repo;
  }

  deleteRepo(repo: Repo): void {
    this.repos.delete(repo.fullName);
    this.repoOrder = this.repoOrder.filter((entry) => entry !== repo);
  }

  // ---------------------------------------------------------------- git objects and refs

  lookup(repo: Repo): (oid: string) => GitObject | undefined {
    return (oid: string) => repo.objects.get(oid);
  }

  putObject(repo: Repo, type: GitObjectType, data: Buffer): string {
    const oid = hashObject(type, data);
    if (!repo.objects.has(oid)) {
      repo.objects.set(oid, { type, data });
      repo.rev += 1;
    }
    return oid;
  }

  getRef(repo: Repo, name: string): string | undefined {
    return repo.refs.get(name);
  }

  setRef(repo: Repo, name: string, oid: string): void {
    repo.refs.set(name, oid);
    repo.rev += 1;
  }

  deleteRef(repo: Repo, name: string): void {
    repo.refs.delete(name);
    repo.rev += 1;
  }

  headRefName(repo: Repo): string {
    return `refs/heads/${repo.defaultBranch}`;
  }

  headOid(repo: Repo): string | undefined {
    return repo.refs.get(this.headRefName(repo));
  }

  /** Resolve a branch name, a full ref, or a raw oid to an oid. */
  resolveRef(repo: Repo, ref: string): string | undefined {
    if (ref === 'HEAD') return this.headOid(repo);
    if (/^[0-9a-f]{40}$/i.test(ref)) return repo.objects.has(ref.toLowerCase()) ? ref.toLowerCase() : undefined;
    if (ref.startsWith('refs/')) return repo.refs.get(ref);
    return repo.refs.get(`refs/heads/${ref}`) ?? repo.refs.get(`refs/tags/${ref}`);
  }

  /** The commit a ref points at, following annotated tags. */
  peelToCommit(repo: Repo, oid: string): string | null {
    return peelObject(this.lookup(repo), oid);
  }

  // ---------------------------------------------------------------- commits

  private identity(): string {
    const stamp = this.clock.now();
    return `${VIEWER_NAME} <${VIEWER_EMAIL}> ${stamp} +0000`;
  }

  /** Create a commit object (no ref moves) and return its oid. */
  makeCommit(repo: Repo, treeOid: string, parents: readonly string[], message: string): string {
    const stamp = this.clock.tick();
    const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${stamp} +0000`;
    const data = buildCommit({
      tree: treeOid,
      parents,
      author: who,
      committer: who,
      message: message.endsWith('\n') ? message : `${message}\n`,
    });
    return this.putObject(repo, 'commit', data);
  }

  /** The flat file map of a commit's tree (empty when the commit is missing). */
  filesOfCommit(repo: Repo, commitOid: string): Map<string, { mode: string; oid: string }> {
    const object = repo.objects.get(commitOid);
    if (!object || object.type !== 'commit') return new Map();
    return flattenTree(this.lookup(repo), parseCommit(object.data).tree);
  }

  /**
   * Apply file changes on top of a branch tip (or an unborn branch) and commit.
   * `changes` maps a path to new bytes, or null to delete the path.
   */
  commitFiles(
    repo: Repo,
    branch: string,
    changes: ReadonlyMap<string, Buffer | null>,
    message: string,
  ): { commitSha: string; treeOid: string } {
    const refName = `refs/heads/${branch}`;
    const tip = repo.refs.get(refName);
    const files = tip ? this.filesOfCommit(repo, tip) : new Map<string, { mode: string; oid: string }>();
    for (const [path, content] of changes) {
      if (content === null) files.delete(path);
      else files.set(path, { mode: '100644', oid: this.putObject(repo, 'blob', content) });
    }
    const treeOid = buildTreeFromPaths((type, data) => this.putObject(repo, type, data), files);
    const parents = tip ? [tip] : [];
    const commitSha = this.makeCommit(repo, treeOid, parents, message);
    this.setRef(repo, refName, commitSha);
    return { commitSha, treeOid };
  }

  /** The commits reachable from `ref`, newest first. */
  listCommits(repo: Repo, ref: string): Array<{ sha: string; message: string; author: string; committer: string; timestamp: number }> {
    const tip = this.resolveRef(repo, ref);
    if (!tip) return [];
    const seen = new Set<string>();
    const queue: string[] = [tip];
    const found: Array<{ sha: string; message: string; author: string; committer: string; timestamp: number }> = [];
    while (queue.length > 0) {
      const oid = queue.pop() as string;
      if (seen.has(oid) || oid === ZERO_OID) continue;
      const object = repo.objects.get(oid);
      if (!object || object.type !== 'commit') continue;
      seen.add(oid);
      const view = parseCommit(object.data);
      const stamp = parseIdentityStamp(view.committer) ?? parseIdentityStamp(view.author) ?? 0;
      found.push({ sha: oid, message: view.message, author: view.author, committer: view.committer, timestamp: stamp });
      for (const parent of view.parents) queue.push(parent);
    }
    found.sort((a, b) => b.timestamp - a.timestamp);
    return found;
  }

  // ---------------------------------------------------------------- diffs and merges

  /** Changed paths between two trees (base -> head), with line counts. */
  diffTrees(repo: Repo, baseCommit: string, headCommit: string): FileChange[] {
    const baseFiles = this.filesOfCommit(repo, baseCommit);
    const headFiles = this.filesOfCommit(repo, headCommit);
    const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
    const changes: FileChange[] = [];
    for (const path of [...paths].sort()) {
      const base = baseFiles.get(path);
      const head = headFiles.get(path);
      if (base && head && base.oid === head.oid) continue;
      if (!base && head) {
        const lines = lineCount(repo, head.oid);
        changes.push({ path, status: 'added', additions: lines, deletions: 0, changes: lines });
      } else if (base && !head) {
        const lines = lineCount(repo, base.oid);
        changes.push({ path, status: 'removed', additions: 0, deletions: lines, changes: lines });
      } else if (base && head) {
        const { additions, deletions } = lineDiff(repo, base.oid, head.oid);
        changes.push({ path, status: 'modified', additions, deletions, changes: additions + deletions });
      }
    }
    return changes;
  }

  /**
   * Is `pull` mergeable? Returns 'MERGEABLE' or 'CONFLICTING': a conflict is
   * a path both sides changed differently since their merge base.
   */
  mergeable(repo: Repo, pull: Pull): 'MERGEABLE' | 'CONFLICTING' {
    return this.mergeAnalysis(repo, pull).conflict ? 'CONFLICTING' : 'MERGEABLE';
  }

  private mergeAnalysis(repo: Repo, pull: Pull): { conflict: boolean; resultFiles: Map<string, { mode: string; oid: string }> } {
    const lookup = this.lookup(repo);
    // The base side is the branch's CURRENT tip: a pull request created
    // before another merge must conflict with that merge's changes.
    const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
    const base = mergeBase(lookup, baseTip, pull.headSha);
    const baseFiles = base ? this.filesOfCommit(repo, base) : new Map<string, { mode: string; oid: string }>();
    const headFiles = this.filesOfCommit(repo, pull.headSha);
    const baseTipFiles = this.filesOfCommit(repo, baseTip);
    const result = new Map(baseTipFiles);
    let conflict = false;
    const paths = new Set([...baseFiles.keys(), ...headFiles.keys(), ...baseTipFiles.keys()]);
    for (const path of paths) {
      const ancestor = baseFiles.get(path);
      const head = headFiles.get(path);
      const current = baseTipFiles.get(path);
      const headChanged = (ancestor?.oid ?? null) !== (head?.oid ?? null);
      const baseChanged = (ancestor?.oid ?? null) !== (current?.oid ?? null);
      if (!headChanged) continue;
      if (baseChanged && (head?.oid ?? null) !== (current?.oid ?? null)) {
        conflict = true;
        continue;
      }
      if (head) result.set(path, head);
      else result.delete(path);
    }
    return { conflict, resultFiles: result };
  }

  /** Squash-merge a pull request onto its base branch; returns the merge commit or null on conflict. */
  squashMerge(repo: Repo, pull: Pull): string | null {
    const analysis = this.mergeAnalysis(repo, pull);
    if (analysis.conflict) return null;
    const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
    const treeOid = buildTreeFromPaths((type, data) => this.putObject(repo, type, data), analysis.resultFiles);
    const message = `Merge pull request #${pull.number} from ${pull.headRef}`;
    const commitSha = this.makeCommit(repo, treeOid, [baseTip], message);
    this.setRef(repo, `refs/heads/${pull.baseRef}`, commitSha);
    return commitSha;
  }

  // ---------------------------------------------------------------- issues

  createIssue(repo: Repo, title: string, body: string, labels: string[]): Issue {
    const stamp = this.clock.tick();
    const issue: Issue = {
      id: this.nextGlobalId(),
      number: repo.nextIssueNumber,
      title,
      body,
      state: 'open',
      labels: [...labels],
      createdSeq: this.nextSeq(),
      createdAt: this.clock.iso(stamp),
      updatedAt: this.clock.iso(stamp),
      comments: [],
    };
    repo.nextIssueNumber += 1;
    repo.issues.set(issue.number, issue);
    return issue;
  }

  addComment(repo: Repo, issue: Issue, body: string): Comment {
    const stamp = this.clock.tick();
    const comment: Comment = { id: this.nextGlobalId(), body, user: VIEWER_LOGIN, createdAt: this.clock.iso(stamp) };
    issue.comments.push(comment);
    issue.updatedAt = this.clock.iso(stamp);
    return comment;
  }

  // ---------------------------------------------------------------- pull requests

  createPull(repo: Repo, title: string, body: string, headRef: string, baseRef: string): Pull {
    const headSha = repo.refs.get(`refs/heads/${headRef}`) ?? '';
    const baseSha = repo.refs.get(`refs/heads/${baseRef}`) ?? '';
    const stamp = this.clock.tick();
    const pull: Pull = {
      id: this.nextGlobalId(),
      number: repo.nextPullNumber,
      title,
      body,
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      headRef,
      baseRef,
      headSha,
      baseSha,
      createdSeq: this.nextSeq(),
      createdAt: this.clock.iso(stamp),
    };
    repo.nextPullNumber += 1;
    repo.pulls.set(pull.number, pull);
    return pull;
  }

  openPullForHead(repo: Repo, headRef: string): Pull | undefined {
    for (const pull of repo.pulls.values()) {
      if (pull.headRef === headRef && pull.state === 'open') return pull;
    }
    return undefined;
  }

  // ---------------------------------------------------------------- misc

  /** The objects reachable from `tips` that `haves` do not already reach. */
  newObjects(repo: Repo, wants: readonly string[], haves: readonly string[], cutAt: ReadonlySet<string>): Map<string, GitObject> {
    const lookup = this.lookup(repo);
    const haveClosure = collectReachable(haves, lookup, { allowMissing: true, cutAt });
    const wantClosure = collectReachable(wants, lookup, { allowMissing: true, cutAt });
    const out = new Map<string, GitObject>();
    for (const oid of wantClosure) {
      if (haveClosure.has(oid)) continue;
      const object = repo.objects.get(oid);
      if (object) out.set(oid, object);
    }
    return out;
  }
}

function parseIdentityStamp(identity: string): number | null {
  const match = / (\d+) [+-]\d{4}$/.exec(identity);
  return match ? Number(match[1]) : null;
}

function blobText(repo: Repo, oid: string): string {
  const object = repo.objects.get(oid);
  if (!object || object.type !== 'blob') return '';
  return object.data.toString('utf8');
}

function lineCount(repo: Repo, oid: string): number {
  const text = blobText(repo, oid);
  if (text === '') return 0;
  return text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
}

/** Line multiset diff: lines present in new but not old are additions, and vice versa. */
function lineDiff(repo: Repo, oldOid: string, newOid: string): { additions: number; deletions: number } {
  const countLines = (text: string): Map<string, number> => {
    const counts = new Map<string, number>();
    if (text === '') return counts;
    const lines = text.split('\n');
    if (lines[lines.length - 1] === '') lines.pop();
    for (const line of lines) counts.set(line, (counts.get(line) ?? 0) + 1);
    return counts;
  };
  const oldCounts = countLines(blobText(repo, oldOid));
  const newCounts = countLines(blobText(repo, newOid));
  let additions = 0;
  let deletions = 0;
  for (const [line, count] of newCounts) {
    const extra = count - (oldCounts.get(line) ?? 0);
    if (extra > 0) additions += extra;
  }
  for (const [line, count] of oldCounts) {
    const extra = count - (newCounts.get(line) ?? 0);
    if (extra > 0) deletions += extra;
  }
  return { additions, deletions };
}

export { buildTag, hashObject, isAncestor, parseTag };
