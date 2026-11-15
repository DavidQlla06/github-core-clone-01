// GraphQL v4, for the fixed set of documents the conformance suite sends:
// repository/viewer/node reads, issue and pull-request queries and mutations,
// plus the introspection the suite probes (__type fields and enum values).
// A small hand-written parser and executor, no dependencies.

import { mergeBase } from './gitobj.ts';
import { parseJsonBody, sendError, sendJson } from './http-util.ts';
import { Store, VIEWER_ID, VIEWER_LOGIN, type Issue, type Pull, type Repo } from './store.ts';
import { b64url, b64urlDecode, isRecord } from './util.ts';
import type { IncomingMessage, ServerResponse } from 'node:http';

// --------------------------------------------------------------------------------------------
// parser
// --------------------------------------------------------------------------------------------

type ValueNode =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: ValueNode[] }
  | { kind: 'object'; fields: Array<{ name: string; value: ValueNode }> };

interface ArgumentNode {
  name: string;
  value: ValueNode;
}

interface FieldNode {
  kind: 'field';
  name: string;
  alias: string | null;
  args: ArgumentNode[];
  selections: SelectionNode[];
}

interface FragmentNode {
  kind: 'fragment';
  typeCondition: string;
  selections: SelectionNode[];
}

type SelectionNode = FieldNode | FragmentNode;

interface OperationNode {
  kind: 'query' | 'mutation';
  name: string | null;
  variables: Array<{ name: string; type: string }>;
  selections: SelectionNode[];
}

type Token =
  | { kind: 'punct'; value: string }
  | { kind: 'name'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: string }
  | { kind: 'float'; value: string };

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === ' ' || ch === '\n' || ch === '\r' || ch === '\t' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && source.startsWith('...', i)) {
      tokens.push({ kind: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if ('{}():$![]=@'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += source[j] as string;
          j += 1;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < source.length && /[0-9.eE+-]/.test(source[j] as string)) j += 1;
      const raw = source.slice(i, j);
      tokens.push(/[.eE]/.test(raw) ? { kind: 'float', value: raw } : { kind: 'int', value: raw });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j] as string)) j += 1;
      tokens.push({ kind: 'name', value: source.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  return tokens;
}

class Parser {
  private pos = 0;
  private readonly tokens: Token[];
  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  private peek(): Token | undefined {
    return this.tokens[this.pos];
  }

  private next(): Token {
    const token = this.tokens[this.pos];
    if (!token) throw new Error('unexpected end of GraphQL document');
    this.pos += 1;
    return token;
  }

  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) throw new Error(`expected ${value}, got ${JSON.stringify(token)}`);
  }

  private acceptPunct(value: string): boolean {
    const token = this.peek();
    if (token?.kind === 'punct' && token.value === value) {
      this.pos += 1;
      return true;
    }
    return false;
  }

  private expectName(): string {
    const token = this.next();
    if (token.kind !== 'name') throw new Error(`expected a name, got ${JSON.stringify(token)}`);
    return token.value;
  }

  parseDocument(): OperationNode[] {
    const operations: OperationNode[] = [];
    while (this.peek() !== undefined) {
      operations.push(this.parseOperation());
    }
    return operations;
  }

  private parseOperation(): OperationNode {
    let kind: 'query' | 'mutation' = 'query';
    const first = this.peek();
    if (first?.kind === 'name' && (first.value === 'query' || first.value === 'mutation')) {
      kind = this.next().value as 'query' | 'mutation';
    }
    let name: string | null = null;
    const next = this.peek();
    if (next?.kind === 'name') name = this.next().value;
    const variables: Array<{ name: string; type: string }> = [];
    if (this.acceptPunct('(')) {
      while (!this.acceptPunct(')')) {
        this.expectPunct('$');
        const varName = this.expectName();
        this.expectPunct(':');
        const type = this.parseType();
        if (this.acceptPunct('=')) this.parseValue();
        variables.push({ name: varName, type });
      }
    }
    const selections = this.parseSelections();
    return { kind, name, variables, selections };
  }

  private parseType(): string {
    if (this.acceptPunct('[')) {
      const inner = this.parseType();
      this.expectPunct(']');
      let out = `[${inner}]`;
      if (this.acceptPunct('!')) out += '!';
      return out;
    }
    const name = this.expectName();
    let out = name;
    if (this.acceptPunct('!')) out += '!';
    return out;
  }

  private parseSelections(): SelectionNode[] {
    this.expectPunct('{');
    const selections: SelectionNode[] = [];
    while (!this.acceptPunct('}')) {
      selections.push(this.parseSelection());
    }
    return selections;
  }

  private parseSelection(): SelectionNode {
    if (this.acceptPunct('...')) {
      const next = this.peek();
      if (next?.kind === 'name' && next.value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        return { kind: 'fragment', typeCondition, selections: this.parseSelections() };
      }
      throw new Error('fragment spreads are not supported');
    }
    const first = this.expectName();
    let name = first;
    let alias: string | null = null;
    if (this.acceptPunct(':')) {
      alias = first;
      name = this.expectName();
    }
    const args: ArgumentNode[] = [];
    if (this.acceptPunct('(')) {
      while (!this.acceptPunct(')')) {
        const argName = this.expectName();
        this.expectPunct(':');
        args.push({ name: argName, value: this.parseValue() });
      }
    }
    let selections: SelectionNode[] = [];
    const next = this.peek();
    if (next?.kind === 'punct' && next.value === '{') selections = this.parseSelections();
    return { kind: 'field', name, alias, args, selections };
  }

  private parseValue(): ValueNode {
    const token = this.next();
    if (token.kind === 'punct' && token.value === '$') {
      return { kind: 'variable', name: this.expectName() };
    }
    if (token.kind === 'punct' && token.value === '[') {
      const values: ValueNode[] = [];
      while (!this.acceptPunct(']')) values.push(this.parseValue());
      return { kind: 'list', values };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields: Array<{ name: string; value: ValueNode }> = [];
      while (!this.acceptPunct('}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      return { kind: 'object', fields };
    }
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'int') return { kind: 'int', value: Number(token.value) };
    if (token.kind === 'float') return { kind: 'float', value: Number(token.value) };
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    throw new Error(`unexpected value token ${JSON.stringify(token)}`);
  }
}

// --------------------------------------------------------------------------------------------
// executor
// --------------------------------------------------------------------------------------------

interface GqlContext {
  store: Store;
}

interface FieldResult {
  value: unknown;
  type: string | null;
  isList?: boolean;
}

type Resolver = (parent: unknown, args: Record<string, unknown>, ctx: GqlContext) => FieldResult | unknown;

function result(value: unknown, type: string | null = null, isList = false): FieldResult {
  return { value, type, isList };
}

function valueOf(node: ValueNode, variables: Record<string, unknown>): unknown {
  switch (node.kind) {
    case 'variable':
      return variables[node.name] ?? null;
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
    case 'enum':
      return node.value;
    case 'null':
      return null;
    case 'list':
      return node.values.map((child) => valueOf(child, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of node.fields) out[field.name] = valueOf(field.value, variables);
      return out;
    }
  }
}

function argsOf(field: FieldNode, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const arg of field.args) out[arg.name] = valueOf(arg.value, variables);
  return out;
}

function issueState(issue: Issue): 'OPEN' | 'CLOSED' {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}

function pullState(pull: Pull): 'OPEN' | 'CLOSED' | 'MERGED' {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function repoGlobalId(repo: Repo): string {
  return b64url(`Repository:${repo.id}`);
}

function issueGlobalId(repo: Repo, issue: Issue): string {
  return b64url(`Issue:${repo.id}:${issue.number}`);
}

function pullGlobalId(repo: Repo, pull: Pull): string {
  return b64url(`PullRequest:${repo.id}:${pull.number}`);
}

function decodeGlobalId(id: string): { kind: string; repoId: number; number: number } | null {
  try {
    const text = b64urlDecode(id);
    const [kind, repoPart, numberPart] = text.split(':');
    if (kind === 'Repository' && repoPart !== undefined) {
      return { kind, repoId: Number(repoPart), number: 0 };
    }
    if ((kind === 'Issue' || kind === 'PullRequest') && repoPart !== undefined && numberPart !== undefined) {
      return { kind, repoId: Number(repoPart), number: Number(numberPart) };
    }
    return null;
  } catch {
    return null;
  }
}

function findRepoById(ctx: GqlContext, id: number): Repo | undefined {
  return ctx.store.listViewerRepos().find((repo) => repo.id === id);
}

/** Resolve a mutation's repositoryId: either the global id or the numeric id. */
function findRepoByInputId(ctx: GqlContext, value: unknown): Repo | undefined {
  if (typeof value === 'string') {
    const decoded = decodeGlobalId(value);
    if (decoded !== null && decoded.kind === 'Repository') return findRepoById(ctx, decoded.repoId);
  }
  const numeric = Number(value ?? 0);
  if (Number.isInteger(numeric) && numeric > 0) return findRepoById(ctx, numeric);
  return undefined;
}

function repoObject(ctx: GqlContext, owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return ctx.store.getRepo(owner, name) ?? null;
}

const ISSUE_FIELDS = ['id', 'number', 'title', 'state', 'body'];
const PULL_REQUEST_FIELDS = ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'];
const REPOSITORY_FIELDS = [
  'id',
  'databaseId',
  'name',
  'nameWithOwner',
  'owner',
  'defaultBranchRef',
  'viewerPermission',
  'hasIssuesEnabled',
  'issue',
  'issues',
  'pullRequests',
  'pullRequest',
];

const TYPE_INFO: Record<string, { fields?: string[]; enumValues?: string[] }> = {
  Issue: { fields: ISSUE_FIELDS },
  PullRequest: { fields: PULL_REQUEST_FIELDS },
  Repository: { fields: REPOSITORY_FIELDS },
  SearchType: { enumValues: ['ISSUE', 'REPOSITORY', 'USER'] },
  IssueState: { enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { enumValues: ['CONFLICTING', 'MERGEABLE', 'UNKNOWN'] },
};

function typeField(args: Record<string, unknown>): FieldResult {
  const name = typeof args.name === 'string' ? args.name : '';
  const info = TYPE_INFO[name];
  if (!info) return result(null, '__Type');
  return result({ __typeName: name, fields: info.fields ?? null, enumValues: info.enumValues ?? null }, '__Type');
}

function pageInfo(hasNextPage: boolean, endCursor: string | null): Record<string, unknown> {
  return { hasNextPage, endCursor };
}

const RESOLVERS: Record<string, Record<string, Resolver>> = {
  Query: {
    viewer: () => result({ login: VIEWER_LOGIN, id: VIEWER_ID }, 'User'),
    repository: (_parent, args, ctx) => {
      const repo = repoObject(ctx, String(args.owner ?? ''), String(args.name ?? ''));
      return result(repo, 'Repository');
    },
    node: (_parent, args, ctx) => {
      const decoded = typeof args.id === 'string' ? decodeGlobalId(args.id) : null;
      if (!decoded) return result(null, null);
      const repo = findRepoById(ctx, decoded.repoId);
      if (!repo) return result(null, null);
      if (decoded.kind === 'Repository') return result(repo, 'Repository');
      if (decoded.kind === 'Issue') {
        const issue = repo.issues.get(decoded.number);
        return result(issue ?? null, 'Issue');
      }
      if (decoded.kind === 'PullRequest') {
        const pull = repo.pulls.get(decoded.number);
        return result(pull ?? null, 'PullRequest');
      }
      return result(null, null);
    },
    __type: (_parent, args) => typeField(args),
  },
  Mutation: {
    createIssue: (_parent, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const repo = findRepoByInputId(ctx, input.repositoryId);
      if (!repo) return result({ issue: null }, 'CreateIssuePayload');
      const issue = ctx.store.createIssue(
        repo,
        typeof input.title === 'string' ? input.title : '',
        typeof input.body === 'string' ? input.body : '',
        [],
      );
      return result({ issue, __repo: repo }, 'CreateIssuePayload');
    },
    closeIssue: (_parent, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = typeof input.issueId === 'string' ? decodeGlobalId(input.issueId) : null;
      if (!decoded || decoded.kind !== 'Issue') return result({ issue: null }, 'CloseIssuePayload');
      const repo = findRepoById(ctx, decoded.repoId);
      const issue = repo?.issues.get(decoded.number);
      if (!issue) return result({ issue: null }, 'CloseIssuePayload');
      issue.state = 'closed';
      issue.updatedAt = ctx.store.clock.iso(ctx.store.clock.tick());
      return result({ issue, __repo: repo }, 'CloseIssuePayload');
    },
    createPullRequest: (_parent, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const repo = findRepoByInputId(ctx, input.repositoryId);
      if (!repo) return result({ pullRequest: null }, 'CreatePullRequestPayload');
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : repo.defaultBranch;
      if (!repo.refs.has(`refs/heads/${head}`) || !repo.refs.has(`refs/heads/${base}`)) {
        return result({ pullRequest: null }, 'CreatePullRequestPayload');
      }
      const existing = ctx.store.openPullForHead(repo, head);
      if (existing) return result({ pullRequest: existing, __repo: repo }, 'CreatePullRequestPayload');
      const pull = ctx.store.createPull(
        repo,
        typeof input.title === 'string' ? input.title : '',
        typeof input.body === 'string' ? input.body : '',
        head,
        base,
      );
      return result({ pullRequest: pull, __repo: repo }, 'CreatePullRequestPayload');
    },
    mergePullRequest: (_parent, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = typeof input.pullRequestId === 'string' ? decodeGlobalId(input.pullRequestId) : null;
      if (!decoded || decoded.kind !== 'PullRequest') return result({ pullRequest: null }, 'MergePullRequestPayload');
      const repo = findRepoById(ctx, decoded.repoId);
      const pull = repo?.pulls.get(decoded.number);
      if (!pull || !repo) return result({ pullRequest: null }, 'MergePullRequestPayload');
      if (pull.state === 'open') {
        const mergeSha = ctx.store.squashMerge(repo, pull);
        if (mergeSha !== null) {
          const stamp = ctx.store.clock.tick();
          pull.state = 'closed';
          pull.merged = true;
          pull.mergedAt = ctx.store.clock.iso(stamp);
          pull.mergeCommitSha = mergeSha;
          pull.baseSha = mergeSha;
        }
      }
      return result({ pullRequest: pull, __repo: repo }, 'MergePullRequestPayload');
    },
    addComment: (_parent, args, ctx) => {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = typeof input.subjectId === 'string' ? decodeGlobalId(input.subjectId) : null;
      if (!decoded) return result({ commentEdge: null }, 'AddCommentPayload');
      const repo = findRepoById(ctx, decoded.repoId);
      if (!repo) return result({ commentEdge: null }, 'AddCommentPayload');
      const issue = decoded.kind === 'Issue' ? repo.issues.get(decoded.number) : undefined;
      if (!issue) return result({ commentEdge: null }, 'AddCommentPayload');
      const comment = ctx.store.addComment(repo, issue, typeof input.body === 'string' ? input.body : '');
      return result({ commentEdge: { node: comment }, __repo: repo }, 'AddCommentPayload');
    },
  },
  User: {
    login: (parent) => (parent as { login: string }).login,
    id: (parent) => (parent as { id: number }).id,
  },
  Repository: {
    id: (parent) => repoGlobalId(parent as Repo),
    databaseId: (parent) => (parent as Repo).id,
    name: (parent) => (parent as Repo).name,
    nameWithOwner: (parent) => (parent as Repo).fullName,
    owner: (parent) => result({ login: (parent as Repo).owner, id: VIEWER_ID }, 'User'),
    defaultBranchRef: (parent) => {
      const repo = parent as Repo;
      const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      return result(tip === undefined ? null : { name: repo.defaultBranch }, 'Ref');
    },
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    issue: (parent, args) => {
      const repo = parent as Repo;
      const issue = repo.issues.get(Number(args.number ?? 0));
      return result(issue ?? null, 'Issue');
    },
    issues: (parent, args) => {
      const repo = parent as Repo;
      let issues = [...repo.issues.values()];
      const states = Array.isArray(args.states) ? (args.states as string[]) : null;
      if (states) {
        const wanted = new Set(states);
        issues = issues.filter((issue) => wanted.has(issueState(issue)));
      }
      const orderBy = isRecord(args.orderBy) ? args.orderBy : {};
      const direction = orderBy.direction === 'ASC' ? 'ASC' : 'DESC';
      issues.sort((a, b) => (direction === 'ASC' ? a.number - b.number : b.number - a.number));
      const first = typeof args.first === 'number' ? args.first : 100;
      const after = typeof args.after === 'string' ? args.after : null;
      const all = issues;
      let start = 0;
      if (after) {
        const decoded = decodeCursor(after);
        const index = all.findIndex((issue) => issue.number === decoded);
        if (index >= 0) start = index + 1;
      }
      const nodes = all.slice(start, start + first);
      const hasNextPage = start + nodes.length < all.length;
      const endCursor = nodes.length > 0 ? encodeCursor(nodes[nodes.length - 1]?.number ?? 0) : null;
      return result(
        { nodes, pageInfo: pageInfo(hasNextPage, endCursor) },
        'IssueConnection',
      );
    },
    pullRequests: (parent, args) => {
      const repo = parent as Repo;
      let pulls = [...repo.pulls.values()].filter((pull) => pull.state === 'open');
      const first = typeof args.first === 'number' ? args.first : 100;
      pulls.sort((a, b) => b.number - a.number);
      const nodes = pulls.slice(0, first);
      return result(
        { nodes, pageInfo: pageInfo(pulls.length > nodes.length, nodes.length > 0 ? encodeCursor(nodes[nodes.length - 1]?.number ?? 0) : null) },
        'PullRequestConnection',
      );
    },
    pullRequest: (parent, args) => {
      const repo = parent as Repo;
      const pull = repo.pulls.get(Number(args.number ?? 0));
      return result(pull ?? null, 'PullRequest');
    },
  },
  Issue: {
    id: (parent, args, ctx) => {
      const issue = parent as Issue;
      const repo = findRepoOfIssue(ctx, issue);
      return repo ? issueGlobalId(repo, issue) : '';
    },
    number: (parent) => (parent as Issue).number,
    title: (parent) => (parent as Issue).title,
    state: (parent) => issueState(parent as Issue),
    body: (parent) => (parent as Issue).body,
  },
  PullRequest: {
    id: (parent, args, ctx) => {
      const pull = parent as Pull;
      const repo = findRepoOfPull(ctx, pull);
      return repo ? pullGlobalId(repo, pull) : '';
    },
    number: (parent) => (parent as Pull).number,
    state: (parent) => pullState(parent as Pull),
    merged: (parent) => (parent as Pull).merged,
    headRefName: (parent) => (parent as Pull).headRef,
    baseRefName: (parent) => (parent as Pull).baseRef,
    mergeable: (parent, args, ctx) => {
      const pull = parent as Pull;
      const repo = findRepoOfPull(ctx, pull);
      if (!repo || pull.state !== 'open') return 'UNKNOWN';
      return ctx.store.mergeable(repo, pull);
    },
    files: (parent, args, ctx) => {
      const pull = parent as Pull;
      const repo = findRepoOfPull(ctx, pull);
      if (!repo) return result({ nodes: [], pageInfo: pageInfo(false, null) }, 'PullRequestChangedFileConnection');
      const base = ctx.store.peelToCommit(repo, pull.baseSha) ?? pull.baseSha;
      const head = ctx.store.peelToCommit(repo, pull.headSha) ?? pull.headSha;
      const ancestor = mergeBase((oid: string) => repo.objects.get(oid), base, head) ?? base;
      const changes = ctx.store.diffTrees(repo, ancestor, head);
      const first = typeof args.first === 'number' ? args.first : 100;
      const nodes = changes.slice(0, first).map((change) => ({ path: change.path }));
      return result({ nodes, pageInfo: pageInfo(changes.length > nodes.length, null) }, 'PullRequestChangedFileConnection');
    },
  },
  IssueConnection: {
    nodes: (parent) => result((parent as { nodes: Issue[] }).nodes, 'Issue', true),
    pageInfo: (parent) => result((parent as { pageInfo: Record<string, unknown> }).pageInfo, 'PageInfo'),
  },
  PullRequestConnection: {
    nodes: (parent) => result((parent as { nodes: Pull[] }).nodes, 'PullRequest', true),
    pageInfo: (parent) => result((parent as { pageInfo: Record<string, unknown> }).pageInfo, 'PageInfo'),
  },
  PullRequestChangedFileConnection: {
    nodes: (parent) => result((parent as { nodes: Array<{ path: string }> }).nodes, 'PullRequestChangedFile', true),
    pageInfo: (parent) => result((parent as { pageInfo: Record<string, unknown> }).pageInfo, 'PageInfo'),
  },
  PullRequestChangedFile: {
    path: (parent) => (parent as { path: string }).path,
  },
  PageInfo: {
    hasNextPage: (parent) => (parent as { hasNextPage: boolean }).hasNextPage,
    endCursor: (parent) => (parent as { endCursor: string | null }).endCursor,
  },
  Ref: {
    name: (parent) => (parent as { name: string }).name,
  },
  __Type: {
    fields: (parent, args) => {
      const info = parent as { fields: string[] | null };
      void args;
      return result((info.fields ?? []).map((name) => ({ name })), '__Field', true);
    },
    enumValues: (parent, args) => {
      const info = parent as { enumValues: string[] | null };
      void args;
      return result((info.enumValues ?? []).map((name) => ({ name })), '__EnumValue', true);
    },
    name: (parent) => (parent as { __typeName: string }).__typeName,
  },
  __Field: {
    name: (parent) => (parent as { name: string }).name,
  },
  __EnumValue: {
    name: (parent) => (parent as { name: string }).name,
  },
  CreateIssuePayload: {
    issue: (parent) => {
      const payload = parent as { issue: Issue; __repo: Repo };
      return result(payload.issue, 'Issue');
    },
  },
  CloseIssuePayload: {
    issue: (parent) => {
      const payload = parent as { issue: Issue; __repo: Repo };
      return result(payload.issue, 'Issue');
    },
  },
  CreatePullRequestPayload: {
    pullRequest: (parent) => {
      const payload = parent as { pullRequest: Pull; __repo: Repo };
      return result(payload.pullRequest, 'PullRequest');
    },
  },
  MergePullRequestPayload: {
    pullRequest: (parent) => {
      const payload = parent as { pullRequest: Pull; __repo: Repo };
      return result(payload.pullRequest, 'PullRequest');
    },
  },
  AddCommentPayload: {
    commentEdge: (parent) => {
      const payload = parent as { commentEdge: { node: unknown }; __repo: Repo };
      return result(payload.commentEdge, 'IssueCommentEdge');
    },
  },
  IssueCommentEdge: {
    node: (parent) => result((parent as { node: unknown }).node, 'IssueComment'),
  },
  IssueComment: {
    id: (parent) => b64url(`IssueComment:${(parent as { id: number }).id}`),
    body: (parent) => (parent as { body: string }).body,
  },
};

function findRepoOfIssue(ctx: GqlContext, issue: Issue): Repo | undefined {
  return ctx.store.listViewerRepos().find((repo) => repo.issues.get(issue.number) === issue);
}

function findRepoOfPull(ctx: GqlContext, pull: Pull): Repo | undefined {
  return ctx.store.listViewerRepos().find((repo) => repo.pulls.get(pull.number) === pull);
}

function encodeCursor(number: number): string {
  return b64url(`cursor:${number}`);
}

function decodeCursor(cursor: string): number {
  try {
    const text = b64urlDecode(cursor);
    const match = /^cursor:(\d+)$/.exec(text);
    return match ? Number(match[1]) : -1;
  } catch {
    return -1;
  }
}

function normalize(resultValue: unknown): FieldResult {
  if (isRecord(resultValue) && 'value' in resultValue && 'type' in resultValue) {
    return resultValue as unknown as FieldResult;
  }
  return { value: resultValue, type: null };
}

function executeSelections(
  typeName: string,
  parent: unknown,
  selections: SelectionNode[],
  variables: Record<string, unknown>,
  ctx: GqlContext,
  errors: Array<{ message: string }>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      if (selection.typeCondition === typeName) {
        Object.assign(out, executeSelections(typeName, parent, selection.selections, variables, ctx, errors));
      }
      continue;
    }
    const key = selection.alias ?? selection.name;
    const table = RESOLVERS[typeName];
    const resolver = table?.[selection.name];
    if (!resolver) {
      errors.push({ message: `Cannot query field "${selection.name}" on type "${typeName}".` });
      out[key] = null;
      continue;
    }
    const args = argsOf(selection, variables);
    let resolved: FieldResult;
    try {
      resolved = normalize(resolver(parent, args, ctx));
    } catch (err) {
      errors.push({ message: err instanceof Error ? err.message : 'resolver failed' });
      out[key] = null;
      continue;
    }
    if (resolved.value === null || resolved.value === undefined) {
      out[key] = null;
      continue;
    }
    if (selection.selections.length > 0 && resolved.type !== null) {
      if (resolved.isList && Array.isArray(resolved.value)) {
        out[key] = resolved.value.map((item) =>
          item === null ? null : executeSelections(resolved.type as string, item, selection.selections, variables, ctx, errors),
        );
      } else {
        out[key] = executeSelections(resolved.type, resolved.value, selection.selections, variables, ctx, errors);
      }
    } else {
      out[key] = resolved.value;
    }
  }
  return out;
}

export interface GraphqlResult {
  data: Record<string, unknown> | null;
  errors?: Array<{ message: string }>;
}

export function executeGraphql(
  store: Store,
  query: string,
  variables: Record<string, unknown>,
  operationName: string | null,
): GraphqlResult {
  const ctx: GqlContext = { store };
  let operations: OperationNode[];
  try {
    operations = new Parser(tokenize(query)).parseDocument();
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
  }
  const operation = operationName
    ? operations.find((op) => op.name === operationName)
    : operations[0];
  if (!operation) return { data: null, errors: [{ message: `unknown operation ${operationName ?? ''}` }] };
  const errors: Array<{ message: string }> = [];
  const rootType = operation.kind === 'mutation' ? 'Mutation' : 'Query';
  const data = executeSelections(rootType, {}, operation.selections, variables, ctx, errors);
  const out: GraphqlResult = { data };
  if (errors.length > 0) out.errors = errors;
  return out;
}

// --------------------------------------------------------------------------------------------
// HTTP entry point
// --------------------------------------------------------------------------------------------

export function handleGraphql(req: IncomingMessage, res: ServerResponse, store: Store, body: Buffer): void {
  const parsed = parseJsonBody(body);
  if (!parsed.ok) {
    sendError(res, 400, 'Problems parsing JSON');
    return;
  }
  const runOne = (operation: unknown): GraphqlResult => {
    if (!isRecord(operation) || typeof operation.query !== 'string') {
      return { data: null, errors: [{ message: 'A GraphQL operation must provide a query string' }] };
    }
    const variables = isRecord(operation.variables) ? operation.variables : {};
    const operationName = typeof operation.operationName === 'string' ? operation.operationName : null;
    return executeGraphql(store, operation.query, variables, operationName);
  };
  if (Array.isArray(parsed.value)) {
    sendJson(res, 200, parsed.value.map(runOne));
    return;
  }
  const resultValue = runOne(parsed.value);
  void req;
  sendJson(res, 200, resultValue);
}
