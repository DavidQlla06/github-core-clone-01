// MCP over Streamable HTTP (JSON-RPC 2.0, plain JSON replies). The legacy
// era is enough: server/discover answers method-not-found so clients fall
// back to initialize, and tools/list + tools/call expose the six canonical
// tools over the same store the REST surface reads.

import type { IncomingMessage, ServerResponse } from 'node:http';
import { parseJsonBody, sendJson } from './http-util.ts';
import { Store, VIEWER_ID, VIEWER_LOGIN, type Issue, type Pull, type Repo } from './store.ts';
import { isRecord } from './util.ts';

const SERVER_NAME = 'forge';
const SERVER_VERSION = '1.0.0';

// --------------------------------------------------------------------------------------------
// tools
// --------------------------------------------------------------------------------------------

interface ToolDef {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, unknown>; required: string[] };
}

const TOOLS: ToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository.' },
        name: { type: 'string', description: 'The name of the repository.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        title: { type: 'string', description: 'The title of the issue.' },
        body: { type: 'string', description: 'The body of the issue.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        title: { type: 'string', description: 'The title of the pull request.' },
        body: { type: 'string', description: 'The body of the pull request.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function repoJson(repo: Repo) {
  return {
    id: repo.id,
    name: repo.name,
    full_name: repo.fullName,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    html_url: `https://example.invalid/${repo.fullName}`,
  };
}

function issueJson(repo: Repo, issue: Issue) {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name })),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    comments: issue.comments.length,
  };
}

function pullJson(repo: Repo, pull: Pull) {
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  return {
    id: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.headRef, sha: headTip ?? pull.headSha },
    base: { ref: pull.baseRef, sha: baseTip ?? pull.baseSha },
    created_at: pull.createdAt,
  };
}

class ToolError extends Error {
  readonly code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

function requireString(args: Record<string, unknown>, name: string): string {
  const value = args[name];
  if (typeof value !== 'string' || value === '') throw new ToolError(-32602, `Missing required argument: ${name}`);
  return value;
}

function findRepo(store: Store, owner: string, name: string): Repo {
  if (owner !== VIEWER_LOGIN) throw new ToolError(-32602, `Repository ${owner}/${name} not found`);
  const repo = store.getRepo(owner, name);
  if (!repo) throw new ToolError(-32602, `Repository ${owner}/${name} not found`);
  return repo;
}

function callTool(store: Store, name: string, args: Record<string, unknown>): unknown {
  switch (name) {
    case 'create_repo': {
      const repoName = requireString(args, 'name');
      const owner = typeof args.owner === 'string' && args.owner !== '' ? args.owner : VIEWER_LOGIN;
      if (owner !== VIEWER_LOGIN) throw new ToolError(-32602, `Cannot create a repository for ${owner}`);
      if (store.getRepo(owner, repoName)) throw new ToolError(-32602, `Repository ${owner}/${repoName} already exists`);
      const repo = store.createRepo(
        owner,
        repoName,
        typeof args.description === 'string' ? args.description : '',
        args.private === true,
      );
      return repoJson(repo);
    }
    case 'get_repo': {
      const repo = findRepo(store, requireString(args, 'owner'), requireString(args, 'repo'));
      return repoJson(repo);
    }
    case 'create_issue': {
      const repo = findRepo(store, requireString(args, 'owner'), requireString(args, 'repo'));
      const issue = store.createIssue(
        repo,
        requireString(args, 'title'),
        typeof args.body === 'string' ? args.body : '',
        [],
      );
      return issueJson(repo, issue);
    }
    case 'list_issues': {
      const repo = findRepo(store, requireString(args, 'owner'), requireString(args, 'repo'));
      const state = typeof args.state === 'string' ? args.state : 'open';
      let issues = [...repo.issues.values()];
      if (state === 'open') issues = issues.filter((issue) => issue.state === 'open');
      else if (state === 'closed') issues = issues.filter((issue) => issue.state === 'closed');
      issues.sort((a, b) => b.createdSeq - a.createdSeq);
      return issues.map((issue) => issueJson(repo, issue));
    }
    case 'create_pull_request': {
      const repo = findRepo(store, requireString(args, 'owner'), requireString(args, 'repo'));
      const head = requireString(args, 'head');
      const base = requireString(args, 'base');
      if (!repo.refs.has(`refs/heads/${head}`) || !repo.refs.has(`refs/heads/${base}`)) {
        throw new ToolError(-32602, 'Head or base branch does not exist');
      }
      const existing = store.openPullForHead(repo, head);
      if (existing) return pullJson(repo, existing);
      const pull = store.createPull(
        repo,
        requireString(args, 'title'),
        typeof args.body === 'string' ? args.body : '',
        head,
        base,
      );
      return pullJson(repo, pull);
    }
    case 'merge_pull_request': {
      const repo = findRepo(store, requireString(args, 'owner'), requireString(args, 'repo'));
      const number = Number(args.pull_number);
      if (!Number.isInteger(number) || number <= 0) throw new ToolError(-32602, 'Missing required argument: pull_number');
      const pull = repo.pulls.get(number);
      if (!pull) throw new ToolError(-32602, `Pull request #${number} not found`);
      if (pull.state === 'closed') throw new ToolError(-32602, 'Pull request is already closed');
      const mergeSha = store.squashMerge(repo, pull);
      if (mergeSha === null) throw new ToolError(-32602, 'Merge conflict');
      const stamp = store.clock.tick();
      pull.state = 'closed';
      pull.merged = true;
      pull.mergedAt = store.clock.iso(stamp);
      pull.mergeCommitSha = mergeSha;
      pull.baseSha = mergeSha;
      return { ...pullJson(repo, pull), merged: true, sha: mergeSha };
    }
    default:
      throw new ToolError(-32601, `Unknown tool: ${name}`);
  }
}

// --------------------------------------------------------------------------------------------
// JSON-RPC transport
// --------------------------------------------------------------------------------------------

interface RpcRequest {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
  params?: unknown;
}

function rpcError(id: unknown, code: number, message: string) {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function rpcResult(id: unknown, resultValue: unknown) {
  return { jsonrpc: '2.0', id: id ?? null, result: resultValue };
}

export function handleMcp(req: IncomingMessage, res: ServerResponse, store: Store, body: Buffer): void {
  if (req.method === 'DELETE') {
    res.writeHead(204);
    res.end();
    return;
  }
  const parsed = parseJsonBody(body);
  if (!parsed.ok) {
    sendJson(res, 400, rpcError(null, -32700, 'Parse error'));
    return;
  }
  const request = parsed.value as RpcRequest;
  if (!isRecord(request) || typeof request.method !== 'string') {
    sendJson(res, 400, rpcError(null, -32600, 'Invalid Request'));
    return;
  }
  const id = 'id' in request ? request.id : undefined;
  const isNotification = id === undefined;
  const params = isRecord(request.params) ? request.params : {};
  const method = request.method;

  if (method === 'server/discover') {
    sendJson(res, 200, rpcError(id, -32601, 'Method not found'));
    return;
  }

  if (method === 'initialize') {
    const requestedVersion = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-03-26';
    if (isNotification) {
      res.writeHead(202);
      res.end();
      return;
    }
    sendJson(res, 200, rpcResult(id, {
      protocolVersion: requestedVersion,
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
    }));
    return;
  }

  if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
    res.writeHead(202);
    res.end();
    return;
  }

  if (isNotification) {
    res.writeHead(202);
    res.end();
    return;
  }

  if (method === 'ping') {
    sendJson(res, 200, rpcResult(id, {}));
    return;
  }

  if (method === 'tools/list') {
    // One frozen constant, so two calls return byte-identical tools.
    sendJson(res, 200, rpcResult(id, { tools: TOOLS }));
    return;
  }

  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? params.arguments : {};
    try {
      const value = callTool(store, name, args);
      const text = JSON.stringify(value);
      sendJson(res, 200, rpcResult(id, {
        content: [{ type: 'text', text }],
        structuredContent: value,
      }));
    } catch (err) {
      if (err instanceof ToolError) {
        sendJson(res, 200, rpcError(id, err.code, err.message));
      } else {
        sendJson(res, 200, rpcError(id, -32603, err instanceof Error ? err.message : 'Internal error'));
      }
    }
    return;
  }

  sendJson(res, 200, rpcError(id, -32601, `Method not found: ${method}`));
}
