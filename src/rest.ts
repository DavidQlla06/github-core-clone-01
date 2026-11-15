// GitHub REST v3: repositories, branches, commits, contents, labels, issues,
// comments and pull requests, over the one in-memory store. Statuses, shapes
// and pagination follow what the conformance suite requires; anything the
// suite never sends is answered the GitHub way where it costs nothing.

import type { IncomingMessage, ServerResponse } from 'node:http';
import { mergeBase, parseCommit, parseTree } from './gitobj.ts';
import { parseJsonBody, sendError, sendJson } from './http-util.ts';
import { Store, VIEWER_EMAIL, VIEWER_ID, VIEWER_LOGIN, VIEWER_NAME, type Issue, type Pull, type Repo } from './store.ts';
import { b64decode, b64encode, b64url, isRecord } from './util.ts';

export interface RestContext {
  store: Store;
  req: IncomingMessage;
  res: ServerResponse;
  segments: string[];
  query: URLSearchParams;
  body: Buffer;
  origin: string;
}

const SCOPES = 'repo, read:org';

// --------------------------------------------------------------------------------------------
// shapes
// --------------------------------------------------------------------------------------------

function userJson(login: string, id: number) {
  return { login, id, node_id: `U_${b64url(`User:${id}`)}`, type: 'User', site_admin: false };
}

function repoJson(repo: Repo) {
  return {
    id: repo.id,
    node_id: `R_${b64url(`Repository:${repo.id}`)}`,
    name: repo.name,
    full_name: repo.fullName,
    owner: userJson(repo.owner, VIEWER_ID),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://example.invalid/${repo.fullName}`,
    clone_url: `https://example.invalid/${repo.fullName}.git`,
    git_url: `git://example.invalid/${repo.fullName}.git`,
    ssh_url: `git@example.invalid:${repo.fullName}.git`,
    created_at: repo.createdAt,
    updated_at: repo.createdAt,
    pushed_at: repo.createdAt,
    language: null,
    fork: false,
    archived: false,
    disabled: false,
    has_issues: true,
    has_projects: false,
    has_wiki: false,
    visibility: repo.isPrivate ? 'private' : 'public',
  };
}

function labelJson(repo: Repo, name: string) {
  const label = repo.labels.get(name);
  return { name, color: label?.color ?? 'ededed', description: label?.description ?? '' };
}

function issueJson(repo: Repo, issue: Issue) {
  return {
    id: issue.id,
    node_id: `I_${b64url(`Issue:${repo.id}:${issue.number}`)}`,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => labelJson(repo, name)),
    user: userJson(VIEWER_LOGIN, VIEWER_ID),
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.state === 'closed' ? issue.updatedAt : null,
    comments: issue.comments.length,
    html_url: `https://example.invalid/${repo.fullName}/issues/${issue.number}`,
  };
}

function commentJson(repo: Repo, issue: Issue, comment: { id: number; body: string; user: string; createdAt: string }) {
  return {
    id: comment.id,
    node_id: `IC_${b64url(`IssueComment:${repo.id}:${issue.number}:${comment.id}`)}`,
    body: comment.body,
    user: userJson(comment.user, VIEWER_ID),
    created_at: comment.createdAt,
    updated_at: comment.createdAt,
    html_url: `https://example.invalid/${repo.fullName}/issues/${issue.number}#issuecomment-${comment.id}`,
  };
}

function pullHeadJson(repo: Repo, pull: Pull, side: 'head' | 'base') {
  const ref = side === 'head' ? pull.headRef : pull.baseRef;
  const tip = repo.refs.get(`refs/heads/${ref}`);
  const sha = tip ?? (side === 'head' ? pull.headSha : pull.baseSha);
  return {
    label: `${repo.owner}:${ref}`,
    ref,
    sha,
    user: userJson(repo.owner, VIEWER_ID),
    repo: repoJson(repo),
  };
}

function pullJson(repo: Repo, pull: Pull) {
  return {
    id: pull.id,
    node_id: `PR_${b64url(`PullRequest:${repo.id}:${pull.number}`)}`,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: pullHeadJson(repo, pull, 'head'),
    base: pullHeadJson(repo, pull, 'base'),
    user: userJson(VIEWER_LOGIN, VIEWER_ID),
    created_at: pull.createdAt,
    updated_at: pull.createdAt,
    closed_at: pull.state === 'closed' ? pull.mergedAt ?? pull.createdAt : null,
    draft: false,
    html_url: `https://example.invalid/${repo.fullName}/pull/${pull.number}`,
  };
}

// --------------------------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------------------------

function repoOr404(ctx: RestContext, owner: string, name: string): Repo | null {
  const repo = owner === VIEWER_LOGIN ? ctx.store.getRepo(owner, name) : undefined;
  if (!repo) {
    sendError(ctx.res, 404, 'Not Found');
    return null;
  }
  return repo;
}

function paginate<T>(ctx: RestContext, items: readonly T[]): { page: T[]; link: string | null } {
  const perPage = Math.min(100, Math.max(1, Number(ctx.query.get('per_page') ?? '30') || 30));
  const page = Math.max(1, Number(ctx.query.get('page') ?? '1') || 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  if (totalPages <= 1) return { page: [...slice], link: null };
  const base = `${ctx.origin}${ctx.req.url?.split('?')[0] ?? ''}`;
  const linkFor = (p: number, rel: string): string => {
    const params = new URLSearchParams(ctx.query);
    params.set('per_page', String(perPage));
    params.set('page', String(p));
    return `<${base}?${params.toString()}>; rel="${rel}"`;
  };
  const links: string[] = [];
  if (page < totalPages) links.push(linkFor(page + 1, 'next'), linkFor(totalPages, 'last'));
  if (page > 1) links.push(linkFor(1, 'first'), linkFor(page - 1, 'prev'));
  return { page: [...slice], link: links.join(', ') };
}

function sendPage<T>(ctx: RestContext, items: readonly T[]): void {
  const { page, link } = paginate(ctx, items);
  sendJson(ctx.res, 200, page, link ? { link, 'x-oauth-scopes': SCOPES } : { 'x-oauth-scopes': SCOPES });
}

function bodyObject(ctx: RestContext): Record<string, unknown> | null {
  const parsed = parseJsonBody(ctx.body);
  if (!parsed.ok) {
    sendError(ctx.res, 400, 'Problems parsing JSON');
    return null;
  }
  if (!isRecord(parsed.value)) {
    sendError(ctx.res, 400, 'Problems parsing JSON');
    return null;
  }
  return parsed.value;
}

function notFoundNumber(value: string): number | null {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** Direct children of a directory inside a commit's tree. */
function listDirectory(
  store: Store,
  repo: Repo,
  commitOid: string,
  dirPath: string,
): Array<{ type: 'file' | 'dir'; name: string; path: string; sha: string }> | null {
  const object = repo.objects.get(commitOid);
  if (!object || object.type !== 'commit') return null;
  const rootTree = parseCommit(object.data).tree;
  let treeOid = rootTree;
  if (dirPath !== '') {
    const segments = dirPath.split('/');
    for (const segment of segments) {
      const tree = repo.objects.get(treeOid);
      if (!tree || tree.type !== 'tree') return null;
      const entry = parseTree(tree.data).find((candidate) => candidate.name === segment && candidate.mode === '40000');
      if (!entry) return null;
      treeOid = entry.oid;
    }
  }
  const tree = repo.objects.get(treeOid);
  if (!tree || tree.type !== 'tree') return null;
  return parseTree(tree.data)
    .map((entry) => ({
      type: (entry.mode === '40000' ? 'dir' : 'file') as 'file' | 'dir',
      name: entry.name,
      path: dirPath === '' ? entry.name : `${dirPath}/${entry.name}`,
      sha: entry.oid,
    }))
    .sort((a, b) => (a.name < b.name ? -1 : 1));
}

// --------------------------------------------------------------------------------------------
// router
// --------------------------------------------------------------------------------------------

export function handleRest(ctx: RestContext): void {
  const { req, res, segments: s } = ctx;
  const method = req.method ?? 'GET';

  // API root and meta.
  if (s.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, {
        current_user_url: '/api/v3/user',
        rate_limit_url: '/api/v3/rate_limit',
        repository_url: '/api/v3/repos/{owner}/{repo}',
      }, { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }
  if (s[0] === 'meta' && s.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, { installed_version: '1.0.0' }, { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // The authenticated user.
  if (s[0] === 'user' && s.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, { ...userJson(VIEWER_LOGIN, VIEWER_ID), name: VIEWER_NAME, email: VIEWER_EMAIL }, { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // POST /user/repos and GET /user/repos.
  if (s[0] === 'user' && s[1] === 'repos' && s.length === 2) {
    if (method === 'POST') {
      const body = bodyObject(ctx);
      if (!body) return;
      const name = typeof body.name === 'string' ? body.name : '';
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name) || name.endsWith('.git')) {
        sendError(res, 422, 'Invalid repository name');
        return;
      }
      if (ctx.store.getRepo(VIEWER_LOGIN, name)) {
        sendError(res, 422, `Repository ${VIEWER_LOGIN}/${name} already exists`);
        return;
      }
      const repo = ctx.store.createRepo(
        VIEWER_LOGIN,
        name,
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      sendJson(res, 201, repoJson(repo), { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (method === 'GET') {
      const repos = ctx.store.listViewerRepos();
      sendPage(ctx, repos.map((repo) => repoJson(repo)));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // /repos/{owner}/{repo}/...
  if (s[0] === 'repos' && s.length >= 3) {
    handleRepoRoute(ctx, s[1] as string, s[2] as string, s.slice(3));
    return;
  }

  sendError(res, 404, 'Not Found');
}

function handleRepoRoute(ctx: RestContext, owner: string, name: string, rest: string[]): void {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';
  const repo = repoOr404(ctx, owner, name);
  if (!repo) return;

  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, repoJson(repo), { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (method === 'PATCH') {
      const body = bodyObject(ctx);
      if (!body) return;
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.name === 'string' && body.name !== repo.name) {
        // Renames are not part of the suite; keep the name.
      }
      sendJson(res, 200, repoJson(repo), { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (method === 'DELETE') {
      ctx.store.deleteRepo(repo);
      res.writeHead(204, { 'x-github-request-id': `req-${Date.now().toString(16)}` });
      res.end();
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  const [head, ...tail] = rest as [string, ...string[]];

  if (head === 'branches') {
    if (tail.length === 0 && method === 'GET') {
      const branches = [...repo.refs.keys()]
        .filter((ref) => ref.startsWith('refs/heads/'))
        .sort()
        .map((ref) => ({
          name: ref.slice('refs/heads/'.length),
          commit: { sha: repo.refs.get(ref) as string },
          protected: false,
        }));
      sendJson(res, 200, branches, { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (tail.length === 1 && method === 'GET') {
      const oid = repo.refs.get(`refs/heads/${tail[0]}`);
      if (!oid) {
        sendError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, { name: tail[0], commit: { sha: oid }, protected: false }, { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (head === 'commits') {
    if (tail.length === 0 && method === 'GET') {
      const ref = ctx.query.get('sha') ?? repo.defaultBranch;
      const commits = ctx.store.listCommits(repo, ref).map((commit) => ({
        sha: commit.sha,
        commit: {
          message: commit.message.replace(/\n+$/, ''),
          author: identityJson(commit.author),
          committer: identityJson(commit.committer),
        },
        author: userJson(VIEWER_LOGIN, VIEWER_ID),
        committer: userJson(VIEWER_LOGIN, VIEWER_ID),
      }));
      sendPage(ctx, commits);
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (head === 'git' && tail[0] === 'refs') {
    if (method === 'POST' && tail.length === 1) {
      const body = bodyObject(ctx);
      if (!body) return;
      const ref = typeof body.ref === 'string' ? body.ref : '';
      const sha = typeof body.sha === 'string' ? body.sha.toLowerCase() : '';
      if (!ref.startsWith('refs/') || !/^[0-9a-f]{40}$/.test(sha) || !repo.objects.has(sha)) {
        sendError(res, 422, 'Invalid ref or sha');
        return;
      }
      if (repo.refs.has(ref)) {
        sendError(res, 422, `Reference ${ref} already exists`);
        return;
      }
      ctx.store.setRef(repo, ref, sha);
      const object = repo.objects.get(sha);
      sendJson(res, 201, { ref, object: { sha, type: object?.type ?? 'commit' } }, { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (method === 'GET' && tail.length >= 2) {
      const refName = `refs/${tail.slice(1).join('/')}`;
      const oid = repo.refs.get(refName);
      if (!oid) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const object = repo.objects.get(oid);
      sendJson(res, 200, { ref: refName, object: { sha: oid, type: object?.type ?? 'commit' } }, { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (head === 'contents') {
    handleContents(ctx, repo, tail.join('/'));
    return;
  }

  if (head === 'labels') {
    if (tail.length === 0 && method === 'POST') {
      const body = bodyObject(ctx);
      if (!body) return;
      const labelName = typeof body.name === 'string' ? body.name : '';
      if (labelName === '') {
        sendError(res, 422, 'Label name is required');
        return;
      }
      if (repo.labels.has(labelName)) {
        sendError(res, 422, `Label ${labelName} already exists`);
        return;
      }
      repo.labels.set(labelName, {
        name: labelName,
        color: typeof body.color === 'string' ? body.color.replace(/^#/, '') : 'ededed',
        description: typeof body.description === 'string' ? body.description : '',
      });
      sendJson(res, 201, labelJson(repo, labelName), { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (tail.length === 0 && method === 'GET') {
      sendJson(res, 200, [...repo.labels.keys()].map((labelName) => labelJson(repo, labelName)), { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (head === 'issues') {
    handleIssues(ctx, repo, tail);
    return;
  }

  if (head === 'pulls') {
    handlePulls(ctx, repo, tail);
    return;
  }

  sendError(res, 404, 'Not Found');
}

function identityJson(identity: string): { name: string; email: string; date: string } {
  const match = /^(.*) <([^>]*)> (\d+) [+-]\d{4}$/.exec(identity);
  if (!match) return { name: VIEWER_NAME, email: VIEWER_EMAIL, date: new Date(0).toISOString() };
  return {
    name: match[1] as string,
    email: match[2] as string,
    date: new Date(Number(match[3]) * 1000).toISOString(),
  };
}

function handleContents(ctx: RestContext, repo: Repo, path: string): void {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';
  const branch = ctx.query.get('ref') ?? undefined;
  const refName = branch ?? repo.defaultBranch;

  if (method === 'GET') {
    const tip = ctx.store.resolveRef(repo, refName);
    if (!tip) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (path === '') {
      const entries = listDirectory(ctx.store, repo, tip, '');
      if (entries === null) {
        sendError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, entries, { 'x-oauth-scopes': SCOPES });
      return;
    }
    const files = ctx.store.filesOfCommit(repo, tip);
    const file = files.get(path);
    if (file) {
      const object = repo.objects.get(file.oid);
      const content = object?.type === 'blob' ? object.data : Buffer.alloc(0);
      sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        size: content.length,
        name: path.split('/').pop() ?? path,
        path,
        content: b64encode(content),
        sha: file.oid,
      }, { 'x-oauth-scopes': SCOPES });
      return;
    }
    const entries = listDirectory(ctx.store, repo, tip, path);
    if (entries !== null) {
      sendJson(res, 200, entries, { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (method === 'PUT') {
    const body = bodyObject(ctx);
    if (!body) return;
    const message = typeof body.message === 'string' ? body.message : 'Update file';
    const contentB64 = typeof body.content === 'string' ? body.content : '';
    const content = b64decode(contentB64);
    const targetBranch = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
    const existingRef = repo.refs.get(`refs/heads/${targetBranch}`);
    const files = existingRef ? ctx.store.filesOfCommit(repo, existingRef) : new Map();
    const existing = files.get(path);
    const sha = typeof body.sha === 'string' ? body.sha.toLowerCase() : undefined;
    if (existing && sha !== undefined && sha !== existing.oid) {
      sendError(res, 409, 'Conflict: the file has changed since the given sha');
      return;
    }
    const changes = new Map<string, Buffer | null>();
    changes.set(path, content);
    const { commitSha } = ctx.store.commitFiles(repo, targetBranch, changes, message);
    const blobOid = ctx.store.putObject(repo, 'blob', content);
    const status = existing ? 200 : 201;
    sendJson(res, status, {
      content: { name: path.split('/').pop() ?? path, path, sha: blobOid, size: content.length, type: 'file', encoding: 'base64' },
      commit: { sha: commitSha, message },
    }, { 'x-oauth-scopes': SCOPES });
    return;
  }

  if (method === 'DELETE') {
    const body = bodyObject(ctx);
    if (!body) return;
    const message = typeof body.message === 'string' ? body.message : 'Delete file';
    const targetBranch = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
    const existingRef = repo.refs.get(`refs/heads/${targetBranch}`);
    const files = existingRef ? ctx.store.filesOfCommit(repo, existingRef) : new Map();
    const existing = files.get(path);
    if (!existing) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const sha = typeof body.sha === 'string' ? body.sha.toLowerCase() : undefined;
    if (sha !== undefined && sha !== existing.oid) {
      sendError(res, 409, 'Conflict: the file has changed since the given sha');
      return;
    }
    const changes = new Map<string, Buffer | null>();
    changes.set(path, null);
    const { commitSha } = ctx.store.commitFiles(repo, targetBranch, changes, message);
    sendJson(res, 200, { commit: { sha: commitSha, message } }, { 'x-oauth-scopes': SCOPES });
    return;
  }

  sendError(res, 404, 'Not Found');
}

function handleIssues(ctx: RestContext, repo: Repo, tail: string[]): void {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';

  if (tail.length === 0) {
    if (method === 'POST') {
      const body = bodyObject(ctx);
      if (!body) return;
      const title = typeof body.title === 'string' ? body.title : '';
      const issueBody = typeof body.body === 'string' ? body.body : '';
      const rawLabels = Array.isArray(body.labels) ? body.labels : [];
      const labels: string[] = [];
      for (const entry of rawLabels) {
        const name = typeof entry === 'string' ? entry : isRecord(entry) && typeof entry.name === 'string' ? entry.name : '';
        if (name === '') continue;
        if (!repo.labels.has(name)) {
          sendError(res, 422, `Label ${name} does not exist`);
          return;
        }
        labels.push(name);
      }
      const issue = ctx.store.createIssue(repo, title, issueBody, labels);
      sendJson(res, 201, issueJson(repo, issue), { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (method === 'GET') {
      const state = ctx.query.get('state') ?? 'open';
      const sort = ctx.query.get('sort') ?? 'created';
      const direction = ctx.query.get('direction') ?? 'desc';
      let issues = [...repo.issues.values()];
      if (state !== 'all') issues = issues.filter((issue) => issue.state === state);
      if (sort === 'created') {
        issues.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
      }
      sendPage(ctx, issues.map((issue) => issueJson(repo, issue)));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  const number = notFoundNumber(tail[0] as string);
  if (number === null) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const issue = repo.issues.get(number);
  if (!issue) {
    sendError(res, 404, 'Not Found');
    return;
  }

  if (tail.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, issueJson(repo, issue), { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (method === 'PATCH') {
      const body = bodyObject(ctx);
      if (!body) return;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
      if (Array.isArray(body.labels)) {
        const labels: string[] = [];
        for (const entry of body.labels) {
          const name = typeof entry === 'string' ? entry : isRecord(entry) && typeof entry.name === 'string' ? entry.name : '';
          if (name !== '' && repo.labels.has(name)) labels.push(name);
        }
        issue.labels = labels;
      }
      issue.updatedAt = ctx.store.clock.iso(ctx.store.clock.tick());
      sendJson(res, 200, issueJson(repo, issue), { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (tail[1] === 'comments') {
    if (method === 'POST') {
      const body = bodyObject(ctx);
      if (!body) return;
      const commentBody = typeof body.body === 'string' ? body.body : '';
      const comment = ctx.store.addComment(repo, issue, commentBody);
      sendJson(res, 201, commentJson(repo, issue, comment), { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (method === 'GET') {
      sendJson(res, 200, issue.comments.map((comment) => commentJson(repo, issue, comment)), { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  sendError(res, 404, 'Not Found');
}

function handlePulls(ctx: RestContext, repo: Repo, tail: string[]): void {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';

  if (tail.length === 0) {
    if (method === 'POST') {
      const body = bodyObject(ctx);
      if (!body) return;
      const head = typeof body.head === 'string' ? body.head : '';
      const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
      const title = typeof body.title === 'string' ? body.title : '';
      const pullBody = typeof body.body === 'string' ? body.body : '';
      if (!repo.refs.has(`refs/heads/${head}`) || !repo.refs.has(`refs/heads/${base}`)) {
        sendError(res, 422, 'Head or base branch does not exist');
        return;
      }
      if (ctx.store.openPullForHead(repo, head)) {
        sendError(res, 422, `A pull request already exists for ${head}`);
        return;
      }
      const pull = ctx.store.createPull(repo, title, pullBody, head, base);
      sendJson(res, 201, pullJson(repo, pull), { 'x-oauth-scopes': SCOPES });
      return;
    }
    if (method === 'GET') {
      const state = ctx.query.get('state') ?? 'open';
      let pulls = [...repo.pulls.values()];
      if (state === 'open') pulls = pulls.filter((pull) => pull.state === 'open');
      else if (state === 'closed') pulls = pulls.filter((pull) => pull.state === 'closed');
      pulls.sort((a, b) => b.createdSeq - a.createdSeq);
      sendPage(ctx, pulls.map((pull) => pullJson(repo, pull)));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  const number = notFoundNumber(tail[0] as string);
  if (number === null) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const pull = repo.pulls.get(number);
  if (!pull) {
    sendError(res, 404, 'Not Found');
    return;
  }

  if (tail.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, pullJson(repo, pull), { 'x-oauth-scopes': SCOPES });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (tail[1] === 'files' && tail.length === 2 && method === 'GET') {
    const base = ctx.store.peelToCommit(repo, pull.baseSha) ?? pull.baseSha;
    const head = ctx.store.peelToCommit(repo, pull.headSha) ?? pull.headSha;
    const ancestor = mergeBase((oid: string) => repo.objects.get(oid), base, head) ?? base;
    const changes = ctx.store.diffTrees(repo, ancestor, head);
    sendJson(res, 200, changes.map((change) => ({
      filename: change.path,
      status: change.status,
      additions: change.additions,
      deletions: change.deletions,
      changes: change.changes,
    })), { 'x-oauth-scopes': SCOPES });
    return;
  }

  if (tail[1] === 'merge' && tail.length === 2 && method === 'PUT') {
    const body = bodyObject(ctx);
    if (!body) return;
    if (pull.state === 'closed') {
      sendError(res, 405, pull.merged ? 'Pull request already merged' : 'Pull request is closed');
      return;
    }
    const mergeSha = ctx.store.squashMerge(repo, pull);
    if (mergeSha === null) {
      sendError(res, 405, 'Merge conflict');
      return;
    }
    const stamp = ctx.store.clock.tick();
    pull.state = 'closed';
    pull.merged = true;
    pull.mergedAt = ctx.store.clock.iso(stamp);
    pull.mergeCommitSha = mergeSha;
    pull.baseSha = mergeSha;
    sendJson(res, 200, { sha: mergeSha, merged: true, message: `Pull request #${pull.number} merged` }, { 'x-oauth-scopes': SCOPES });
    return;
  }

  sendError(res, 404, 'Not Found');
}
