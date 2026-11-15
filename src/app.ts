// The HTTP server: one in-memory store, four surfaces. Routing is by path
// prefix; every API call needs the bearer token from MAKEFUN_SHOP_TOKEN,
// /healthz needs none, and git smart HTTP authenticates the same way git
// does (it does not — the checks send the token but never require it there).

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { handleGraphql } from './graphql.ts';
import { handleInfoRefs, handleReceivePack, handleUploadPack, type GitRequest } from './gitproto.ts';
import { readBody, sendError, sendJson } from './http-util.ts';
import { handleMcp } from './mcp.ts';
import { handleRest } from './rest.ts';
import { Store } from './store.ts';

export interface AppOptions {
  shopToken: string;
}

export function createApp(options: AppOptions) {
  const store = new Store();
  const { shopToken } = options;

  function authorized(req: IncomingMessage): boolean {
    const header = req.headers.authorization ?? '';
    if (!header.startsWith('Bearer ')) return false;
    const token = header.slice('Bearer '.length);
    if (token === '') return false;
    if (shopToken === '') return true;
    return token === shopToken;
  }

  function decodeSegments(pathname: string): string[] {
    return pathname
      .split('/')
      .filter((segment) => segment !== '')
      .map((segment) => {
        try {
          return decodeURIComponent(segment);
        } catch {
          return segment;
        }
      });
  }

  const server = createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);
        const segments = decodeSegments(url.pathname);
        const method = req.method ?? 'GET';

        // Health check: no auth, no body.
        if (url.pathname === '/healthz' && method === 'GET') {
          sendJson(res, 200, { ok: true });
          return;
        }

        // REST v3.
        if (segments[0] === 'api' && segments[1] === 'v3') {
          if (!authorized(req)) {
            sendError(res, 401, 'Requires authentication');
            return;
          }
          const body = method === 'GET' || method === 'HEAD' ? Buffer.alloc(0) : await readBody(req);
          handleRest({
            store,
            req,
            res,
            segments: segments.slice(2),
            query: url.searchParams,
            body,
            origin: `http://${req.headers.host ?? '127.0.0.1'}`,
          });
          return;
        }

        // GraphQL.
        if (segments[0] === 'api' && segments[1] === 'graphql' && segments.length === 2) {
          if (method !== 'POST') {
            sendError(res, 404, 'Not Found');
            return;
          }
          if (!authorized(req)) {
            sendError(res, 401, 'Requires authentication');
            return;
          }
          const body = await readBody(req);
          handleGraphql(req, res, store, body);
          return;
        }

        // MCP.
        if (segments[0] === 'mcp' && segments.length === 1) {
          if (method !== 'POST' && method !== 'DELETE') {
            sendError(res, 404, 'Not Found');
            return;
          }
          if (!authorized(req)) {
            sendError(res, 401, 'Requires authentication');
            return;
          }
          const body = method === 'DELETE' ? Buffer.alloc(0) : await readBody(req);
          handleMcp(req, res, store, body);
          return;
        }

        // Git smart HTTP: /{owner}/{repo}.git/info/refs,
        // /{owner}/{repo}.git/git-upload-pack, /{owner}/{repo}.git/git-receive-pack.
        if (segments.length >= 3 && segments[1]?.endsWith('.git')) {
          const owner = segments[0] as string;
          const repo = (segments[1] as string).slice(0, -'.git'.length);
          const suffix = segments.slice(2).join('/');
          const git: GitRequest = {
            owner,
            repo,
            service: suffix === 'git-receive-pack' ? 'git-receive-pack' : 'git-upload-pack',
            suffix,
          };
          if (suffix === 'info/refs' && method === 'GET') {
            handleInfoRefs(req, res, store, git, url.searchParams.get('service'));
            return;
          }
          if (suffix === 'git-upload-pack' && method === 'POST') {
            const body = await readBody(req);
            handleUploadPack(req, res, store, git, body);
            return;
          }
          if (suffix === 'git-receive-pack' && method === 'POST') {
            const body = await readBody(req);
            handleReceivePack(req, res, store, git, body);
            return;
          }
          sendError(res, 404, 'Not Found');
          return;
        }

        sendError(res, 404, 'Not Found');
      } catch (err) {
        if (!res.headersSent) sendError(res, 500, err instanceof Error ? err.message : 'Internal Server Error');
        else res.end();
      }
    })();
  });

  return { server, store };
}
