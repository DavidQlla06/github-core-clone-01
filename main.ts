// Entry point: the trial lifecycle. The harness mounts the repo read-only,
// gives us a MAKEFUN_ENV_URL, and expects us to bind an ephemeral port,
// register it, and wait until the harness says it is done.
//
// The forge itself is a statically linked native binary (./forge, built from
// forge.c) — it binds the ephemeral port, serves the GitHub API + git
// protocol, and prints "PORT <n>" on stdout. This file only spawns it,
// registers the port, and waits for the harness to finish.

import { spawn, type ChildProcess } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const envUrl = process.env.MAKEFUN_ENV_URL;
const shopToken = process.env.MAKEFUN_SHOP_TOKEN ?? '';

if (envUrl === undefined || envUrl === '') {
  console.error('MAKEFUN_ENV_URL is not set');
  process.exit(1);
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const forgePath = path.join(__dirname, 'forge');

let child: ChildProcess | null = null;

function shutdown(code: number): void {
  if (child !== null && child.exitCode === null) {
    try { child.kill('SIGTERM'); } catch { /* already gone */ }
  }
  process.exit(code);
}

process.on('SIGTERM', () => shutdown(0));
process.on('SIGINT', () => shutdown(0));

async function main(): Promise<void> {
  // The checkout may strip the executable bit (e.g. API-created blobs are
  // 100644); best effort only — the repo may be mounted read-only.
  try {
    const fs = await import('node:fs');
    fs.chmodSync(forgePath, 0o755);
  } catch { /* git mode 100755 is the real fix; ignore */ }
  child = spawn(forgePath, [], {
    env: { ...process.env, MAKEFUN_SHOP_TOKEN: shopToken },
    stdio: ['ignore', 'pipe', 'inherit'],
  });

  child.on('error', (err) => {
    console.error(`failed to spawn forge: ${err.message}`);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    console.error(`forge exited early: code=${code} signal=${signal}`);
    process.exit(1);
  });

  // Wait for the "PORT <n>" line on the child's stdout.
  const port = await new Promise<number>((resolve, reject) => {
    let buf = '';
    const onData = (chunk: Buffer) => {
      buf += chunk.toString();
      const m = buf.match(/PORT (\d+)/);
      if (m) {
        child!.stdout!.off('data', onData);
        resolve(parseInt(m[1], 10));
      }
    };
    child!.stdout!.on('data', onData);
    setTimeout(() => reject(new Error('forge did not print a PORT line in time')), 10000);
  });

  const registerResponse = await fetch(`${envUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ port }),
  });
  if (!registerResponse.ok) {
    console.error(`register failed: HTTP ${registerResponse.status}`);
    shutdown(1);
  }

  // Poll until the harness is done; never hold a request open, never exit early.
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    let done = false;
    try {
      const response = await fetch(`${envUrl}/done`);
      if (response.ok) {
        const body = (await response.json()) as { done?: unknown };
        done = body.done === true;
      }
    } catch {
      // A failed poll is not a reason to stop: keep polling.
    }
    if (done) break;
  }

  shutdown(0);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  shutdown(1);
});
