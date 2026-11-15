// Entry point: the trial lifecycle. The harness mounts the repo read-only,
// gives us a MAKEFUN_ENV_URL, and expects us to bind an ephemeral port,
// register it, and wait until the harness says it is done. No other work
// happens here; the forge itself lives in src/app.ts.

import { createApp } from './src/app.ts';

const envUrl = process.env.MAKEFUN_ENV_URL;
const shopToken = process.env.MAKEFUN_SHOP_TOKEN ?? '';

if (envUrl === undefined || envUrl === '') {
  console.error('MAKEFUN_ENV_URL is not set');
  process.exit(1);
}

const { server } = createApp({ shopToken });

async function main(): Promise<void> {
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('failed to bind a port');
  }
  const port = address.port;

  const registerResponse = await fetch(`${envUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ port }),
  });
  if (!registerResponse.ok) {
    console.error(`register failed: HTTP ${registerResponse.status}`);
    process.exit(1);
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

  server.close();
  process.exit(0);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
