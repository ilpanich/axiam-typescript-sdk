// Regression test for the BUILT ESM bundle's ability to build an https.Agent
// (§6 customCa / §6.1 clientCert).
//
// Why this exists as a separate file from mtls.test.ts: that test imports
// `../../src/rest/client.js` — vitest's own transform, where a bare `require`
// resolves fine. The shipped artifact does not behave the same way. tsup emits
// a `require` shim into the ESM output that throws
//   Dynamic require of "https" is not supported
// under genuine Node ESM, which is what `axiam-sdk/node`'s `import` condition
// resolves to. So every consumer using customCa or a client certificate from
// ESM failed at construction while the entire source-level test suite stayed
// green. Testing the source can never catch that class of bug; this test loads
// dist/node/index.mjs the way a real consumer does.
//
// Skips (does not fail) when dist/ has not been built — `npm run build` first,
// or run this in CI after the build step.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const distEntry = resolve(here, '../../dist/node/index.mjs');
const built = existsSync(distEntry);

// A syntactically valid PEM is enough: the agent is constructed eagerly at
// client-construction time, which is where the shim used to throw. No socket
// is ever opened here.
const PEM = [
  '-----BEGIN CERTIFICATE-----',
  'MIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv',
  '-----END CERTIFICATE-----',
  '',
].join('\n');

// The client identity goes into a TLS secure context at construction (so customCa ADDS to the process
// trust store, #176), and OpenSSL parses it there: it must be a real certificate and key.
function makeIdentity(): { cert: string; key: string } {
  const dir = mkdtempSync(join(tmpdir(), 'axiam-dist-esm-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'k.pem', '-out', 'c.pem', '-days', '2', '-subj', '/CN=dist-esm'], { cwd: dir, stdio: 'pipe' });
    return { cert: readFileSync(join(dir, 'c.pem'), 'utf8'), key: readFileSync(join(dir, 'k.pem'), 'utf8') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const identity = built ? makeIdentity() : { cert: '', key: '' };

describe.skipIf(!built)('built ESM bundle (dist/node/index.mjs)', () => {
  it('constructs a client with customCa without a dynamic-require failure', async () => {
    const { createNodeClient } = await import(pathToFileURL(distEntry).href);
    expect(() =>
      createNodeClient({
        baseUrl: 'https://localhost:8443',
        tenantSlug: 'default',
        orgSlug: 'bench-org',
        customCa: PEM,
      }),
    ).not.toThrow();
  });

  it('constructs a client with a §6.1 client identity without a dynamic-require failure', async () => {
    const { createNodeClient } = await import(pathToFileURL(distEntry).href);
    expect(() =>
      createNodeClient({
        baseUrl: 'https://localhost:8443',
        tenantSlug: 'default',
        orgSlug: 'bench-org',
        customCa: PEM,
        clientCert: identity.cert,
        clientKey: identity.key,
      }),
    ).not.toThrow();
  });

  it('never reaches the throwing require shim', async () => {
    // Belt and braces: assert on the failure MESSAGE too, so a future change
    // that reintroduces the shim fails with an obvious diagnosis rather than
    // some downstream symptom.
    const { createNodeClient } = await import(pathToFileURL(distEntry).href);
    let message = '';
    try {
      createNodeClient({
        baseUrl: 'https://localhost:8443',
        tenantSlug: 'default',
        orgSlug: 'bench-org',
        customCa: PEM,
      });
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).not.toMatch(/Dynamic require/i);
  });
});

describe.skipIf(built)('built ESM bundle', () => {
  it('is not built — run `npm run build` to exercise the dist regression tests', () => {
    expect(built).toBe(false);
  });
});
