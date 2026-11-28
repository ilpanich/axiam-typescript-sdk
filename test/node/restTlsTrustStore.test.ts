// #176 — the REST agent's customCa is ADDED to the process trust store, never
// substituted for it (CONTRACT.md §6). Same child-process approach as
// jwksTlsTrustStore.test.ts: under `--use-openssl-ca` the store is OpenSSL's
// (SSL_CERT_FILE), fixed at process start, so the parent generates two private
// CAs and re-runs THIS file in a child vitest whose environment trusts CA-A;
// the child then checks a REST client with customCa = CA-B reaches both a CA-A
// and a CA-B server, on every agent the SDK builds, and that a hostname
// mismatch is still refused.

import { execFileSync, spawnSync } from 'node:child_process';
import { createServer, type Server } from 'node:https';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createSession } from '../../src/rest/session.js';
import { createNodeSession } from '../../src/node/session.js';

const CHILD_DIR = process.env.AXIAM_TRUST_STORE_DIR;

function openssl(args: string[], cwd: string): void {
  execFileSync('openssl', args, { cwd, stdio: 'pipe' });
}

/** A CA named `name` and a server certificate it signs for `san`, as files in `dir`. */
function makeCa(dir: string, name: string, san = 'IP:127.0.0.1'): void {
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.crt`, '-days', '2', '-subj', `/CN=Trust ${name}`], dir);
  openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}-srv.key`, '-out', `${name}-srv.csr`, '-subj', '/CN=server', '-addext', `subjectAltName=${san}`], dir);
  openssl(['x509', '-req', '-in', `${name}-srv.csr`, '-CA', `${name}.crt`, '-CAkey', `${name}.key`, '-CAcreateserial', '-out', `${name}-srv.crt`, '-days', '2', '-copy_extensions', 'copyall'], dir);
}

describe.skipIf(CHILD_DIR !== undefined)('#176 REST trust store (parent)', () => {
  it('keeps the OpenSSL store under --use-openssl-ca and adds customCa to it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'axiam-rest-trust-'));
    try {
      makeCa(dir, 'A');
      makeCa(dir, 'B');
      makeCa(dir, 'M', 'DNS:not-localhost.invalid'); // signed by CA-M (trusted), wrong name
      const env: NodeJS.ProcessEnv = { ...process.env, AXIAM_TRUST_STORE_DIR: dir, SSL_CERT_FILE: join(dir, 'A.crt'), NODE_OPTIONS: '--use-openssl-ca' };
      for (const k of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'GLOBAL_AGENT_HTTPS_PROXY']) delete env[k];
      const r = spawnSync(process.execPath, [join(process.cwd(), 'node_modules/vitest/vitest.mjs'), 'run', 'test/node/restTlsTrustStore.test.ts'], { env, encoding: 'utf8', timeout: 90_000 });
      expect(r.stdout + r.stderr).toMatch(/4 passed/);
      expect(r.status).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 120_000);
});

describe.runIf(CHILD_DIR !== undefined)('#176 REST trust store (child, SSL_CERT_FILE = CA-A, --use-openssl-ca)', () => {
  const servers: Server[] = [];
  const urls: Record<string, string> = {};
  const read = (f: string): string => readFileSync(join(CHILD_DIR as string, f), 'utf8');

  beforeAll(async () => {
    for (const name of ['A', 'B', 'M']) {
      const s = createServer({ key: read(`${name}-srv.key`), cert: read(`${name}-srv.crt`) }, (_q, res) => {
        res.setHeader('content-type', 'application/json');
        res.end('{"ok":true}');
      });
      s.on('tlsClientError', () => undefined);
      await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
      servers.push(s);
      urls[name] = `https://127.0.0.1:${(s.address() as AddressInfo).port}/probe`;
    }
  });
  afterAll(async () => {
    await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  });

  const opts = (): { baseUrl: string; tenantSlug: string; customCa: string } => ({ baseUrl: urls.A as string, tenantSlug: 'acme', customCa: read('B.crt') });

  it('plain session: a CA-A server (process store) stays reachable and a CA-B server is reachable through customCa', async () => {
    const s = createSession(opts());
    await expect(s.axios.get(urls.A as string)).resolves.toMatchObject({ status: 200 });
    await expect(s.axios.get(urls.B as string)).resolves.toMatchObject({ status: 200 });
  });

  it('Node persona (cookie-jar agent): same, and the no-credentials agent too', async () => {
    const s = createNodeSession(opts());
    await expect(s.axios.get(urls.A as string)).resolves.toMatchObject({ status: 200 });
    await expect(s.axios.get(urls.B as string)).resolves.toMatchObject({ status: 200 });
    await expect(s.axios.get(urls.A as string, s.noCredentialsConfig())).resolves.toMatchObject({ status: 200 });
    await expect(s.axios.get(urls.B as string, s.noCredentialsConfig())).resolves.toMatchObject({ status: 200 });
  });

  it('a server the process store does not trust is still refused without customCa', async () => {
    const s = createNodeSession({ baseUrl: urls.A as string, tenantSlug: 'acme' });
    await expect(s.axios.get(urls.B as string)).rejects.toThrow();
  });

  it('hostname verification still applies with customCa (a trusted CA does not excuse a wrong name)', async () => {
    const s = createNodeSession({ ...opts(), customCa: read('M.crt') });
    await expect(s.axios.get(urls.M as string)).rejects.toThrow(/altnames|hostname|IP/i);
  });
});
