// #175 — customCa is ADDED to the process trust store on the JWKS path, never
// substituted for it. Under `--use-openssl-ca` the store is OpenSSL's
// (SSL_CERT_FILE), which can only be chosen at process start, so the parent
// test generates two private CAs and re-runs THIS file in a child vitest whose
// environment trusts CA-A through OpenSSL; the child then verifies that a
// verifier configured with customCa = CA-B reaches both a CA-A and a CA-B server.

import { execFileSync, spawnSync } from 'node:child_process';
import { createServer, type Server } from 'node:https';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createVerifier } from '../../src/node/jwks.js';

const CHILD_DIR = process.env.AXIAM_TRUST_STORE_DIR;

function openssl(args: string[], cwd: string): void {
  execFileSync('openssl', args, { cwd, stdio: 'pipe' });
}

/** A CA named `name` and a 127.0.0.1 server certificate it signs, as files in `dir`. */
function makeCa(dir: string, name: string): void {
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.crt`, '-days', '2', '-subj', `/CN=Trust ${name}`], dir);
  openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}-srv.key`, '-out', `${name}-srv.csr`, '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], dir);
  openssl(['x509', '-req', '-in', `${name}-srv.csr`, '-CA', `${name}.crt`, '-CAkey', `${name}.key`, '-CAcreateserial', '-out', `${name}-srv.crt`, '-days', '2', '-copy_extensions', 'copyall'], dir);
}

describe.skipIf(CHILD_DIR !== undefined)('#175 trust store (parent)', () => {
  it('keeps the OpenSSL store under --use-openssl-ca and adds customCa to it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'axiam-jwks-trust-'));
    try {
      makeCa(dir, 'A');
      makeCa(dir, 'B');
      const env: NodeJS.ProcessEnv = { ...process.env, AXIAM_TRUST_STORE_DIR: dir, SSL_CERT_FILE: join(dir, 'A.crt'), NODE_OPTIONS: '--use-openssl-ca' };
      for (const k of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'GLOBAL_AGENT_HTTPS_PROXY']) delete env[k];
      const r = spawnSync(process.execPath, [join(process.cwd(), 'node_modules/vitest/vitest.mjs'), 'run', 'test/node/jwksTlsTrustStore.test.ts'], { env, encoding: 'utf8', timeout: 90_000 });
      expect(r.stdout + r.stderr).toMatch(/2 passed/);
      expect(r.status).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 120_000);
});

describe.runIf(CHILD_DIR !== undefined)('#175 trust store (child, SSL_CERT_FILE = CA-A, --use-openssl-ca)', () => {
  const servers: Server[] = [];
  const urls: Record<string, string> = {};
  let token: string;
  const read = (f: string): string => readFileSync(join(CHILD_DIR as string, f), 'utf8');

  beforeAll(async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jwk = await exportJWK(publicKey);
    jwk.kid = 'ts-kid';
    jwk.alg = 'EdDSA';
    token = await new SignJWT({ tenant_id: 't-1' }).setProtectedHeader({ alg: 'EdDSA', kid: 'ts-kid' }).setSubject('u').setIssuer('axiam').setExpirationTime('1h').sign(privateKey);
    for (const name of ['A', 'B']) {
      const s = createServer({ key: read(`${name}-srv.key`), cert: read(`${name}-srv.crt`) }, (_q, res) => {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ keys: [jwk] }));
      });
      s.on('tlsClientError', () => undefined);
      await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
      servers.push(s);
      urls[name] = `https://127.0.0.1:${(s.address() as AddressInfo).port}`;
    }
  });
  afterAll(async () => {
    await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  });

  it('a CA-A server (process store) stays reachable when customCa is CA-B', async () => {
    const v = createVerifier(urls.A, { ca: read('B.crt') });
    await expect(v.verifyAccessToken(token, { expectedTenantId: 't-1' })).resolves.toMatchObject({ sub: 'u' });
  });

  it('a CA-B server is reachable through customCa', async () => {
    const v = createVerifier(urls.B, { ca: read('B.crt') });
    await expect(v.verifyAccessToken(token, { expectedTenantId: 't-1' })).resolves.toMatchObject({ sub: 'u' });
  });
});
