// #175 — the Node JWKS fetch must honour the same TLS material as the REST
// client (CONTRACT.md §6 customCa, §6.1 client identity). A real local HTTPS
// server whose certificate only a private test CA vouches for stands in for a
// private-CA deployment; msw cannot cover this because it never handshakes.
// A verifier WITHOUT the CA must still refuse: strict verification stays on.

import { execFileSync } from 'node:child_process';
import { createServer, type Server } from 'node:https';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createJwksVerifier, createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { createNodeSession } from '../../src/node/session.js';
import { nodeTlsOptionsOf, createSession } from '../../src/rest/session.js';

interface Pki {
  caCert: string;
  serverKey: string;
  serverCert: string;
  clientKey: string;
  clientCert: string;
}

function openssl(args: string[], cwd: string): void {
  execFileSync('openssl', args, { cwd, stdio: 'pipe' });
}

function generatePki(dir: string): Pki {
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '2', '-subj', '/CN=AXIAM Test CA'], dir);
  openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], dir);
  openssl(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.crt', '-days', '2', '-copy_extensions', 'copyall'], dir);
  openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'client.key', '-out', 'client.csr', '-subj', '/CN=axiam-device-1'], dir);
  openssl(['x509', '-req', '-in', 'client.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'client.crt', '-days', '2'], dir);
  const read = (f: string): string => readFileSync(join(dir, f), 'utf8');
  return {
    caCert: read('ca.crt'),
    serverKey: read('server.key'),
    serverCert: read('server.crt'),
    clientKey: read('client.key'),
    clientCert: read('client.crt'),
  };
}

const KID = 'tls-kid-1';

describe('#175 — JWKS fetch honours customCa and the client identity', () => {
  let pki: Pki;
  let dir: string;
  let open: Server;
  let mutual: Server;
  let openUrl: string;
  let mutualUrl: string;
  let token: string;
  let hits = { open: 0, mutual: 0 };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'axiam-jwks-tls-'));
    pki = generatePki(dir);
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jwk = await exportJWK(publicKey);
    jwk.kid = KID;
    jwk.alg = 'EdDSA';
    token = await new SignJWT({ tenant_id: 't-1' })
      .setProtectedHeader({ alg: 'EdDSA', kid: KID })
      .setSubject('user-1')
      .setIssuer('axiam')
      .setExpirationTime('1h')
      .sign(privateKey);
    const body = JSON.stringify({ keys: [jwk] });
    const handler = (which: 'open' | 'mutual') => (_req: unknown, res: import('node:http').ServerResponse) => {
      hits[which] += 1;
      res.setHeader('content-type', 'application/json');
      res.end(body);
    };
    open = createServer({ key: pki.serverKey, cert: pki.serverCert }, handler('open'));
    mutual = createServer(
      { key: pki.serverKey, cert: pki.serverCert, ca: pki.caCert, requestCert: true, rejectUnauthorized: true },
      handler('mutual'),
    );
    // A tls-level rejection surfaces as 'tlsClientError'; nothing to do with it.
    open.on('tlsClientError', () => undefined);
    mutual.on('tlsClientError', () => undefined);
    await Promise.all(
      [open, mutual].map((s) => new Promise<void>((r) => s.listen(0, '127.0.0.1', r))),
    );
    openUrl = `https://127.0.0.1:${(open.address() as AddressInfo).port}`;
    mutualUrl = `https://127.0.0.1:${(mutual.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await Promise.all([open, mutual].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  });

  it('createVerifier(baseUrl, { ca }) fetches the JWKS from a private-CA server', async () => {
    const verifier = createVerifier(openUrl, { ca: pki.caCert });
    const claims = await verifier.verifyAccessToken(token, { expectedTenantId: 't-1' });
    expect(claims.sub).toBe('user-1');
  });

  it('createJwksVerifier(uri, { ca }) fetches from an explicit jwks_uri', async () => {
    const verifier = createJwksVerifier(`${openUrl}${JWKS_PATH}`, { ca: pki.caCert });
    await expect(verifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('a verifier WITHOUT the CA still refuses (verification is not weakened)', async () => {
    const verifier = createVerifier(openUrl);
    await expect(verifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).rejects.toThrow();
  });

  it('a verifier trusting the CA but presenting no client certificate is refused by an mTLS server', async () => {
    const verifier = createVerifier(mutualUrl, { ca: pki.caCert });
    await expect(verifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).rejects.toThrow();
  });

  it('createVerifier(baseUrl, { ca, cert, key }) presents the client identity', async () => {
    const verifier = createVerifier(mutualUrl, { ca: pki.caCert, cert: pki.clientCert, key: pki.clientKey });
    await expect(verifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).resolves.toMatchObject({ sub: 'user-1' });
    expect(hits.mutual).toBeGreaterThan(0);
  });

  it('createNodeSession wires customCa into session.jwksVerifier', async () => {
    const session = createNodeSession({ baseUrl: openUrl, tenantSlug: 'acme', customCa: pki.caCert });
    const claims = await session.jwksVerifier.verifyAccessToken(token, { expectedTenantId: 't-1' });
    expect(claims.sub).toBe('user-1');
  });

  it('createNodeSession wires the client identity into session.jwksVerifier', async () => {
    const session = createNodeSession({
      baseUrl: mutualUrl,
      tenantSlug: 'acme',
      customCa: pki.caCert,
      clientCert: pki.clientCert,
      clientKey: pki.clientKey,
    });
    await expect(session.jwksVerifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('a trusted CA does not excuse a hostname mismatch (verification stays strict)', async () => {
    const before = hits.open;
    const port = (open.address() as AddressInfo).port;
    const verifier = createVerifier(`https://localhost:${port}`, { ca: pki.caCert });
    await expect(verifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).rejects.toThrow();
    expect(hits.open).toBe(before);
  });

  it('the client identity goes only to the base-URL origin; another origin gets customCa alone', () => {
    const session = createSession({
      baseUrl: 'https://iam.example.com',
      tenantSlug: 'acme',
      customCa: pki.caCert,
      clientCert: pki.clientCert,
      clientKey: pki.clientKey,
    });
    const same = nodeTlsOptionsOf(session, 'https://iam.example.com/oauth2/jwks');
    expect(same).toEqual({ ca: pki.caCert, cert: pki.clientCert, key: pki.clientKey });
    expect(nodeTlsOptionsOf(session, 'https://IAM.example.com:443/x')).toEqual(same);
    expect(nodeTlsOptionsOf(session, 'https://keys.other.example/jwks')).toEqual({ ca: pki.caCert });
    expect(nodeTlsOptionsOf(session, 'https://iam.example.com:8443/jwks')).toEqual({ ca: pki.caCert });
    expect(nodeTlsOptionsOf(session, 'http://iam.example.com/jwks')).toEqual({ ca: pki.caCert });
  });

  it('nodeTlsOptionsOf exposes the session TLS material to the OIDC verifier (and nothing for a plain session)', () => {
    const withCa = createSession({ baseUrl: openUrl, tenantSlug: 'acme', customCa: pki.caCert });
    expect(nodeTlsOptionsOf(withCa)).toEqual({ ca: pki.caCert });
    const plain = createSession({ baseUrl: openUrl, tenantSlug: 'acme' });
    expect(nodeTlsOptionsOf(plain)).toBeUndefined();
  });
});
