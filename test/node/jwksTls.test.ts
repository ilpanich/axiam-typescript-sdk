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
import { createServer as createTlsServer, type Server as TlsServer } from 'node:tls';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
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

  // ---- review follow-ups -------------------------------------------------

  const listen = (s: { listen: (p: number, h: string, cb: () => void) => unknown; address: () => unknown }): Promise<number> =>
    new Promise((r) => s.listen(0, '127.0.0.1', () => r((s.address() as AddressInfo).port)));

  /** A raw TLS server writing `reply` verbatim to every connection; counts live sockets. */
  async function rawServer(reply: string): Promise<{ url: string; server: TlsServer; live: () => number }> {
    let live = 0;
    const server = createTlsServer({ key: pki.serverKey, cert: pki.serverCert }, (sock) => {
      live += 1;
      sock.on('close', () => (live -= 1));
      sock.on('error', () => undefined);
      sock.on('data', () => sock.write(reply));
    });
    server.on('tlsClientError', () => undefined);
    const port = await listen(server as never);
    return { url: `https://127.0.0.1:${port}`, server, live: () => live };
  }

  it('an abnormal status (999) is rejected promptly, throws nothing uncaught, and a later fetch works', async () => {
    const raw = await rawServer('HTTP/1.1 999 Nope\r\nContent-Length: 0\r\n\r\n');
    try {
      const started = Date.now();
      const verifier = createVerifier(raw.url, { ca: pki.caCert });
      await expect(verifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).rejects.toThrow();
      expect(Date.now() - started).toBeLessThan(4000);
      // A fresh verifier (own cache, own cooldown) is unaffected.
      const ok = createVerifier(openUrl, { ca: pki.caCert });
      await expect(ok.verifyAccessToken(token, { expectedTenantId: 't-1' })).resolves.toMatchObject({ sub: 'user-1' });
    } finally {
      await new Promise((r) => raw.server.close(r));
    }
  });

  it('a 302 is not followed and the verification is refused', async () => {
    const before = hits.open;
    const redirector = createServer({ key: pki.serverKey, cert: pki.serverCert }, (_req, res) => {
      res.statusCode = 302;
      res.setHeader('location', `${openUrl}${JWKS_PATH}`);
      res.end();
    });
    const port = await listen(redirector);
    try {
      const verifier = createVerifier(`https://127.0.0.1:${port}`, { ca: pki.caCert });
      await expect(verifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).rejects.toThrow();
      expect(hits.open).toBe(before);
    } finally {
      await new Promise((r) => redirector.close(r));
    }
  });

  it('a stalled body fails at the SDK deadline and leaves no socket open', async () => {
    const raw = await rawServer('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"keys":[');
    try {
      const started = Date.now();
      const verifier = createVerifier(raw.url, { ca: pki.caCert });
      await expect(verifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).rejects.toThrow();
      const took = Date.now() - started;
      expect(took).toBeGreaterThanOrEqual(4000);
      expect(took).toBeLessThan(8000);
      await new Promise((r) => setTimeout(r, 200));
      expect(raw.live()).toBe(0);
    } finally {
      await new Promise((r) => raw.server.close(r));
    }
  }, 15000);

  it('a 304 to a conditional request keeps the held keys', async () => {
    const seen: Array<string | undefined> = [];
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jwk = await exportJWK(publicKey);
    jwk.kid = 'k304';
    jwk.alg = 'EdDSA';
    const tok = await new SignJWT({ tenant_id: 't-1' })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'k304' })
      .setSubject('user-304')
      .setIssuer('axiam')
      .setExpirationTime('1h')
      .sign(privateKey);
    const srv = createServer({ key: pki.serverKey, cert: pki.serverCert }, (req, res) => {
      const inm = req.headers['if-none-match'];
      seen.push(inm as string | undefined);
      res.setHeader('etag', '"v1"');
      res.setHeader('cache-control', 'max-age=1');
      if (inm === '"v1"') {
        res.statusCode = 304;
        res.end();
        return;
      }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ keys: [jwk] }));
    });
    const port = await listen(srv);
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const verifier = createVerifier(`https://127.0.0.1:${port}`, { ca: pki.caCert });
      await expect(verifier.verifyAccessToken(tok, { expectedTenantId: 't-1' })).resolves.toMatchObject({ sub: 'user-304' });
      vi.setSystemTime(Date.now() + 61_000);
      await expect(verifier.verifyAccessToken(tok, { expectedTenantId: 't-1' })).resolves.toMatchObject({ sub: 'user-304' });
      // The refresh is not awaited by a verification that still holds usable keys.
      await vi.waitFor(() => expect(seen).toContain('"v1"'));
    } finally {
      vi.useRealTimers();
      await new Promise((r) => srv.close(r));
    }
  });

  it('an unconditional 304 fails on the TLS path', async () => {
    const srv = createServer({ key: pki.serverKey, cert: pki.serverCert }, (_req, res) => {
      res.statusCode = 304;
      res.end();
    });
    const port = await listen(srv);
    try {
      const verifier = createVerifier(`https://127.0.0.1:${port}`, { ca: pki.caCert });
      await expect(verifier.verifyAccessToken(token, { expectedTenantId: 't-1' })).rejects.toThrow();
    } finally {
      await new Promise((r) => srv.close(r));
    }
  });
});
