// End-to-end proof that axiamMiddleware (Express) and axiamPlugin (Fastify)
// actually apply CONTRACT.md §10.1 rule 9 (contract 1.51 fix) — not just
// that authenticateRequest() does when called directly with proofs (that is
// verifyCore.test.ts's job). Before this fix neither middleware module
// applied rule 9 at all: a cnf-bound token passed straight through as an
// ordinary bearer credential.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { Request, Response } from 'express';
import Fastify from 'fastify';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { axiamMiddleware, type AxiamRequest } from '../../src/middleware/express.js';
import { axiamPlugin, type AxiamFastifyRequest } from '../../src/middleware/fastify.js';

const BASE_URL = 'https://axiam-rule9.test';

function fakeRes(): Response {
  const res: Partial<Response> = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res as Response;
}

/** A minimal fake `tls.TLSSocket` carrying a peer certificate. */
function fakeTlsSocket(der: Uint8Array) {
  return {
    encrypted: true,
    getPeerCertificate: (_detailed?: boolean) => ({ raw: der }),
  };
}

describe('§10.1 rule 9 end-to-end — axiamMiddleware (Express)', () => {
  const server = setupServer();
  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  async function setupJwks() {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const kid = 'rule9-express-kid';
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.alg = 'EdDSA';
    server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })));
    return { privateKey, kid };
  }

  async function boundToken(privateKey: CryptoKey, kid: string, x5tS256: string): Promise<string> {
    return new SignJWT({ tenant_id: 'tenant-1', cnf: { 'x5t#S256': x5tS256 } })
      .setProtectedHeader({ alg: 'EdDSA', kid })
      .setSubject('user-1')
      .setIssuer('axiam')
      .setExpirationTime('1h')
      .sign(privateKey);
  }

  it('a device-bound token over a plain (no-TLS-evidence) connection is refused with 401', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await boundToken(privateKey, kid, 'thumbprint-xyz');
    const session = { jwksVerifier: createVerifier(BASE_URL), tenantHeaderValue: 'tenant-1' };

    // No `.socket` at all — this is exactly the shape express.test.ts's
    // existing passing tests already use for an ordinary bearer token, and
    // it is what every route guard reached before this fix.
    const req = { headers: { authorization: `Bearer ${token}` } } as unknown as Request;
    const res = fakeRes();
    const next = vi.fn();

    await axiamMiddleware(session)(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(401);
    expect((req as AxiamRequest).axiamUser).toBeUndefined();
  });

  it('a device-bound token IS accepted when req.socket carries the matching client certificate', async () => {
    const { privateKey, kid } = await setupJwks();
    const der = new Uint8Array([10, 20, 30, 40, 50]);
    // Derive the real thumbprint the same way the middleware will, so the
    // token names exactly the certificate the fake socket presents.
    const { certificateThumbprintS256 } = await import('../../src/node/jwks.js');
    const thumbprint = await certificateThumbprintS256(der);
    const token = await boundToken(privateKey, kid, thumbprint);
    const session = { jwksVerifier: createVerifier(BASE_URL), tenantHeaderValue: 'tenant-1' };

    const req = {
      headers: { authorization: `Bearer ${token}` },
      socket: fakeTlsSocket(der),
    } as unknown as Request;
    const res = fakeRes();
    const next = vi.fn();

    await axiamMiddleware(session)(req, res, next);

    expect(res.status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledOnce();
    expect((req as AxiamRequest).axiamUser?.userId).toBe('user-1');
  });

  it('an ordinary (unbound) token is unaffected — the positive regression', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await new SignJWT({ tenant_id: 'tenant-1' })
      .setProtectedHeader({ alg: 'EdDSA', kid })
      .setSubject('user-1')
      .setIssuer('axiam')
      .setExpirationTime('1h')
      .sign(privateKey);
    const session = { jwksVerifier: createVerifier(BASE_URL), tenantHeaderValue: 'tenant-1' };

    const req = { headers: { authorization: `Bearer ${token}` } } as unknown as Request;
    const res = fakeRes();
    const next = vi.fn();

    await axiamMiddleware(session)(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });
});

describe('§10.1 rule 9 end-to-end — axiamPlugin (Fastify)', () => {
  const server = setupServer();
  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  async function setupJwks() {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const kid = 'rule9-fastify-kid';
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.alg = 'EdDSA';
    server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })));
    return { privateKey, kid };
  }

  async function buildApp(session: { jwksVerifier: ReturnType<typeof createVerifier>; tenantHeaderValue: string }) {
    const app = Fastify();
    await app.register(axiamPlugin(session));
    app.get('/protected', async (request) => ({ axiamUser: (request as AxiamFastifyRequest).axiamUser }));
    await app.ready();
    return app;
  }

  it('a device-bound token over Fastify\'s plain injected connection (no TLS evidence) is refused with 401', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await new SignJWT({ tenant_id: 'tenant-1', cnf: { 'x5t#S256': 'thumbprint-xyz' } })
      .setProtectedHeader({ alg: 'EdDSA', kid })
      .setSubject('user-1')
      .setIssuer('axiam')
      .setExpirationTime('1h')
      .sign(privateKey);
    const session = { jwksVerifier: createVerifier(BASE_URL), tenantHeaderValue: 'tenant-1' };
    const app = await buildApp(session);

    const res = await app.inject({ method: 'GET', url: '/protected', headers: { authorization: `Bearer ${token}` } });

    expect(res.statusCode).toBe(401);
    await app.close();
  });

  it('an ordinary (unbound) token still passes through axiamPlugin — the positive regression', async () => {
    const { privateKey, kid } = await setupJwks();
    const token = await new SignJWT({ tenant_id: 'tenant-1' })
      .setProtectedHeader({ alg: 'EdDSA', kid })
      .setSubject('user-1')
      .setIssuer('axiam')
      .setExpirationTime('1h')
      .sign(privateKey);
    const session = { jwksVerifier: createVerifier(BASE_URL), tenantHeaderValue: 'tenant-1' };
    const app = await buildApp(session);

    const res = await app.inject({ method: 'GET', url: '/protected', headers: { authorization: `Bearer ${token}` } });

    expect(res.statusCode).toBe(200);
    expect(res.json().axiamUser.userId).toBe('user-1');
    await app.close();
  });
});
