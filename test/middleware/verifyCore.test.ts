// authenticateRequest claim-validation branches (middleware/verifyCore.ts,
// §10/CR-03): missing sub, missing tenant_id, tenant mismatch, and the
// scope -> roles mapping. Tokens are signed against a locally-served JWKS
// (msw) with fields deliberately omitted to hit each guard.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/index.js';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { authenticateRequest } from '../../src/middleware/verifyCore.js';

const BASE_URL = 'https://axiam-verifycore.test';
const KID = 'vc-kid';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

async function setup(): Promise<CryptoKey> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const jwk = await exportJWK(publicKey);
  jwk.kid = KID;
  jwk.alg = 'EdDSA';
  server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })));
  return privateKey;
}

function baseJwt(): SignJWT {
  return new SignJWT({ tenant_id: 'tenant-1', scope: 'read write' })
    .setProtectedHeader({ alg: 'EdDSA', kid: KID })
    .setIssuer('axiam')
    .setExpirationTime('1h');
}

function sessionFor(tenant = 'tenant-1') {
  return { jwksVerifier: createVerifier(BASE_URL), tenantHeaderValue: tenant };
}

describe('authenticateRequest', () => {
  it('maps verified claims to an identity, deriving roles from scope', async () => {
    const key = await setup();
    const token = await baseJwt().setSubject('user-1').sign(key);

    const identity = await authenticateRequest(sessionFor(), token);

    expect(identity).toEqual({ userId: 'user-1', tenantId: 'tenant-1', roles: ['read', 'write'] });
  });

  it('yields an empty roles array when scope is absent', async () => {
    const key = await setup();
    const token = await new SignJWT({ tenant_id: 'tenant-1' })
      .setProtectedHeader({ alg: 'EdDSA', kid: KID })
      .setIssuer('axiam')
      .setSubject('user-1')
      .setExpirationTime('1h')
      .sign(key);

    const identity = await authenticateRequest(sessionFor(), token);
    expect(identity.roles).toEqual([]);
  });

  it('throws AuthError on an unverifiable token', async () => {
    await setup();
    await expect(authenticateRequest(sessionFor(), 'not-a-jwt')).rejects.toBeInstanceOf(AuthError);
  });

  it('throws AuthError when the sub claim is missing', async () => {
    const key = await setup();
    const token = await baseJwt().sign(key); // no setSubject
    await expect(authenticateRequest(sessionFor(), token)).rejects.toThrow('invalid sub claim');
  });

  it('throws AuthError when the tenant_id claim is missing', async () => {
    const key = await setup();
    const token = await new SignJWT({ scope: 'read' })
      .setProtectedHeader({ alg: 'EdDSA', kid: KID })
      .setIssuer('axiam')
      .setSubject('user-1')
      .setExpirationTime('1h')
      .sign(key);
    await expect(authenticateRequest(sessionFor(), token)).rejects.toThrow('invalid tenant_id claim');
  });

  it('throws AuthError when the token tenant does not match the configured tenant (CR-03)', async () => {
    const key = await setup();
    const token = await baseJwt().setSubject('user-1').sign(key); // tenant-1
    await expect(authenticateRequest(sessionFor('tenant-2'), token)).rejects.toThrow(
      'does not match configured tenant',
    );
  });

  // -------------------------------------------------------------------------
  // §10.1 rule 9 (contract 1.51 fix). Before this fix authenticateRequest
  // never applied rule 9 at all — a cnf-bound token (every device token from
  // authenticateDevice(), §6.1) was accepted as an ordinary bearer
  // credential by axiamMiddleware/axiamPlugin, the exact defect the §10.1
  // rule 9 preamble describes as recurring "independently in two SDKs".
  // -------------------------------------------------------------------------

  describe('§10.1 rule 9 — cnf (contract 1.51 fix)', () => {
    it('a certificate-bound token is refused with no evidence (the default — no third argument)', async () => {
      const key = await setup();
      const token = await new SignJWT({
        tenant_id: 'tenant-1',
        cnf: { 'x5t#S256': 'thumbprint-abc' },
      })
        .setProtectedHeader({ alg: 'EdDSA', kid: KID })
        .setIssuer('axiam')
        .setSubject('user-1')
        .setExpirationTime('1h')
        .sign(key);

      // No third argument — the exact call every route guard made before
      // this fix, and the one this whole fix is about.
      await expect(authenticateRequest(sessionFor(), token)).rejects.toBeInstanceOf(AuthError);
    });

    it('a certificate-bound token is accepted when the matching certificate thumbprint is supplied', async () => {
      const key = await setup();
      const token = await new SignJWT({
        tenant_id: 'tenant-1',
        cnf: { 'x5t#S256': 'thumbprint-abc' },
      })
        .setProtectedHeader({ alg: 'EdDSA', kid: KID })
        .setIssuer('axiam')
        .setSubject('user-1')
        .setExpirationTime('1h')
        .sign(key);

      const identity = await authenticateRequest(sessionFor(), token, {
        certificateThumbprint: 'thumbprint-abc',
      });
      expect(identity.userId).toBe('user-1');
    });

    it('a certificate-bound token is refused when the presented certificate differs', async () => {
      const key = await setup();
      const token = await new SignJWT({
        tenant_id: 'tenant-1',
        cnf: { 'x5t#S256': 'thumbprint-abc' },
      })
        .setProtectedHeader({ alg: 'EdDSA', kid: KID })
        .setIssuer('axiam')
        .setSubject('user-1')
        .setExpirationTime('1h')
        .sign(key);

      await expect(
        authenticateRequest(sessionFor(), token, { certificateThumbprint: 'a-different-thumbprint' }),
      ).rejects.toBeInstanceOf(AuthError);
    });

    it('an empty cnf object is refused, never read as unbound', async () => {
      const key = await setup();
      const token = await new SignJWT({ tenant_id: 'tenant-1', cnf: {} })
        .setProtectedHeader({ alg: 'EdDSA', kid: KID })
        .setIssuer('axiam')
        .setSubject('user-1')
        .setExpirationTime('1h')
        .sign(key);

      await expect(authenticateRequest(sessionFor(), token)).rejects.toBeInstanceOf(AuthError);
      await expect(
        authenticateRequest(sessionFor(), token, { certificateThumbprint: 'anything' }),
      ).rejects.toBeInstanceOf(AuthError);
    });

    it('the positive regression: an unbound token is still accepted with or without evidence present', async () => {
      const key = await setup();
      const token = await baseJwt().setSubject('user-1').sign(key); // no cnf at all

      // No proofs.
      await expect(authenticateRequest(sessionFor(), token)).resolves.toMatchObject({ userId: 'user-1' });
      // Proofs present anyway — an unbound token does not care.
      await expect(
        authenticateRequest(sessionFor(), token, { certificateThumbprint: 'unrelated' }),
      ).resolves.toMatchObject({ userId: 'user-1' });
    });
  });
});
