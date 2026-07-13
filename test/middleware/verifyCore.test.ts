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
});
