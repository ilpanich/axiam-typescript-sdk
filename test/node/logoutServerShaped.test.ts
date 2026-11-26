// CONTRACT.md §12.7.3 rule 1 and §12.7.6 (contract 1.69, #880): the back-channel
// logout token the SERVER signs carries the header exactly
// {"alg":"EdDSA","typ":"logout+jwt","kid":"<kid>"} and is verified by selecting
// the key BY `kid`. These tests use that shape and nothing else: the fixture
// signer adds no header member the server does not send, and the JWKS holds two
// keys with the signing key second, so a verifier that takes the first or only
// key fails them.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { decodeProtectedHeader, SignJWT } from 'jose';
import { AuthError } from '../../src/core/index.js';
import { createJwksVerifier } from '../../src/node/jwks.js';
import {
  CLIENT_ID,
  createClient,
  createMockState,
  createServer,
  discoveryHandler,
  generateSigningKey,
  ISSUER,
  jwksHandler,
  JWKS_URI,
  signLogoutToken,
  TENANT_ID,
  type OidcMockState,
} from './oidcTestKit.js';

const server = createServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/** Discovery, plus a JWKS in the order given (the rotation shape). */
function mount(state: OidcMockState, keys: Array<Awaited<ReturnType<typeof generateSigningKey>>>): void {
  server.use(discoveryHandler(state), jwksHandler(state, keys.map((k) => k.jwk)));
}

async function reason(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (err) {
    expect(err).toBeInstanceOf(AuthError);
    return (err as AuthError).reason;
  }
  throw new Error('expected a rejection');
}

describe('verifyLogoutToken — a server-shaped token (§12.7.6, contract 1.69)', () => {
  it('verifies: header exactly {alg, typ: logout+jwt, kid}, a two-key JWKS, the signing key not first', async () => {
    const state = createMockState();
    const other = await generateSigningKey('previous-key');
    const signing = await generateSigningKey('current-key');
    mount(state, [other, signing]);
    const token = await signLogoutToken(signing, { typ: 'logout+jwt' });

    // The fixture adds nothing the server does not send.
    expect(decodeProtectedHeader(token)).toEqual({ alg: 'EdDSA', typ: 'logout+jwt', kid: 'current-key' });

    const { oidc } = createClient();
    const verified = await oidc.verifyLogoutToken(token);
    expect(verified.sid).toBeDefined();
    expect(verified.sub).toBe('user-1');
    expect(verified.jti).toBeDefined();
  });

  it('a kid-less token is refused as unknown_kid against a ONE-key JWKS whose key did sign it, with no JWKS fetch', async () => {
    const state = createMockState();
    const signing = await generateSigningKey('only-key');
    mount(state, [signing]);
    const token = await signLogoutToken(signing, { typ: 'logout+jwt', omitKid: true });
    expect(decodeProtectedHeader(token)).toEqual({ alg: 'EdDSA', typ: 'logout+jwt' });

    const { oidc } = createClient();
    expect(await reason(oidc.verifyLogoutToken(token))).toBe('unknown_kid');
    expect(state.jwksCalls).toBe(0);
  });

  it('an unknown kid is refused as unknown_kid, with at most one JWKS re-fetch for a burst', async () => {
    const state = createMockState();
    const published = await generateSigningKey('published-key');
    mount(state, [published]);
    const rogue = await generateSigningKey('rogue-key');
    const { oidc } = createClient();

    for (let i = 0; i < 5; i += 1) {
      const token = await signLogoutToken(rogue, { typ: 'logout+jwt' });
      expect(await reason(oidc.verifyLogoutToken(token))).toBe('unknown_kid');
    }
    // One cold load; the cooldown window refuses every later re-fetch.
    expect(state.jwksCalls).toBeLessThanOrEqual(2);
  });
});

describe('rules 10 and 11 stay off the logout and ID-token paths (§10.1, §12.7.3)', () => {
  it('the logout token (typ logout+jwt) and an ID token (typ JWT) verify, while the access-token guard refuses both', async () => {
    const state = createMockState();
    const other = await generateSigningKey('previous-key');
    const signing = await generateSigningKey('current-key');
    mount(state, [other, signing]);
    const { oidc } = createClient();

    // Logout path: its typ is logout+jwt, which rule 10 would refuse.
    const logout = await signLogoutToken(signing, { typ: 'logout+jwt' });
    await expect(oidc.verifyLogoutToken(logout)).resolves.toMatchObject({ sub: 'user-1' });

    // ID-token path, through the verifier the access-token guard shares. The
    // ID token carries typ JWT (rule 10 would refuse it) and no tenant_id.
    const nowSec = Math.floor(Date.now() / 1000);
    const idToken = await new SignJWT({ nonce: 'n' })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: signing.kid })
      .setSubject('user-1')
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setIssuedAt(nowSec)
      .setExpirationTime(nowSec + 600)
      .sign(signing.privateKey);
    expect(decodeProtectedHeader(idToken).typ).toBe('JWT');

    const verifier = createJwksVerifier(JWKS_URI);
    await expect(
      verifier.verifyIdToken(idToken, { issuer: ISSUER, clientId: CLIENT_ID, nonce: 'n' }),
    ).resolves.toMatchObject({ sub: 'user-1' });

    // The guard refuses both (rule 10: typ; logout+jwt and JWT are not at+jwt).
    for (const token of [logout, idToken]) {
      await expect(verifier.verifyAccessToken(token, { expectedTenantId: TENANT_ID })).rejects.toThrow();
    }
    await expect(
      verifier.verifyAccessToken(logout, { expectedTenantId: TENANT_ID }),
    ).rejects.toThrow(/typ/);
  });
});
