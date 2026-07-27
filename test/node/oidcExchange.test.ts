// oidcExchange: authorization-code grant + the full §12.4 ID-token
// validation checklist (CONTRACT.md §12.1, §12.4).
//
// One failing test per §12.4 rule, as the contract requires:
//   rule 1 alg      -> "alg: none" + "non-EdDSA alg"
//   rule 2 kid      -> "unknown kid (single re-fetch then fail)" + "no kid"
//                      + "signature mismatch"
//   rule 3 iss      -> "issuer mismatch"
//   rule 4 aud      -> "audience mismatch" + "multiple aud without azp"
//   rule 5 time     -> "expired" + "iat in the future" + "nbf in the future"
//   rule 6 nonce    -> "nonce mismatch" + "nonce absent"
//   rule 7 discard  -> "no token material is returned on failure"

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { HttpResponse } from 'msw';
import { AuthError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import { createNodeSession } from '../../src/node/session.js';
import { createOidcClient } from '../../src/node/oidc.js';
import {
  BASE_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  discoveryHandler,
  generateSigningKey,
  ISSUER,
  jwksHandler,
  REDIRECT_URI,
  signIdToken,
  TENANT_ID,
  tokenHandler,
  tokenResponse,
  unsignedIdToken,
  type OidcMockState,
  type SigningKey,
} from './oidcTestKit.js';

const NONCE = 'the-request-nonce';
const CODE = 'authorization-code-value';

/** Wire up discovery + JWKS + a token endpoint returning `idToken`. */
async function setup(options: { idToken?: string; keys?: SigningKey[] } = {}): Promise<{
  state: OidcMockState;
  key: SigningKey;
}> {
  const key = options.keys?.[0] ?? (await generateSigningKey('rp-kid-1'));
  const state = createMockState();
  const handlers = [
    discoveryHandler(state),
    jwksHandler(state, (options.keys ?? [key]).map((k) => k.jwk)),
    tokenHandler(state, () =>
      HttpResponse.json(
        tokenResponse({
          refresh_token: 'refresh-token-value',
          scope: 'openid profile',
          ...(options.idToken !== undefined ? { id_token: options.idToken } : {}),
        }),
      ),
    ),
  ];
  server.use(...handlers);
  return { state, key };
}

const server = createServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('oidcExchange happy path (§12.1)', () => {
  it('posts a form-encoded authorization_code grant with tenant_id as a QUERY parameter', async () => {
    const key = await generateSigningKey('rp-kid-happy');
    const idToken = await signIdToken(key, { nonce: NONCE });
    const { state } = await setup({ idToken, keys: [key] });
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.oidcExchange({
      code: CODE,
      codeVerifier: new Sensitive('verifier-value'),
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
    });

    // Wire shape (§12.1 notes 1–3).
    expect(state.tokenContentTypes[0]).toContain('application/x-www-form-urlencoded');
    expect(state.tokenTenantIds[0]).toBe(TENANT_ID);
    const form = state.tokenForms[0];
    expect(form.get('grant_type')).toBe('authorization_code');
    expect(form.get('code')).toBe(CODE);
    expect(form.get('code_verifier')).toBe('verifier-value');
    expect(form.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('client_secret')).toBe(CLIENT_SECRET);
    // No field outside the grant's documented set (§12.1).
    expect([...form.keys()].sort()).toEqual([
      'client_id',
      'client_secret',
      'code',
      'code_verifier',
      'grant_type',
      'redirect_uri',
    ]);

    // Result shape (§12.1, §12.5).
    expect(tokens.accessToken).toBeInstanceOf(Sensitive);
    expect(tokens.accessToken.expose()).toBe('access-token-value');
    expect(tokens.refreshToken?.expose()).toBe('refresh-token-value');
    expect(tokens.idToken?.expose()).toBe(idToken);
    expect(tokens.tokenType).toBe('Bearer');
    expect(tokens.expiresIn).toBe(900);
    expect(tokens.scope).toBe('openid profile');
    expect(tokens.idClaims?.sub).toBe('user-1');
    expect(tokens.idClaims?.iss).toBe(ISSUER);
    expect(tokens.idClaims?.nonce).toBe(NONCE);
  });

  it('accepts a bare-string code verifier (rehydrated from a caller session)', async () => {
    const key = await generateSigningKey('rp-kid-bare');
    const { state } = await setup({ idToken: await signIdToken(key, { nonce: NONCE }), keys: [key] });
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.oidcExchange({
      code: CODE,
      codeVerifier: 'plain-string-verifier',
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
    });

    expect(state.tokenForms[0].get('code_verifier')).toBe('plain-string-verifier');
  });

  it('omits client_secret entirely for a public client (never sends an empty value)', async () => {
    const key = await generateSigningKey('rp-kid-public');
    const { state } = await setup({ idToken: await signIdToken(key, { nonce: NONCE }), keys: [key] });
    const { oidc } = createClient();

    await oidc.oidcExchange({
      code: CODE,
      codeVerifier: 'v',
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
    });

    expect(state.tokenForms[0].has('client_secret')).toBe(false);
  });

  it('preserves unknown ID-token claims (§12.1 — MUST NOT reject them)', async () => {
    const key = await generateSigningKey('rp-kid-extra');
    const idToken = await signIdToken(key, {
      nonce: NONCE,
      extraClaims: { email: 'user@example.com', custom_org_tier: 'gold' },
    });
    await setup({ idToken, keys: [key] });
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.oidcExchange({
      code: CODE,
      codeVerifier: 'v',
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
    });

    expect(tokens.idClaims?.email).toBe('user@example.com');
    expect(tokens.idClaims?.custom_org_tier).toBe('gold');
  });

  it('reuses a caller-supplied discovery document instead of fetching one', async () => {
    const key = await generateSigningKey('rp-kid-cfg');
    const { state } = await setup({ idToken: await signIdToken(key, { nonce: NONCE }), keys: [key] });
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const configuration = await oidc.oidcDiscover();
    expect(state.discoveryCalls).toBe(1);

    await oidc.oidcExchange({
      code: CODE,
      codeVerifier: 'v',
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
      configuration,
    });

    expect(state.discoveryCalls).toBe(1);
  });
});

describe('oidcExchange ID-token validation failures (§12.4)', () => {
  /** Run an exchange expected to fail, returning the raised AuthError. */
  async function expectFailure(idToken: string, keys?: SigningKey[], nonce = NONCE): Promise<AuthError> {
    await setup({ idToken, ...(keys ? { keys } : {}) });
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const error = await oidc
      .oidcExchange({ code: CODE, codeVerifier: 'v', redirectUri: REDIRECT_URI, nonce })
      .then(
        () => undefined,
        (err: unknown) => err,
      );
    expect(error).toBeInstanceOf(AuthError);
    return error as AuthError;
  }

  it('rule 1 — rejects alg: none outright', async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const token = unsignedIdToken({
      iss: ISSUER,
      sub: 'user-1',
      aud: CLIENT_ID,
      exp: nowSec + 3600,
      iat: nowSec,
      nonce: NONCE,
    });
    const error = await expectFailure(token);
    expect(error.reason).toBe('invalid_alg');
  });

  it('rule 1 — rejects a non-EdDSA algorithm (HS256) even when otherwise well-formed', async () => {
    const { SignJWT } = await import('jose');
    const hsToken = await new SignJWT({ nonce: NONCE })
      .setProtectedHeader({ alg: 'HS256', kid: 'rp-kid-1' })
      .setSubject('user-1')
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode('a-32-byte-symmetric-secret-value!'));

    const error = await expectFailure(hsToken);
    expect(error.reason).toBe('invalid_alg');
  });

  it('rule 2 — an unknown kid triggers a single JWKS re-fetch and then fails', async () => {
    const published = await generateSigningKey('published-kid');
    const rogue = await generateSigningKey('rogue-kid');
    const idToken = await signIdToken(rogue, { nonce: NONCE });
    // Only `published` is in the JWKS, so `rogue-kid` can never be matched.
    await setup({ idToken, keys: [published] });
    const state = createMockState();
    server.use(jwksHandler(state, [published.jwk]));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const error = await oidc
      .oidcExchange({ code: CODE, codeVerifier: 'v', redirectUri: REDIRECT_URI, nonce: NONCE })
      .then(
        () => undefined,
        (err: unknown) => err as AuthError,
      );

    expect(error?.reason).toBe('unknown_kid');
    // Exactly one JWKS fetch: jose's cooldown bounds the re-fetch to one per
    // window, which is §12.4 rule 2's "one re-fetch then fail".
    expect(state.jwksCalls).toBe(1);
  });

  it('rule 2 — rejects a token with no kid header', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const { SignJWT } = await import('jose');
    const noKid = await new SignJWT({ nonce: NONCE })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setSubject('user-1')
      .setIssuer(ISSUER)
      .setAudience(CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(key.privateKey);

    const error = await expectFailure(noKid, [key]);
    expect(error.reason).toBe('unknown_kid');
  });

  it('rule 2 — rejects a token signed by another key under a published kid', async () => {
    const published = await generateSigningKey('shared-kid');
    const impostor = await generateSigningKey('shared-kid');
    // Signed by the impostor but labelled with the published kid, so the key
    // lookup succeeds and only the signature check can catch it.
    const idToken = await signIdToken(impostor, { nonce: NONCE, kid: 'shared-kid' });

    const error = await expectFailure(idToken, [published]);
    expect(error.reason).toBe('invalid_signature');
  });

  it('rule 3 — rejects an issuer that does not exactly equal the discovery issuer', async () => {
    const key = await generateSigningKey('rp-kid-1');
    // A trailing slash is a mismatch: no normalization is permitted.
    const idToken = await signIdToken(key, { nonce: NONCE, issuer: `${ISSUER}/` });

    const error = await expectFailure(idToken, [key]);
    expect(error.reason).toBe('invalid_issuer');
  });

  it('rule 4 — rejects an audience that does not contain this client_id', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const idToken = await signIdToken(key, { nonce: NONCE, audience: 'some-other-client' });

    const error = await expectFailure(idToken, [key]);
    expect(error.reason).toBe('invalid_audience');
  });

  it('rule 4 — rejects multiple audiences without a matching azp', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const idToken = await signIdToken(key, {
      nonce: NONCE,
      audience: [CLIENT_ID, 'another-client'],
    });

    const error = await expectFailure(idToken, [key]);
    expect(error.reason).toBe('invalid_audience');
  });

  it('rule 4 — accepts multiple audiences when azp equals this client_id', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const idToken = await signIdToken(key, {
      nonce: NONCE,
      audience: [CLIENT_ID, 'another-client'],
      azp: CLIENT_ID,
    });
    await setup({ idToken, keys: [key] });
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.oidcExchange({
      code: CODE,
      codeVerifier: 'v',
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
    });
    expect(tokens.idClaims?.azp).toBe(CLIENT_ID);
  });

  it('rule 5 — rejects an expired token', async () => {
    const key = await generateSigningKey('rp-kid-1');
    // 10 minutes in the past — well beyond the 60 s skew allowance.
    const idToken = await signIdToken(key, { nonce: NONCE, expiresInSec: -600 });

    const error = await expectFailure(idToken, [key]);
    expect(error.reason).toBe('token_expired');
  });

  it('rule 5 — rejects an iat in the future beyond the skew allowance', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const idToken = await signIdToken(key, {
      nonce: NONCE,
      issuedAtSec: Math.floor(Date.now() / 1000) + 600,
    });

    const error = await expectFailure(idToken, [key]);
    expect(error.reason).toBe('token_expired');
  });

  it('rule 5 — rejects an nbf in the future', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const idToken = await signIdToken(key, {
      nonce: NONCE,
      notBeforeSec: Math.floor(Date.now() / 1000) + 600,
    });

    const error = await expectFailure(idToken, [key]);
    expect(error.reason).toBe('token_expired');
  });

  it('rule 6 — rejects a nonce that does not match the request nonce', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const idToken = await signIdToken(key, { nonce: 'a-different-nonce' });

    const error = await expectFailure(idToken, [key]);
    expect(error.reason).toBe('nonce_mismatch');
  });

  it('rule 6 — rejects a missing nonce claim (mandatory for oidcExchange)', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const idToken = await signIdToken(key, { nonce: null });

    const error = await expectFailure(idToken, [key]);
    expect(error.reason).toBe('nonce_mismatch');
  });

  it('rule 7 — discards the whole token set: no access/refresh token reaches the caller', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const idToken = await signIdToken(key, { nonce: 'wrong' });
    const error = await expectFailure(idToken, [key]);

    // The error carries no token material of any kind (§12.3 rule 3, §2).
    const serialized = `${error.message} ${JSON.stringify(error, Object.getOwnPropertyNames(error))}`;
    expect(serialized).not.toContain('access-token-value');
    expect(serialized).not.toContain('refresh-token-value');
    expect(serialized).not.toContain(idToken);
    expect(serialized).not.toContain(CLIENT_SECRET);
    // There is no "partial success" object to inspect — the promise rejected.
    expect(error.reason).toBe('nonce_mismatch');
  });

  it('has no option to disable ID-token validation (§12.4 rule 7)', () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const surface = [
      ...Object.getOwnPropertyNames(Object.getPrototypeOf(oidc) as object),
      ...Object.keys(oidc as unknown as Record<string, unknown>),
    ];
    expect(surface.some((name) => /skip|disable|insecure|unsafe/i.test(name))).toBe(false);
  });
});

describe('oidcExchange OAuth2 protocol errors (§12.3 rule 3)', () => {
  it('maps a 400 invalid_grant body to OAuthProtocolError with "<error>: <error_description>"', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () =>
        HttpResponse.json(
          { error: 'invalid_grant', error_description: 'authorization code expired' },
          { status: 400 },
        ),
      ),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const error = await oidc
      .oidcExchange({ code: CODE, codeVerifier: 'v', redirectUri: REDIRECT_URI, nonce: NONCE })
      .then(
        () => undefined,
        (err: unknown) => err,
      );

    expect(error).toBeInstanceOf(OAuthProtocolError);
    // Still an AuthError — contract 1.4 is additive (§2 sub-type table).
    expect(error).toBeInstanceOf(AuthError);
    const protocolError = error as OAuthProtocolError;
    expect(protocolError.error).toBe('invalid_grant');
    expect(protocolError.errorDescription).toBe('authorization code expired');
    expect(protocolError.message).toBe('invalid_grant: authorization code expired');
  });

  it('raises AuthError client-side, with no wire call, when the tenant is a slug', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    // A client whose only tenant identifier is a slug cannot fill the required
    // tenant_id UUID query parameter (§12.3 rule 4).
    const slugSession = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'acme' });
    const slugOidc = createOidcClient(slugSession, {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    await expect(
      slugOidc.oidcExchange({ code: CODE, codeVerifier: 'v', redirectUri: REDIRECT_URI, nonce: NONCE }),
    ).rejects.toThrow(/tenant_id UUID/);
    expect(state.tokenCalls).toBe(0);
  });

  it('rejects a non-UUID tenantId argument client-side rather than sending a slug', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(
      oidc.oidcExchange({
        code: CODE,
        codeVerifier: 'v',
        redirectUri: REDIRECT_URI,
        nonce: NONCE,
        tenantId: 'acme-slug',
      }),
    ).rejects.toThrow(/must be a UUID/);
    expect(state.tokenCalls).toBe(0);
  });
});
