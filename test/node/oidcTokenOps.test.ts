// oidcRefresh, loginClientCredentials, introspect, revoke
// (CONTRACT.md §12.1, §12.3 rules 3–4, §9).

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { AuthError, NetworkError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import { createOidcClient, DISCOVERY_PATH } from '../../src/node/oidc.js';
import { createNodeClient, createNodeSession } from '../../src/node/session.js';
import {
  BASE_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  discoveryHandler,
  generateSigningKey,
  INTROSPECT_ENDPOINT,
  ISSUER,
  jwksHandler,
  ORG_ID,
  REVOKE_ENDPOINT,
  signIdToken,
  TENANT_ID,
  tokenHandler,
  tokenResponse,
  TOKEN_ENDPOINT,
} from './oidcTestKit.js';

const server = createServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('oidcRefresh (§12.1, §9)', () => {
  it('posts a refresh_token grant with the documented field set', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ refresh_token: 'rotated-refresh' }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.oidcRefresh({ refreshToken: new Sensitive('old-refresh'), scope: 'openid' });

    const form = state.tokenForms[0];
    expect(form.get('grant_type')).toBe('refresh_token');
    expect(form.get('refresh_token')).toBe('old-refresh');
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('client_secret')).toBe(CLIENT_SECRET);
    expect(form.get('scope')).toBe('openid');
    expect([...form.keys()].sort()).toEqual([
      'client_id',
      'client_secret',
      'grant_type',
      'refresh_token',
      'scope',
    ]);
    expect(state.tokenTenantIds[0]).toBe(TENANT_ID);
    expect(tokens.refreshToken?.expose()).toBe('rotated-refresh');
  });

  it('omits scope when the caller does not narrow it', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.oidcRefresh({ refreshToken: 'r' });

    expect(state.tokenForms[0].has('scope')).toBe(false);
  });

  it('collapses concurrent refreshes into ONE token request and shares the result (§9 rules 1–2)', async () => {
    const state = createMockState();
    let tokenCalls = 0;
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async () => {
        tokenCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return HttpResponse.json(tokenResponse({ access_token: `access-${tokenCalls}` }));
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    // Warm the discovery cache so all five callers race on the refresh alone.
    await oidc.oidcDiscover();

    const results = await Promise.all(
      Array.from({ length: 5 }, () => oidc.oidcRefresh({ refreshToken: 'r' })),
    );

    expect(tokenCalls).toBe(1);
    for (const tokens of results) {
      expect(tokens.accessToken.expose()).toBe('access-1');
    }
  });

  it('allows a fresh refresh after the previous one settled (not a permanent lock)', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.oidcRefresh({ refreshToken: 'r1' });
    await oidc.oidcRefresh({ refreshToken: 'r2' });

    expect(state.tokenCalls).toBe(2);
    expect(state.tokenForms.map((f) => f.get('refresh_token'))).toEqual(['r1', 'r2']);
  });

  it('validates an id_token in the refresh response but skips the nonce rule (§12.4 rule 6)', async () => {
    const key = await generateSigningKey('refresh-kid');
    // No nonce claim at all — legal for a refresh-issued ID token.
    const idToken = await signIdToken(key, { nonce: null });
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ id_token: idToken }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.oidcRefresh({ refreshToken: 'r' });

    expect(tokens.idClaims?.iss).toBe(ISSUER);
    expect(tokens.idClaims?.nonce).toBeUndefined();
  });

  it('still enforces rules 1–5 on a refresh-issued id_token', async () => {
    const key = await generateSigningKey('refresh-kid-bad');
    const idToken = await signIdToken(key, { nonce: null, issuer: 'https://evil.example' });
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ id_token: idToken }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.oidcRefresh({ refreshToken: 'r' })).rejects.toMatchObject({
      reason: 'invalid_issuer',
    });
  });

  it('retries the §9 guard when a cookie-session refresh is already holding it', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcDiscover();

    // Occupy the shared session guard with the §1 cookie-session refresh path,
    // which cannot produce an OidcTokenSet.
    let releaseSessionRefresh: (() => void) | undefined;
    const sessionRefresh = session.refreshGuard(
      () =>
        new Promise<void>((resolve) => {
          releaseSessionRefresh = resolve;
        }),
    );

    const refreshPromise = oidc.oidcRefresh({ refreshToken: 'r' });
    releaseSessionRefresh?.();
    await sessionRefresh;

    // The OIDC refresh still produces its token set, on a later guard attempt.
    await expect(refreshPromise).resolves.toMatchObject({ tokenType: 'Bearer' });
    expect(state.tokenCalls).toBe(1);
  });

  it('fails loudly if the guard never runs its callback (bounded, never spins)', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const session = createNodeSession({ baseUrl: BASE_URL, tenantId: TENANT_ID });
    // A pathological guard that swallows every callback.
    Object.defineProperty(session, 'refreshGuard', { value: async () => {}, configurable: true });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID, clientSecret: CLIENT_SECRET });

    await expect(oidc.oidcRefresh({ refreshToken: 'r' })).rejects.toThrow(
      /could not acquire the single-flight refresh guard/,
    );
    expect(state.tokenCalls).toBe(0);
  });

  it('maps a 400 invalid_grant to OAuthProtocolError without entering a refresh loop', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () =>
        HttpResponse.json(
          { error: 'invalid_grant', error_description: 'refresh token revoked' },
          { status: 400 },
        ),
      ),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const error = await oidc.oidcRefresh({ refreshToken: 'r' }).then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(OAuthProtocolError);
    expect((error as OAuthProtocolError).message).toBe('invalid_grant: refresh token revoked');
    // Exactly one attempt — no silent retry.
    expect(state.tokenCalls).toBe(1);
  });
});

describe('loginClientCredentials (§12.1)', () => {
  it('posts a client_credentials grant with only the documented fields', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ scope: 'authz:check' }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.loginClientCredentials({ scope: 'authz:check' });

    const form = state.tokenForms[0];
    expect(form.get('grant_type')).toBe('client_credentials');
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('client_secret')).toBe(CLIENT_SECRET);
    expect([...form.keys()].sort()).toEqual(['client_id', 'client_secret', 'grant_type', 'scope']);
    expect(state.tokenTenantIds[0]).toBe(TENANT_ID);
    expect(tokens.accessToken.expose()).toBe('access-token-value');
    expect(tokens.idToken).toBeUndefined();
    expect(tokens.idClaims).toBeUndefined();
    expect(tokens.scope).toBe('authz:check');
  });

  it('works with no arguments at all and omits an unrequested scope', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials();

    expect(state.tokenForms[0].has('scope')).toBe(false);
  });

  it('raises AuthError client-side for a public client (no clientSecret)', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    await expect(oidc.loginClientCredentials()).rejects.toThrow(/confidential-client credentials/);
    expect(state.tokenCalls).toBe(0);
  });

  it('optionally adopts the token as the session bearer credential, but never for /oauth2/*', async () => {
    const state = createMockState();
    let protectedAuthHeader: string | null = null;
    let tokenEndpointAuthHeader: string | null | undefined;
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        tokenEndpointAuthHeader = request.headers.get('authorization');
        return HttpResponse.json(tokenResponse({ access_token: 'm2m-access-token' }));
      }),
      http.get(`${BASE_URL}/api/v1/protected`, ({ request }) => {
        protectedAuthHeader = request.headers.get('authorization');
        return HttpResponse.json({ ok: true });
      }),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials({ adoptAsCredential: true });
    await session.axios.get('/api/v1/protected');

    expect(protectedAuthHeader).toBe('Bearer m2m-access-token');
    // The client authenticates itself in the FORM body at /oauth2/* (§12.1
    // note 3) — no Authorization header is added there.
    expect(tokenEndpointAuthHeader).toBeNull();
  });

  it('does not touch the session credential unless adoption was requested', async () => {
    const state = createMockState();
    let protectedAuthHeader: string | null = null;
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse())),
      http.get(`${BASE_URL}/api/v1/protected`, ({ request }) => {
        protectedAuthHeader = request.headers.get('authorization');
        return HttpResponse.json({ ok: true });
      }),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials();
    await session.axios.get('/api/v1/protected');

    expect(protectedAuthHeader).toBeNull();
  });
});

describe('introspect (§12.1, RFC 7662)', () => {
  it('posts a form body to the introspection endpoint and maps the response', async () => {
    const state = createMockState();
    let captured: URLSearchParams | undefined;
    let tenantIdQuery: string | null = null;
    server.use(
      discoveryHandler(state),
      http.post(INTROSPECT_ENDPOINT, async ({ request }) => {
        tenantIdQuery = new URL(request.url).searchParams.get('tenant_id');
        captured = new URLSearchParams(await request.text());
        return HttpResponse.json({
          active: true,
          sub: 'user-9',
          client_id: CLIENT_ID,
          scope: 'openid profile',
          token_type: 'Bearer',
          exp: 1_800_000_900,
          iat: 1_800_000_000,
        });
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const result = await oidc.introspect({
      token: new Sensitive('token-to-check'),
      tokenTypeHint: 'access_token',
    });

    expect(tenantIdQuery).toBe(TENANT_ID);
    expect(captured?.get('token')).toBe('token-to-check');
    expect(captured?.get('client_id')).toBe(CLIENT_ID);
    expect(captured?.get('client_secret')).toBe(CLIENT_SECRET);
    expect(captured?.get('token_type_hint')).toBe('access_token');
    expect(result).toEqual({
      active: true,
      sub: 'user-9',
      clientId: CLIENT_ID,
      scope: 'openid profile',
      tokenType: 'Bearer',
      exp: 1_800_000_900,
      iat: 1_800_000_000,
    });
  });

  it('returns { active: false } with no metadata for an inactive token', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(INTROSPECT_ENDPOINT, () => HttpResponse.json({ active: false, sub: null, exp: null })),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.introspect({ token: 'unknown' })).resolves.toEqual({ active: false });
  });

  it('omits token_type_hint when the caller does not supply one', async () => {
    const state = createMockState();
    let captured: URLSearchParams | undefined;
    server.use(
      discoveryHandler(state),
      http.post(INTROSPECT_ENDPOINT, async ({ request }) => {
        captured = new URLSearchParams(await request.text());
        return HttpResponse.json({ active: true });
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.introspect({ token: 't' });

    expect(captured?.has('token_type_hint')).toBe(false);
  });

  it('a 401 becomes OAuthProtocolError and does NOT trigger the §9 refresh guard', async () => {
    const state = createMockState();
    let sessionRefreshCalls = 0;
    server.use(
      discoveryHandler(state),
      http.post(`${BASE_URL}/api/v1/auth/refresh`, () => {
        sessionRefreshCalls += 1;
        return HttpResponse.json({ expires_in: 900 });
      }),
      http.post(INTROSPECT_ENDPOINT, () =>
        HttpResponse.json(
          { error: 'invalid_client', error_description: 'client authentication failed' },
          { status: 401 },
        ),
      ),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    // The refresh interceptor only fires for an authenticated session, so make
    // the test hostile: pretend we are logged in.
    session.authenticated = true;

    const error = await oidc.introspect({ token: 't' }).then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(OAuthProtocolError);
    expect(error).toBeInstanceOf(AuthError);
    expect((error as OAuthProtocolError).error).toBe('invalid_client');
    expect((error as OAuthProtocolError).message).toBe('invalid_client: client authentication failed');
    // §12.3 rule 3: a client-credential failure is not a session expiry.
    expect(sessionRefreshCalls).toBe(0);
  });

  it('raises AuthError client-side for a public client', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    await expect(oidc.introspect({ token: 't' })).rejects.toThrow(/confidential-client credentials/);
  });
});

describe('revoke (§12.1, RFC 7009)', () => {
  it('posts a form body to the revocation endpoint and resolves with no value', async () => {
    const state = createMockState();
    let captured: URLSearchParams | undefined;
    let tenantIdQuery: string | null = null;
    server.use(
      discoveryHandler(state),
      http.post(REVOKE_ENDPOINT, async ({ request }) => {
        tenantIdQuery = new URL(request.url).searchParams.get('tenant_id');
        captured = new URLSearchParams(await request.text());
        return new HttpResponse(null, { status: 200 });
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(
      oidc.revoke({ token: new Sensitive('token-to-revoke'), tokenTypeHint: 'refresh_token' }),
    ).resolves.toBeUndefined();

    expect(tenantIdQuery).toBe(TENANT_ID);
    expect(captured?.get('token')).toBe('token-to-revoke');
    expect(captured?.get('client_secret')).toBe(CLIENT_SECRET);
    expect(captured?.get('token_type_hint')).toBe('refresh_token');
  });

  it('is idempotent: a 200 for an unknown/already-revoked token is success', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      // RFC 7009: the server answers 200 for tokens it has never seen.
      http.post(REVOKE_ENDPOINT, () => new HttpResponse(null, { status: 200 })),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.revoke({ token: 'never-existed' })).resolves.toBeUndefined();
    await expect(oidc.revoke({ token: 'never-existed' })).resolves.toBeUndefined();
    await expect(oidc.revoke({ token: 'never-existed' })).resolves.toBeUndefined();
  });

  it('surfaces a 401 as OAuthProtocolError', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(REVOKE_ENDPOINT, () =>
        HttpResponse.json({ error: 'invalid_client', error_description: 'bad secret' }, { status: 401 }),
      ),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.revoke({ token: 't' })).rejects.toBeInstanceOf(OAuthProtocolError);
  });

  it('surfaces a transport failure as NetworkError', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(REVOKE_ENDPOINT, () => HttpResponse.json({ oops: true }, { status: 500 })),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.revoke({ token: 't' })).rejects.toBeInstanceOf(NetworkError);
  });

  it('raises AuthError client-side for a public client', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    await expect(oidc.revoke({ token: 't' })).rejects.toThrow(/confidential-client credentials/);
  });
});

describe('transport, caching and interceptor paths', () => {
  it('surfaces a connection failure (no HTTP response at all) as NetworkError', async () => {
    server.use(http.get(`${BASE_URL}${DISCOVERY_PATH}`, () => HttpResponse.error()));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const error = await oidc.oidcDiscover().then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(NetworkError);
    expect((error as NetworkError).message).toBe('oidc discovery request failed');
  });

  it('does not invent a message from a non-object error body', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => new HttpResponse('gateway exploded', { status: 502 })),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const error = await oidc.loginClientCredentials().then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(NetworkError);
    expect((error as NetworkError).message).toBe('token request failed');
  });

  it('reuses one JWKS verifier (and its cached key set) across exchanges', async () => {
    const key = await generateSigningKey('reuse-kid');
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, async () =>
        HttpResponse.json(tokenResponse({ id_token: await signIdToken(key, { nonce: 'n' }) })),
      ),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.oidcExchange({ code: 'c1', codeVerifier: 'v', redirectUri: 'https://app/cb', nonce: 'n' });
    await oidc.oidcExchange({ code: 'c2', codeVerifier: 'v', redirectUri: 'https://app/cb', nonce: 'n' });

    expect(state.tokenCalls).toBe(2);
    // One JWKS fetch for two validations: the verifier — and jose's key-set
    // cache inside it — is built once per jwks_uri, not per call.
    expect(state.jwksCalls).toBe(1);
  });

  it('installs the credential-adoption interceptor only once across repeated adoptions', async () => {
    const state = createMockState();
    const authHeaders: (string | null)[] = [];
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ access_token: 'm2m-token' }))),
      http.get(`${BASE_URL}/api/v1/protected`, ({ request }) => {
        authHeaders.push(request.headers.get('authorization'));
        return HttpResponse.json({ ok: true });
      }),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials({ adoptAsCredential: true });
    await oidc.loginClientCredentials({ adoptAsCredential: true });
    await session.axios.get('/api/v1/protected');

    // A single header, not a duplicated one — the interceptor was not stacked.
    expect(authHeaders).toEqual(['Bearer m2m-token']);
  });

  it('honours a narrowed clockSkewSec when validating an id_token', async () => {
    const key = await generateSigningKey('skew-kid');
    // Expired 30 s ago: inside the default 60 s allowance, outside a 5 s one.
    const idToken = await signIdToken(key, { nonce: null, expiresInSec: -30 });
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ id_token: idToken }))),
    );

    const lenient = createClient({ clientSecret: CLIENT_SECRET });
    await expect(lenient.oidc.oidcRefresh({ refreshToken: 'r' })).resolves.toMatchObject({
      tokenType: 'Bearer',
    });

    const strict = createClient({ clientSecret: CLIENT_SECRET, clockSkewSec: 5 });
    await expect(strict.oidc.oidcRefresh({ refreshToken: 'r' })).rejects.toMatchObject({
      reason: 'token_expired',
    });
  });

  it('rejects a malformed id_token that is not a well-formed JWS', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ id_token: 'not-a-jwt-at-all' }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.oidcRefresh({ refreshToken: 'r' })).rejects.toMatchObject({
      reason: 'invalid_alg',
    });
  });

  it('a 401 from /oauth2/introspect on a fully-wired client stays out of the §9 guard', async () => {
    // The realistic wiring: an AxiamClient installs the CSRF + reactive
    // 401->refresh interceptors on the session, and the OidcClient shares it.
    const state = createMockState();
    let sessionRefreshCalls = 0;
    server.use(
      discoveryHandler(state),
      http.post(`${BASE_URL}/api/v1/auth/refresh`, () => {
        sessionRefreshCalls += 1;
        return HttpResponse.json({ expires_in: 900 });
      }),
      http.post(INTROSPECT_ENDPOINT, () =>
        HttpResponse.json(
          { error: 'invalid_client', error_description: 'client authentication failed' },
          { status: 401 },
        ),
      ),
    );
    const client = createNodeClient({ baseUrl: BASE_URL, tenantId: TENANT_ID, orgId: ORG_ID });
    client.session.authenticated = true;
    const oidc = createOidcClient(client.session, {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    const error = await oidc.introspect({ token: 't' }).then(
      () => undefined,
      (err: unknown) => err,
    );

    // The interceptor mapped it (SKIP_REFRESH covers /oauth2/*) and the OIDC
    // layer passed the already-mapped AxiamError straight through.
    expect(error).toBeInstanceOf(OAuthProtocolError);
    expect((error as OAuthProtocolError).message).toBe('invalid_client: client authentication failed');
    expect(sessionRefreshCalls).toBe(0);
  });
});
