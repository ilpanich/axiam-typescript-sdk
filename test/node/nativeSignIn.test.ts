// Native sign-in with a provider ID token — CONTRACT.md §37 (contract 1.65).
//
// The thirteen §37.9 tests, by the contract's names. Every secret is generated
// at run time, and an assertion that fails never prints it.

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { createHash } from 'node:crypto';
import { AuthError, NetworkError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import { ValidationError } from '../../src/management/errors.js';
import { createOidcClient, PROVIDER_ID_TOKEN_GRANT_TYPE } from '../../src/node/oidc.js';
import { nativeNonce } from '../../src/node/oidcPkce.js';
import { createNodeSession } from '../../src/node/session.js';
import { exhaustiveErrorRenderings, freshSecret } from '../redaction.js';
import {
  BASE_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  discoveryDocument,
  discoveryHandler,
  generateSigningKey,
  jwksHandler,
  ORG_ID,
  signIdToken,
  TENANT_ID,
  tokenHandler,
  tokenResponse,
  TOKEN_ENDPOINT,
} from './oidcTestKit.js';

const server = createServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const NONCE_VECTOR = 'n-0S6_WzA2Mj';
const NONCE_VECTOR_SHA256 = '0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19';
const GENERIC_DESCRIPTION = 'the provider ID token is not acceptable';

/** Mount discovery + a token handler; returns the state so tests can count and inspect requests. */
function mount(responder: (form: URLSearchParams) => Response | Promise<Response>, doc = discoveryDocument()) {
  const state = createMockState();
  const headers: Headers[] = [];
  server.use(
    discoveryHandler(state, doc),
    http.post(TOKEN_ENDPOINT, async ({ request }) => {
      state.tokenCalls += 1;
      headers.push(request.headers);
      state.tokenTenantIds.push(new URL(request.url).searchParams.get('tenant_id'));
      state.tokenContentTypes.push(request.headers.get('content-type'));
      const text = await request.text();
      const form = new URLSearchParams(text);
      state.tokenForms.push(form);
      rawBodies.push(text);
      return responder(form);
    }),
  );
  return { state, headers };
}
let rawBodies: string[] = [];
afterEach(() => {
  rawBodies = [];
});

const oauthError = (error: string, description = `${error} description`, status = 400, init: ResponseInit = {}) =>
  HttpResponse.json({ error, error_description: description }, { status, ...init });
const ok = () => HttpResponse.json(tokenResponse());

describe('loginWithProviderIdToken (§37)', () => {
  it('request_body_exact', async () => {
    const { state, headers } = mount(() => ok());
    const { oidc } = createClient();
    const configuration = discoveryDocument();

    await oidc.loginWithProviderIdToken('prov', 'the-id-token', 'the-nonce', {
      configuration,
      scopes: ['openid', 'profile'],
      resource: 'https://api.example.com',
    });

    expect(state.tokenCalls).toBe(1);
    expect(state.tokenTenantIds[0]).toBe(TENANT_ID);
    expect(state.tokenContentTypes[0]).toContain('application/x-www-form-urlencoded');
    const form = state.tokenForms[0]!;
    expect(form.has('tenant_id')).toBe(false);
    expect([...form.keys()].sort()).toEqual(
      ['client_id', 'grant_type', 'id_token', 'nonce', 'provider', 'resource', 'scope'].sort(),
    );
    expect(form.get('grant_type')).toBe('urn:axiam:params:oauth:grant-type:provider-id-token');
    expect(form.get('grant_type')).toBe(PROVIDER_ID_TOKEN_GRANT_TYPE);
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('scope')).toBe('openid profile');
    expect(form.get('resource')).toBe('https://api.example.com');
    expect(headers[0]!.get('authorization')).toBeNull();
    expect(headers[0]!.get('cookie')).toBeNull();
    expect(headers[0]!.get('x-csrf-token')).toBeNull();

    // No scopes, no resource: neither key is sent, and `openid` is not added.
    await oidc.loginWithProviderIdToken('prov', 'the-id-token', 'the-nonce', { configuration });
    const bare = state.tokenForms[1]!;
    expect([...bare.keys()].sort()).toEqual(['client_id', 'grant_type', 'id_token', 'nonce', 'provider']);
    expect(bare.has('scope')).toBe(false);
    // An empty list is the same as none: never `scope=`.
    await oidc.loginWithProviderIdToken('prov', 'the-id-token', 'the-nonce', { configuration, scopes: [] });
    expect(state.tokenForms[2]!.has('scope')).toBe(false);
  });

  it('raw_nonce_sent_not_hash', async () => {
    const key = await generateSigningKey('native-kid');
    // A fixture token whose own `nonce` claim carries the hash.
    const idToken = await signIdToken(key, { nonce: NONCE_VECTOR_SHA256 });
    const { state } = mount(() => ok());
    const { oidc } = createClient();

    await oidc.loginWithProviderIdToken('prov', idToken, NONCE_VECTOR, { configuration: discoveryDocument() });

    expect(state.tokenForms[0]!.get('nonce')).toBe(NONCE_VECTOR);
    expect(state.tokenForms[0]!.get('id_token')).toBe(idToken);
    expect(rawBodies[0]).not.toContain(NONCE_VECTOR_SHA256);
    expect(rawBodies[0]).not.toContain(NONCE_VECTOR_SHA256.toUpperCase());
    // A wrapped nonce is sent byte for byte too.
    await oidc.loginWithProviderIdToken('prov', new Sensitive(idToken), new Sensitive(NONCE_VECTOR), {
      configuration: discoveryDocument(),
    });
    expect(state.tokenForms[1]!.get('nonce')).toBe(NONCE_VECTOR);
  });

  it('provider_sent_verbatim', async () => {
    const { state } = mount(() => ok());
    const { oidc } = createClient();
    const configuration = discoveryDocument();
    const uuid = '3f2b8c1e-0a4d-4f6e-9b1a-7c5d2e8f9a10';
    for (const provider of [uuid, 'Corp-Okta', 'google']) {
      await oidc.loginWithProviderIdToken(provider, 't', 'n', { configuration });
    }
    expect(state.tokenForms.map((f) => f.get('provider'))).toEqual([uuid, 'Corp-Okta', 'google']);
    // One request per call, in total: no sso_providers lookup, no discovery fetch.
    expect(state.tokenCalls).toBe(3);
    expect(state.discoveryCalls).toBe(0);
  });

  it('public_client_sends_client_id_only', async () => {
    const { state, headers } = mount(() => ok());
    const { oidc } = createClient(); // no secret

    const tokens = await oidc.loginWithProviderIdToken('prov', 't', 'n', { configuration: discoveryDocument() });

    expect(tokens.accessToken.expose()).toBe('access-token-value');
    const form = state.tokenForms[0]!;
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.has('client_secret')).toBe(false);
    expect(form.has('client_assertion')).toBe(false);
    expect(headers[0]!.get('authorization')).toBeNull();
  });

  it('confidential_client_sends_its_credential', async () => {
    for (const methods of [['client_secret_post'], ['client_secret_basic']]) {
      const { state, headers } = mount(
        () => ok(),
        discoveryDocument({ token_endpoint_auth_methods_supported: methods }),
      );
      const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
      await oidc.loginWithProviderIdToken('prov', 't', 'n');
      expect(state.tokenForms[0]!.get('client_secret')).toBe(CLIENT_SECRET);
      expect(headers[0]!.get('authorization')).toBeNull();
      server.resetHandlers();
    }
  });

  it('empty_inputs_refused_locally', async () => {
    const { state } = mount(() => ok());
    const { oidc } = createClient();
    const configuration = discoveryDocument();

    const attempts: Array<[string, string, string]> = [
      ['', 't', 'n'],
      ['prov', '', 'n'],
      ['prov', 't', ''],
    ];
    for (const [p, t, n] of attempts) {
      await expect(oidc.loginWithProviderIdToken(p, t, n, { configuration })).rejects.toBeInstanceOf(ValidationError);
    }
    await expect(
      oidc.loginWithProviderIdToken('prov', new Sensitive(''), new Sensitive('n'), { configuration }),
    ).rejects.toBeInstanceOf(ValidationError);

    // A slug-only client (§12.3 rule 4): the taxonomy error, before discovery too.
    const session = createNodeSession({ baseUrl: BASE_URL, tenantId: 'my-tenant-slug', orgId: ORG_ID });
    const slugOnly = createOidcClient(session, { clientId: CLIENT_ID });
    await expect(slugOnly.loginWithProviderIdToken('prov', 't', 'n')).rejects.toBeInstanceOf(AuthError);
    await expect(slugOnly.loginWithProviderIdToken('prov', 't', 'n', { configuration })).rejects.toBeInstanceOf(
      AuthError,
    );

    expect(state.tokenCalls).toBe(0);
    expect(state.discoveryCalls).toBe(0);
  });

  it('generic_invalid_grant_mapped', async () => {
    const { state } = mount(() => oauthError('invalid_grant', GENERIC_DESCRIPTION));
    const { oidc, session } = createClient();
    const guard = vi.spyOn(session, 'refreshGuard');

    const err = await oidc
      .loginWithProviderIdToken('prov', 't', 'n', { configuration: discoveryDocument() })
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OAuthProtocolError);
    const protocol = err as OAuthProtocolError;
    expect(protocol.error).toBe('invalid_grant');
    expect(protocol.errorDescription).toBe(GENERIC_DESCRIPTION);
    expect(protocol.message).toBe(`invalid_grant: ${GENERIC_DESCRIPTION}`);
    expect(state.tokenCalls).toBe(1);
    expect(guard).not.toHaveBeenCalled();
  });

  it('consent_required_mapped', async () => {
    const { state } = mount(() => oauthError('consent_required'));
    const { oidc } = createClient();
    await expect(
      oidc.loginWithProviderIdToken('prov', 't', 'n', { configuration: discoveryDocument(), scopes: ['profile'] }),
    ).rejects.toMatchObject({ error: 'consent_required' });
    expect(state.tokenCalls).toBe(1);
    expect(state.tokenForms[0]!.get('grant_type')).toBe(PROVIDER_ID_TOKEN_GRANT_TYPE);
  });

  it('client_and_scope_refusals_surfaced', async () => {
    const cases: Array<[string, number, ResponseInit]> = [
      ['unauthorized_client', 400, {}],
      ['invalid_client', 401, { headers: { 'WWW-Authenticate': 'Basic realm="oauth2"' } }],
      ['invalid_scope', 400, {}],
      ['invalid_target', 400, {}],
    ];
    for (const [code, status, init] of cases) {
      const { state } = mount(() => oauthError(code, `${code} text`, status, init));
      const { oidc, session } = createClient();
      const guard = vi.spyOn(session, 'refreshGuard');
      const err = await oidc
        .loginWithProviderIdToken('prov', 't', 'n', { configuration: discoveryDocument(), scopes: ['address'] })
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(OAuthProtocolError);
      expect((err as OAuthProtocolError).error).toBe(code);
      // One request each: the scope is not narrowed and re-sent, a 401 never enters §9.
      expect(state.tokenCalls).toBe(1);
      expect(guard).not.toHaveBeenCalled();
      server.resetHandlers();
    }
  });

  it('rate_limit_with_retry_after_mapped', async () => {
    const { state } = mount(() =>
      HttpResponse.json({ error: 'rate_limit_exceeded' }, { status: 429, headers: { 'Retry-After': '7' } }),
    );
    const { oidc } = createClient();
    const err = await oidc
      .loginWithProviderIdToken('prov', 't', 'n', { configuration: discoveryDocument() })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('rate_limit_exceeded');
    // This SDK does not expose Retry-After on OAuthProtocolError (device_poll: same).
    expect(state.tokenCalls).toBe(1);
  });

  it('server_error_not_retried', async () => {
    let count = 0;
    server.use(
      http.post(TOKEN_ENDPOINT, () => {
        count += 1;
        return HttpResponse.json({ error: 'server_error', error_description: 'datastore down' }, { status: 500 });
      }),
    );
    const { oidc } = createClient();
    const configuration = discoveryDocument();
    const withBody = await oidc.loginWithProviderIdToken('prov', 't', 'n', { configuration }).catch((e: unknown) => e);
    expect(withBody).toBeInstanceOf(OAuthProtocolError);
    expect((withBody as OAuthProtocolError).error).toBe('server_error');
    expect(count).toBe(1);

    // A 500 with no body is a NetworkError.
    count = 0;
    server.use(
      http.post(TOKEN_ENDPOINT, () => {
        count += 1;
        return new HttpResponse(null, { status: 500 });
      }),
    );
    const bare = await oidc.loginWithProviderIdToken('prov', 't', 'n', { configuration }).catch((e: unknown) => e);
    expect(bare).toBeInstanceOf(NetworkError);
    expect(bare).not.toBeInstanceOf(OAuthProtocolError);
    expect(count).toBe(1);

    // A transport failure after the request is sent.
    count = 0;
    server.use(
      http.post(TOKEN_ENDPOINT, () => {
        count += 1;
        return HttpResponse.error();
      }),
    );
    const dropped = await oidc.loginWithProviderIdToken('prov', 't', 'n', { configuration }).catch((e: unknown) => e);
    expect(dropped).toBeInstanceOf(NetworkError);
    expect(count).toBe(1);
  });

  it('result_is_the_ordinary_token_set', async () => {
    const key = await generateSigningKey('native-kid-2');
    const raw = 'raw-nonce-value-123';
    const idToken = await signIdToken(key, { nonce: raw });
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, () =>
        HttpResponse.json(
          tokenResponse({
            token_type: 'DPoP',
            refresh_token: 'rt',
            id_token: idToken,
            scope: 'openid profile',
          }),
        ),
      ),
    );
    const { oidc, session } = createClient();

    const tokens = await oidc.loginWithProviderIdToken('prov', 'provider-token', raw, { scopes: ['openid'] });

    expect(tokens.tokenType).toBe('DPoP');
    expect(tokens.scope).toBe('openid profile');
    expect(tokens.refreshToken?.expose()).toBe('rt');
    expect(tokens.idToken?.expose()).toBe(idToken);
    expect(tokens.idClaims?.sub).toBe('user-1');
    expect(tokens.accessToken).toBeInstanceOf(Sensitive);
    // This SDK returns the set and does not adopt it (the deviceLogin posture, rule 9).
    expect(session.deviceAccessToken).toBeUndefined();
    let authorization: string | null = 'unset';
    server.use(
      http.get(`${BASE_URL}/adoption-probe`, ({ request }) => {
        authorization = request.headers.get('authorization');
        return HttpResponse.json({});
      }),
    );
    await session.axios.get(`${BASE_URL}/adoption-probe`);
    expect(authorization).toBeNull();

    // A mismatching claim is the nonce_mismatch AuthError, and no token set escapes.
    const mismatch = await oidc.loginWithProviderIdToken('prov', 'provider-token', 'a-different-nonce', {
      scopes: ['openid'],
    }).catch((e: unknown) => e);
    expect(mismatch).toBeInstanceOf(AuthError);
    expect((mismatch as AuthError).message).toMatch(/nonce/i);

    // Without refresh_token and id_token, both are absent.
    server.resetHandlers();
    const plain = createMockState();
    server.use(discoveryHandler(plain), tokenHandler(plain, () => ok()));
    const bare = await createClient().oidc.loginWithProviderIdToken('prov', 't', 'n');
    expect(bare.refreshToken).toBeUndefined();
    expect(bare.idToken).toBeUndefined();
    expect(bare.idClaims).toBeUndefined();
  });

  it('no_secret_in_logs_or_errors', async () => {
    const idToken = `fixture-id-token-${freshSecret()}`;
    const nonce = `fixture-raw-nonce-${freshSecret()}`;
    const logged: string[] = [];
    const spies = (['log', 'info', 'warn', 'error', 'debug', 'trace'] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
        logged.push(args.map((a) => String(a)).join(' '));
      }),
    );
    const telemetry: unknown[] = [];
    const session = createNodeSession({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      orgId: ORG_ID,
      telemetryHook: (e) => telemetry.push(e),
    });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });
    const configuration = discoveryDocument();

    const scenarios: Array<() => Response> = [
      () => ok(),
      () => oauthError('invalid_grant', GENERIC_DESCRIPTION),
      () => oauthError('consent_required'),
      () => oauthError('invalid_client', 'bad client', 401),
      () => HttpResponse.json({ error: 'rate_limit_exceeded' }, { status: 429, headers: { 'Retry-After': '7' } }),
      () => HttpResponse.json({ error: 'server_error', error_description: 'x' }, { status: 500 }),
      () => new HttpResponse(null, { status: 500 }),
      () => HttpResponse.error(),
    ];
    const renderings: string[] = [];
    for (const scenario of scenarios) {
      server.use(http.post(TOKEN_ENDPOINT, () => scenario()));
      try {
        const set = await oidc.loginWithProviderIdToken('prov', new Sensitive(idToken), new Sensitive(nonce), {
          configuration,
        });
        renderings.push(exhaustiveErrorRenderings(set));
      } catch (err) {
        renderings.push(exhaustiveErrorRenderings(err));
      }
      server.resetHandlers();
    }
    // The local refusals (test 5) carry neither value either.
    for (const call of [
      () => oidc.loginWithProviderIdToken('', idToken, nonce, { configuration }),
      () => oidc.loginWithProviderIdToken('prov', '', nonce, { configuration }),
      () => oidc.loginWithProviderIdToken('prov', idToken, '', { configuration }),
    ]) {
      renderings.push(exhaustiveErrorRenderings(await call().catch((e: unknown) => e)));
    }
    spies.forEach((s) => s.mockRestore());

    const haystack = [...renderings, ...logged, JSON.stringify(telemetry)].join('\n');
    expect(haystack.includes(idToken), 'the provider ID token reached a log, error or telemetry sink').toBe(false);
    expect(haystack.includes(nonce), 'the raw nonce reached a log, error or telemetry sink').toBe(false);

    // ProviderNonce.raw's own rendering.
    const pair = nativeNonce();
    const rawValue = pair.raw.expose();
    expect(exhaustiveErrorRenderings(pair).includes(rawValue)).toBe(false);
    expect(`${pair.raw}${JSON.stringify(pair)}`.includes(rawValue)).toBe(false);
  });
});

describe('nativeNonce (§37.4)', () => {
  it('native_nonce_pair', () => {
    const pair = nativeNonce();
    const raw = pair.raw.expose();

    expect(raw).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(raw).not.toContain('=');
    expect(Buffer.from(raw, 'base64url').length).toBeGreaterThanOrEqual(32);
    expect(pair.hashed).toMatch(/^[0-9a-f]{64}$/);
    expect(pair.hashed).toBe(createHash('sha256').update(Buffer.from(raw, 'utf8')).digest('hex'));

    const other = nativeNonce();
    expect(other.raw.expose()).not.toBe(raw);
    expect(other.hashed).not.toBe(pair.hashed);

    // `raw` is wrapped; `hashed` is a plain string.
    expect(pair.raw).toBeInstanceOf(Sensitive);
    expect(String(pair.raw)).toBe('[SENSITIVE]');
    expect(typeof pair.hashed).toBe('string');
  });

  it('hashes the §37.4 fixed vector', () => {
    // The vector tests the hashing step only; `raw` itself is random.
    expect(createHash('sha256').update(NONCE_VECTOR, 'utf8').digest('hex')).toBe(NONCE_VECTOR_SHA256);
  });
});
