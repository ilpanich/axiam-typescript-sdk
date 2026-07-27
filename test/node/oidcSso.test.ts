// ssoStart / ssoComplete — the upstream-IdP federation path
// (CONTRACT.md §12.1 notes 6–7, §12.3 rule 4, §4 cookie jar).

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { CookieJar } from 'tough-cookie';
import { http, HttpResponse } from 'msw';
import { AuthError, NetworkError } from '../../src/core/index.js';
import { createOidcClient, SSO_CALLBACK_PATH, SSO_START_PATH } from '../../src/node/oidc.js';
import { createNodeSession, NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { wrapAxios } from '../../src/node/cookieJar.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';
import { BASE_URL, CLIENT_ID, createClient, createServer, ORG_ID, TENANT_ID } from './oidcTestKit.js';

const FEDERATION_CONFIG_ID = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff';
const SSO_REDIRECT_URI = 'https://app.example.com/after-login';

const server = createServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('ssoStart (§12.1)', () => {
  it('posts a JSON body with the session tenant/org UUIDs and maps the response', async () => {
    let captured: Record<string, unknown> | undefined;
    server.use(
      http.post(`${BASE_URL}${SSO_START_PATH}`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          authorize_url: 'https://idp.example.com/authorize?state=abc',
          state: 'abc',
          expires_in_secs: 600,
        });
      }),
    );
    const { oidc } = createClient();

    const result = await oidc.ssoStart({
      federationConfigId: FEDERATION_CONFIG_ID,
      redirectUri: SSO_REDIRECT_URI,
    });

    expect(captured).toEqual({
      federation_config_id: FEDERATION_CONFIG_ID,
      redirect_uri: SSO_REDIRECT_URI,
      tenant_id: TENANT_ID,
      org_id: ORG_ID,
    });
    expect(result).toEqual({
      authorizeUrl: 'https://idp.example.com/authorize?state=abc',
      state: 'abc',
      expiresInSecs: 600,
    });
    // §12.1 note 7: the federation nonce never leaves the server, so there is
    // no nonce anywhere in the result.
    expect(Object.keys(result)).not.toContain('nonce');
  });

  it('sends slug forms when the client was constructed with slugs', async () => {
    let captured: Record<string, unknown> | undefined;
    server.use(
      http.post(`${BASE_URL}${SSO_START_PATH}`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ authorize_url: 'https://idp/x', state: 's', expires_in_secs: 600 });
      }),
    );
    const session = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'acme-org' });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });

    await oidc.ssoStart({ federationConfigId: FEDERATION_CONFIG_ID, redirectUri: SSO_REDIRECT_URI });

    expect(captured).toMatchObject({ tenant_slug: 'acme', org_slug: 'acme-org' });
    expect(captured).not.toHaveProperty('tenant_id');
    expect(captured).not.toHaveProperty('org_id');
  });

  it('lets per-call arguments override the session context', async () => {
    let captured: Record<string, unknown> | undefined;
    server.use(
      http.post(`${BASE_URL}${SSO_START_PATH}`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ authorize_url: 'https://idp/x', state: 's', expires_in_secs: 600 });
      }),
    );
    const { oidc } = createClient();

    await oidc.ssoStart({
      federationConfigId: FEDERATION_CONFIG_ID,
      redirectUri: SSO_REDIRECT_URI,
      tenantSlug: 'other-tenant',
      orgSlug: 'other-org',
    });

    // The UUID form still wins when the session carries one (§5.1 precedence).
    expect(captured).toMatchObject({ tenant_id: TENANT_ID, org_id: ORG_ID });
  });

  it('raises AuthError client-side, with no wire call, when tenant context is missing', async () => {
    let calls = 0;
    server.use(
      http.post(`${BASE_URL}${SSO_START_PATH}`, () => {
        calls += 1;
        return HttpResponse.json({ authorize_url: 'x', state: 's', expires_in_secs: 600 });
      }),
    );
    // A session cannot be built without a tenant (§5), so simulate the
    // resolved-to-nothing case by blanking both tenant forms.
    const session = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'org' });
    Object.defineProperty(session, 'tenantSlug', { value: undefined, configurable: true });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });

    await expect(
      oidc.ssoStart({ federationConfigId: FEDERATION_CONFIG_ID, redirectUri: SSO_REDIRECT_URI }),
    ).rejects.toThrow(/requires tenant context/);
    expect(calls).toBe(0);
  });

  it('raises AuthError client-side, with no wire call, when org context is missing', async () => {
    let calls = 0;
    server.use(
      http.post(`${BASE_URL}${SSO_START_PATH}`, () => {
        calls += 1;
        return HttpResponse.json({ authorize_url: 'x', state: 's', expires_in_secs: 600 });
      }),
    );
    const session = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });

    const error = await oidc
      .ssoStart({ federationConfigId: FEDERATION_CONFIG_ID, redirectUri: SSO_REDIRECT_URI })
      .then(
        () => undefined,
        (err: unknown) => err,
      );

    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).message).toMatch(/requires organization context/);
    expect(calls).toBe(0);
  });

  it('maps a 401 (unknown org/tenant slug) onto the §2 taxonomy', async () => {
    server.use(
      http.post(`${BASE_URL}${SSO_START_PATH}`, () =>
        HttpResponse.json({ message: 'unknown tenant' }, { status: 401 }),
      ),
    );
    const { oidc } = createClient();

    await expect(
      oidc.ssoStart({ federationConfigId: FEDERATION_CONFIG_ID, redirectUri: SSO_REDIRECT_URI }),
    ).rejects.toBeInstanceOf(AuthError);
  });
});

describe('ssoComplete (§12.1 note 6, §4)', () => {
  /**
   * A NodeSession over a caller-controlled, pre-seeded cookie jar — the same
   * shape `test/node/nodeSession.test.ts` uses. Set-Cookie does not propagate
   * into a real jar through msw, so the jar is seeded with what the server
   * would have set and the assertion is that `ssoComplete` runs the same
   * post-authentication sync `login()` does, i.e. that the §4 jar is where the
   * session actually comes from.
   */
  async function seededSession(cookies: Record<string, string>): Promise<NodeSession> {
    const jar = new CookieJar();
    for (const [name, value] of Object.entries(cookies)) {
      await jar.setCookie(`${name}=${value}; Path=/`, BASE_URL);
    }
    const options = { baseUrl: BASE_URL, tenantId: TENANT_ID, orgId: ORG_ID };
    const base = createSession(options);
    wrapAxios(base.axios, jar);
    return new NodeSession(
      options,
      base,
      new TokenManager(jar, BASE_URL, base.tenantHeaderValue),
      createVerifier(BASE_URL),
      jar,
    );
  }

  function callbackHandler(body: Record<string, unknown>) {
    return http.post(`${BASE_URL}${SSO_CALLBACK_PATH}`, async ({ request }) => {
      const received = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...body, echoed_state: received.state });
    });
  }

  it('posts state+code and maps SsoLoginSuccessResponse, which carries no token material', async () => {
    let captured: Record<string, unknown> | undefined;
    server.use(
      http.post(`${BASE_URL}${SSO_CALLBACK_PATH}`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          user_id: '99999999-8888-7777-6666-555555555555',
          session_id: '12121212-3434-5656-7878-909090909090',
          expires_in: 900,
          redirect_uri: SSO_REDIRECT_URI,
        });
      }),
    );
    const { oidc } = createClient();

    const result = await oidc.ssoComplete({ state: 'abc', code: 'idp-code' });

    // §12.1 note 7: `state` is round-tripped unmodified and no nonce is sent.
    expect(captured).toEqual({ state: 'abc', code: 'idp-code' });
    expect(result).toEqual({
      userId: '99999999-8888-7777-6666-555555555555',
      sessionId: '12121212-3434-5656-7878-909090909090',
      expiresIn: 900,
      redirectUri: SSO_REDIRECT_URI,
    });
    // §12.1 note 6: the response body has no token/secret field at all.
    expect(Object.keys(result).sort()).toEqual(['expiresIn', 'redirectUri', 'sessionId', 'userId']);
  });

  it('takes the session from the §4 cookie jar via the same post-login sync as login()', async () => {
    server.use(
      callbackHandler({
        user_id: 'u',
        session_id: 's',
        expires_in: 900,
        redirect_uri: SSO_REDIRECT_URI,
      }),
    );
    const session = await seededSession({
      axiam_access: 'sso-session-access-token',
      axiam_csrf: 'sso-csrf-value',
    });
    const onAuthenticated = vi.spyOn(session, 'onAuthenticated');
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });

    await oidc.ssoComplete({ state: 'abc', code: 'idp-code' });

    expect(session.authenticated).toBe(true);
    expect(onAuthenticated).toHaveBeenCalledOnce();
    // The hook read the httpOnly session cookie and the CSRF cookie out of the
    // jar — without a jar (§4) there would be nothing to read and the session
    // would be silently lost.
    expect(session.tokenManager.cachedAccessToken()?.expose()).toBe('sso-session-access-token');
    expect(session.csrfToken).toBe('sso-csrf-value');
  });

  it('leaves the session unauthenticated when the state was already consumed (401)', async () => {
    server.use(
      http.post(`${BASE_URL}${SSO_CALLBACK_PATH}`, () =>
        HttpResponse.json({ message: 'state not found or expired' }, { status: 401 }),
      ),
    );
    const { session, oidc } = createClient();

    await expect(oidc.ssoComplete({ state: 'stale', code: 'code' })).rejects.toBeInstanceOf(AuthError);
    expect(session.authenticated).toBe(false);
    expect(session.csrfToken).toBeUndefined();
    expect(session.tokenManager.cachedAccessToken()).toBeNull();
  });

  it('surfaces a 5xx as NetworkError', async () => {
    server.use(
      http.post(`${BASE_URL}${SSO_CALLBACK_PATH}`, () => HttpResponse.json({}, { status: 503 })),
    );
    const { oidc } = createClient();

    await expect(oidc.ssoComplete({ state: 'abc', code: 'code' })).rejects.toBeInstanceOf(NetworkError);
  });
});
