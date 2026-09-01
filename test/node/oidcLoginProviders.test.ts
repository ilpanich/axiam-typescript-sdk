// The four public "Sign in with X" operations added by contract 1.38 —
// ssoProviders, ssoStartOauth2, ssoCompleteOauth2, ssoCompleteHandoff
// (CONTRACT.md §12.1).
//
// Two kinds of assertion live here, and both are needed.
//
// The wire-shape tests read the vendored `openapi.json` and assert the method,
// path, content type and — for ssoProviders — the *parameter location* the
// server declares, then assert that what this SDK actually puts on the wire
// matches. Asserting only against the mock would pin the SDK to the test's own
// idea of the endpoint; asserting only against the spec would not notice an
// SDK that agrees with the spec and calls something else.
//
// The rule tests cover the four §12.1 notes easiest to get quietly wrong:
// note 9 (an empty provider list is a success, not a not-found), note 10
// (`protocol` selects the start operation), note 12 (a handoff 401 is terminal
// and is never retried) and rule 12a (a 400 from a start call is a
// configuration refusal, not something to retry).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { CookieJar } from 'tough-cookie';
import { http, HttpResponse } from 'msw';
import { AuthError, NetworkError } from '../../src/core/index.js';
import {
  createOidcClient,
  SSO_HANDOFF_PATH,
  SSO_OAUTH2_CALLBACK_PATH,
  SSO_OAUTH2_START_PATH,
  SSO_PROVIDERS_PATH,
  SSO_START_PATH,
} from '../../src/node/oidc.js';
import {
  HANDOFF_CODE_TTL_SECS,
  HANDOFF_QUERY_PARAM,
  PROTOCOL_OAUTH2,
  PROTOCOL_OIDC_CONNECT,
  PROTOCOL_SAML,
} from '../../src/node/oidcTypes.js';
import { createNodeSession, NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { wrapAxios } from '../../src/node/cookieJar.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';
import { BASE_URL, CLIENT_ID, createClient, createServer, ORG_ID, TENANT_ID } from './oidcTestKit.js';

const CONFIG_ID = 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff';
const REDIRECT = 'https://app.example.com/after-login';

const server = createServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

interface OpenApiSpec {
  paths: Record<string, Record<string, Record<string, unknown>>>;
  components: { schemas: Record<string, Record<string, unknown>> };
}

const spec: OpenApiSpec = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../openapi.json', import.meta.url)), 'utf8'),
) as OpenApiSpec;

/** Walk a path of keys through the spec, returning `undefined` at the first gap. */
function dig(root: unknown, ...keys: string[]): unknown {
  let node = root;
  for (const key of keys) {
    if (typeof node !== 'object' || node === null) {
      return undefined;
    }
    node = (node as Record<string, unknown>)[key];
  }
  return node;
}

/** The `$ref` of an operation's `application/json` 200 body. */
function responseRef(operation: unknown): unknown {
  return dig(operation, 'responses', '200', 'content', 'application/json', 'schema', '$ref');
}

/** The `$ref` of an operation's `application/json` request body. */
function requestRef(operation: unknown): unknown {
  return dig(operation, 'requestBody', 'content', 'application/json', 'schema', '$ref');
}

function provider(id: string, kind: string, protocol: string): Record<string, unknown> {
  return {
    id,
    provider_kind: kind,
    display_name: kind,
    protocol,
    has_bundled_mark: true,
    inherited: false,
  };
}

// ---------------------------------------------------------------------------
// Wire shape, against openapi.json
// ---------------------------------------------------------------------------

describe('openapi.json declares the four operations where the SDK calls them', () => {
  it('gives ssoProviders a GET with no request body', () => {
    const op = spec.paths[SSO_PROVIDERS_PATH]?.get;
    expect(op).toBeDefined();
    expect(op?.requestBody).toBeUndefined();
    expect(responseRef(op)).toBe('#/components/schemas/PublicFederationProvidersResponse');
  });

  it.each([
    [SSO_OAUTH2_START_PATH, 'OAuth2StartRequest', 'OAuth2StartResponse'],
    [SSO_OAUTH2_CALLBACK_PATH, 'OAuth2CallbackRequest', 'SsoLoginSuccessResponse'],
    [SSO_HANDOFF_PATH, 'SsoHandoffRequest', 'SsoLoginSuccessResponse'],
  ])('gives %s a POST with an application/json %s body answering %s', (path, request, response) => {
    const op = spec.paths[path]?.post;
    expect(op).toBeDefined();
    expect(requestRef(op)).toBe(`#/components/schemas/${request}`);
    expect(responseRef(op)).toBe(`#/components/schemas/${response}`);
  });

  // §12.1: ssoProviders takes org_slug/org_id and the optional tenant pair as
  // QUERY parameters. The neighbouring start operations take the same four
  // identifiers in a JSON body, and the two are one copy-paste apart.
  it('puts every ssoProviders identifier in the query string', () => {
    const params = spec.paths[SSO_PROVIDERS_PATH]?.get?.parameters as
      | Array<{ name: string; in: string }>
      | undefined;
    expect(params).toBeDefined();
    for (const p of params ?? []) {
      expect(p.in, `${p.name} must be a query parameter, not a body field`).toBe('query');
    }
    expect((params ?? []).map((p) => p.name).sort()).toEqual([
      'org_id',
      'org_slug',
      'tenant_id',
      'tenant_slug',
    ]);
  });

  it('models PublicFederationProvider with the six required fields and a nullable button_icon', () => {
    const schema = spec.components.schemas.PublicFederationProvider;
    expect((schema?.required as string[]).slice().sort()).toEqual([
      'display_name',
      'has_bundled_mark',
      'id',
      'inherited',
      'protocol',
      'provider_kind',
    ]);
    const props = schema?.properties as Record<string, { type?: unknown }>;
    expect(props.button_icon).toBeDefined();
    expect(props.button_icon.type).toContain('null');
    // The unauthenticated response carries no configuration, by construction.
    for (const absent of ['client_id', 'client_secret', 'metadata_url', 'token_endpoint']) {
      expect(props[absent], `${absent} must not reach the public response`).toBeUndefined();
    }
  });

  // §12.1 note 11: the verifier is generated and held server-side, so neither
  // schema carries PKCE material and neither may the SDK.
  it.each(['OAuth2StartRequest', 'OAuth2StartResponse'])(
    '%s carries no PKCE material',
    (name) => {
      const props = spec.components.schemas[name]?.properties as Record<string, unknown>;
      for (const pkce of ['code_verifier', 'code_challenge', 'code_challenge_method']) {
        expect(props[pkce], `${name} must not carry ${pkce}`).toBeUndefined();
      }
    },
  );

  it('models SsoHandoffRequest as just the code', () => {
    const schema = spec.components.schemas.SsoHandoffRequest;
    expect(Object.keys(schema?.properties as Record<string, unknown>)).toEqual(['code']);
    expect(schema?.required).toEqual(['code']);
  });
});

// ---------------------------------------------------------------------------
// Wire shape, against what the SDK actually sends
// ---------------------------------------------------------------------------

describe('ssoProviders (§12.1)', () => {
  it('sends the identifiers as query parameters and no body', async () => {
    let url: URL | undefined;
    let body = '';
    server.use(
      http.get(`${BASE_URL}${SSO_PROVIDERS_PATH}`, async ({ request }) => {
        url = new URL(request.url);
        body = await request.text();
        return HttpResponse.json({ providers: [] });
      }),
    );
    // A slug-configured session, so the slug forms are what resolve. The UUID
    // form wins when both are available, exactly as it does for `ssoStart`.
    const session = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'ignored', orgSlug: 'ignored' });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });

    await oidc.ssoProviders({ orgSlug: 'acme', tenantSlug: 'engineering' });

    expect(url?.pathname).toBe(SSO_PROVIDERS_PATH);
    expect(url?.searchParams.get('org_slug')).toBe('acme');
    expect(url?.searchParams.get('tenant_slug')).toBe('engineering');
    // The UUID forms are absent, not empty: an unset identifier is omitted.
    expect(url?.searchParams.get('org_id')).toBeNull();
    expect(url?.searchParams.get('tenant_id')).toBeNull();
    expect(body, 'ssoProviders is a GET with no body (§12.1)').toBe('');
  });

  it('defaults the workspace to the session context when the caller names none', async () => {
    let url: URL | undefined;
    server.use(
      http.get(`${BASE_URL}${SSO_PROVIDERS_PATH}`, ({ request }) => {
        url = new URL(request.url);
        return HttpResponse.json({ providers: [] });
      }),
    );
    const { oidc } = createClient();

    await oidc.ssoProviders();

    expect(url?.searchParams.get('org_id')).toBe(ORG_ID);
    expect(url?.searchParams.get('tenant_id')).toBe(TENANT_ID);
  });

  // §12.1 note 9. All three cases the endpoint makes indistinguishable are
  // ordinary successes; mapping any of them to an error would restore the
  // two-valued answer the empty list removes, and with it the
  // organization-slug oracle.
  it('treats an empty list as a success, not an error, in all three cases', async () => {
    server.use(http.get(`${BASE_URL}${SSO_PROVIDERS_PATH}`, () => HttpResponse.json({ providers: [] })));
    const { oidc } = createClient();

    for (const params of [
      { orgSlug: 'no-such-organization' },
      { orgId: ORG_ID, tenantId: TENANT_ID },
      {},
    ]) {
      const list = await oidc.ssoProviders(params);
      expect(list.providers).toEqual([]);
    }
  });

  // Unlike ssoStart/ssoStartOauth2, a request naming no workspace at all is
  // sent rather than refused client-side: a 400 here against a 200 [] for an
  // unknown slug would be the same oracle by another route (§12.1 note 9).
  it('sends the request even when nothing resolves a workspace', async () => {
    let calls = 0;
    server.use(
      http.get(`${BASE_URL}${SSO_PROVIDERS_PATH}`, () => {
        calls += 1;
        return HttpResponse.json({ providers: [] });
      }),
    );
    const session = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });

    const list = await oidc.ssoProviders();

    expect(calls).toBe(1);
    expect(list.providers).toEqual([]);
  });

  it('maps every field faithfully, including the nullable button_icon', async () => {
    server.use(
      http.get(`${BASE_URL}${SSO_PROVIDERS_PATH}`, () =>
        HttpResponse.json({
          providers: [
            {
              id: '33333333-3333-3333-3333-333333333333',
              provider_kind: 'google',
              display_name: 'Google',
              protocol: PROTOCOL_OIDC_CONNECT,
              has_bundled_mark: true,
              inherited: true,
              button_icon: null,
            },
            {
              id: '44444444-4444-4444-4444-444444444444',
              provider_kind: 'generic_oauth2',
              display_name: 'Acme SSO',
              protocol: PROTOCOL_OAUTH2,
              has_bundled_mark: false,
              inherited: false,
              button_icon: 'data:image/png;base64,iVBORw0KGgo=',
            },
          ],
        }),
      ),
    );
    const { oidc } = createClient();

    const { providers } = await oidc.ssoProviders();

    expect(providers[0]).toEqual({
      id: '33333333-3333-3333-3333-333333333333',
      providerKind: 'google',
      displayName: 'Google',
      protocol: PROTOCOL_OIDC_CONNECT,
      hasBundledMark: true,
      // inherited is reported so an admin surface can show that a provider is
      // not the tenant's to edit; nothing here computes it (§12.1 note 13).
      inherited: true,
    });
    expect(providers[0]?.buttonIcon).toBeUndefined();
    expect(providers[1]?.buttonIcon).toBe('data:image/png;base64,iVBORw0KGgo=');
    expect(providers[1]?.hasBundledMark).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// §12.1 note 10 — `protocol` selects the start operation
// ---------------------------------------------------------------------------

describe('protocol dispatch (§12.1 note 10)', () => {
  // All three branches. The dispatch is written the way an application must
  // write it — on `protocol`, never on `providerKind` — and the assertion is
  // on which endpoint the resulting call reached.
  //
  // `providerKind` is deliberately misleading in this fixture: the Saml row is
  // `google`, the kind whose OIDC connector everybody assumes. A dispatch that
  // read the kind would send it to the OIDC start endpoint and be caught here.
  it('routes OidcConnect, OAuth2 and Saml to three different places', async () => {
    const reached: string[] = [];
    server.use(
      http.get(`${BASE_URL}${SSO_PROVIDERS_PATH}`, () =>
        HttpResponse.json({
          providers: [
            provider('55555555-5555-5555-5555-555555555555', 'microsoft', PROTOCOL_OIDC_CONNECT),
            provider('66666666-6666-6666-6666-666666666666', 'github', PROTOCOL_OAUTH2),
            provider('77777777-7777-7777-7777-777777777777', 'google', PROTOCOL_SAML),
          ],
        }),
      ),
      http.post(`${BASE_URL}${SSO_START_PATH}`, () => {
        reached.push(SSO_START_PATH);
        return HttpResponse.json({ authorize_url: 'https://idp/x', state: 's', expires_in_secs: 600 });
      }),
      http.post(`${BASE_URL}${SSO_OAUTH2_START_PATH}`, () => {
        reached.push(SSO_OAUTH2_START_PATH);
        return HttpResponse.json({ authorize_url: 'https://gh/x', state: 's', expires_in_secs: 600 });
      }),
    );
    const { oidc } = createClient();

    const { providers } = await oidc.ssoProviders();
    let samlSeen = false;

    for (const p of providers) {
      if (p.protocol === PROTOCOL_OIDC_CONNECT) {
        await oidc.ssoStart({ federationConfigId: p.id, redirectUri: REDIRECT });
      } else if (p.protocol === PROTOCOL_OAUTH2) {
        await oidc.ssoStartOauth2({ federationConfigId: p.id, redirectUri: REDIRECT });
      } else if (p.protocol === PROTOCOL_SAML) {
        // Saml goes to the SAML login endpoint, which §12.1 note 10 says is
        // NOT a §12 vocabulary operation. The branch exists so a Saml provider
        // is never quietly handed to one of the other two.
        samlSeen = true;
      } else {
        throw new Error(`unknown protocol ${p.protocol}`);
      }
    }

    expect(samlSeen).toBe(true);
    expect(reached).toEqual([SSO_START_PATH, SSO_OAUTH2_START_PATH]);
  });
});

// ---------------------------------------------------------------------------
// ssoStartOauth2
// ---------------------------------------------------------------------------

describe('ssoStartOauth2 (§12.1)', () => {
  it('posts the OAuth2StartRequest body and sends no PKCE material', async () => {
    let captured: Record<string, unknown> | undefined;
    let contentType: string | null = null;
    server.use(
      http.post(`${BASE_URL}${SSO_OAUTH2_START_PATH}`, async ({ request }) => {
        contentType = request.headers.get('content-type');
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          authorize_url: 'https://github.com/login/oauth/authorize?state=abc',
          state: 'abc',
          expires_in_secs: 600,
        });
      }),
    );
    const { oidc } = createClient();

    const result = await oidc.ssoStartOauth2({
      federationConfigId: CONFIG_ID,
      redirectUri: REDIRECT,
    });

    expect(contentType).toMatch(/^application\/json/);
    expect(captured).toEqual({
      federation_config_id: CONFIG_ID,
      redirect_uri: REDIRECT,
      tenant_id: TENANT_ID,
      org_id: ORG_ID,
    });
    // §12.1 note 11: the verifier is server-side. Its absence is the contract.
    for (const pkce of ['code_verifier', 'code_challenge', 'code_challenge_method']) {
      expect(captured?.[pkce]).toBeUndefined();
    }
    expect(result).toEqual({
      authorizeUrl: 'https://github.com/login/oauth/authorize?state=abc',
      state: 'abc',
      expiresInSecs: 600,
    });
  });

  it('raises AuthError client-side, with no wire call, when org context is missing', async () => {
    let calls = 0;
    server.use(
      http.post(`${BASE_URL}${SSO_OAUTH2_START_PATH}`, () => {
        calls += 1;
        return HttpResponse.json({ authorize_url: 'x', state: 's', expires_in_secs: 600 });
      }),
    );
    const session = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });

    const error = await oidc
      .ssoStartOauth2({ federationConfigId: CONFIG_ID, redirectUri: REDIRECT })
      .then(
        () => undefined,
        (err: unknown) => err,
      );

    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).message).toMatch(/requires organization context/);
    expect(calls).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// §12.1 rule 12a — a 400 from a start call is a configuration refusal
// ---------------------------------------------------------------------------

describe('rule 12a — a refused redirect_uri origin (§12.1)', () => {
  // On the SAML and Apple flows the identity provider never validates the SPA
  // redirect_uri, so the server confines it to its own issuer origin plus
  // AXIAM__AUTH__SSO_SPA_ORIGINS and answers 400 otherwise.
  //
  // That 400 is a CONFIGURATION refusal — §2's 400 row, whose taxonomy member
  // in this SDK is NetworkError ("malformed request / SDK programming error"),
  // as distinct from the 401 AuthError an unknown workspace gets. It must not
  // be retried: the deployment will refuse the same origin every time.
  it.each([
    ['ssoStart', SSO_START_PATH],
    ['ssoStartOauth2', SSO_OAUTH2_START_PATH],
  ])('maps a 400 from %s to NetworkError and does not retry it', async (operation, path) => {
    let calls = 0;
    server.use(
      http.post(`${BASE_URL}${path}`, () => {
        calls += 1;
        return HttpResponse.json(
          { message: 'redirect_uri origin is not permitted for this deployment' },
          { status: 400 },
        );
      }),
    );
    const { oidc } = createClient();
    const params = { federationConfigId: CONFIG_ID, redirectUri: 'https://attacker.example/' };

    const error = await (operation === 'ssoStart'
      ? oidc.ssoStart(params)
      : oidc.ssoStartOauth2(params)
    ).then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(NetworkError);
    expect(error).not.toBeInstanceOf(AuthError);
    expect(calls, 'the refusal must not be retried — the origin will be refused again').toBe(1);
  });

  // A 401 is the uniform "unknown workspace or provider" answer, and is a
  // DIFFERENT taxonomy member. Asserted so the two cannot quietly collapse.
  it('keeps a 401 from the same endpoint an AuthError', async () => {
    server.use(
      http.post(`${BASE_URL}${SSO_OAUTH2_START_PATH}`, () =>
        HttpResponse.json({ message: 'unknown tenant' }, { status: 401 }),
      ),
    );
    const { oidc } = createClient();

    await expect(
      oidc.ssoStartOauth2({ federationConfigId: CONFIG_ID, redirectUri: REDIRECT }),
    ).rejects.toBeInstanceOf(AuthError);
  });
});

// ---------------------------------------------------------------------------
// The two completions
// ---------------------------------------------------------------------------

describe('ssoCompleteOauth2 / ssoCompleteHandoff (§12.1 notes 6 and 12, §4)', () => {
  /**
   * A NodeSession over a caller-controlled, pre-seeded cookie jar — the same
   * shape `test/node/oidcSso.test.ts` uses. Set-Cookie does not propagate into
   * a real jar through msw, so the jar is seeded with what the server would
   * have set and the assertion is that the operation runs the same
   * post-authentication sync `login()` does.
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

  const successBody = {
    user_id: '99999999-8888-7777-6666-555555555555',
    session_id: '12121212-3434-5656-7878-909090909090',
    expires_in: 900,
    redirect_uri: REDIRECT,
  };

  it('ssoCompleteOauth2 posts state+code and maps SsoLoginSuccessResponse', async () => {
    let captured: Record<string, unknown> | undefined;
    server.use(
      http.post(`${BASE_URL}${SSO_OAUTH2_CALLBACK_PATH}`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(successBody);
      }),
    );
    const { oidc } = createClient();

    const result = await oidc.ssoCompleteOauth2({ state: 'abc', code: 'provider-code' });

    expect(captured).toEqual({ state: 'abc', code: 'provider-code' });
    // §12.1 note 6: the response body has no token/secret field at all.
    expect(Object.keys(result).sort()).toEqual(['expiresIn', 'redirectUri', 'sessionId', 'userId']);
    expect(result.userId).toBe(successBody.user_id);
  });

  it('ssoCompleteHandoff posts just the code and maps SsoLoginSuccessResponse', async () => {
    let captured: Record<string, unknown> | undefined;
    server.use(
      http.post(`${BASE_URL}${SSO_HANDOFF_PATH}`, async ({ request }) => {
        captured = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(successBody);
      }),
    );
    const { oidc } = createClient();

    const result = await oidc.ssoCompleteHandoff({ code: 'handoff-code' });

    expect(captured).toEqual({ code: 'handoff-code' });
    expect(result.sessionId).toBe(successBody.session_id);
    expect(result.redirectUri).toBe(REDIRECT);
  });

  it.each([
    ['ssoCompleteOauth2', SSO_OAUTH2_CALLBACK_PATH],
    ['ssoCompleteHandoff', SSO_HANDOFF_PATH],
  ])('%s takes the session from the §4 cookie jar via the same sync as login()', async (op, path) => {
    server.use(http.post(`${BASE_URL}${path}`, () => HttpResponse.json(successBody)));
    const session = await seededSession({
      axiam_access: 'federation-session-access-token',
      axiam_csrf: 'federation-csrf-value',
    });
    const onAuthenticated = vi.spyOn(session, 'onAuthenticated');
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });

    if (op === 'ssoCompleteOauth2') {
      await oidc.ssoCompleteOauth2({ state: 'abc', code: 'c' });
    } else {
      await oidc.ssoCompleteHandoff({ code: 'h' });
    }

    expect(session.authenticated).toBe(true);
    expect(onAuthenticated).toHaveBeenCalledOnce();
  });

  // §12.1 note 12. Unknown, expired and already-redeemed all answer the same
  // 401, on purpose. The code is spent either way, so a retry cannot succeed
  // and would only widen the window in which it sits in a log.
  it('treats a handoff 401 as terminal and sends exactly one request', async () => {
    let calls = 0;
    server.use(
      http.post(`${BASE_URL}${SSO_HANDOFF_PATH}`, () => {
        calls += 1;
        return HttpResponse.json({ message: 'unauthorized' }, { status: 401 });
      }),
    );
    const { oidc } = createClient();

    await expect(
      oidc.ssoCompleteHandoff({ code: 'spent-or-expired-or-never-existed' }),
    ).rejects.toBeInstanceOf(AuthError);
    expect(calls, 'the redemption must not be retried: the code is gone either way').toBe(1);
  });

  it('exports the handoff query parameter and TTL a caller codes against', () => {
    expect(HANDOFF_QUERY_PARAM).toBe('axiam_handoff');
    expect(HANDOFF_CODE_TTL_SECS).toBe(60);
  });
});
