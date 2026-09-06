// RFC 8705 §5 `mtls_endpoint_aliases` — CONTRACT.md §21.3 rule 2 (contract 1.40).
//
// The rule has one sentence and three named ways to get it wrong, and this file
// is organised around them rather than around the SDK's method list:
//
//   * a call going over mTLS prefers the alias;
//   * a call NOT going over mTLS keeps the top-level entry;
//   * an ABSENT member means "no separate mTLS host", never "unsupported";
//   * only the six listed endpoints are ever aliased — not
//     `authorization_endpoint`, `end_session_endpoint` or `jwks_uri`;
//   * `issuer` is not an endpoint, does not move, and still governs `iss`
//     validation by exact string for a token minted at an alias host.
//
// "Over mTLS" here is the §6.1 client identity on the session: configure a
// certificate and every request this client makes presents it.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { AuthError } from '../../src/core/index.js';
import {
  BASE_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  deviceAuthorizationResponse,
  discoveryDocument,
  discoveryHandler,
  END_SESSION_ENDPOINT,
  generateSigningKey,
  ISSUER,
  jwksHandler,
  JWKS_URI,
  MTLS_BASE_URL,
  MTLS_DEVICE_AUTHORIZATION_ENDPOINT,
  MTLS_INTROSPECT_ENDPOINT,
  MTLS_PAR_ENDPOINT,
  MTLS_REVOKE_ENDPOINT,
  MTLS_TOKEN_ENDPOINT,
  mtlsEndpointAliases,
  REDIRECT_URI,
  signIdToken,
  TENANT_ID,
  TOKEN_ENDPOINT,
  tokenResponse,
  type OidcMockState,
} from './oidcTestKit.js';

const NONCE = 'the-request-nonce';
const CODE = 'authorization-code-value';

const server = createServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/** A discovery document carrying all six aliases on the mTLS origin. */
function withAliases() {
  return discoveryDocument({ mtls_endpoint_aliases: mtlsEndpointAliases() });
}

/**
 * Record which absolute URLs are POSTed to. Both origins are registered for
 * every endpoint, so choosing the wrong one is a recorded call rather than an
 * unhandled-request failure — the assertion then names the host that was used.
 */
function recorder(): { hits: string[]; handlers: ReturnType<typeof http.post>[] } {
  const hits: string[] = [];
  const paths = [
    '/oauth2/token',
    '/oauth2/introspect',
    '/oauth2/revoke',
    '/oauth2/device_authorization',
    '/oauth2/par',
  ];
  const body = (path: string): Record<string, unknown> => {
    if (path === '/oauth2/device_authorization') return deviceAuthorizationResponse();
    if (path === '/oauth2/par') return { request_uri: 'urn:ietf:params:oauth:request_uri:x', expires_in: 60 };
    if (path === '/oauth2/introspect') return { active: true };
    if (path === '/oauth2/revoke') return {};
    return tokenResponse();
  };
  const handlers = paths.flatMap((path) =>
    [BASE_URL, MTLS_BASE_URL].map((origin) =>
      http.post(`${origin}${path}`, ({ request }) => {
        hits.push(new URL(request.url).origin + new URL(request.url).pathname);
        return HttpResponse.json(body(path));
      }),
    ),
  );
  return { hits, handlers };
}

function setup(state: OidcMockState, document = withAliases()) {
  const { hits, handlers } = recorder();
  server.use(discoveryHandler(state, document), ...handlers);
  return hits;
}

describe('§21.3 rule 2 — the document round-trips the member', () => {
  it('exposes mtls_endpoint_aliases when the server publishes it', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state, withAliases()));
    const { oidc } = createClient();

    const configuration = await oidc.oidcDiscover();

    expect(configuration.mtls_endpoint_aliases).toEqual(mtlsEndpointAliases());
    // The six, and only the six. A seventh key here would mean the SDK invented one.
    expect(Object.keys(configuration.mtls_endpoint_aliases ?? {}).sort()).toEqual([
      'device_authorization_endpoint',
      'introspection_endpoint',
      'pushed_authorization_request_endpoint',
      'revocation_endpoint',
      'token_endpoint',
      'userinfo_endpoint',
    ]);
  });

  it('leaves it undefined — not null, not an error — when the server omits it', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state, discoveryDocument()));
    const { oidc } = createClient({ mtls: true });

    const configuration = await oidc.oidcDiscover();

    expect(configuration.mtls_endpoint_aliases).toBeUndefined();
    expect('mtls_endpoint_aliases' in configuration).toBe(false);
  });

  it('does not drop the member when the top-level endpoints are unchanged', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state, withAliases()));
    const { oidc } = createClient();

    const configuration = await oidc.oidcDiscover();

    // The aliases sit ALONGSIDE the conventional entries; neither replaces the other
    // in the parsed document.
    expect(configuration.token_endpoint).toBe(TOKEN_ENDPOINT);
    expect(configuration.mtls_endpoint_aliases?.token_endpoint).toBe(MTLS_TOKEN_ENDPOINT);
  });
});

describe('§21.3 rule 2 — a call over mTLS prefers the alias', () => {
  it('sends the authorization-code exchange to the alias token endpoint', async () => {
    const state = createMockState();
    const hits = setup(state);
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, mtls: true });

    await oidc.oidcExchange({ code: CODE, codeVerifier: 'v'.repeat(43), redirectUri: REDIRECT_URI, nonce: NONCE });

    expect(hits).toEqual([MTLS_TOKEN_ENDPOINT]);
  });

  it('sends introspect, revoke, deviceAuthorize and oidcPar to their aliases', async () => {
    const state = createMockState();
    const hits = setup(state);
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, mtls: true });

    await oidc.introspect({ token: 'access-token-value' });
    await oidc.revoke({ token: 'access-token-value' });
    await oidc.deviceAuthorize({});
    const configuration = await oidc.oidcDiscover();
    const request = await oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI, scope: 'openid' });
    await oidc.oidcPar({ request, redirectUri: REDIRECT_URI, scope: 'openid' });

    expect(hits).toEqual([
      MTLS_INTROSPECT_ENDPOINT,
      MTLS_REVOKE_ENDPOINT,
      MTLS_DEVICE_AUTHORIZATION_ENDPOINT,
      MTLS_PAR_ENDPOINT,
    ]);
  });

  it('keeps the mandatory tenant_id query parameter on the alias URL (§12.1 note 2)', async () => {
    const state = createMockState();
    const seen: string[] = [];
    server.use(
      discoveryHandler(state, withAliases()),
      http.post(MTLS_TOKEN_ENDPOINT, ({ request }) => {
        seen.push(new URL(request.url).searchParams.get('tenant_id') ?? '');
        return HttpResponse.json(tokenResponse());
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, mtls: true });

    await oidc.loginClientCredentials({});

    expect(seen).toEqual([TENANT_ID]);
  });
});

describe('§21.3 rule 2 consequence 1 — absence means "no separate host"', () => {
  it('an mTLS client against a document with no aliases keeps using the top-level endpoints', async () => {
    const state = createMockState();
    const hits = setup(state, discoveryDocument());
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, mtls: true });

    await oidc.oidcExchange({ code: CODE, codeVerifier: 'v'.repeat(43), redirectUri: REDIRECT_URI, nonce: NONCE });
    await oidc.introspect({ token: 'access-token-value' });

    // Not an error, and not the alias origin: the conventional endpoints serve
    // both populations on a `client_auth = optional` single-listener deployment.
    expect(hits).toEqual([TOKEN_ENDPOINT, `${BASE_URL}/oauth2/introspect`]);
  });

  it('a client NOT doing mTLS keeps the top-level endpoints even when aliases are published', async () => {
    const state = createMockState();
    const hits = setup(state);
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.oidcExchange({ code: CODE, codeVerifier: 'v'.repeat(43), redirectUri: REDIRECT_URI, nonce: NONCE });
    await oidc.revoke({ token: 'access-token-value' });

    expect(hits).toEqual([TOKEN_ENDPOINT, `${BASE_URL}/oauth2/revoke`]);
  });

  it('still reports an unsupported grant when neither the top level nor an alias names the endpoint', async () => {
    const state = createMockState();
    const document = discoveryDocument({ mtls_endpoint_aliases: mtlsEndpointAliases() });
    delete document.device_authorization_endpoint;
    delete (document.mtls_endpoint_aliases as unknown as Record<string, unknown>).device_authorization_endpoint;
    setup(state, document);
    const { oidc } = createClient({ mtls: true });

    await expect(oidc.deviceAuthorize({})).rejects.toBeInstanceOf(AuthError);
  });
});

describe('§21.3 rule 2 consequence 2 — no alias is ever synthesised', () => {
  it('oidcBegin keeps the front-channel authorization_endpoint on the conventional host', async () => {
    const state = createMockState();
    setup(state);
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, mtls: true });

    const configuration = await oidc.oidcDiscover();
    const request = await oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI, scope: 'openid' });

    // A browser sent to an mTLS host raises a native certificate-chooser dialog.
    expect(new URL(request.url).origin).toBe(BASE_URL);
  });

  it('logoutUrl keeps end_session_endpoint on the conventional host', async () => {
    const state = createMockState();
    setup(state);
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, mtls: true });

    const url = await oidc.logoutUrl({ idToken: 'not-a-real-token', postLogoutRedirectUri: REDIRECT_URI });

    expect(url.startsWith(END_SESSION_ENDPOINT)).toBe(true);
    expect(new URL(url).origin).toBe(BASE_URL);
  });

  it('ID-token verification fetches jwks_uri from the conventional host', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const state = createMockState();
    const idToken = await signIdToken(key, { nonce: NONCE });
    server.use(
      discoveryHandler(state, withAliases()),
      jwksHandler(state, [key.jwk]),
      http.post(MTLS_TOKEN_ENDPOINT, () => HttpResponse.json(tokenResponse({ id_token: idToken }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, mtls: true });

    const tokens = await oidc.oidcExchange({
      code: CODE,
      codeVerifier: 'v'.repeat(43),
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
    });

    // jwks_uri is public key material and gains nothing from a handshake, so it
    // is not in the aliasable six. `jwksHandler` only serves the conventional
    // origin; a synthesised alias would have made this an unhandled request.
    expect(state.jwksCalls).toBe(1);
    expect(JWKS_URI.startsWith(BASE_URL)).toBe(true);
    expect(tokens.idClaims?.sub).toBe('user-1');
  });
});

describe('§21.3 rule 2 consequence 3 — issuer is never aliased', () => {
  it('accepts a token minted at the alias endpoint whose iss is the unchanged issuer', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const state = createMockState();
    const idToken = await signIdToken(key, { nonce: NONCE, issuer: ISSUER });
    server.use(
      discoveryHandler(state, withAliases()),
      jwksHandler(state, [key.jwk]),
      http.post(MTLS_TOKEN_ENDPOINT, () => HttpResponse.json(tokenResponse({ id_token: idToken }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, mtls: true });

    const tokens = await oidc.oidcExchange({
      code: CODE,
      codeVerifier: 'v'.repeat(43),
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
    });

    expect(tokens.idClaims?.iss).toBe(ISSUER);
    // The check that matters: the expected issuer is NOT derived from the host
    // that was called. An SDK that did so would reject every token it obtains
    // over mTLS.
    expect(ISSUER).not.toBe(MTLS_BASE_URL);
  });

  it('rejects a token whose iss is the alias host rather than the issuer', async () => {
    const key = await generateSigningKey('rp-kid-1');
    const state = createMockState();
    const idToken = await signIdToken(key, { nonce: NONCE, issuer: MTLS_BASE_URL });
    server.use(
      discoveryHandler(state, withAliases()),
      jwksHandler(state, [key.jwk]),
      http.post(MTLS_TOKEN_ENDPOINT, () => HttpResponse.json(tokenResponse({ id_token: idToken }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, mtls: true });

    await expect(
      oidc.oidcExchange({ code: CODE, codeVerifier: 'v'.repeat(43), redirectUri: REDIRECT_URI, nonce: NONCE }),
    ).rejects.toBeInstanceOf(AuthError);
  });

  it('leaves issuer itself untouched in the parsed document', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state, withAliases()));
    const { oidc } = createClient({ mtls: true });

    const configuration = await oidc.oidcDiscover();

    expect(configuration.issuer).toBe(ISSUER);
    expect(Object.keys(configuration.mtls_endpoint_aliases ?? {})).not.toContain('issuer');
  });
});
