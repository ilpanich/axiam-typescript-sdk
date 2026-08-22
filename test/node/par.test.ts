// Pushed Authorization Requests — CONTRACT.md §26.
//
// The first test is the one this section exists for: the endpoint answers
// **201**, and a success predicate written `status === 200` treats every
// successful push as a failure while passing every other test here.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { AuthError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import { createNodeSession } from '../../src/node/session.js';
import { createOidcClient } from '../../src/node/oidc.js';
import {
  BASE_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  PAR_ENDPOINT,
  REDIRECT_URI,
  TENANT_ID,
  createClient,
  createServer,
  discoveryDocument,
  discoveryDocumentWithoutOptionalEndpoints,
} from './oidcTestKit.js';

const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c';

const server = createServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/** Captured pushes, so the assertions can look at what actually went out. */
let pushes: Array<{ form: URLSearchParams; tenantId: string | null; contentType: string | null }>;

beforeEach(() => {
  pushes = [];
});

function parHandler(respond: () => Response = () => created()) {
  return http.post(PAR_ENDPOINT, async ({ request }) => {
    pushes.push({
      form: new URLSearchParams(await request.text()),
      tenantId: new URL(request.url).searchParams.get('tenant_id'),
      contentType: request.headers.get('content-type'),
    });
    return respond();
  });
}

function created() {
  // RFC 9126 §2.2 — Created, not OK.
  return HttpResponse.json({ request_uri: REQUEST_URI, expires_in: 90 }, { status: 201 });
}

async function push(options: { clientSecret?: string } = {}) {
  const { oidc } = createClient({ clientSecret: options.clientSecret ?? CLIENT_SECRET });
  const configuration = discoveryDocument();
  const request = oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI, scope: 'openid profile' });
  const pushed = await oidc.oidcPar({
    request,
    redirectUri: REDIRECT_URI,
    scope: 'openid profile',
    configuration,
  });
  return { oidc, request, pushed };
}

// ---------------------------------------------------------------------------
// §26.1 — the 201, and the wire shape
// ---------------------------------------------------------------------------

describe('§26.1 the push', () => {
  it('treats 201 as success', async () => {
    server.use(parHandler());
    const { pushed } = await push();

    expect(pushed.requestUri.expose()).toBe(REQUEST_URI);
    expect(pushed.expiresIn).toBe(90);
  });

  it('posts a form-encoded body with tenant_id in the query, not the body', async () => {
    server.use(parHandler());
    await push();

    const [sent] = pushes;
    expect(sent!.contentType).toContain('application/x-www-form-urlencoded');
    expect(sent!.tenantId).toBe(TENANT_ID);
    expect(sent!.form.get('tenant_id')).toBeNull();
  });

  it('pushes exactly the parameters §26.2 rule 1 names', async () => {
    server.use(parHandler());
    const { request } = await push();

    const form = pushes[0]!.form;
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('response_type')).toBe('code');
    expect(form.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(form.get('scope')).toBe('openid profile');
    expect(form.get('state')).toBe(request.state);
    expect(form.get('nonce')).toBe(request.nonce);
    expect(form.get('code_challenge_method')).toBe('S256');
    expect(form.get('code_challenge')).toBeTruthy();
    expect(form.get('client_secret')).toBe(CLIENT_SECRET);
  });

  it('omits client_secret for a public client rather than sending an empty one', async () => {
    server.use(parHandler());
    const { oidc } = createClient();
    const configuration = discoveryDocument();
    const request = oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI });
    await oidc.oidcPar({ request, redirectUri: REDIRECT_URI, configuration });

    expect(pushes[0]!.form.has('client_secret')).toBe(false);
  });

  it('adds openid to the scope when the caller omits it', async () => {
    server.use(parHandler());
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const configuration = discoveryDocument();
    const request = oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI });
    await oidc.oidcPar({ request, redirectUri: REDIRECT_URI, scope: 'profile', configuration });

    expect(pushes[0]!.form.get('scope')).toBe('openid profile');
  });

  it('errors rather than concatenating a URL when the OP advertises no PAR endpoint', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const configuration = discoveryDocumentWithoutOptionalEndpoints();
    const request = oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI });

    await expect(
      oidc.oidcPar({ request, redirectUri: REDIRECT_URI, configuration }),
    ).rejects.toBeInstanceOf(AuthError);
    expect(pushes).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// §26.2 rule 2 — the authorization URL carries exactly two parameters
// ---------------------------------------------------------------------------

describe('§26.2 rule 2 the redirect URL', () => {
  it('carries client_id and request_uri and NOTHING else', async () => {
    server.use(parHandler());
    const { pushed } = await push();

    const url = new URL(pushed.authorizationUrl);
    // Asserted on the full parameter set, not on the presence of the two: the
    // server REFUSES a request mixing a request_uri with inline authorization
    // parameters rather than merging them, and re-adding them "for
    // compatibility" restores the parameter-confusion attack the refusal
    // prevents.
    expect([...url.searchParams.keys()].sort()).toEqual(['client_id', 'request_uri']);
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(url.searchParams.get('request_uri')).toBe(REQUEST_URI);
  });

  it('points at the discovery document’s authorization_endpoint', async () => {
    server.use(parHandler());
    const { pushed } = await push();
    expect(pushed.authorizationUrl.startsWith(`${BASE_URL}/oauth2/authorize`)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// §26.2 rules 1 and 6 — one generator, one code_verifier
// ---------------------------------------------------------------------------

describe('§26.2 continuity with oidcBegin and oidcExchange', () => {
  it('carries oidcBegin’s state, nonce and verifier through unchanged', async () => {
    server.use(parHandler());
    const { request, pushed } = await push();

    expect(pushed.state).toBe(request.state);
    expect(pushed.nonce).toBe(request.nonce);
    // The same verifier object, so there is exactly one value to keep and no
    // second place for the two to disagree (§26.2 rule 6).
    expect(pushed.codeVerifier.expose()).toBe(request.codeVerifier.expose());
  });

  it('pushes the challenge derived from that same verifier', async () => {
    server.use(parHandler());
    const { pushed } = await push();

    const { createHash } = await import('node:crypto');
    const expected = createHash('sha256')
      .update(pushed.codeVerifier.expose())
      .digest('base64url');
    expect(pushes[0]!.form.get('code_challenge')).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// §26.2 rule 4 / §26.3 — retries and errors
// ---------------------------------------------------------------------------

describe('§26 failure handling', () => {
  it('does not retry a 5xx — it is a POST that creates state', async () => {
    server.use(parHandler(() => new HttpResponse(null, { status: 503 })));
    await expect(push()).rejects.toThrow();
    expect(pushes).toHaveLength(1);
  });

  it('does not retry a transport failure either', async () => {
    let attempts = 0;
    server.use(
      http.post(PAR_ENDPOINT, () => {
        attempts += 1;
        return HttpResponse.error();
      }),
    );
    await expect(push()).rejects.toThrow();
    expect(attempts).toBe(1);
  });

  it('maps invalid_client through the shared OAuth2 mapper', async () => {
    server.use(
      parHandler(() =>
        HttpResponse.json(
          { error: 'invalid_client', error_description: 'client authentication failed' },
          { status: 401 },
        ),
      ),
    );

    await expect(push()).rejects.toBeInstanceOf(OAuthProtocolError);
    await expect(push()).rejects.toMatchObject({ error: 'invalid_client' });
  });

  it('maps invalid_request the same way', async () => {
    server.use(
      parHandler(() =>
        HttpResponse.json(
          { error: 'invalid_request', error_description: 'redirect_uri not registered' },
          { status: 400 },
        ),
      ),
    );
    await expect(push()).rejects.toMatchObject({ error: 'invalid_request' });
  });

  it('raises client-side, with no wire call, for a slug-only client', async () => {
    server.use(parHandler());
    const session = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'globex' });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });
    const configuration = discoveryDocument();
    const request = oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI });

    await expect(
      oidc.oidcPar({ request, redirectUri: REDIRECT_URI, configuration }),
    ).rejects.toBeInstanceOf(AuthError);
    expect(pushes).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// §26.5 — sensitivity
// ---------------------------------------------------------------------------

describe('§26.5 sensitivity', () => {
  it('wraps request_uri, which is a bearer handle for its window', async () => {
    server.use(parHandler());
    const { pushed } = await push();

    expect(pushed.requestUri).toBeInstanceOf(Sensitive);
    const surfaces = `${JSON.stringify(pushed)}${String(pushed.requestUri)}`;
    expect(surfaces).not.toContain(REQUEST_URI);
    // …but it must still reach the redirect URL, which is the point of it.
    expect(pushed.authorizationUrl).toContain(encodeURIComponent(REQUEST_URI));
  });

  it('keeps the code verifier and the client secret out of serialization', async () => {
    server.use(parHandler());
    const { pushed } = await push();

    const serialized = JSON.stringify(pushed);
    expect(serialized).not.toContain(pushed.codeVerifier.expose());
    expect(serialized).not.toContain(CLIENT_SECRET);
  });

  it('leaves expiresIn, state and nonce readable — they are not secrets', async () => {
    server.use(parHandler());
    const { pushed } = await push();

    expect(typeof pushed.state).toBe('string');
    expect(typeof pushed.nonce).toBe('string');
    expect(pushed.expiresIn).toBe(90);
  });
});
