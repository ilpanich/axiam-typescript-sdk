// oidcLoginHandlers — the Express "Login with AXIAM" glue (CONTRACT.md §12).

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import type { Request, Response } from 'express';
import { oidcLoginHandlers } from '../../src/middleware/express.js';
import { MemoryOidcStateStore, type OidcStateEntry } from '../../src/node/oidcState.js';
import type { OidcTokenSet } from '../../src/node/oidcTypes.js';
import {
  BASE_URL,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  discoveryHandler,
  generateSigningKey,
  jwksHandler,
  REDIRECT_URI,
  signIdToken,
  tokenHandler,
  tokenResponse,
  TOKEN_ENDPOINT,
} from '../node/oidcTestKit.js';
import { DISCOVERY_PATH } from '../../src/node/oidc.js';

const server = createServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/** A minimal Express `Response` double recording status/json/redirect. */
function fakeRes(): Response & {
  statusCode?: number;
  body?: unknown;
  redirectedTo?: string;
} {
  const res: Record<string, unknown> = {};
  res.status = vi.fn((code: number) => {
    res.statusCode = code;
    return res;
  });
  res.json = vi.fn((body: unknown) => {
    res.body = body;
    return res;
  });
  res.redirect = vi.fn((url: string) => {
    res.redirectedTo = url;
    return res;
  });
  return res as unknown as Response & { statusCode?: number; body?: unknown; redirectedTo?: string };
}

function fakeReq(query: Record<string, unknown> = {}): Request {
  return { query } as unknown as Request;
}

/** A MemoryOidcStateStore that also records what was saved, so a test can read the nonce. */
function capturingStore(): { store: MemoryOidcStateStore; saved: OidcStateEntry[] } {
  const store = new MemoryOidcStateStore();
  const saved: OidcStateEntry[] = [];
  const originalSave = store.save.bind(store);
  store.save = async (entry: OidcStateEntry) => {
    saved.push(entry);
    await originalSave(entry);
  };
  return { store, saved };
}

describe('oidcLoginHandlers login route (§12)', () => {
  it('redirects to the authorization endpoint and parks the state', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const { login } = oidcLoginHandlers({
      client: oidc,
      store,
      redirectUri: REDIRECT_URI,
      scope: 'openid profile',
    });

    const res = fakeRes();
    await login(fakeReq(), res, vi.fn());

    expect(res.redirectedTo).toContain(`${BASE_URL}/oauth2/authorize?`);
    const query = new URL(res.redirectedTo!).searchParams;
    expect(query.get('scope')).toBe('openid profile');
    expect(saved).toHaveLength(1);
    // The parked state is exactly the one in the redirect URL.
    expect(query.get('state')).toBe(saved[0].state);
    expect(saved[0].nonce).toBe(query.get('nonce'));
    expect(saved[0].redirectUri).toBe(REDIRECT_URI);
    expect(store.size).toBe(1);
  });

  it('stores a returnTo query parameter with the login state', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();
    const { store, saved } = capturingStore();
    const { login } = oidcLoginHandlers({ client: oidc, store, redirectUri: REDIRECT_URI });

    await login(fakeReq({ returnTo: '/dashboard' }), fakeRes(), vi.fn());

    expect(saved[0].returnTo).toBe('/dashboard');
  });

  it('ignores a non-string returnTo', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();
    const { store, saved } = capturingStore();
    const { login } = oidcLoginHandlers({ client: oidc, store, redirectUri: REDIRECT_URI });

    await login(fakeReq({ returnTo: ['/a', '/b'] }), fakeRes(), vi.fn());

    expect(saved[0].returnTo).toBeUndefined();
  });

  it('fails closed with 503 when discovery is unreachable', async () => {
    server.use(http.get(`${BASE_URL}${DISCOVERY_PATH}`, () => HttpResponse.json({}, { status: 500 })));
    const { oidc } = createClient();
    const store = new MemoryOidcStateStore();
    const logged: string[] = [];
    const { login } = oidcLoginHandlers({
      client: oidc,
      store,
      redirectUri: REDIRECT_URI,
      logger: { debug: (_event, message) => logged.push(message) },
    });

    const res = fakeRes();
    await login(fakeReq(), res, vi.fn());

    expect(res.statusCode).toBe(503);
    expect(res.body).toMatchObject({ error: 'oidc_unavailable' });
    expect(res.redirectedTo).toBeUndefined();
    expect(store.size).toBe(0);
    expect(logged).toContain('oidc login could not be started');
  });
});

describe('oidcLoginHandlers callback route (§12)', () => {
  /** Wire discovery + JWKS + a token endpoint that echoes the parked nonce. */
  async function setupExchange(saved: OidcStateEntry[]): Promise<void> {
    const key = await generateSigningKey('express-oidc-kid');
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      http.post(TOKEN_ENDPOINT, async () =>
        HttpResponse.json(
          tokenResponse({
            id_token: await signIdToken(key, { nonce: saved[saved.length - 1].nonce }),
          }),
        ),
      ),
    );
  }

  it('consumes the state, exchanges the code, and redirects to the stored returnTo', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const received: OidcTokenSet[] = [];
    const handlers = oidcLoginHandlers({
      client: oidc,
      store,
      redirectUri: REDIRECT_URI,
      onSuccess: (tokens) => {
        received.push(tokens);
      },
    });

    server.use(discoveryHandler(createMockState()));
    await handlers.login(fakeReq({ returnTo: '/dashboard' }), fakeRes(), vi.fn());
    await setupExchange(saved);

    const res = fakeRes();
    await handlers.callback(fakeReq({ state: saved[0].state, code: 'idp-code' }), res, vi.fn());

    expect(res.redirectedTo).toBe('/dashboard');
    expect(received).toHaveLength(1);
    expect(received[0].idClaims?.sub).toBe('user-1');
    // Single-use: the state is gone from the store.
    expect(store.size).toBe(0);
  });

  it('prefers an explicit successRedirect over the stored returnTo', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const handlers = oidcLoginHandlers({
      client: oidc,
      store,
      redirectUri: REDIRECT_URI,
      successRedirect: '/home',
    });

    server.use(discoveryHandler(createMockState()));
    await handlers.login(fakeReq({ returnTo: '/dashboard' }), fakeRes(), vi.fn());
    await setupExchange(saved);

    const res = fakeRes();
    await handlers.callback(fakeReq({ state: saved[0].state, code: 'c' }), res, vi.fn());

    expect(res.redirectedTo).toBe('/home');
  });

  it('replies 200 with a token-free summary when no redirect is configured', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const handlers = oidcLoginHandlers({ client: oidc, store, redirectUri: REDIRECT_URI });

    server.use(discoveryHandler(createMockState()));
    await handlers.login(fakeReq(), fakeRes(), vi.fn());
    await setupExchange(saved);

    const res = fakeRes();
    await handlers.callback(fakeReq({ state: saved[0].state, code: 'c' }), res, vi.fn());

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ authenticated: true, sub: 'user-1', expiresIn: 900 });
    expect(JSON.stringify(res.body)).not.toContain('access-token-value');
  });

  it('replies 400 when state or code is missing', async () => {
    const { oidc } = createClient();
    const handlers = oidcLoginHandlers({
      client: oidc,
      store: new MemoryOidcStateStore(),
      redirectUri: REDIRECT_URI,
    });

    const noState = fakeRes();
    await handlers.callback(fakeReq({ code: 'c' }), noState, vi.fn());
    expect(noState.statusCode).toBe(400);
    expect(noState.body).toMatchObject({ error: 'invalid_request' });

    const noCode = fakeRes();
    await handlers.callback(fakeReq({ state: 's' }), noCode, vi.fn());
    expect(noCode.statusCode).toBe(400);
  });

  it('replies 401 for an unknown state, and for a replayed one (single-use)', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const handlers = oidcLoginHandlers({ client: oidc, store, redirectUri: REDIRECT_URI });

    const unknown = fakeRes();
    await handlers.callback(fakeReq({ state: 'never-issued', code: 'c' }), unknown, vi.fn());
    expect(unknown.statusCode).toBe(401);
    expect(unknown.body).toMatchObject({ error: 'authentication_failed' });

    server.use(discoveryHandler(createMockState()));
    await handlers.login(fakeReq(), fakeRes(), vi.fn());
    await setupExchange(saved);
    await handlers.callback(fakeReq({ state: saved[0].state, code: 'c' }), fakeRes(), vi.fn());

    // Replay of a state that already succeeded: rejected identically.
    const replay = fakeRes();
    await handlers.callback(fakeReq({ state: saved[0].state, code: 'c' }), replay, vi.fn());
    expect(replay.statusCode).toBe(401);
  });

  it('replies 401 when the IdP returned an error instead of a code', async () => {
    const { oidc } = createClient();
    const handlers = oidcLoginHandlers({
      client: oidc,
      store: new MemoryOidcStateStore(),
      redirectUri: REDIRECT_URI,
    });

    const withDescription = fakeRes();
    await handlers.callback(
      fakeReq({ error: 'access_denied', error_description: 'user cancelled' }),
      withDescription,
      vi.fn(),
    );
    expect(withDescription.statusCode).toBe(401);
    expect(withDescription.body).toMatchObject({ message: 'access_denied: user cancelled' });

    const bare = fakeRes();
    await handlers.callback(fakeReq({ error: 'server_error' }), bare, vi.fn());
    expect(bare.body).toMatchObject({ message: 'server_error' });
  });

  it('replies 401 when the token endpoint returns an OAuth2 protocol error', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const handlers = oidcLoginHandlers({ client: oidc, store, redirectUri: REDIRECT_URI });

    server.use(discoveryHandler(createMockState()));
    await handlers.login(fakeReq(), fakeRes(), vi.fn());
    server.use(
      tokenHandler(createMockState(), () =>
        HttpResponse.json(
          { error: 'invalid_grant', error_description: 'code expired' },
          { status: 400 },
        ),
      ),
    );

    const res = fakeRes();
    await handlers.callback(fakeReq({ state: saved[0].state, code: 'c' }), res, vi.fn());

    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({
      error: 'authentication_failed',
      message: 'invalid_grant: code expired',
    });
  });

  it('replies 401 when ID-token validation fails', async () => {
    const key = await generateSigningKey('express-bad-kid');
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const handlers = oidcLoginHandlers({ client: oidc, store, redirectUri: REDIRECT_URI });

    server.use(discoveryHandler(createMockState()));
    await handlers.login(fakeReq(), fakeRes(), vi.fn());
    server.use(
      jwksHandler(createMockState(), [key.jwk]),
      http.post(TOKEN_ENDPOINT, async () =>
        HttpResponse.json(tokenResponse({ id_token: await signIdToken(key, { nonce: 'not-the-nonce' }) })),
      ),
    );

    const res = fakeRes();
    await handlers.callback(fakeReq({ state: saved[0].state, code: 'c' }), res, vi.fn());

    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({ error: 'authentication_failed' });
    expect(JSON.stringify(res.body)).toContain('nonce_mismatch');
  });

  it('replies 503 (never a silent success) when the token endpoint is unreachable', async () => {
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const logged: string[] = [];
    const handlers = oidcLoginHandlers({
      client: oidc,
      store,
      redirectUri: REDIRECT_URI,
      logger: { debug: (_event, message) => logged.push(message) },
    });

    server.use(discoveryHandler(createMockState()));
    await handlers.login(fakeReq(), fakeRes(), vi.fn());
    server.use(http.post(TOKEN_ENDPOINT, () => HttpResponse.json({}, { status: 502 })));

    const res = fakeRes();
    await handlers.callback(fakeReq({ state: saved[0].state, code: 'c' }), res, vi.fn());

    expect(res.statusCode).toBe(503);
    expect(res.body).toMatchObject({ error: 'oidc_unavailable' });
    expect(logged).toContain('token exchange transport failure');
  });
});
