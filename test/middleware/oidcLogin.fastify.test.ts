// oidcLoginPlugin — the Fastify "Login with AXIAM" glue (CONTRACT.md §12).
// Same core as the Express variant, so these tests concentrate on the
// adapter: route registration, the 302, and outcome-to-reply translation.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import Fastify, { type FastifyInstance } from 'fastify';
import { oidcLoginPlugin } from '../../src/middleware/fastify.js';
import { MemoryOidcStateStore, type OidcStateEntry } from '../../src/node/oidcState.js';
import type { OidcLoginOptions } from '../../src/middleware/oidcLoginCore.js';
import type { OidcTokenSet } from '../../src/node/oidcTypes.js';
import { DISCOVERY_PATH } from '../../src/node/oidc.js';
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
  tokenResponse,
  TOKEN_ENDPOINT,
} from '../node/oidcTestKit.js';

const server = createServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/** A MemoryOidcStateStore that records what was saved. */
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

async function buildApp(
  options: OidcLoginOptions & { loginPath?: string; callbackPath?: string },
): Promise<FastifyInstance> {
  const app = Fastify();
  await app.register(oidcLoginPlugin(options));
  await app.ready();
  return app;
}

describe('oidcLoginPlugin (Fastify, §12)', () => {
  it('registers /auth/login and 302s to the authorization endpoint', async () => {
    server.use(discoveryHandler(createMockState()));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const app = await buildApp({ client: oidc, store, redirectUri: REDIRECT_URI, scope: 'openid email' });

    const response = await app.inject({ method: 'GET', url: '/auth/login?returnTo=/reports' });

    expect(response.statusCode).toBe(302);
    const location = response.headers.location as string;
    expect(location).toContain(`${BASE_URL}/oauth2/authorize?`);
    expect(new URL(location).searchParams.get('scope')).toBe('openid email');
    expect(saved[0].returnTo).toBe('/reports');
    expect(store.size).toBe(1);

    await app.close();
  });

  it('honours custom route paths', async () => {
    server.use(discoveryHandler(createMockState()));
    const { oidc } = createClient();
    const app = await buildApp({
      client: oidc,
      store: new MemoryOidcStateStore(),
      redirectUri: REDIRECT_URI,
      loginPath: '/sso/start',
      callbackPath: '/sso/finish',
    });

    expect((await app.inject({ method: 'GET', url: '/sso/start' })).statusCode).toBe(302);
    // The default paths are not registered when custom ones are given.
    expect((await app.inject({ method: 'GET', url: '/auth/login' })).statusCode).toBe(404);
    // The callback route exists (400 = registered but missing state/code).
    expect((await app.inject({ method: 'GET', url: '/sso/finish' })).statusCode).toBe(400);

    await app.close();
  });

  it('completes the callback, calls onSuccess, and 302s to the stored returnTo', async () => {
    const key = await generateSigningKey('fastify-oidc-kid');
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    const received: OidcTokenSet[] = [];
    server.use(discoveryHandler(createMockState()));
    const app = await buildApp({
      client: oidc,
      store,
      redirectUri: REDIRECT_URI,
      onSuccess: (tokens, entry) => {
        received.push(tokens);
        expect(entry.returnTo).toBe('/reports');
      },
    });

    await app.inject({ method: 'GET', url: '/auth/login?returnTo=/reports' });
    server.use(
      jwksHandler(createMockState(), [key.jwk]),
      http.post(TOKEN_ENDPOINT, async () =>
        HttpResponse.json(tokenResponse({ id_token: await signIdToken(key, { nonce: saved[0].nonce }) })),
      ),
    );

    const response = await app.inject({
      method: 'GET',
      url: `/auth/callback?state=${encodeURIComponent(saved[0].state)}&code=idp-code`,
    });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('/reports');
    expect(received).toHaveLength(1);
    expect(store.size).toBe(0);

    await app.close();
  });

  it('replies 200 with a token-free summary when no redirect is configured', async () => {
    const key = await generateSigningKey('fastify-oidc-kid2');
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const { store, saved } = capturingStore();
    server.use(discoveryHandler(createMockState()));
    const app = await buildApp({ client: oidc, store, redirectUri: REDIRECT_URI });

    await app.inject({ method: 'GET', url: '/auth/login' });
    server.use(
      jwksHandler(createMockState(), [key.jwk]),
      http.post(TOKEN_ENDPOINT, async () =>
        HttpResponse.json(tokenResponse({ id_token: await signIdToken(key, { nonce: saved[0].nonce }) })),
      ),
    );

    const response = await app.inject({
      method: 'GET',
      url: `/auth/callback?state=${encodeURIComponent(saved[0].state)}&code=c`,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ authenticated: true, sub: 'user-1', expiresIn: 900 });
    expect(response.body).not.toContain('access-token-value');

    await app.close();
  });

  it('replies 401 for an unknown state and 400 for a malformed callback', async () => {
    const { oidc } = createClient();
    const app = await buildApp({
      client: oidc,
      store: new MemoryOidcStateStore(),
      redirectUri: REDIRECT_URI,
    });

    const unknown = await app.inject({ method: 'GET', url: '/auth/callback?state=nope&code=c' });
    expect(unknown.statusCode).toBe(401);
    expect(unknown.json()).toMatchObject({ error: 'authentication_failed' });

    const malformed = await app.inject({ method: 'GET', url: '/auth/callback?code=c' });
    expect(malformed.statusCode).toBe(400);
    expect(malformed.json()).toMatchObject({ error: 'invalid_request' });

    const idpError = await app.inject({
      method: 'GET',
      url: '/auth/callback?error=access_denied&error_description=nope',
    });
    expect(idpError.statusCode).toBe(401);
    expect(idpError.json()).toMatchObject({ message: 'access_denied: nope' });

    await app.close();
  });

  it('fails closed with 503 when discovery is unreachable', async () => {
    server.use(http.get(`${BASE_URL}${DISCOVERY_PATH}`, () => HttpResponse.json({}, { status: 500 })));
    const { oidc } = createClient();
    const app = await buildApp({
      client: oidc,
      store: new MemoryOidcStateStore(),
      redirectUri: REDIRECT_URI,
    });

    const response = await app.inject({ method: 'GET', url: '/auth/login' });

    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({ error: 'oidc_unavailable' });

    await app.close();
  });
});
