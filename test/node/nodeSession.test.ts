// NodeSession construction + auth hooks (node/session.ts): createNodeSession
// / createNodeClient wiring, doRefresh()'s POST /auth/refresh + token/csrf
// resync-from-jar, and onAuthenticated()'s jar -> csrfToken sync. The jar is
// pre-seeded and injected directly (mirroring grpc/checkAccess.test.ts's
// buildTestSession), so the sync paths are asserted without depending on
// Set-Cookie propagation through the mock transport.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { CookieJar } from 'tough-cookie';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createNodeClient, createNodeSession, NodeSession } from '../../src/node/session.js';
import { AxiamClient } from '../../src/rest/client.js';
import { createSession } from '../../src/rest/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';
import { ACCESS_COOKIE, CSRF_COOKIE } from '../../src/node/cookieJar.js';

const BASE_URL = 'https://axiam-node-session.test';

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/auth/refresh`, () =>
    HttpResponse.json({ expires_in: 900 }, { status: 200 }),
  ),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/** Build a NodeSession over a caller-controlled, pre-seedable cookie jar. */
async function seededSession(cookies: Record<string, string>): Promise<NodeSession> {
  const jar = new CookieJar();
  for (const [name, value] of Object.entries(cookies)) {
    await jar.setCookie(`${name}=${value}; Path=/`, BASE_URL);
  }
  const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
  const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
  const jwksVerifier = createVerifier(BASE_URL);
  return new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
}

describe('createNodeSession / createNodeClient', () => {
  it('builds a NodeSession with a token manager and JWKS verifier', () => {
    const session = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    expect(session).toBeInstanceOf(NodeSession);
    expect(session.tokenManager).toBeDefined();
    expect(session.jwksVerifier).toBeDefined();
    expect(session.tenantHeaderValue).toBe('acme');
  });

  it('createNodeClient returns an AxiamClient backed by the Node session', () => {
    const client = createNodeClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    expect(client).toBeInstanceOf(AxiamClient);
    expect(client.session).toBeInstanceOf(NodeSession);
  });
});

describe('NodeSession.doRefresh', () => {
  it('posts /auth/refresh and resyncs the cached access token + csrf from the jar', async () => {
    const session = await seededSession({
      [ACCESS_COOKIE]: 'refreshed-access-token',
      [CSRF_COOKIE]: 'csrf-999',
    });

    await session.doRefresh();

    expect(session.tokenManager.cachedAccessToken()?.expose()).toBe('refreshed-access-token');
    expect(session.csrfToken).toBe('csrf-999');
  });
});

describe('NodeSession.onAuthenticated', () => {
  it('syncs csrfToken + cached access token from the jar', async () => {
    const session = await seededSession({
      [ACCESS_COOKIE]: 'login-access-token',
      [CSRF_COOKIE]: 'csrf-111',
    });

    await session.onAuthenticated();

    expect(session.csrfToken).toBe('csrf-111');
    expect(session.tokenManager.cachedAccessToken()?.expose()).toBe('login-access-token');
  });

  it('leaves csrfToken undefined when no csrf cookie is present in the jar', async () => {
    const session = await seededSession({ [ACCESS_COOKIE]: 'tok' });

    await session.onAuthenticated();

    expect(session.csrfToken).toBeUndefined();
    expect(session.tokenManager.cachedAccessToken()?.expose()).toBe('tok');
  });
});
