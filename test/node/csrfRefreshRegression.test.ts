// Regression test for 05b9b8f (H8 SDK bench): both REST refresh paths —
// AxiamClient.refresh() (rest/auth.ts) and the reactive 401 handler
// (rest/interceptors.ts) — must resync the Node persona's in-memory
// session.csrfToken via session.onAuthenticated?.() after a successful raw
// refresh POST, because the server mints a fresh random axiam_csrf cookie on
// every successful login AND every successful refresh. Before the fix,
// neither path called onAuthenticated?.() after refreshing, so csrfToken
// stayed pinned to the login-time value forever: the FIRST refresh worked
// (the login-time csrf value was still valid), but every state-changing call
// after that — including a second refresh() — echoed a stale X-CSRF-Token
// and got 403 "Authorization denied: CSRF validation failed".
//
// The mock server below models the real server's CSRF middleware closely
// enough to catch this: it tracks the ONE currently-valid axiam_csrf value,
// rotates it (to a fresh value) on every successful login/refresh, and 403s
// any state-changing request (including a refresh POST) whose X-CSRF-Token
// does not match the CURRENT value. Cookies are written directly into the
// jar from within the handlers (mirroring test/node/csrf.test.ts's
// doRefresh test) rather than relying on Set-Cookie propagating through
// axios-cookiejar-support — msw intercepts before that agent-level
// machinery runs.
//
// Only the Node persona is affected: the browser persona has no
// onAuthenticated hook and reads document.cookie live on every request, so
// it was never exposed to this bug (asserted cheaply below alongside the
// main regression coverage).

import { CookieJar } from 'tough-cookie';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createVerifier } from '../../src/node/jwks.js';
import { ACCESS_COOKIE, CSRF_COOKIE, wrapAxios } from '../../src/node/cookieJar.js';
import { NodeSession } from '../../src/node/session.js';
import { createSession } from '../../src/rest/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { AxiamClient } from '../../src/rest/client.js';

const BASE_URL = 'https://axiam-csrf-refresh-regression.test';

/**
 * The ONE csrf value the mock server currently considers valid — rotated on
 * every successful login/refresh, mirroring the real server's CSRF
 * middleware (CONTRACT.md §3, crates/axiam-api-rest/src/handlers/auth.rs).
 */
let serverCsrf = '';
let csrfCounter = 0;
/** How many times GET /api/v1/protected should 401 before it starts succeeding — drives the reactive single-flight refresh scenario. */
let protectedGetFailuresRemaining = 0;
/**
 * The jar backing the session under test in the current test — handlers
 * write rotated cookies directly into it (see file header re: msw + jar
 * interaction).
 */
let activeJar: CookieJar | undefined;

function nextCsrf(prefix: string): string {
  csrfCounter += 1;
  return `${prefix}-${csrfCounter}`;
}

function presentedCsrf(headers: Headers): string | null {
  return headers.get('x-csrf-token');
}

const CSRF_DENIED_BODY = { error: 'authorization_denied', message: 'Authorization denied: CSRF validation failed' };

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/auth/login`, async () => {
    serverCsrf = nextCsrf('csrf-login');
    await activeJar!.setCookie(`${ACCESS_COOKIE}=access-token-login; Path=/`, BASE_URL);
    await activeJar!.setCookie(`${CSRF_COOKIE}=${serverCsrf}; Path=/`, BASE_URL);
    return HttpResponse.json(
      {
        user: { id: 'user-1', username: 'alice', email: 'alice@example.com' },
        session_id: 'session-1',
        expires_in: 900,
      },
      { status: 200 },
    );
  }),
  // Mirrors the server rotating axiam_csrf on every successful refresh AND
  // rejecting a refresh whose own X-CSRF-Token is already stale (the "second
  // refresh()" scenario from the commit message) — a real mutating endpoint.
  http.post(`${BASE_URL}/api/v1/auth/refresh`, async ({ request }) => {
    if (presentedCsrf(request.headers) !== serverCsrf) {
      return HttpResponse.json(CSRF_DENIED_BODY, { status: 403 });
    }
    serverCsrf = nextCsrf('csrf-refresh');
    await activeJar!.setCookie(`${ACCESS_COOKIE}=access-token-refreshed-${csrfCounter}; Path=/`, BASE_URL);
    await activeJar!.setCookie(`${CSRF_COOKIE}=${serverCsrf}; Path=/`, BASE_URL);
    return HttpResponse.json({ expires_in: 900 }, { status: 200 });
  }),
  // A generic mutating endpoint guarded by the same CSRF check as any real
  // AXIAM state-changing endpoint (§3) — stands in for "whatever call the
  // caller makes next", per the commit message.
  http.post(`${BASE_URL}/api/v1/echo`, ({ request }) => {
    if (presentedCsrf(request.headers) !== serverCsrf) {
      return HttpResponse.json(CSRF_DENIED_BODY, { status: 403 });
    }
    return HttpResponse.json({ ok: true }, { status: 200 });
  }),
  // 401s protectedGetFailuresRemaining times, then succeeds — drives the
  // reactive single-flight refresh interceptor. GET is a safe method (§3) so
  // this endpoint itself never needs a CSRF token.
  http.get(`${BASE_URL}/api/v1/protected`, () => {
    if (protectedGetFailuresRemaining > 0) {
      protectedGetFailuresRemaining -= 1;
      return HttpResponse.json({ error: 'authentication_failed' }, { status: 401 });
    }
    return HttpResponse.json({ ok: true }, { status: 200 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
beforeEach(() => {
  serverCsrf = '';
  csrfCounter = 0;
  protectedGetFailuresRemaining = 0;
  activeJar = undefined;
});
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/**
 * Build a real jar-backed NodeSession wrapped in an AxiamClient (mirrors
 * test/node/csrf.test.ts's buildTestSession, extended with an AxiamClient so
 * login()/refresh() are exercised through the actual public API surface
 * rather than by calling NodeSession internals directly).
 */
function buildClient(): AxiamClient {
  const jar = new CookieJar();
  activeJar = jar;
  const base = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
  wrapAxios(base.axios, jar);
  const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
  const jwksVerifier = createVerifier(BASE_URL);
  const session = new NodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' }, session);
}

async function login(client: AxiamClient): Promise<void> {
  const result = await client.login('alice@example.com', 'password123');
  expect(result.status).toBe('authenticated');
}

describe('CSRF resync after refresh — explicit AxiamClient.refresh() (rest/auth.ts, 05b9b8f)', () => {
  it('login -> refresh() -> a second state-changing call succeeds', async () => {
    const client = buildClient();
    await login(client);

    await client.refresh();

    const response = await client.session.axios.post('/api/v1/echo', {});
    expect(response.status).toBe(200);
  });

  it('login -> refresh() -> refresh() (the second refresh is itself state-changing) succeeds', async () => {
    const client = buildClient();
    await login(client);

    await client.refresh();
    await expect(client.refresh()).resolves.toBeUndefined();
  });
});

describe('CSRF resync after refresh — reactive 401 handler (rest/interceptors.ts, 05b9b8f)', () => {
  it('a 401 triggers the reactive refresh; the retry succeeds and a following state-changing call also succeeds', async () => {
    const client = buildClient();
    await login(client);

    protectedGetFailuresRemaining = 1;
    const retried = await client.session.axios.get('/api/v1/protected');
    expect(retried.status).toBe(200);

    // This is the assertion that actually catches the bug: the GET retry
    // above needs no CSRF header (safe method) and would succeed either way
    // — it's this FOLLOWING mutating call that echoes whatever csrfToken the
    // reactive refresh left behind.
    const followUp = await client.session.axios.post('/api/v1/echo', {});
    expect(followUp.status).toBe(200);
  });
});

describe('browser persona is unaffected (reads document.cookie live; no onAuthenticated hook)', () => {
  it('the base SharedSession (browser persona) has no onAuthenticated implementation', () => {
    const session = createSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    expect(session.onAuthenticated).toBeUndefined();
  });
});
