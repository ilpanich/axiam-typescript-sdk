// §24.1/§24.8 (contract 1.45) — the Node-persona half of the two "no session"
// WebAuthn setup operations that MSW cannot prove on its own:
//
// - CSRF-token capture on a successful `setup/register/finish`, mirrored from
//   `mfaSetupConfirm` (§25.2 rule 2) — same pattern as
//   test/node/csrf.test.ts's `buildTestSession`: the jar is pre-seeded with
//   the `axiam_csrf` cookie a real Set-Cookie response would have written,
//   because msw's mocked ClientRequest/response pair never reaches the
//   cookie-agent's own Set-Cookie handling (see that file's comment).
// - "no session credential attached", which needs a REAL server: the
//   jar-injected `Cookie` header is applied inside the custom http.Agent's
//   `addRequest()` override, a layer msw's interceptor never reaches either
//   (proven directly below by a control call, so the negative result cannot
//   pass vacuously).
//
// The rest of §24.8's required assertions for these two operations (options/
// response pass-through, opaque tokens, 401/403/503 mapping) need no real
// jar and live in test/rest/webauthn.test.ts alongside the other six.

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { CookieJar } from 'tough-cookie';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { NodeSession } from '../../src/node/session.js';
import { ACCESS_COOKIE, CSRF_COOKIE, wrapAxios } from '../../src/node/cookieJar.js';
import { createSession } from '../../src/rest/session.js';
import { installInterceptors } from '../../src/rest/interceptors.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';
import { AxiamClient } from '../../src/rest/client.js';
import { REGISTRATION_RESPONSE as SETUP_RESPONSE, STATE_TOKEN } from '../rest/webauthnFixtures.js';

const BASE_URL = 'https://axiam-node-webauthn-setup.test';
const SETUP_TOKEN = 'setup-token-fixture-value-do-not-log';
const START_PATH = '/api/v1/auth/webauthn/setup/register/start';
const FINISH_PATH = '/api/v1/auth/webauthn/setup/register/finish';

const LOGIN_SUCCESS_WIRE = {
  user: { id: 'u1', username: 'alice', email: 'alice@example.com' },
  session_id: 's1',
  expires_in: 900,
};

/** Build a real jar-backed NodeSession, optionally pre-seeding cookies (mirrors test/node/csrf.test.ts). */
async function buildSession(baseUrl: string, cookies: Record<string, string> = {}): Promise<NodeSession> {
  const jar = new CookieJar();
  for (const [name, value] of Object.entries(cookies)) {
    await jar.setCookie(`${name}=${value}; Path=/`, baseUrl);
  }
  const base = createSession({ baseUrl, tenantSlug: 'acme' });
  wrapAxios(base.axios, jar);
  const tokenManager = new TokenManager(jar, baseUrl, base.tenantHeaderValue);
  const jwksVerifier = createVerifier(baseUrl);
  const session = new NodeSession({ baseUrl, tenantSlug: 'acme' }, base, tokenManager, jwksVerifier, jar);
  installInterceptors(session.axios, session);
  return session;
}

// ---------------------------------------------------------------------------
// CSRF capture on adoption (msw — mirrors test/node/csrf.test.ts)
// ---------------------------------------------------------------------------

describe('webauthnSetupRegisterFinish adopts credentials exactly as mfaSetupConfirm does', () => {
  let capturedHeaders: Record<string, string> = {};

  const server = setupServer(
    http.post(`${BASE_URL}${FINISH_PATH}`, () => HttpResponse.json(LOGIN_SUCCESS_WIRE)),
    http.post(`${BASE_URL}/api/v1/echo`, ({ request }) => {
      capturedHeaders = {};
      request.headers.forEach((value, key) => (capturedHeaders[key] = value));
      return HttpResponse.json({ ok: true });
    }),
  );

  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
  afterEach(() => {
    server.resetHandlers();
    capturedHeaders = {};
  });
  afterAll(() => server.close());

  it('leaves the client authenticated, exactly as mfaSetupConfirm does', async () => {
    const session = await buildSession(BASE_URL, { [CSRF_COOKIE]: 'csrf-from-setup-finish' });
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' }, session);
    expect(client.session.authenticated).toBe(false);

    const result = await client.webauthnSetupRegisterFinish(
      SETUP_TOKEN,
      STATE_TOKEN,
      'Alice’s security key',
      SETUP_RESPONSE,
    );

    expect(client.session.authenticated).toBe(true);
    expect(result.status).toBe('authenticated');
  });

  it('captures the CSRF token, and a state-changing call right after carries it', async () => {
    const session = await buildSession(BASE_URL, { [CSRF_COOKIE]: 'csrf-from-setup-finish' });
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' }, session);

    expect(session.csrfToken).toBeUndefined();
    await client.webauthnSetupRegisterFinish(SETUP_TOKEN, STATE_TOKEN, 'key', SETUP_RESPONSE);
    expect(session.csrfToken).toBe('csrf-from-setup-finish');

    await session.axios.post('/api/v1/echo', {});
    expect(capturedHeaders['x-csrf-token']).toBe('csrf-from-setup-finish');
  });
});

// ---------------------------------------------------------------------------
// "carries no session credential" (§24.8) — needs a REAL server: msw's mocked
// ClientRequest never reaches the custom http.Agent's addRequest() override
// that injects jar cookies (a jar cookie never reaches a captured header
// under msw, fix or no fix — see test/node/csrf.test.ts's comment on the same
// blind spot). The control test below proves this harness's real server does
// not have it, so the negative result after it is not vacuous.
// ---------------------------------------------------------------------------

describe('setup/register/* carries no session credential (§24.8)', () => {
  let server: Server;
  let baseUrl: string;
  let requests: Array<{ path: string; cookie: string | undefined; authorization: string | undefined }>;

  beforeAll(async () => {
    requests = [];
    server = createServer((req, res) => {
      requests.push({
        path: req.url ?? '',
        cookie: req.headers.cookie,
        authorization: req.headers.authorization,
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      if (req.url === START_PATH) {
        res.end(JSON.stringify({ challenge: { publicKey: {} }, state_token: 'srv-state' }));
      } else if (req.url === FINISH_PATH) {
        res.end(JSON.stringify(LOGIN_SUCCESS_WIRE));
      } else {
        res.end(JSON.stringify({ ok: true }));
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('control: an ordinary authenticated call DOES carry the jar cookie over this real transport', async () => {
    requests = [];
    const session = await buildSession(baseUrl, { [ACCESS_COOKIE]: 'leaked-if-attached' });

    await session.axios.post('/api/v1/echo', {});

    expect(requests.at(-1)?.cookie).toContain('leaked-if-attached');
  });

  it('does not attach the cookie or an Authorization header to setup/register/start or /finish, even with a session configured', async () => {
    requests = [];
    const session = await buildSession(baseUrl, {
      [ACCESS_COOKIE]: 'leaked-if-attached',
      [CSRF_COOKIE]: 'leaked-csrf-if-attached',
    });
    // "A session is configured": authenticated, with a real cookie the
    // control test above just proved rides on an ordinary call over this
    // exact transport, plus the csrfToken store an ordinary POST would forward.
    session.authenticated = true;
    session.csrfToken = 'leaked-csrf-if-attached';
    const client = new AxiamClient({ baseUrl, tenantSlug: 'acme' }, session);

    await client.webauthnSetupRegisterStart(SETUP_TOKEN);
    await client.webauthnSetupRegisterFinish(SETUP_TOKEN, 'srv-state', 'key', SETUP_RESPONSE);

    const startReq = requests.find((r) => r.path === START_PATH);
    const finishReq = requests.find((r) => r.path === FINISH_PATH);
    expect(startReq?.cookie).toBeUndefined();
    expect(startReq?.authorization).toBeUndefined();
    expect(finishReq?.cookie).toBeUndefined();
    expect(finishReq?.authorization).toBeUndefined();
  });
});
