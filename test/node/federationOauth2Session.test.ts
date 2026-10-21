// The federation `oauth2` routes are session endpoints, not `/oauth2/*` ones — C163-01.
//
// `POST /api/v1/auth/federation/oauth2/start|callback` merely contain `oauth2/`; the contract 1.63
// rule that withholds the session cookie and `X-CSRF-Token` binds the `/oauth2/*` routes only
// (a path-prefix match). The callback's `Set-Cookie` session must land in the jar and ride the next call.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { createNodeSession } from '../../src/node/session.js';
import { installInterceptors, isOAuth2Endpoint } from '../../src/rest/interceptors.js';
import { createOidcClient } from '../../src/node/oidc.js';

const BASE_URL = 'https://axiam.test';
const server = setupServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('isOAuth2Endpoint is a path-prefix match', () => {
  it.each([
    ['/oauth2/token', BASE_URL, true],
    [`${BASE_URL}/oauth2/device_authorization?x=1`, BASE_URL, true],
    ['/oauth2/par', `${BASE_URL}/axiam/`, true],
    [`${BASE_URL}/axiam/oauth2/token`, `${BASE_URL}/axiam`, true],
    ['/api/v1/auth/federation/oauth2/callback', BASE_URL, false],
    [`${BASE_URL}/api/v1/auth/federation/oauth2/start`, BASE_URL, false],
    ['/api/v1/echo', BASE_URL, false],
    [undefined, BASE_URL, false],
  ] as const)('%s under %s -> %s', (url, base, expected) => {
    expect(isOAuth2Endpoint(url, base)).toBe(expected);
  });
});

describe('federation OAuth2 sign-in keeps its session (C163-01)', () => {
  it('ssoStartOauth2 carries the session cookie and CSRF header; ssoCompleteOauth2 sets a session the next POST sends', async () => {
    const seen: Array<{ label: string; cookie: string | null; csrf: string | null }> = [];
    const record = (label: string, request: Request): void => {
      seen.push({ label, cookie: request.headers.get('cookie'), csrf: request.headers.get('x-csrf-token') });
    };
    server.use(
      http.get(`${BASE_URL}/api/v1/seed`, () =>
        new HttpResponse(null, {
          status: 204,
          headers: [
            ['Set-Cookie', 'axiam_access=old-access; Path=/'],
            ['Set-Cookie', 'axiam_csrf=old-csrf; Path=/'],
          ],
        }),
      ),
      http.post(`${BASE_URL}/api/v1/auth/federation/oauth2/start`, ({ request }) => {
        record('start', request);
        return HttpResponse.json({ authorize_url: 'https://idp.example/authorize', state: 's', expires_in_secs: 300 });
      }),
      http.post(`${BASE_URL}/api/v1/auth/federation/oauth2/callback`, ({ request }) => {
        record('callback', request);
        return HttpResponse.json(
          { user_id: 'u', session_id: 'sess', expires_in: 900, redirect_uri: 'https://app.example/after' },
          {
            headers: [
              ['Set-Cookie', 'axiam_access=fed-access; Path=/'],
              ['Set-Cookie', 'axiam_csrf=c; Path=/'],
            ],
          },
        );
      }),
      http.post(`${BASE_URL}/api/v1/echo`, ({ request }) => {
        record('echo', request);
        return HttpResponse.json({ ok: true });
      }),
    );
    // The Node persona: a real cookie jar, with the production interceptors on its transport.
    const session = createNodeSession({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    installInterceptors(session.axios, session);
    const oidc = createOidcClient(session, { clientId: 'app' });
    await session.axios.get('/api/v1/seed');
    session.csrfToken = 'old-csrf';

    await oidc.ssoStartOauth2({
      federationConfigId: '33333333-3333-4333-8333-333333333333',
      redirectUri: 'https://app.example/cb',
      orgId: '11111111-1111-4111-8111-111111111111',
    });
    await oidc.ssoCompleteOauth2({ state: 's', code: 'c' });
    await session.axios.post('/api/v1/echo', {});

    const start = seen.find((s) => s.label === 'start')!;
    expect(start.cookie).toContain('axiam_access=old-access');
    expect(start.csrf).toBe('old-csrf');
    const echo = seen.find((s) => s.label === 'echo')!;
    expect(echo.cookie).toContain('axiam_access=fed-access');
    expect(echo.csrf).toBe('c');
  });
});
