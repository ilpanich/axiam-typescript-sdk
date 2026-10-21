// No `axiam_*` session cookie and no `X-CSRF-Token` on `/oauth2/*` — CONTRACT.md §6.1 rule 11,
// §12.1 rule 3 and §14.6 third paragraph (contract 1.63).
//
// A client whose cookie jar holds a session (`axiam_access`, `axiam_csrf`) makes a device
// authorization, a device poll and a token request: none carries a cookie or the CSRF header.
// A control request to a non-`/oauth2/` path proves the jar and the CSRF token are in place.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { installInterceptors } from '../../src/rest/interceptors.js';
import {
  BASE_URL,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  DEVICE_AUTHORIZATION_ENDPOINT,
  deviceAuthorizationResponse,
  discoveryHandler,
  TOKEN_ENDPOINT,
  tokenResponse,
} from './oidcTestKit.js';
import { Sensitive } from '../../src/core/index.js';

const server = createServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

interface Seen {
  label: string;
  cookie: string | null;
  csrf: string | null;
}

describe('no session cookie and no CSRF header on /oauth2/* (contract 1.63, §14.6)', () => {
  it('a jar holding session cookies rides an ordinary POST but none of the /oauth2/* requests', async () => {
    const seen: Seen[] = [];
    const record = (label: string, request: Request): void => {
      seen.push({ label, cookie: request.headers.get('cookie'), csrf: request.headers.get('x-csrf-token') });
    };
    server.use(
      discoveryHandler(createMockState()),
      http.post(`${BASE_URL}/api/v1/login`, () =>
        new HttpResponse(null, {
          status: 204,
          headers: [
            ['Set-Cookie', 'axiam_access=session-access; Path=/'],
            ['Set-Cookie', 'axiam_csrf=csrf-value; Path=/'],
          ],
        }),
      ),
      http.post(`${BASE_URL}/api/v1/echo`, ({ request }) => {
        record('control', request);
        return HttpResponse.json({ ok: true });
      }),
      http.post(DEVICE_AUTHORIZATION_ENDPOINT, ({ request }) => {
        record('device_authorize', request);
        return HttpResponse.json(deviceAuthorizationResponse());
      }),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        const form = new URLSearchParams(await request.text());
        record(`token:${form.get('grant_type') ?? ''}`, request);
        return HttpResponse.json(tokenResponse());
      }),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    installInterceptors(session.axios, session);
    await session.axios.post('/api/v1/login', {});
    session.csrfToken = 'csrf-value';

    await session.axios.post('/api/v1/echo', {});
    await oidc.deviceAuthorize({ scope: 'openid' });
    await oidc.devicePoll({ deviceCode: new Sensitive('device-code-value') });
    await oidc.loginClientCredentials({});

    expect(seen.map((s) => s.label)).toEqual([
      'control',
      'device_authorize',
      'token:urn:ietf:params:oauth:grant-type:device_code',
      'token:client_credentials',
    ]);
    // The control proves the jar and the CSRF token were in place and would have been sent.
    expect(seen[0]!.cookie).toContain('axiam_access=session-access');
    expect(seen[0]!.csrf).toBe('csrf-value');
    for (const request of seen.slice(1)) {
      expect(request.cookie, `${request.label} carried a cookie`).toBeNull();
      expect(request.csrf, `${request.label} carried X-CSRF-Token`).toBeNull();
    }
  });
});
