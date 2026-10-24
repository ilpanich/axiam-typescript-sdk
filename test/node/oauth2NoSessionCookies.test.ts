// No `axiam_*` session cookie and no `X-CSRF-Token` on `/oauth2/*` — CONTRACT.md §6.1 rule 11,
// §12.1 rule 3 and §14.6 third paragraph (contract 1.63).
//
// A client that signed in through `login()` against a mock that sets `axiam_access` and
// `axiam_csrf` makes a device authorization, a device poll and a token request: none carries a
// cookie or the CSRF header. As §14.6 asks, the control comes *after* them: the same client's next
// state-changing management request carries the `Cookie` and the `X-CSRF-Token`.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { AxiamClient } from '../../src/rest/client.js';
import {
  BASE_URL,
  CLIENT_SECRET,
  ORG_ID,
  TENANT_ID,
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
  it('a client signed in through login() sends neither on the /oauth2/* requests, and both on the next management POST', async () => {
    const seen: Seen[] = [];
    const record = (label: string, request: Request): void => {
      seen.push({ label, cookie: request.headers.get('cookie'), csrf: request.headers.get('x-csrf-token') });
    };
    server.use(
      discoveryHandler(createMockState()),
      http.post(`${BASE_URL}/api/v1/auth/login`, () =>
        HttpResponse.json(
          { user: { id: 'user-1', username: 'alice', email: 'alice@example.com' }, session_id: 'session-1', expires_in: 900 },
          {
            headers: [
              ['Set-Cookie', 'axiam_access=session-access; Path=/'],
              ['Set-Cookie', 'axiam_csrf=csrf-value; Path=/'],
            ],
          },
        ),
      ),
      http.post(DEVICE_AUTHORIZATION_ENDPOINT, ({ request }) => {
        record('device_authorize', request);
        return HttpResponse.json(deviceAuthorizationResponse());
      }),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        const form = new URLSearchParams(await request.text());
        record(`token:${form.get('grant_type') ?? ''}`, request);
        return HttpResponse.json(tokenResponse());
      }),
      http.post(`${BASE_URL}/api/v1/groups`, ({ request }) => {
        record('management POST', request);
        return HttpResponse.json({ id: 'group-1', name: 'staff' }, { status: 201 });
      }),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantId: TENANT_ID, orgId: ORG_ID }, session);

    const login = await client.login('alice@example.com', 'password123');
    expect(login.status).toBe('authenticated');

    await oidc.deviceAuthorize({ scope: 'openid' });
    await oidc.devicePoll({ deviceCode: new Sensitive('device-code-value') });
    await oidc.loginClientCredentials({});
    await client.groups.create({ name: 'staff', description: 'staff group' });

    expect(seen.map((s) => s.label)).toEqual([
      'device_authorize',
      'token:urn:ietf:params:oauth:grant-type:device_code',
      'token:client_credentials',
      'management POST',
    ]);
    for (const request of seen.slice(0, 3)) {
      expect(request.cookie, `${request.label} carried a cookie`).toBeNull();
      expect(request.csrf, `${request.label} carried X-CSRF-Token`).toBeNull();
    }
    // The control, after the /oauth2/* calls: the jar and the CSRF forwarding were in place
    // throughout, so the assertions above cannot have passed for want of them.
    const control = seen[3]!;
    expect(control.cookie).toContain('axiam_access=session-access');
    expect(control.cookie).toContain('axiam_csrf=csrf-value');
    expect(control.csrf).toBe('csrf-value');
  });
});
