// No session or adopted bearer on `/oauth2/*` — CONTRACT.md §6.1 rule 11,
// §12.1 rule 3 and §14.6 (contract 1.62; conformance review C162-05).
//
// Every `/oauth2/*` endpoint authenticates the client through the form body (or
// the TLS certificate). A client that holds an adopted §6.1 device credential
// (`authenticateDevice()`) or an adopted client-credentials token must not
// attach it to those requests: the assertions below run the device
// authorization, the device poll, a client-credentials request and a refresh
// with each credential in place and require no `Authorization` header on any.
// A control request to a non-`/oauth2/` path proves the credential is in place
// (so the assertion is not vacuous), and the RFC 7592 registration call —
// whose token the caller passes explicitly — still carries exactly that token
// (see also `clientRegistration.test.ts`).

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { Sensitive } from '../../src/core/index.js';
import { installDeviceTokenInterceptor } from '../../src/rest/interceptors.js';
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

const server = createServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const ECHO_URL = `${BASE_URL}/api/v1/echo`;

interface Seen {
  label: string;
  authorization: string | null;
}

function mount(seen: Seen[]): void {
  const state = createMockState();
  server.use(
    discoveryHandler(state),
    http.post(DEVICE_AUTHORIZATION_ENDPOINT, ({ request }) => {
      seen.push({ label: 'device_authorize', authorization: request.headers.get('authorization') });
      return HttpResponse.json(deviceAuthorizationResponse());
    }),
    http.post(TOKEN_ENDPOINT, async ({ request }) => {
      const form = new URLSearchParams(await request.text());
      seen.push({
        label: `token:${form.get('grant_type') ?? ''}`,
        authorization: request.headers.get('authorization'),
      });
      return HttpResponse.json(tokenResponse({ refresh_token: 'rotated-refresh' }));
    }),
    http.post(ECHO_URL, ({ request }) => {
      seen.push({ label: 'control', authorization: request.headers.get('authorization') });
      return HttpResponse.json({ ok: true });
    }),
  );
}

async function runOAuth2Calls(oidc: ReturnType<typeof createClient>['oidc']): Promise<void> {
  await oidc.deviceAuthorize({ scope: 'openid' });
  await oidc.devicePoll({ deviceCode: new Sensitive('device-code-value') });
  await oidc.loginClientCredentials({});
  await oidc.oidcRefresh({ refreshToken: new Sensitive('refresh-token-value') });
}

describe('no session or adopted bearer on /oauth2/* (C162-05)', () => {
  it('an adopted §6.1 device credential rides ordinary calls but none of the /oauth2/* requests', async () => {
    const seen: Seen[] = [];
    mount(seen);
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    // `AxiamClient`'s constructor installs this interceptor on its session; a bare
    // `NodeSession` has none, so install the production one here.
    installDeviceTokenInterceptor(session.axios, session);
    session.deviceAccessToken = new Sensitive('adopted-device-token');

    await session.axios.post('/api/v1/echo', {});
    await runOAuth2Calls(oidc);

    expect(seen.map((s) => s.label)).toEqual([
      'control',
      'device_authorize',
      'token:urn:ietf:params:oauth:grant-type:device_code',
      'token:client_credentials',
      'token:refresh_token',
    ]);
    // The control proves the credential was in place and would have been sent.
    expect(seen[0]!.authorization).toBe('Bearer adopted-device-token');
    for (const request of seen.slice(1)) {
      expect(request.authorization, `${request.label} carried an Authorization header`).toBeNull();
    }
  });

  it('an adopted client-credentials bearer rides ordinary calls but none of the /oauth2/* requests', async () => {
    const seen: Seen[] = [];
    mount(seen);
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials({ adoptAsCredential: true });
    seen.length = 0;
    await session.axios.post('/api/v1/echo', {});
    await runOAuth2Calls(oidc);

    expect(seen[0]!.label).toBe('control');
    expect(seen[0]!.authorization).toBe('Bearer access-token-value');
    expect(seen).toHaveLength(5);
    for (const request of seen.slice(1)) {
      expect(request.authorization, `${request.label} carried an Authorization header`).toBeNull();
    }
  });
});
