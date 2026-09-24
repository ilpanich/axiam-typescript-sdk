// CONTRACT.md §5.2 rule 1, C-12 question 5: an SSO/federation completion
// establishes a new session, possibly as a different principal, and its
// response carries no LoginUserInfo. The acting-tenant gate a previous login
// set must not survive it, or `actingTenant()` keeps refusing on the previous
// principal's report. A completion the server refuses establishes nothing
// and must leave the gate as it was.
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AuthzError, Sensitive } from '../../src/core/index.js';
import { AxiamClient } from '../../src/rest/client.js';
import {
  createOidcClient,
  SSO_CALLBACK_PATH,
  SSO_HANDOFF_PATH,
  SSO_OAUTH2_CALLBACK_PATH,
} from '../../src/node/oidc.js';

const BASE_URL = 'https://axiam.test';
const TENANT_ID = '22222222-2222-4222-8222-222222222222';
const OTHER_TENANT = '99999999-9999-4999-8999-999999999999';

function anyPassword(): string {
  return `pw-${Math.random().toString(36).slice(2)}-${Date.now()}`;
}

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/auth/login`, () =>
    HttpResponse.json(
      {
        user: {
          id: 'user-1',
          username: 'tenant-admin',
          email: 'admin@example.com',
          organization_level: false,
          tenant_id: TENANT_ID,
          principal_tenant_id: TENANT_ID,
          org_id: 'org-1',
        },
        session_id: 'session-1',
        expires_in: 900,
      },
      { status: 200 },
    ),
  ),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const ssoSuccess = {
  user_id: 'user-2',
  session_id: 'session-2',
  expires_in: 900,
  redirect_uri: 'https://app.example.com/after-login',
};

const completions = [
  {
    name: 'ssoComplete',
    path: SSO_CALLBACK_PATH,
    run: (oidc: ReturnType<typeof createOidcClient>) => oidc.ssoComplete({ state: 's', code: 'c' }),
  },
  {
    name: 'ssoCompleteOauth2',
    path: SSO_OAUTH2_CALLBACK_PATH,
    run: (oidc: ReturnType<typeof createOidcClient>) => oidc.ssoCompleteOauth2({ state: 's', code: 'c' }),
  },
  {
    name: 'ssoCompleteHandoff',
    path: SSO_HANDOFF_PATH,
    run: (oidc: ReturnType<typeof createOidcClient>) => oidc.ssoCompleteHandoff({ code: 'c' }),
  },
] as const;

async function restrictedClient() {
  const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
  await client.login('tenant-admin', anyPassword());
  // Precondition: the login's report gates the helper client-side.
  expect(() => client.actingTenant(OTHER_TENANT)).toThrow(AuthzError);
  const oidc = createOidcClient(client.session, { clientId: 'app' });
  return { client, oidc };
}

describe('§5.2 rule 1: an SSO/federation completion resets the acting-tenant gate', () => {
  for (const completion of completions) {
    it(`${completion.name} resets a stale gate, so actingTenant() lets the server decide`, async () => {
      const { client, oidc } = await restrictedClient();
      server.use(http.post(`${BASE_URL}${completion.path}`, () => HttpResponse.json(ssoSuccess)));

      await completion.run(oidc);

      expect(client.session.principalScope).toBeUndefined();
      expect(() => client.actingTenant(OTHER_TENANT)).not.toThrow();
    });

    it(`a refused ${completion.name} leaves the gate as the login set it`, async () => {
      const { client, oidc } = await restrictedClient();
      server.use(
        http.post(`${BASE_URL}${completion.path}`, () =>
          HttpResponse.json({ error: 'invalid_request', message: 'refused' }, { status: 400 }),
        ),
      );

      await expect(completion.run(oidc)).rejects.toThrow();

      expect(client.session.principalScope?.organizationLevel).toBe(false);
      expect(() => client.actingTenant(OTHER_TENANT)).toThrow(AuthzError);
    });
  }
});

// CONTRACT 1.52 N4.4 (C-12): "Any later session-establishing call replaces
// it [the device credential] ... an SSO completion ..." Before this fix,
// none of the three SSO/federation completions touched
// `session.deviceAccessToken` — `#forgetPreviousPrincipal()` cleared only
// `principalScope`/`decisionMemo` — so a client that had called
// authenticateDevice() and then completed a federation sign-in kept riding
// the STALE device credential on every later request:
// installDeviceTokenInterceptor sends it unconditionally whenever
// `deviceAccessToken` is set, silently overriding the brand-new cookie
// session ssoComplete/etc. just established.
describe('CONTRACT 1.52 N4.4 (C-12) — an SSO/federation completion replaces a previously-adopted device credential', () => {
  for (const completion of completions) {
    it(`${completion.name} clears a previously-adopted device credential on success`, async () => {
      const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
      const oidc = createOidcClient(client.session, { clientId: 'app' });
      client.session.deviceAccessToken = new Sensitive('stale-device-token');

      server.use(http.post(`${BASE_URL}${completion.path}`, () => HttpResponse.json(ssoSuccess)));
      await completion.run(oidc);

      expect(client.session.deviceAccessToken).toBeUndefined();
    });

    it(`twin (I4): a refused ${completion.name} leaves an ABSENT device credential absent`, async () => {
      const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
      const oidc = createOidcClient(client.session, { clientId: 'app' });
      expect(client.session.deviceAccessToken).toBeUndefined();

      server.use(
        http.post(`${BASE_URL}${completion.path}`, () =>
          HttpResponse.json({ error: 'invalid_request', message: 'refused' }, { status: 400 }),
        ),
      );
      await expect(completion.run(oidc)).rejects.toThrow();

      expect(client.session.deviceAccessToken).toBeUndefined();
    });
  }
});
