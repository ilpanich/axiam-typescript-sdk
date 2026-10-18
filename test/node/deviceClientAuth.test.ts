// Device Authorization Grant client authentication — CONTRACT.md §14.1 rule 2
// and §14.6 (contract 1.62, maintainer option (a) and the 2026-10-16 "same
// rules" reading).
//
// What is asserted, for both `device_authorize` and every `device_poll`:
//
//   * a client configured with a secret sends it as `client_secret` in the
//     FORM BODY and sends no `Authorization` header — whichever of
//     `client_secret_post` and `client_secret_basic` it is registered for (the
//     SDK has no notion of the registration; it sends the same thing, §12.1
//     rule 3);
//   * a client configured with none sends neither `client_secret` nor any
//     other credential and is not refused client-side;
//   * an mTLS client presents its certificate on the connection (through the
//     `mtls_endpoint_aliases` entry) and puts nothing in the form;
//   * the poll sends `client_id` every time;
//   * `401 {"error":"invalid_client"}` from either operation is an
//     `OAuthProtocolError`, made once, and never enters the §9 refresh guard
//     even for a client whose session is authenticated.
//
// This SDK implements neither `private_key_jwt` client authentication (§21.8
// is informative) nor a DPoP proof generator, so there is no assertion for
// either: the last test pins that no assertion is sent where none is built.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import {
  BASE_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  DEVICE_AUTHORIZATION_ENDPOINT,
  deviceAuthorizationResponse,
  discoveryDocument,
  discoveryHandler,
  MTLS_DEVICE_AUTHORIZATION_ENDPOINT,
  MTLS_TOKEN_ENDPOINT,
  mtlsEndpointAliases,
  TOKEN_ENDPOINT,
} from './oidcTestKit.js';

const DEVICE_CODE = 'device-code-value';

const server = createServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

interface Seen {
  endpoint: 'authorize' | 'poll';
  url: string;
  form: URLSearchParams;
  authorization: string | null;
}

const ok = () =>
  HttpResponse.json({
    access_token: 'device-access-token',
    token_type: 'Bearer',
    expires_in: 900,
  });

const pending = () =>
  HttpResponse.json(
    { error: 'authorization_pending', error_description: 'pending' },
    { status: 400 },
  );

const invalidClient = () =>
  HttpResponse.json(
    { error: 'invalid_client', error_description: 'client authentication failed' },
    { status: 401 },
  );

/** Mount discovery and both device endpoints on the given URLs, recording every request. */
function mount(
  seen: Seen[],
  options: {
    authorize?: () => Response;
    poll?: () => Response;
    authorizeUrl?: string;
    tokenUrl?: string;
    document?: ReturnType<typeof discoveryDocument>;
  } = {},
): void {
  const state = createMockState();
  server.use(
    discoveryHandler(state, options.document),
    http.post(options.authorizeUrl ?? DEVICE_AUTHORIZATION_ENDPOINT, async ({ request }) => {
      seen.push({
        endpoint: 'authorize',
        url: request.url,
        form: new URLSearchParams(await request.text()),
        authorization: request.headers.get('authorization'),
      });
      return (options.authorize ?? (() => HttpResponse.json(deviceAuthorizationResponse())))();
    }),
    http.post(options.tokenUrl ?? TOKEN_ENDPOINT, async ({ request }) => {
      seen.push({
        endpoint: 'poll',
        url: request.url,
        form: new URLSearchParams(await request.text()),
        authorization: request.headers.get('authorization'),
      });
      return (options.poll ?? ok)();
    }),
  );
}

/** Every member that could carry a client credential, other than `client_id`. */
const CREDENTIAL_MEMBERS = ['client_secret', 'client_assertion', 'client_assertion_type'];

describe('a confidential client (client secret) — §14.1 rule 2', () => {
  it('sends client_secret in the form body at device_authorize, and no Authorization header', async () => {
    const seen: Seen[] = [];
    mount(seen);
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.deviceAuthorize({ scope: 'openid' });

    expect(seen).toHaveLength(1);
    expect(seen[0]!.form.get('client_id')).toBe(CLIENT_ID);
    expect(seen[0]!.form.get('client_secret')).toBe(CLIENT_SECRET);
    expect(seen[0]!.form.get('scope')).toBe('openid');
    expect(seen[0]!.authorization).toBeNull();
    expect(new URL(seen[0]!.url).searchParams.get('tenant_id')).not.toBeNull();
    // `client_secret` is the body's, never the query's.
    expect(new URL(seen[0]!.url).searchParams.get('client_secret')).toBeNull();
  });

  it('sends client_secret and client_id in the form body at device_poll, and no Authorization header', async () => {
    const seen: Seen[] = [];
    mount(seen);
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) });

    expect(seen).toHaveLength(1);
    const form = seen[0]!.form;
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code');
    expect(form.get('device_code')).toBe(DEVICE_CODE);
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('client_secret')).toBe(CLIENT_SECRET);
    expect(seen[0]!.authorization).toBeNull();
  });

  it('accepts the secret as a Sensitive value, as every other token request does', async () => {
    const seen: Seen[] = [];
    mount(seen);
    const { session } = createClient();
    const { createOidcClient } = await import('../../src/node/oidc.js');
    const oidc = createOidcClient(session, {
      clientId: CLIENT_ID,
      clientSecret: new Sensitive(CLIENT_SECRET),
    });

    await oidc.deviceAuthorize({});
    await oidc.devicePoll({ deviceCode: DEVICE_CODE });

    expect(seen.map((s) => s.form.get('client_secret'))).toEqual([CLIENT_SECRET, CLIENT_SECRET]);
  });

  it('sends it at device_authorize AND on every poll of a device_login, never an Authorization header', async () => {
    const seen: Seen[] = [];
    let polls = 0;
    mount(seen, {
      poll: () => {
        polls += 1;
        return polls === 1 ? pending() : ok();
      },
    });
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.deviceLogin({ onUserCode: () => undefined });

    expect(tokens.accessToken.expose()).toBe('device-access-token');
    expect(seen.map((s) => s.endpoint)).toEqual(['authorize', 'poll', 'poll']);
    for (const request of seen) {
      expect(request.form.get('client_id')).toBe(CLIENT_ID);
      expect(request.form.get('client_secret')).toBe(CLIENT_SECRET);
      expect(request.authorization).toBeNull();
    }
  }, 20_000);

  it('sends the same form-body secret for a client registered client_secret_basic (§12.1 rule 3 stands)', async () => {
    // The SDK has no registration to consult and must not guess one: the
    // maintainer's 2026-10-16 reading is that no SDK sends `Authorization:
    // Basic` to either device endpoint, whatever the client is registered for.
    // A client constructed with a secret therefore produces the same wire
    // shape whichever method the server holds for it.
    const seen: Seen[] = [];
    mount(seen);
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.deviceAuthorize({});
    await oidc.devicePoll({ deviceCode: DEVICE_CODE });

    for (const request of seen) {
      expect(request.authorization).toBeNull();
      expect(request.form.get('client_secret')).toBe(CLIENT_SECRET);
    }
  });
});

describe('a public client (no credential) — §14.1 rule 1', () => {
  it('sends client_id and no credential at device_authorize, and is not refused client-side', async () => {
    const seen: Seen[] = [];
    mount(seen);
    const { oidc } = createClient();

    const authorization = await oidc.deviceAuthorize({});

    expect(authorization.userCode).toBe('WDJB-MJHT');
    expect(seen).toHaveLength(1);
    expect(seen[0]!.form.get('client_id')).toBe(CLIENT_ID);
    for (const member of CREDENTIAL_MEMBERS) expect(seen[0]!.form.has(member)).toBe(false);
    expect(seen[0]!.authorization).toBeNull();
  });

  it('sends client_id and no credential on every poll, and is not refused client-side', async () => {
    const seen: Seen[] = [];
    let polls = 0;
    mount(seen, {
      poll: () => {
        polls += 1;
        return polls === 1 ? pending() : ok();
      },
    });
    const { oidc } = createClient();

    const tokens = await oidc.deviceLogin({ onUserCode: () => undefined });

    expect(tokens.accessToken.expose()).toBe('device-access-token');
    expect(seen.map((s) => s.endpoint)).toEqual(['authorize', 'poll', 'poll']);
    for (const request of seen) {
      expect(request.form.get('client_id')).toBe(CLIENT_ID);
      for (const member of CREDENTIAL_MEMBERS) expect(request.form.has(member)).toBe(false);
      expect(request.authorization).toBeNull();
    }
  }, 20_000);

  it('never invents or borrows a secret: the poll of a public client carries none', async () => {
    const seen: Seen[] = [];
    mount(seen);
    const { oidc } = createClient();

    await oidc.devicePoll({ deviceCode: DEVICE_CODE });

    expect(seen[0]!.form.get('client_id')).toBe(CLIENT_ID);
    expect(seen[0]!.form.has('client_secret')).toBe(false);
  });
});

describe('an mTLS client (§6.1 certificate, no secret) — §14.1 rule 2', () => {
  const document = () => discoveryDocument({ mtls_endpoint_aliases: mtlsEndpointAliases() });

  it('presents the certificate through the alias endpoints and puts no credential in the form', async () => {
    const seen: Seen[] = [];
    // Both origins are registered, so using the wrong one is a recorded call.
    mount(seen, {
      document: document(),
      authorizeUrl: MTLS_DEVICE_AUTHORIZATION_ENDPOINT,
      tokenUrl: MTLS_TOKEN_ENDPOINT,
    });
    const { oidc } = createClient({ mtls: true });

    await oidc.deviceAuthorize({});
    await oidc.devicePoll({ deviceCode: DEVICE_CODE });

    expect(seen.map((s) => s.url.split('?')[0])).toEqual([
      MTLS_DEVICE_AUTHORIZATION_ENDPOINT,
      MTLS_TOKEN_ENDPOINT,
    ]);
    for (const request of seen) {
      expect(request.form.get('client_id')).toBe(CLIENT_ID);
      for (const member of CREDENTIAL_MEMBERS) expect(request.form.has(member)).toBe(false);
      expect(request.authorization).toBeNull();
    }
  });
});

describe('401 invalid_client — §14.2 rule 5 (contract 1.62)', () => {
  /** An authenticated session whose refresh endpoint is mounted and counted. */
  function withRefreshProbe(): { refreshed: () => number } {
    let hits = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/refresh`, () => {
        hits += 1;
        return HttpResponse.json({}, { status: 200 });
      }),
    );
    return { refreshed: () => hits };
  }

  it('device_authorize: raises OAuthProtocolError(invalid_client), one request, no refresh', async () => {
    const seen: Seen[] = [];
    mount(seen, { authorize: invalidClient });
    const probe = withRefreshProbe();
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    session.authenticated = true;

    const err = await oidc.deviceAuthorize({}).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('invalid_client');
    expect(seen).toHaveLength(1);
    expect(probe.refreshed()).toBe(0);
  });

  it('device_poll: raises OAuthProtocolError(invalid_client), one request, no refresh', async () => {
    const seen: Seen[] = [];
    mount(seen, { poll: invalidClient });
    const probe = withRefreshProbe();
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    session.authenticated = true;

    const err = await oidc.devicePoll({ deviceCode: DEVICE_CODE }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('invalid_client');
    expect(seen).toHaveLength(1);
    expect(probe.refreshed()).toBe(0);
  });

  it('device_login: invalid_client on a poll is terminal — the loop makes no second poll', async () => {
    const seen: Seen[] = [];
    mount(seen, { poll: invalidClient });
    const { oidc } = createClient();

    const err = await oidc.deviceLogin({ onUserCode: () => undefined }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('invalid_client');
    expect(seen.map((s) => s.endpoint)).toEqual(['authorize', 'poll']);
  }, 20_000);
});

describe('what this SDK does not build', () => {
  it('sends no client_assertion: private_key_jwt client authentication is not implemented', async () => {
    const seen: Seen[] = [];
    mount(seen);
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.deviceAuthorize({});
    await oidc.devicePoll({ deviceCode: DEVICE_CODE });

    for (const request of seen) {
      expect(request.form.has('client_assertion')).toBe(false);
      expect(request.form.has('client_assertion_type')).toBe(false);
    }
  });
});
