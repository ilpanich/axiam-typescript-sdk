// Device Authorization Grant — CONTRACT.md §14.
//
// The §14.6 required assertions split across two levels, deliberately:
//
//   * Interval ARITHMETIC — interval from the response, `slow_down` raising it
//     permanently, polling stopping at `expires_in` — is asserted against
//     `PollSchedule` directly. It is pure logic, so it is tested exactly and
//     instantly, including cases (a 30-minute grant, three cumulative
//     `slow_down`s) no wall-clock test could reach.
//
//   * WIRE behaviour lives in the integration tests below: which answers loop,
//     which terminate, how many requests actually go out, and the §14.3 rule 2
//     ordering guarantee. Intervals in these fixtures are 1 s.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { AuthError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import {
  DEFAULT_POLL_INTERVAL_SECS,
  PollSchedule,
  SLOW_DOWN_INCREMENT_SECS,
} from '../../src/node/oidc.js';
import {
  BASE_URL,
  createClient,
  createMockState,
  createServer,
  DEVICE_AUTHORIZATION_ENDPOINT,
  deviceAuthorizationResponse,
  discoveryDocumentWithoutOptionalEndpoints,
  discoveryHandler,
  TOKEN_ENDPOINT,
  type OidcMockState,
} from './oidcTestKit.js';

const DEVICE_CODE = 'device-code-value';
const USER_CODE = 'WDJB-MJHT';

const server = createServer();
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' });
});
afterEach(() => {
  server.resetHandlers();
});
afterAll(() => {
  server.close();
});

function oauthError(code: string): Response {
  return HttpResponse.json(
    { error: code, error_description: `${code} description` },
    { status: 400 },
  );
}

const pending = (): Response => oauthError('authorization_pending');
const slowDown = (): Response => oauthError('slow_down');
const success = (): Response =>
  HttpResponse.json({
    access_token: 'device-access-token',
    token_type: 'Bearer',
    expires_in: 900,
    refresh_token: 'device-refresh-token',
  });

/** Mount discovery + device authorization + a scripted token endpoint. */
function mountFlow(
  state: OidcMockState,
  script: Array<() => Response>,
  authorizationOverrides: Record<string, unknown> = {},
): { calls: () => number; forms: URLSearchParams[] } {
  let index = 0;
  const forms: URLSearchParams[] = [];

  server.use(
    discoveryHandler(state),
    http.post(DEVICE_AUTHORIZATION_ENDPOINT, async ({ request }) => {
      forms.push(new URLSearchParams(await request.text()));
      return HttpResponse.json(deviceAuthorizationResponse(authorizationOverrides));
    }),
    http.post(TOKEN_ENDPOINT, async ({ request }) => {
      forms.push(new URLSearchParams(await request.text()));
      const responder = script[index] ?? script[script.length - 1];
      index += 1;
      return responder!();
    }),
  );

  return { calls: () => index, forms };
}

// ---------------------------------------------------------------------------
// §14.2 arithmetic — PollSchedule
// ---------------------------------------------------------------------------

describe('PollSchedule (§14.2 rules 1, 2, 4)', () => {
  it('falls back to the RFC default only when the interval is absent or zero', () => {
    expect(new PollSchedule(0, 600).intervalSecs).toBe(DEFAULT_POLL_INTERVAL_SECS);
    expect(new PollSchedule(7, 600).intervalSecs).toBe(7);
  });

  it('raises the interval on slow_down, cumulatively, and never resets it', () => {
    const schedule = new PollSchedule(5, 1800);
    schedule.slowDown();
    expect(schedule.intervalSecs).toBe(5 + SLOW_DOWN_INCREMENT_SECS);
    schedule.slowDown();
    expect(schedule.intervalSecs).toBe(15);

    // Polling on must not undo the raise. This is the rule implementations get
    // wrong: backing off for one round and returning to the original interval
    // earns another `slow_down`, forever.
    schedule.tick();
    schedule.tick();
    expect(schedule.intervalSecs).toBe(15);
  });

  it('stops at the deadline', () => {
    const schedule = new PollSchedule(5, 12);
    expect(schedule.tick()).toBe(true); // t=5
    expect(schedule.tick()).toBe(true); // t=10
    expect(schedule.tick()).toBe(false); // t=15 is past 12
  });

  it('lets a slowed interval exhaust the grant early', () => {
    const schedule = new PollSchedule(5, 20);
    expect(schedule.tick()).toBe(true);
    schedule.slowDown();
    schedule.slowDown();
    expect(schedule.intervalSecs).toBe(15);
    expect(schedule.tick()).toBe(false);
  });

  it('never polls when the interval covers the whole grant', () => {
    expect(new PollSchedule(30, 30).tick()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// deviceAuthorize
// ---------------------------------------------------------------------------

describe('deviceAuthorize (§14.1)', () => {
  it('is unauthenticated, form-encoded, and sends tenant_id as a query param', async () => {
    const state = createMockState();
    const { forms } = mountFlow(state, [() => success()]);

    // No client secret: §14.1 says a device that cannot show a browser cannot
    // hold one, and the SDK must not refuse such a client.
    const { oidc } = createClient();
    const authorization = await oidc.deviceAuthorize({ scope: 'openid profile' });

    const form = forms[0]!;
    expect(form.get('client_secret')).toBeNull();
    expect(form.get('scope')).toBe('openid profile');
    expect(form.get('tenant_id')).toBeNull();

    expect(authorization.userCode).toBe(USER_CODE);
    expect(authorization.interval).toBe(1);
    expect(authorization.verificationUriComplete).toBe(`${BASE_URL}/device?user_code=WDJB-MJHT`);
  });

  it('defaults an absent interval to 5 s and never to something faster', async () => {
    const state = createMockState();
    mountFlow(state, [() => success()], { interval: null });

    const { oidc } = createClient();
    const authorization = await oidc.deviceAuthorize();

    expect(authorization.interval).toBe(DEFAULT_POLL_INTERVAL_SECS);
  });

  it('errors, rather than guessing a URL, when the server advertises no endpoint', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state, discoveryDocumentWithoutOptionalEndpoints()));

    const { oidc } = createClient();
    await expect(oidc.deviceAuthorize()).rejects.toThrow(AuthError);
    await expect(oidc.deviceAuthorize()).rejects.toThrow(/device_authorization_endpoint/);
  });
});

// ---------------------------------------------------------------------------
// §14.2 wire behaviour
// ---------------------------------------------------------------------------

describe('deviceLogin polling (§14.2)', () => {
  it('loops on authorization_pending rather than raising', async () => {
    const state = createMockState();
    const flow = mountFlow(state, [
      () => pending(),
      () => pending(),
      () => pending(),
      () => success(),
    ]);

    const { oidc } = createClient();
    const tokens = await oidc.deviceLogin({ onUserCode: () => {} });

    expect(flow.calls()).toBe(4);
    expect(tokens.accessToken.expose()).toBe('device-access-token');
  });

  it('treats slow_down as non-terminal', async () => {
    // The back-off arithmetic is asserted against PollSchedule; what matters
    // here is that `slow_down` is not mistaken for a terminal answer. An SDK
    // that let it fall through would abort a grant the user is still approving.
    const state = createMockState();
    const flow = mountFlow(state, [() => slowDown(), () => success()]);

    const { oidc } = createClient();
    const tokens = await oidc.deviceLogin({ onUserCode: () => {} });

    expect(flow.calls()).toBe(2);
    expect(tokens.accessToken.expose()).toBe('device-access-token');
  }, 20_000);

  it.each([
    ['access_denied', 'expired_token'],
    ['expired_token', 'access_denied'],
  ])('raises %s distinctly from %s', async (code, other) => {
    // §14.2 rule 3: "a human said no" and "nobody answered" are the only two
    // pieces of information the device can act on.
    const state = createMockState();
    mountFlow(state, [() => oauthError(code)]);

    const { oidc } = createClient();
    const err = await oidc.deviceLogin({ onUserCode: () => {} }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe(code);
    expect((err as OAuthProtocolError).error).not.toBe(other);
  });

  it('stops polling at expires_in even while the server still says pending', async () => {
    const state = createMockState();
    // 2-second grant, 1-second interval: one poll at t=1, then the t=2 tick is
    // the deadline and must not be sent.
    const flow = mountFlow(state, [() => pending()], { expires_in: 2, interval: 1 });

    const { oidc } = createClient();
    const err = await oidc.deviceLogin({ onUserCode: () => {} }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('expired_token');
    expect(flow.calls()).toBe(1);
  });

  it('retries a 5xx mid-poll rather than treating it as terminal', async () => {
    const state = createMockState();
    const flow = mountFlow(state, [
      () => pending(),
      () => new HttpResponse('upstream restarting', { status: 500 }),
      () => new HttpResponse('still restarting', { status: 503 }),
      () => success(),
    ]);

    const { oidc } = createClient();
    const tokens = await oidc.deviceLogin({ onUserCode: () => {} });

    expect(flow.calls()).toBe(4);
    expect(tokens.accessToken.expose()).toBe('device-access-token');
  });
});

// ---------------------------------------------------------------------------
// §14.3 deviceLogin
// ---------------------------------------------------------------------------

describe('deviceLogin (§14.3)', () => {
  it('surfaces the user code BEFORE the first poll', async () => {
    const state = createMockState();
    const order: string[] = [];

    server.use(
      discoveryHandler(state),
      http.post(DEVICE_AUTHORIZATION_ENDPOINT, () =>
        HttpResponse.json(deviceAuthorizationResponse()),
      ),
      http.post(TOKEN_ENDPOINT, () => {
        order.push('poll');
        return success();
      }),
    );

    const { oidc } = createClient();
    let seen: string | undefined;
    await oidc.deviceLogin({
      onUserCode: (authorization) => {
        order.push('userCode');
        seen = authorization.userCode;
      },
    });

    // Ordering, not just presence (§14.6).
    expect(order).toEqual(['userCode', 'poll']);
    expect(seen).toBe(USER_CODE);
  });

  it('awaits an async onUserCode before polling', async () => {
    // A device rendering a QR code may need to await a paint. Polling before
    // that resolves would defeat rule 2 just as surely as not calling back.
    const state = createMockState();
    const order: string[] = [];

    server.use(
      discoveryHandler(state),
      http.post(DEVICE_AUTHORIZATION_ENDPOINT, () =>
        HttpResponse.json(deviceAuthorizationResponse()),
      ),
      http.post(TOKEN_ENDPOINT, () => {
        order.push('poll');
        return success();
      }),
    );

    const { oidc } = createClient();
    await oidc.deviceLogin({
      onUserCode: async () => {
        await new Promise((resolve) => setTimeout(resolve, 20));
        order.push('userCode');
      },
    });

    expect(order).toEqual(['userCode', 'poll']);
  });

  it('returns a token set carrying the access token', async () => {
    const state = createMockState();
    mountFlow(state, [() => success()]);

    const { oidc } = createClient();
    const tokens = await oidc.deviceLogin({ onUserCode: () => {} });

    // §14.6 as amended by the contract 1.7 errata: the assertion is on the
    // returned token set. Adoption is the same MAY as loginClientCredentials.
    expect(tokens.accessToken.expose()).toBe('device-access-token');
    expect(tokens.tokenType).toBe('Bearer');
    expect(tokens.refreshToken?.expose()).toBe('device-refresh-token');
  });

  it('redacts the device code but not the user code', async () => {
    const state = createMockState();
    mountFlow(state, [() => success()]);

    const { oidc } = createClient();
    const authorization = await oidc.deviceAuthorize();

    expect(authorization.deviceCode).toBeInstanceOf(Sensitive);
    expect(String(authorization.deviceCode)).not.toContain(DEVICE_CODE);
    // §14.5: userCode is NOT wrapped — it exists to be read aloud, and
    // wrapping it would defeat the one thing it is for.
    expect(authorization.userCode).toBe(USER_CODE);
  });
});

// ---------------------------------------------------------------------------
// devicePoll standalone
// ---------------------------------------------------------------------------

describe('devicePoll (§14.1)', () => {
  it('surfaces pending answers so a hand-rolled loop sees what deviceLogin sees', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => pending()),
    );

    const { oidc } = createClient();
    const err = await oidc
      .devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) })
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('authorization_pending');
  });

  it('sends the device-code grant type', async () => {
    const state = createMockState();
    const forms: URLSearchParams[] = [];
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        forms.push(new URLSearchParams(await request.text()));
        return success();
      }),
    );

    const { oidc } = createClient();
    await oidc.devicePoll({ deviceCode: DEVICE_CODE });

    expect(forms[0]!.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code');
    expect(forms[0]!.get('device_code')).toBe(DEVICE_CODE);
  });
});
