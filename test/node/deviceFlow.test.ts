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

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { AuthError, NetworkError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import {
  createOidcClient,
  DEFAULT_POLL_INTERVAL_SECS,
  DISCOVERY_PATH,
  PollSchedule,
  SLOW_DOWN_INCREMENT_SECS,
} from '../../src/node/oidc.js';
import { createNodeSession } from '../../src/node/session.js';
import {
  BASE_URL,
  CLIENT_ID,
  createClient,
  createMockState,
  createServer,
  DEVICE_AUTHORIZATION_ENDPOINT,
  deviceAuthorizationResponse,
  discoveryDocumentWithoutOptionalEndpoints,
  discoveryHandler,
  ORG_ID,
  TENANT_ID,
  TOKEN_ENDPOINT,
  type OidcMockState,
} from './oidcTestKit.js';

const DEVICE_CODE = 'device-code-value';
const USER_CODE = 'WDJB-MJHT';

const server = createServer();
beforeAll(() => {
  server.listen({ onUnhandledFrame: 'error' });
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
const rateLimited = (retryAfter?: string): Response =>
  HttpResponse.json(
    { error: 'rate_limit_exceeded' },
    { status: 429, ...(retryAfter !== undefined ? { headers: { 'Retry-After': retryAfter } } : {}) },
  );
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

describe('PollSchedule: a 429 rate_limit_exceeded (§14.2 rule 9, contract 1.64)', () => {
  it('waits Retry-After as a minimum, in place of one interval, and leaves the interval alone', () => {
    const schedule = new PollSchedule(5, 600);
    schedule.rateLimited(30);
    expect(schedule.waitSecs).toBe(30);
    expect(schedule.tick()).toBe(true);
    // Served once: the next wait is the unchanged interval.
    expect(schedule.intervalSecs).toBe(5);
    expect(schedule.waitSecs).toBe(5);
  });

  it('never waits less than the interval', () => {
    const schedule = new PollSchedule(5, 600);
    schedule.rateLimited(1);
    expect(schedule.waitSecs).toBe(5);
    schedule.rateLimited(undefined);
    expect(schedule.waitSecs).toBe(5);
  });

  it('caps a Retry-After past the deadline at the deadline', () => {
    const schedule = new PollSchedule(5, 20);
    expect(schedule.tick()).toBe(true); // 15 s left
    schedule.rateLimited(60);
    expect(schedule.tick()).toBe(false);
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

/**
 * Record every sleep the polling loop takes and run it at once: the loop's
 * waits are asserted as the delays it asked for, not slept on a wall clock.
 */
function recordSleeps(): { delays: number[]; restore: () => void } {
  const realSetTimeout = globalThis.setTimeout;
  const delays: number[] = [];
  const spy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((
    fn: () => void,
    ms?: number,
    ...args: unknown[]
  ) => {
    // Only the loop's own sleep: other libraries keep timers of their own.
    if (ms !== undefined && new Error().stack?.includes('src/node/oidc')) {
      delays.push(ms);
      return realSetTimeout(fn, 0);
    }
    return realSetTimeout(fn, ms, ...args);
  }) as typeof setTimeout);
  return { delays, restore: () => spy.mockRestore() };
}

describe('deviceLogin polling (§14.2)', () => {
  let sleeps: ReturnType<typeof recordSleeps>;
  beforeEach(() => {
    sleeps = recordSleeps();
  });
  afterEach(() => {
    sleeps.restore();
  });

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
    expect(sleeps.delays).toEqual([1000, 1000, 1000, 1000]);
  });

  it('treats slow_down as non-terminal and raises the interval for the polls after it', async () => {
    // A `400 slow_down` adds 5 s, permanently (the arithmetic is also asserted against
    // PollSchedule); an SDK that let it fall through would abort a grant the user is
    // still approving.
    const state = createMockState();
    const flow = mountFlow(state, [() => slowDown(), () => pending(), () => success()]);

    const { oidc } = createClient();
    const tokens = await oidc.deviceLogin({ onUserCode: () => {} });

    expect(flow.calls()).toBe(3);
    expect(tokens.accessToken.expose()).toBe('device-access-token');
    expect(sleeps.delays).toEqual([1000, 6000, 6000]);
  });

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

  it('measures the deadline on the clock, so the time a poll takes counts against it (C164-05)', async () => {
    const state = createMockState();
    let nowMs = 0;
    const clock = {
      now: () => nowMs,
      sleep: (ms: number): Promise<void> => {
        nowMs += ms;
        return Promise.resolve();
      },
    };
    // Every poll takes 2 s of the clock; the grant lasts 5 s, the interval is 1 s.
    const flow = mountFlow(
      state,
      [
        () => {
          nowMs += 2000;
          return pending();
        },
      ],
      { expires_in: 5, interval: 1 },
    );

    const { oidc } = createClient();
    const err = await oidc.deviceLogin({ onUserCode: () => {}, clock }).catch((e: unknown) => e);

    // t=1 poll (ends 3), t=4 poll (ends 6): the next wait would end at 7 > 5.
    // Counting the sleeps alone would have allowed two more polls.
    expect((err as OAuthProtocolError).error).toBe('expired_token');
    expect(flow.calls()).toBe(2);
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

  it('retries a 500 {"error":"server_error"} mid-poll: a 5xx is a transport failure whatever its body (§14.2 rule 6)', async () => {
    // The body AXIAM's own token endpoint sends on an internal failure.
    const state = createMockState();
    const flow = mountFlow(state, [
      () => pending(),
      () =>
        HttpResponse.json(
          { error: 'server_error', error_description: 'internal error' },
          { status: 500 },
        ),
      () => success(),
    ]);

    const { oidc } = createClient();
    const tokens = await oidc.deviceLogin({ onUserCode: () => {} });

    expect(flow.calls()).toBe(3);
    expect(tokens.accessToken.expose()).toBe('device-access-token');
  });

  describe('a 429 on a poll is waited out (§14.2 rule 9, contract 1.64)', () => {
    it('waits at least Retry-After, polls again and completes, with the interval unchanged', async () => {
      const state = createMockState();
      // The server's own body: `{"error":"rate_limit_exceeded"}`, no error_description.
      // 429, then pending, then success: the sleep before the poll that follows
      // the waited-out round is the original interval, not five seconds longer.
      const flow = mountFlow(state, [() => rateLimited('3'), () => pending(), () => success()], {
        interval: 1,
        expires_in: 600,
      });

      const { oidc } = createClient();
      const tokens = await oidc.deviceLogin({ onUserCode: () => {} });

      expect(tokens.accessToken.expose()).toBe('device-access-token');
      expect(flow.calls()).toBe(3);
      // interval, then Retry-After (>= 3 s), then the interval again.
      expect(sleeps.delays).toEqual([1000, 3000, 1000]);
    });

    it('serves a 429 without a Retry-After as one ordinary interval', async () => {
      const state = createMockState();
      const flow = mountFlow(state, [() => rateLimited(), () => success()], { interval: 1 });

      const { oidc } = createClient();
      await oidc.deviceLogin({ onUserCode: () => {} });

      expect(flow.calls()).toBe(2);
      expect(sleeps.delays).toEqual([1000, 1000]);
    });

    it('honours the Retry-After of a bodiless 429 (a proxy\'s) as the floor', async () => {
      const state = createMockState();
      const flow = mountFlow(
        state,
        [() => new HttpResponse(null, { status: 429, headers: { 'Retry-After': '7' } }), () => success()],
        { interval: 1 },
      );

      const { oidc } = createClient();
      await oidc.deviceLogin({ onUserCode: () => {} });

      expect(flow.calls()).toBe(2);
      expect(sleeps.delays).toEqual([1000, 7000]);
    });

    it('does not raise the interval for a 429 whose body says slow_down: the status decides', async () => {
      const state = createMockState();
      const flow = mountFlow(
        state,
        [
          () =>
            HttpResponse.json(
              { error: 'slow_down' },
              { status: 429, headers: { 'Retry-After': '2' } },
            ),
          () => pending(),
          () => success(),
        ],
        { interval: 1 },
      );

      const { oidc } = createClient();
      await oidc.deviceLogin({ onUserCode: () => {} });

      expect(flow.calls()).toBe(3);
      // interval, Retry-After (2 s), then the interval again: not 6 s.
      expect(sleeps.delays).toEqual([1000, 2000, 1000]);
    });

    it('caps a Retry-After past expires_in at the deadline: expired_token, nothing sent after it', async () => {
      const state = createMockState();
      const flow = mountFlow(state, [() => rateLimited('3600'), () => success()], {
        interval: 1,
        expires_in: 5,
      });

      const { oidc } = createClient();
      const err = await oidc.deviceLogin({ onUserCode: () => {} }).catch((e: unknown) => e);

      expect(err).toBeInstanceOf(OAuthProtocolError);
      expect((err as OAuthProtocolError).error).toBe('expired_token');
      expect(flow.calls()).toBe(1);
      expect(sleeps.delays).toEqual([1000]);
    });

    it('surfaces the 429 from a single devicePoll as rate_limit_exceeded, never slow_down', async () => {
      const state = createMockState();
      server.use(
        discoveryHandler(state),
        http.post(TOKEN_ENDPOINT, () => rateLimited('2')),
      );

      const { oidc } = createClient();
      const err = await oidc
        .devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) })
        .catch((e: unknown) => e);

      expect(err).toBeInstanceOf(OAuthProtocolError);
      expect((err as OAuthProtocolError).error).toBe('rate_limit_exceeded');
    });

    it('surfaces a 429 whose body says slow_down from a single devicePoll as rate_limit_exceeded', async () => {
      const state = createMockState();
      server.use(
        discoveryHandler(state),
        http.post(TOKEN_ENDPOINT, () => HttpResponse.json({ error: 'slow_down' }, { status: 429 })),
      );

      const { oidc } = createClient();
      const err = await oidc
        .devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) })
        .catch((e: unknown) => e);

      expect((err as OAuthProtocolError).error).toBe('rate_limit_exceeded');
    });
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

// ---------------------------------------------------------------------------
// §2: a 429 on the other token requests (C164-23)
// ---------------------------------------------------------------------------

describe('a 429 on /oauth2/token outside the device poll (§2, §14.2 rule 9)', () => {
  it('loginClientCredentials raises the server\'s 429 {"error":"rate_limit_exceeded"} as OAuthProtocolError', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => rateLimited('2')),
    );

    const { oidc } = createClient({ clientSecret: 'secret' });
    const err = await oidc.loginClientCredentials({}).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('rate_limit_exceeded');
  });

  it('a 500 {"error":"server_error"} stays a NetworkError: a 5xx is a transport failure whatever its body', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => HttpResponse.json({ error: 'server_error' }, { status: 500 })),
    );

    const { oidc } = createClient({ clientSecret: 'secret' });
    const err = await oidc.loginClientCredentials({}).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(NetworkError);
  });
});

// ---------------------------------------------------------------------------
// §14.2 rule 6, §16: the poll is retried inside the attempt on a 5xx (C164-25)
// ---------------------------------------------------------------------------

describe('a 5xx or transport failure on a poll is §16-retried inside the attempt (§14.2 rule 6, §16.2)', () => {
  const serverError = (): Response =>
    HttpResponse.json({ error: 'server_error', error_description: 'internal error' }, { status: 500 });

  it('a single devicePoll makes three requests for two 500 server_error answers and a 200, and returns the tokens', async () => {
    const state = createMockState();
    const flow = mountFlow(state, [() => serverError(), () => serverError(), () => success()]);

    const { oidc } = createClient();
    const tokens = await oidc.devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) });

    expect(tokens.accessToken.expose()).toBe('device-access-token');
    expect(flow.calls()).toBe(3);
  });

  it('a third 500 in a row exhausts the cap: three requests, then the NetworkError', async () => {
    const state = createMockState();
    const flow = mountFlow(state, [() => serverError()]);

    const { oidc } = createClient();
    const err = await oidc.devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(NetworkError);
    expect(flow.calls()).toBe(3);
  });

  it('deviceLogin completes within one interval on those three requests', async () => {
    const state = createMockState();
    const flow = mountFlow(state, [() => serverError(), () => serverError(), () => success()]);
    const sleeps = recordSleeps();
    try {
      const { oidc } = createClient();
      await oidc.deviceLogin({ onUserCode: () => {} });

      expect(flow.calls()).toBe(3);
      // One interval before the poll; the two §16 backoffs inside it are under a second.
      expect(sleeps.delays.filter((ms) => ms >= 1000)).toEqual([1000]);
      expect(sleeps.delays).toHaveLength(3);
    } finally {
      sleeps.restore();
    }
  });

  it('a 429 is not retried inside the poll: one request, the wait is the loop\'s', async () => {
    const state = createMockState();
    const flow = mountFlow(state, [() => rateLimited('1'), () => success()]);

    const { oidc } = createClient();
    const err = await oidc.devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) }).catch((e: unknown) => e);

    expect((err as OAuthProtocolError).error).toBe('rate_limit_exceeded');
    expect(flow.calls()).toBe(1);
  });

  it.each([
    ['a transport failure twice, then a 200: three requests and the tokens', 2, 3, true],
    ['three transport failures in a row: three requests, then the NetworkError', 3, 3, false],
  ])('%s', async (_label, failures, requests, succeeds) => {
    // §14.6 (W7.1c): "The same holds for a transport failure" (C164-38).
    const state = createMockState();
    let calls = 0;
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => {
        calls += 1;
        return calls <= failures ? HttpResponse.error() : success();
      }),
    );

    const { oidc } = createClient();
    const outcome = await oidc.devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) }).catch((e: unknown) => e);

    expect(calls).toBe(requests);
    if (succeeds) {
      expect((outcome as { accessToken: Sensitive<string> }).accessToken.expose()).toBe('device-access-token');
    } else {
      expect(outcome).toBeInstanceOf(NetworkError);
    }
  });

  it('with retry disabled a transport failure makes one request', async () => {
    const state = createMockState();
    let calls = 0;
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => {
        calls += 1;
        return HttpResponse.error();
      }),
    );

    const session = createNodeSession({ baseUrl: BASE_URL, tenantId: TENANT_ID, orgId: ORG_ID, retryEnabled: false });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });
    const err = await oidc.devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(NetworkError);
    expect(calls).toBe(1);
  });

  it('with retry disabled a 5xx makes one request per poll', async () => {
    const state = createMockState();
    const flow = mountFlow(state, [() => serverError(), () => success()]);

    const session = createNodeSession({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      orgId: ORG_ID,
      retryEnabled: false,
    });
    const oidc = createOidcClient(session, { clientId: CLIENT_ID });
    const err = await oidc.devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(NetworkError);
    expect(flow.calls()).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// §14.2 rule 4: a §16 retry inside the poll never passes the deadline (C164-36)
// ---------------------------------------------------------------------------

/**
 * Fail fast, by assertion, if anything really sleeps a minute or more: the loop's waits run on the
 * injected clock, so a long real timer means a retry wait escaped the deadline bound (and would
 * otherwise show only as vitest's timeout).
 */
function recordLongTimers(): { long: number[]; restore: () => void } {
  const realSetTimeout = globalThis.setTimeout;
  const long: number[] = [];
  const spy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number, ...args: unknown[]) => {
    if (ms !== undefined && ms >= 60_000) {
      long.push(ms);
      return realSetTimeout(fn, 0);
    }
    return realSetTimeout(fn, ms, ...args);
  }) as typeof setTimeout);
  return { long, restore: () => spy.mockRestore() };
}

describe('a §16 retry inside the poll is bounded by the deadline (§14.2 rule 4, §34.2 P10)', () => {
  /** A clock that never sleeps: `sleep` advances it and records the wait. */
  function fakeClock(): { now: () => number; sleep: (ms: number) => Promise<void>; at: () => number } {
    let t = 0;
    return {
      now: () => t,
      sleep: (ms: number) => {
        t += ms;
        return Promise.resolve();
      },
      at: () => t,
    };
  }

  it('503 + Retry-After 120 on every poll, expires_in 30, interval 5: one request at 5 s, none at or after 30 s, expired_token', async () => {
    const state = createMockState();
    const clock = fakeClock();
    const times: number[] = [];
    server.use(
      discoveryHandler(state),
      http.post(DEVICE_AUTHORIZATION_ENDPOINT, () =>
        HttpResponse.json(deviceAuthorizationResponse({ expires_in: 30, interval: 5 })),
      ),
      http.post(TOKEN_ENDPOINT, () => {
        times.push(clock.at());
        return HttpResponse.json(
          { error: 'temporarily_unavailable' },
          { status: 503, headers: { 'Retry-After': '120' } },
        );
      }),
    );

    const timers = recordLongTimers();
    try {
      const { oidc } = createClient();
      const err = await oidc.deviceLogin({ onUserCode: () => {}, clock }).catch((e: unknown) => e);

      expect((err as OAuthProtocolError).error).toBe('expired_token');
      expect(timers.long).toEqual([]);
      expect(times).toEqual([5000]);
      expect(clock.at()).toBeLessThanOrEqual(30_000);
    } finally {
      timers.restore();
    }
  }, 5000);

  /**
   * A poll sent `leftMs` before the deadline and answered with a bare 500 (no Retry-After, so the
   * wait is the jittered backoff alone): `Math.random` is pinned, so the first backoff is
   * `random * 200` ms and decides the outcome (C164-45).
   */
  async function bareFiveHundredNearDeadline(
    expiresIn: number,
    random: number,
  ): Promise<{ times: number[]; err: unknown }> {
    const state = createMockState();
    const clock = fakeClock();
    const times: number[] = [];
    server.use(
      discoveryHandler(state),
      http.post(DEVICE_AUTHORIZATION_ENDPOINT, () =>
        HttpResponse.json(deviceAuthorizationResponse({ expires_in: expiresIn, interval: 5 })),
      ),
      http.post(TOKEN_ENDPOINT, () => {
        times.push(clock.at());
        return HttpResponse.json({ error: 'server_error' }, { status: 500 });
      }),
    );
    const randomSpy = vi.spyOn(Math, 'random').mockReturnValue(random);
    try {
      const { oidc } = createClient();
      const err = await oidc.deviceLogin({ onUserCode: () => {}, clock }).catch((e: unknown) => e);
      return { times, err };
    } finally {
      randomSpy.mockRestore();
    }
  }

  it('a bare 500 100 ms before the deadline, jitter at its maximum (200 ms): no retry is sent', async () => {
    const { times, err } = await bareFiveHundredNearDeadline(5.1, 1);

    expect((err as OAuthProtocolError).error).toBe('expired_token');
    expect(times).toEqual([5000]);
  }, 5000);

  it('a bare 500 100 ms before the deadline, jitter at 50 ms: that retry is before the deadline and is sent, the next wait is refused', async () => {
    const { times, err } = await bareFiveHundredNearDeadline(5.1, 0.25);

    expect((err as OAuthProtocolError).error).toBe('expired_token');
    expect(times).toEqual([5000, 5050]);
  }, 5000);

  it('a wait that lands exactly on the deadline is refused (>= , not >)', async () => {
    // expires_in 5.2: the deadline is 5200 ms; the poll at 5000 ms, a 200 ms backoff reaches it.
    const { times, err } = await bareFiveHundredNearDeadline(5.2, 1);

    expect((err as OAuthProtocolError).error).toBe('expired_token');
    expect(times).toEqual([5000]);
  }, 5000);

  it('a standalone devicePoll keeps the unbounded §16 behaviour: it has no deadline', async () => {
    const state = createMockState();
    const flow = mountFlow(state, [
      () => new HttpResponse(null, { status: 503, headers: { 'Retry-After': '1' } }),
      () => success(),
    ]);
    const sleeps = recordSleeps();
    try {
      const { oidc } = createClient();
      await oidc.devicePoll({ deviceCode: new Sensitive(DEVICE_CODE) });

      expect(flow.calls()).toBe(2);
      expect(sleeps.delays.some((ms) => ms >= 1000)).toBe(true);
    } finally {
      sleeps.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// §2: the 429 mapping is the OAuth2 form endpoints' only (C164-31)
// ---------------------------------------------------------------------------

describe('a 429 {"error":"rate_limit_exceeded"} outside the OAuth2 form endpoints stays a NetworkError (§2, C164-31)', () => {
  it('discovery', async () => {
    server.use(
      http.get(`${BASE_URL}${DISCOVERY_PATH}`, () => rateLimited('1')),
    );

    const { oidc } = createClient();
    const err = await oidc.oidcDiscover().catch((e: unknown) => e);

    expect(err).toBeInstanceOf(NetworkError);
  });

  it('ssoProviders', async () => {
    server.use(http.get(`${BASE_URL}/api/v1/auth/federation/providers`, () => rateLimited('1')));

    const { oidc } = createClient();
    const err = await oidc.ssoProviders().catch((e: unknown) => e);

    expect(err).toBeInstanceOf(NetworkError);
  });
});
