// CIBA — CONTRACT.md §33.8's sixteen required tests (nine initiation and
// polling, four ping, three signed request), mirroring the Rust reference's
// tests/ciba_test.rs t01–t16, plus the §21.3.1 seventh alias at work.
//
// No credential, key or token literal: the client secret, the auth_req_id,
// the notification token and every signing key are generated at run time, and
// no failure message prints one.

import { generateKeyPairSync, randomBytes, randomUUID, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer as createNetServer, type Server as NetServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { decodeProtectedHeader, jwtVerify } from 'jose';
import { http, HttpResponse, passthrough } from 'msw';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AuthError, NetworkError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import { ValidationError } from '../../src/management/errors.js';
import {
  CIBA_GRANT_TYPE,
  CibaRequestSigner,
  isAccessDenied,
  isExpiredToken,
} from '../../src/node/oidc.js';
import type {
  CibaClock,
  CibaInitiateParams,
  CibaInitiateResponse,
  OidcConfiguration,
} from '../../src/node/oidcTypes.js';
import {
  BC_AUTHORIZE_ENDPOINT,
  CLIENT_ID,
  createClient,
  createServer,
  discoveryDocument,
  generateSigningKey,
  ISSUER,
  JWKS_URI,
  MTLS_BC_AUTHORIZE_ENDPOINT,
  mtlsEndpointAliases,
  signIdToken,
  TENANT_ID,
  TOKEN_ENDPOINT,
} from './oidcTestKit.js';
import { assertNoFragment, errorRenderings, freshSecret, renderings } from '../redaction.js';

const server = createServer();
beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const random = (): string => randomBytes(32).toString('base64url');

interface Seen {
  form: URLSearchParams;
  tenantQuery: string | null;
  url: string;
  at: number;
}

/** A clock that never sleeps: `sleep` advances it and records the wait (seconds). */
class TestClock implements CibaClock {
  readonly start = 1_000_000_000;
  offset = 0;
  readonly sleeps: number[] = [];
  now(): number {
    return this.start + this.offset;
  }
  async sleep(ms: number): Promise<void> {
    this.offset += ms;
    this.sleeps.push(ms / 1000);
  }
}

function confidentialClient() {
  const secret = freshSecret();
  return { ...createClient({ clientSecret: secret }), secret };
}

function oauthError(status: number, code: string): Response {
  return HttpResponse.json({ error: code, error_description: `${code} here` }, { status });
}

/** Answer the token endpoint from `script`, one entry per request (the last repeats). */
function tokenScript(script: Array<() => Response | Promise<Response>>, clock?: TestClock): Seen[] {
  const seen: Seen[] = [];
  server.use(
    http.post(TOKEN_ENDPOINT, async ({ request }) => {
      const url = new URL(request.url);
      seen.push({
        form: new URLSearchParams(await request.text()),
        tenantQuery: url.searchParams.get('tenant_id'),
        url: url.origin + url.pathname,
        at: clock ? clock.offset / 1000 : 0,
      });
      return script[Math.min(seen.length - 1, script.length - 1)]!();
    }),
  );
  return seen;
}

function bcAuthorize(respond: () => Response, endpoint = BC_AUTHORIZE_ENDPOINT): Seen[] {
  const seen: Seen[] = [];
  server.use(
    http.post(endpoint, async ({ request }) => {
      const url = new URL(request.url);
      seen.push({
        form: new URLSearchParams(await request.text()),
        tenantQuery: url.searchParams.get('tenant_id'),
        url: url.origin + url.pathname,
        at: 0,
      });
      return respond();
    }),
  );
  return seen;
}

const accepted = (extra: Record<string, unknown> = {}) => () =>
  HttpResponse.json({ auth_req_id: random(), expires_in: 120, interval: 5, ...extra });

function params(extra: Partial<CibaInitiateParams> = {}): CibaInitiateParams {
  return { scope: 'openid profile', loginHint: 'ada', configuration: discoveryDocument(), ...extra } as CibaInitiateParams;
}

function initiated(authReqId: string, expiresIn: number, interval: number, at: number): CibaInitiateResponse {
  return { authReqId: new Sensitive(authReqId), expiresIn, interval, receivedAt: at };
}

async function tokensWithIdToken(): Promise<() => Response> {
  const key = await generateSigningKey('ciba-id-token-key');
  server.use(http.get(JWKS_URI, () => HttpResponse.json({ keys: [key.jwk] })));
  const idToken = await signIdToken(key, { nonce: null });
  return () =>
    HttpResponse.json({
      access_token: random(),
      token_type: 'Bearer',
      expires_in: 900,
      scope: 'openid profile',
      id_token: idToken,
    });
}

const keys = (form: URLSearchParams): string[] => [...new Set(form.keys())].sort();

// ── 1. Redaction ────────────────────────────────────────────────────────────

describe('§33.8 (1) — redaction', () => {
  it('the notification token and auth_req_id are on the wire and in no rendering', async () => {
    const { oidc } = confidentialClient();
    const notification = random();
    const authReqId = random();
    const seen = bcAuthorize(() => HttpResponse.json({ auth_req_id: authReqId, expires_in: 120, interval: 5 }));
    const p = params({ delivery: { mode: 'ping', clientNotificationToken: new Sensitive(notification) } });
    assertNoFragment(renderings(p), notification, 'params');

    const response = await oidc.cibaInitiate(p);
    assertNoFragment(renderings(response), authReqId, 'response');
    expect(response.authReqId.expose() === authReqId, 'auth_req_id differs').toBe(true);
    expect(seen[0]!.form.get('client_notification_token') === notification, 'token not on the wire').toBe(true);

    server.resetHandlers();
    bcAuthorize(() => oauthError(400, 'invalid_binding_message'));
    const err = await oidc.cibaInitiate(p).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).errorDescription).toBe('invalid_binding_message here');
    assertNoFragment(errorRenderings(err), notification, 'error');
  });
});

// ── 2. Client authentication is mandatory ───────────────────────────────────

describe('§33.8 (2) — client authentication is mandatory', () => {
  it('no credential: AuthError and zero requests; with one: sent, tenant_id in the query only', async () => {
    const initiate = bcAuthorize(accepted());
    const polls = tokenScript([() => oauthError(400, 'authorization_pending')]);

    const { oidc: publicClient } = createClient();
    await expect(publicClient.cibaInitiate(params())).rejects.toBeInstanceOf(AuthError);
    await expect(
      publicClient.cibaPoll({ authReqId: new Sensitive(random()), configuration: discoveryDocument() }),
    ).rejects.toBeInstanceOf(AuthError);
    expect(initiate).toHaveLength(0);
    expect(polls).toHaveLength(0);

    const { oidc, secret } = confidentialClient();
    await oidc.cibaInitiate(params());
    await oidc.cibaPoll({ authReqId: new Sensitive(random()), configuration: discoveryDocument() }).catch(() => undefined);
    for (const seen of [initiate[0]!, polls[0]!]) {
      expect(seen.form.get('client_id')).toBe(CLIENT_ID);
      expect(seen.form.get('client_secret') === secret, 'client_secret not sent').toBe(true);
      expect(seen.form.has('tenant_id')).toBe(false);
      expect(seen.tenantQuery).toBe(TENANT_ID);
    }
    expect(polls[0]!.form.get('grant_type')).toBe(CIBA_GRANT_TYPE);

    // A tls_client_auth client: the certificate is the credential.
    const { oidc: mtls } = createClient({ mtls: true });
    await mtls.cibaInitiate(params());
    expect(initiate[1]!.form.get('client_id')).toBe(CLIENT_ID);
    expect(initiate[1]!.form.has('client_secret')).toBe(false);
  });

  it('§21.3.1: an mTLS call uses the seventh alias; a non-mTLS one the top-level endpoint', async () => {
    const top = bcAuthorize(accepted());
    const alias = bcAuthorize(accepted(), MTLS_BC_AUTHORIZE_ENDPOINT);
    const configuration: OidcConfiguration = discoveryDocument({ mtls_endpoint_aliases: mtlsEndpointAliases() });
    const { oidc: mtls } = createClient({ mtls: true });
    await mtls.cibaInitiate(params({ configuration }));
    const { oidc } = confidentialClient();
    await oidc.cibaInitiate(params({ configuration }));
    expect(alias.map((s) => s.url)).toEqual([MTLS_BC_AUTHORIZE_ENDPOINT]);
    expect(top.map((s) => s.url)).toEqual([BC_AUTHORIZE_ENDPOINT]);
    expect(alias[0]!.tenantQuery).toBe(TENANT_ID);
  });

  it('a server that advertises no CIBA endpoint is refused locally', async () => {
    const { oidc } = confidentialClient();
    const configuration = discoveryDocument();
    delete configuration.backchannel_authentication_endpoint;
    await expect(oidc.cibaInitiate(params({ configuration }))).rejects.toBeInstanceOf(AuthError);
  });
});

// ── 3. The initiate request ─────────────────────────────────────────────────

describe('§33.8 (3) — exactly the members set are sent', () => {
  it('minimal and full forms; both hints, neither, and ping without a token are refused locally', async () => {
    const { oidc } = confidentialClient();
    const seen = bcAuthorize(accepted());
    await oidc.cibaInitiate(params());
    const token = random();
    await oidc.cibaInitiate({
      scope: 'openid profile',
      idTokenHint: 'an.id.token',
      bindingMessage: 'W4SCT',
      requestedExpiry: 120,
      acrValues: 'urn:axiam:acr:mfa',
      resource: 'https://api.example.test',
      delivery: { mode: 'ping', clientNotificationToken: new Sensitive(token) },
      configuration: discoveryDocument(),
    });
    expect(keys(seen[0]!.form)).toEqual(['client_id', 'client_secret', 'login_hint', 'scope']);
    expect(keys(seen[1]!.form)).toEqual([
      'acr_values',
      'binding_message',
      'client_id',
      'client_notification_token',
      'client_secret',
      'id_token_hint',
      'requested_expiry',
      'resource',
      'scope',
    ]);
    expect(seen[1]!.form.get('requested_expiry')).toBe('120');
    expect(seen[1]!.form.get('client_notification_token') === token, 'token not sent').toBe(true);
    for (const forbidden of ['login_hint_token', 'user_code', 'request_uri', 'request']) {
      expect(seen[1]!.form.has(forbidden)).toBe(false);
    }

    const refusals: CibaInitiateParams[] = [
      { scope: 'openid', loginHint: 'a', idTokenHint: 'b', configuration: discoveryDocument() } as unknown as CibaInitiateParams,
      { scope: 'openid', configuration: discoveryDocument() } as unknown as CibaInitiateParams,
      params({ delivery: { mode: 'ping', clientNotificationToken: new Sensitive('') } }),
      params({ delivery: { mode: 'ping' } as never }),
    ];
    for (const p of refusals) {
      await expect(oidc.cibaInitiate(p)).rejects.toBeInstanceOf(ValidationError);
    }
    expect(seen).toHaveLength(2);
    // @ts-expect-error — both hints cannot be written.
    const both: CibaInitiateParams = { scope: 'openid', loginHint: 'a', idTokenHint: 'b' };
    // @ts-expect-error — there is no login_hint_token / user_code / request_uri parameter.
    const extra: CibaInitiateParams = { scope: 'openid', loginHint: 'a', userCode: 'x' };
    void both;
    void extra;
  });
});

// ── 4. No retry on initiate ─────────────────────────────────────────────────

describe('§33.8 (4) — initiate is sent once on 503, 429 and a dropped connection', () => {
  let listener: NetServer;
  let accepts = 0;
  beforeAll(async () => {
    listener = createNetServer((socket) => {
      accepts += 1;
      socket.destroy();
    });
    await new Promise<void>((resolve) => listener.listen(0, '127.0.0.1', resolve));
  });
  afterAll(() => new Promise<void>((resolve) => listener.close(() => resolve())));

  it('503 → NetworkError, 429 → OAuthProtocolError rate_limit_exceeded, one request each', async () => {
    const { oidc } = confidentialClient(); // retry enabled (the default)
    let seen = bcAuthorize(() => new HttpResponse(null, { status: 503 }));
    await expect(oidc.cibaInitiate(params())).rejects.toBeInstanceOf(NetworkError);
    expect(seen).toHaveLength(1);
    server.resetHandlers();
    seen = bcAuthorize(() => oauthError(429, 'rate_limit_exceeded'));
    const err = await oidc.cibaInitiate(params()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('rate_limit_exceeded');
    expect(seen).toHaveLength(1);
  });

  it('a dropped connection: NetworkError, exactly one connection', async () => {
    const { port } = listener.address() as AddressInfo;
    const endpoint = `http://127.0.0.1:${port}/oauth2/bc-authorize`;
    server.use(http.post(endpoint, () => passthrough()));
    const { oidc } = confidentialClient();
    const configuration = discoveryDocument({ backchannel_authentication_endpoint: endpoint });
    const err = await oidc.cibaInitiate(params({ configuration })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(accepts).toBe(1);
  });
});

// ── 5. Poll outcomes ────────────────────────────────────────────────────────

describe('§33.8 (5) — poll outcomes', () => {
  it('pending loops, slow_down persists (+5 s twice), then tokens', async () => {
    const { oidc } = confidentialClient();
    const tokens = await tokensWithIdToken();
    const clock = new TestClock();
    const seen = tokenScript(
      [
        () => oauthError(400, 'slow_down'),
        () => oauthError(400, 'slow_down'),
        () => oauthError(400, 'authorization_pending'),
        tokens,
      ],
      clock,
    );
    const id = random();
    const set = await oidc.cibaAwait(initiated(id, 600, 5, clock.start), {
      configuration: discoveryDocument(),
      clock,
    });
    expect(set.idClaims).toBeDefined();
    expect(clock.sleeps).toEqual([5, 10, 15, 15]);
    expect(seen.every((s) => s.form.get('grant_type') === CIBA_GRANT_TYPE && s.form.get('auth_req_id') === id)).toBe(
      true,
    );
  });

  it.each([
    ['access_denied', (e: unknown) => isAccessDenied(e) && !isExpiredToken(e)],
    ['expired_token', (e: unknown) => isExpiredToken(e) && !isAccessDenied(e)],
    ['invalid_grant', (e: unknown) => e instanceof OAuthProtocolError && e.error === 'invalid_grant'],
    ['a_code_nobody_defined', (e: unknown) => e instanceof AuthError && (e as OAuthProtocolError).error === 'a_code_nobody_defined'],
  ])('%s is terminal after one request', async (code, check) => {
    const { oidc } = confidentialClient();
    const clock = new TestClock();
    const seen = tokenScript([() => oauthError(400, code)], clock);
    const err = await oidc
      .cibaAwait(initiated(random(), 600, 5, clock.start), { configuration: discoveryDocument(), clock })
      .catch((e: unknown) => e);
    expect(check(err)).toBe(true);
    expect(seen).toHaveLength(1);
  });

  it('a bodiless 400 falls back to §2 and is terminal', async () => {
    const { oidc } = confidentialClient();
    const clock = new TestClock();
    const seen = tokenScript([() => new HttpResponse(null, { status: 400 })], clock);
    const err = await oidc
      .cibaAwait(initiated(random(), 600, 5, clock.start), { configuration: discoveryDocument(), clock })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(seen).toHaveLength(1);
  });
});

// ── 6. The first poll waits ─────────────────────────────────────────────────

describe('§33.8 (6) — the first poll waits the interval, or 5 s', () => {
  it.each([
    [7, 7],
    [undefined, 5],
    [0, 5],
  ])('interval %s → first poll at %s s', async (inResponse, expected) => {
    const { oidc } = confidentialClient();
    const clock = new TestClock();
    const body: Record<string, unknown> = { auth_req_id: random(), expires_in: 300 };
    if (inResponse !== undefined) body.interval = inResponse;
    bcAuthorize(() => HttpResponse.json(body));
    const seen = tokenScript([() => oauthError(400, 'access_denied')], clock);
    const response = await oidc.cibaInitiate(params());
    expect(response.interval).toBe(expected);
    response.receivedAt = clock.start;
    await oidc.cibaAwait(response, { configuration: discoveryDocument(), clock }).catch(() => undefined);
    expect(seen[0]!.at).toBe(expected);
  });
});

// ── 7. Deadline ─────────────────────────────────────────────────────────────

describe('§33.8 (7) — no request after expires_in; expired_token raised locally', () => {
  it('expires_in 12, interval 5: requests at 5 and 10 s, nothing at 15', async () => {
    const { oidc } = confidentialClient();
    const clock = new TestClock();
    const seen = tokenScript([() => oauthError(400, 'authorization_pending')], clock);
    const err = await oidc
      .cibaAwait(initiated(random(), 12, 5, clock.start), { configuration: discoveryDocument(), clock })
      .catch((e: unknown) => e);
    expect(isExpiredToken(err)).toBe(true);
    expect(seen.map((s) => s.at)).toEqual([5, 10]);
  });
});

// ── 8. Transient failure is not terminal ────────────────────────────────────

describe('§33.8 (8) — a 500 and a 429 mid-loop are survived', () => {
  it('then a 200 with id_token and access_token', async () => {
    const { oidc } = confidentialClient();
    const tokens = await tokensWithIdToken();
    const clock = new TestClock();
    const seen = tokenScript(
      [
        () => oauthError(400, 'authorization_pending'),
        // Contract 1.59 §34.2 P8: the 500 carries the body AXIAM's token
        // endpoint actually sends, and is transient whatever its body.
        () => HttpResponse.json({ error: 'server_error' }, { status: 500 }),
        () => oauthError(429, 'rate_limit_exceeded'),
        tokens,
      ],
      clock,
    );
    const set = await oidc.cibaAwait(initiated(random(), 600, 5, clock.start), {
      configuration: discoveryDocument(),
      clock,
    });
    expect(set.accessToken.expose().length).toBeGreaterThan(0);
    expect(set.idToken).toBeDefined();
    expect(set.idClaims).toBeDefined();
    expect(seen).toHaveLength(4);
  });

  it('a bodiless 429 and a 503 are retried inside one cibaPoll (§16)', async () => {
    const { oidc } = confidentialClient();
    const tokens = await tokensWithIdToken();
    const seen = tokenScript([
      () => new HttpResponse(null, { status: 429 }),
      () => new HttpResponse(null, { status: 503 }),
      tokens,
    ]);
    await oidc.cibaPoll({ authReqId: new Sensitive(random()), configuration: discoveryDocument() });
    expect(seen).toHaveLength(3);
  });

  it('a 500 and a 503 with an error member are retried inside one cibaPoll too (§34.2 P8)', async () => {
    const { oidc } = confidentialClient();
    const tokens = await tokensWithIdToken();
    const seen = tokenScript([
      () => HttpResponse.json({ error: 'server_error' }, { status: 500 }),
      () => HttpResponse.json({ error: 'temporarily_unavailable' }, { status: 503 }),
      tokens,
    ]);
    const outcome = await oidc.cibaPoll({ authReqId: new Sensitive(random()), configuration: discoveryDocument() });
    expect('error' in outcome && outcome.error !== undefined).toBe(false);
    expect(seen).toHaveLength(3);
  });
});

// ── 9. Single use ───────────────────────────────────────────────────────────

describe('§33.8 (9) — a second redemption is invalid_grant and not retried', () => {
  it('exactly two requests', async () => {
    const { oidc } = confidentialClient();
    const tokens = await tokensWithIdToken();
    const seen = tokenScript([tokens, () => oauthError(400, 'invalid_grant')]);
    const id = new Sensitive(random());
    await oidc.cibaPoll({ authReqId: id, configuration: discoveryDocument() });
    const err = await oidc.cibaPoll({ authReqId: id, configuration: discoveryDocument() }).catch((e: unknown) => e);
    expect((err as OAuthProtocolError).error).toBe('invalid_grant');
    expect(seen).toHaveLength(2);
  });
});

// ── 10–13. The ping ─────────────────────────────────────────────────────────

const pingHeaders = (...authorization: string[]): string[] => {
  const raw = ['Content-Type', 'application/json'];
  for (const a of authorization) raw.push('Authorization', a);
  return raw;
};

describe('§33.8 (10) — a valid ping returns its auth_req_id', () => {
  it('in any scheme case and any header shape, as Sensitive', () => {
    const { oidc } = confidentialClient();
    const token = random();
    const id = random();
    const body = JSON.stringify({ auth_req_id: id });
    const expected = new Sensitive(token);
    for (const scheme of ['Bearer', 'bearer', 'BEARER']) {
      const header = `${scheme} ${token}`;
      for (const headers of [
        pingHeaders(header),
        { authorization: header, 'content-type': 'application/json' },
        new Map([['Authorization', header]]),
      ]) {
        const got = oidc.cibaHandlePing(headers, body, expected);
        expect(got).toBeInstanceOf(Sensitive);
        expect(got.expose() === id, 'auth_req_id differs').toBe(true);
        assertNoFragment(renderings(got), id, 'ping result');
      }
    }
    expect(oidc.cibaHandlePing(pingHeaders(`Bearer ${token}`), Buffer.from(body), expected).expose() === id).toBe(true);
    expect(oidc.cibaHandlePing(pingHeaders(`Bearer ${token}`), { auth_req_id: id }, expected).expose() === id).toBe(true);
  });
});

describe('§33.8 (11) — a wrong, absent, empty, duplicated or Basic Authorization is refused', () => {
  it('AuthError naming no value; the comparison is crypto.timingSafeEqual', () => {
    const { oidc } = confidentialClient();
    const token = random();
    const lastDiffers = token.slice(0, -1) + (token.endsWith('a') ? 'b' : 'a');
    const body = JSON.stringify({ auth_req_id: random() });
    const expected = new Sensitive(token);
    const cases: string[][] = [
      pingHeaders(`Bearer ${random()}`),
      pingHeaders(),
      pingHeaders(''),
      pingHeaders('Bearer '),
      pingHeaders(`Bearer ${token}`, `Bearer ${token}`),
      pingHeaders(`Basic ${token}`),
      pingHeaders(`Bearer ${lastDiffers}`),
      pingHeaders(`Bearer  ${token}`),
      pingHeaders(`Bearer${token}`),
    ];
    for (const headers of cases) {
      let caught: unknown;
      try {
        oidc.cibaHandlePing(headers, body, expected);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(AuthError);
      assertNoFragment(errorRenderings(caught), token, 'ping refusal');
    }
    // An empty expected token never matches.
    expect(() => oidc.cibaHandlePing(pingHeaders('Bearer x'), body, new Sensitive(''))).toThrow(AuthError);
    // No timing harness here, so §33.8 test 11 is asserted structurally: the
    // token comparison is node:crypto's constant-time one.
    const source = readFileSync(new URL('../../src/node/oidc.ts', import.meta.url), 'utf8');
    expect(source.includes('return timingSafeEqual(presented, expected);')).toBe(true);
    expect(source.includes('if (!constantTimeEqual(token, expected)) throw refused();')).toBe(true);
  });
});

describe('§33.8 (12) — a malformed body is a ValidationError; extras are ignored', () => {
  it('not JSON, no auth_req_id, empty, not a string, not an object', () => {
    const { oidc } = confidentialClient();
    const token = random();
    const headers = pingHeaders(`Bearer ${token}`);
    const expected = new Sensitive(token);
    for (const body of [
      'not json',
      '{}',
      JSON.stringify({ auth_req_id: '' }),
      JSON.stringify({ auth_req_id: 42 }),
      JSON.stringify(['auth_req_id']),
      'null',
    ]) {
      expect(() => oidc.cibaHandlePing(headers, body, expected)).toThrow(ValidationError);
    }
    const id = random();
    const got = oidc.cibaHandlePing(
      headers,
      JSON.stringify({ auth_req_id: id, status: 'approved', access_token: 'x' }),
      expected,
    );
    expect(got.expose() === id).toBe(true);
  });
});

describe('§33.8 (13) — the ping helper makes no network call', () => {
  it('the mock records zero requests', () => {
    const { oidc } = confidentialClient();
    let requests = 0;
    const onRequest = (): void => {
      requests += 1;
    };
    server.events.on('request:start', onRequest);
    try {
      const token = random();
      oidc.cibaHandlePing(pingHeaders(`Bearer ${token}`), JSON.stringify({ auth_req_id: random() }), new Sensitive(token));
    } finally {
      server.events.removeListener('request:start', onRequest);
    }
    expect(requests).toBe(0);
  });
});

// ── 14–16. The signed form ──────────────────────────────────────────────────

function ed25519(): { pem: string; publicKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { pem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string, publicKey };
}

function p256(): { pem: string; publicKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { pem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string, publicKey };
}

describe('§33.8 (14) — the signed request is one member, under the registered alg, with a fresh jti', () => {
  it('EdDSA: exactly client auth + request; header alg/kid; verified claims; ES256 too', async () => {
    const { oidc, secret } = confidentialClient();
    const seen = bcAuthorize(accepted());
    const { pem, publicKey } = ed25519();
    const signer = await CibaRequestSigner.create('EdDSA', new Sensitive(pem), 'client-key-1');
    const notification = random();
    const p = params({
      bindingMessage: 'W4SCT',
      requestedExpiry: 90,
      delivery: { mode: 'ping', clientNotificationToken: new Sensitive(notification) },
      signer,
    });
    await oidc.cibaInitiate(p);
    await oidc.cibaInitiate(p);

    const jtis: string[] = [];
    for (const s of seen) {
      expect(keys(s.form)).toEqual(['client_id', 'client_secret', 'request']);
      expect(s.form.get('client_secret') === secret).toBe(true);
      const request = s.form.get('request')!;
      const header = decodeProtectedHeader(request);
      expect(header.alg).toBe('EdDSA');
      expect(header.kid).toBe('client-key-1');
      const { payload } = await jwtVerify(request, publicKey, { issuer: CLIENT_ID, audience: ISSUER });
      const exp = payload.exp!;
      const nbf = payload.nbf!;
      expect(typeof payload.iat).toBe('number');
      expect(exp - nbf <= 3600 && exp > nbf).toBe(true);
      expect(payload.login_hint).toBe('ada');
      expect(payload.scope).toBe('openid profile');
      expect(payload.binding_message).toBe('W4SCT');
      expect(payload.requested_expiry).toBe(90);
      expect(payload.client_notification_token === notification).toBe(true);
      expect(typeof payload.jti).toBe('string');
      expect((payload.jti as string).length).toBeGreaterThanOrEqual(32);
      jtis.push(payload.jti as string);
    }
    expect(jtis[0]).not.toBe(jtis[1]);

    const ec = p256();
    const es = await CibaRequestSigner.create('ES256', new Sensitive(ec.pem));
    expect(es.alg).toBe('ES256');
    await oidc.cibaInitiate(params({ signer: es }));
    const last = seen.at(-1)!.form.get('request')!;
    expect(decodeProtectedHeader(last).alg).toBe('ES256');
    await jwtVerify(last, ec.publicKey, { issuer: CLIENT_ID, audience: ISSUER });

    // A KeyObject works as well as a PEM.
    const { privateKey } = generateKeyPairSync('ed25519');
    expect((await CibaRequestSigner.create('EdDSA', privateKey)).alg).toBe('EdDSA');
  });
});

describe('§33.8 (15) — no key, no algorithm, or a key for another algorithm is refused before any request', () => {
  it('local ValidationError, zero requests', async () => {
    const seen = bcAuthorize(accepted());
    const ed = ed25519();
    const ec = p256();
    const { publicKey } = generateKeyPairSync('ed25519');
    const cases: Array<[string, unknown]> = [
      ['EdDSA', new Sensitive('')],
      ['ES256', new Sensitive(ed.pem)],
      ['PS256', new Sensitive(ec.pem)],
      ['EdDSA', new Sensitive(ec.pem)],
      ['RS256', new Sensitive(ed.pem)],
      [undefined as unknown as string, new Sensitive(ed.pem)],
      ['EdDSA', undefined],
      ['EdDSA', publicKey],
    ];
    for (const [alg, key] of cases) {
      await expect(CibaRequestSigner.create(alg as never, key as never)).rejects.toBeInstanceOf(ValidationError);
    }
    // With a signer, every member travels inside `request`: the parameters
    // offer no channel for another form parameter beside it (test 14 asserts
    // the form carries nothing else).
    expect(seen).toHaveLength(0);
  });
});

describe('§33.8 (16) — the key and the request appear in no rendering', () => {
  it('signer, params and the error raised', async () => {
    const { oidc } = confidentialClient();
    const seen = bcAuthorize(() => oauthError(400, 'invalid_request'));
    const { pem } = ed25519();
    const bodyLine = pem.split('\n')[1]!;
    const signer = await CibaRequestSigner.create('EdDSA', new Sensitive(pem));
    const p = params({ signer });
    const err = await oidc.cibaInitiate(p).catch((e: unknown) => e);
    const request = seen[0]!.form.get('request')!;
    for (const rendering of [renderings(signer), renderings(p), errorRenderings(err)]) {
      assertNoFragment(rendering, bodyLine, 'key');
      assertNoFragment(rendering, request, 'request');
    }
    expect(String(signer)).toBe('CibaRequestSigner(EdDSA)');
  });
});

describe('CIBA misc', () => {
  it('a malformed initiate or token response is a NetworkError, not retried', async () => {
    const { oidc } = confidentialClient();
    bcAuthorize(() => HttpResponse.json({ nope: true }));
    await expect(oidc.cibaInitiate(params())).rejects.toBeInstanceOf(NetworkError);
    const seen = tokenScript([() => HttpResponse.text('not json', { status: 200 })]);
    await expect(
      oidc.cibaPoll({ authReqId: new Sensitive(random()), configuration: discoveryDocument() }),
    ).rejects.toBeInstanceOf(NetworkError);
    expect(seen).toHaveLength(1);
  });

  it('a transport failure on poll is not terminal for cibaAwait', async () => {
    const { oidc } = createClient({ clientSecret: freshSecret() });
    const clock = new TestClock();
    let calls = 0;
    const tokens = await tokensWithIdToken();
    server.use(
      http.post(TOKEN_ENDPOINT, () => {
        calls += 1;
        return calls <= 3 ? HttpResponse.error() : tokens();
      }),
    );
    const set = await oidc.cibaAwait(initiated(random(), 600, 5, clock.start), {
      configuration: discoveryDocument(),
      clock,
    });
    expect(set.accessToken).toBeInstanceOf(Sensitive);
    expect(clock.sleeps).toEqual([5, 5]);
    void randomUUID;
  });
});
