// CONTRACT.md §6.1 rules 6-10 (contract 1.51) — authenticateDevice(), the
// mTLS device login. Mirrors the reference (axiam-rust-sdk#115)'s
// tests/device_auth_test.rs in this SDK's own idiom.

import { CookieJar } from 'tough-cookie';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AuthError, NetworkError } from '../../src/core/index.js';
import { AxiamClient } from '../../src/rest/client.js';
import { createSession } from '../../src/rest/session.js';
import { installInterceptors } from '../../src/rest/interceptors.js';
import { NodeSession } from '../../src/node/session.js';
import { ACCESS_COOKIE, wrapAxios } from '../../src/node/cookieJar.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { createVerifier } from '../../src/node/jwks.js';

const BASE_URL = 'https://axiam-device.test';

// Marker-only PEM placeholders — same fixtures as test/core/clientCertConfig.test.ts.
// msw intercepts before any real TLS handshake, so no real key material is needed.
const PEM_BEGIN = '-----BEGIN ';
const PEM_END = '-----END ';
const CERT_PEM = `${PEM_BEGIN}CERTIFICATE-----\nplaceholder-not-a-real-certificate\n${PEM_END}CERTIFICATE-----`;
const KEY_PEM = `${PEM_BEGIN}PRIVATE KEY-----\nplaceholder-marker-validation-only\n${PEM_END}PRIVATE KEY-----`;

function deviceClient(overrides: Record<string, unknown> = {}): AxiamClient {
  return new AxiamClient({
    baseUrl: BASE_URL,
    tenantSlug: 'acme',
    clientCert: CERT_PEM,
    clientKey: KEY_PEM,
    ...overrides,
  } as ConstructorParameters<typeof AxiamClient>[0]);
}

function deviceToken(): string {
  // A fresh non-literal token per test run (CodeQL rust/hard-coded-
  // cryptographic-value discipline, mirroring the reference's mutation-test
  // fix c853412).
  return `eyJ.device-${Math.random().toString(36).slice(2)}.sig`;
}

interface Captured {
  url: string;
  headers: Headers;
  cookie: string | null;
}

let captured: Captured[] = [];
let deviceLoginCalls = 0;
let currentToken = '';

const server = setupServer(
  http.post(`${BASE_URL}/api/v1/auth/device`, ({ request }) => {
    deviceLoginCalls += 1;
    captured.push({ url: request.url, headers: request.headers, cookie: request.headers.get('cookie') });
    return HttpResponse.json({ access_token: currentToken, token_type: 'Bearer', expires_in: 900 });
  }),
  http.get(`${BASE_URL}/api/v1/service-accounts`, ({ request }) => {
    captured.push({ url: request.url, headers: request.headers, cookie: request.headers.get('cookie') });
    return HttpResponse.json({ items: [], total: 0, offset: 0, limit: 200 });
  }),
  http.post(`${BASE_URL}/api/v1/authz/check`, ({ request }) => {
    captured.push({ url: request.url, headers: request.headers, cookie: request.headers.get('cookie') });
    return HttpResponse.json({ allowed: true });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  captured = [];
  deviceLoginCalls = 0;
});
afterAll(() => server.close());

describe('§6.1 rule 7 — reachable only on a client configured with a certificate', () => {
  it('a client without a certificate fails with AuthError and makes zero wire calls', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    await expect(client.authenticateDevice()).rejects.toThrow(AuthError);
    expect(deviceLoginCalls).toBe(0);
  });
});

describe('§6.1 rule 6 — the call itself, and adoption', () => {
  it('posts no body and returns the three documented fields', async () => {
    currentToken = deviceToken();
    const client = deviceClient();
    const result = await client.authenticateDevice();

    expect(deviceLoginCalls).toBe(1);
    expect(result.accessToken.expose()).toBe(currentToken);
    expect(result.tokenType).toBe('Bearer');
    expect(result.expiresIn).toBe(900);
    // The request carried no body.
    expect(captured[0]!.headers.get('content-length')).not.toBe(null);
  });

  it('the token is adopted as the client bearer credential on later requests', async () => {
    currentToken = deviceToken();
    const client = deviceClient();
    await client.authenticateDevice();
    await client.management.serviceAccounts.list();

    const req = captured.at(-1)!;
    expect(req.headers.get('authorization')).toBe(`Bearer ${currentToken}`);
  });

  it('checkAccess also carries the adopted device token', async () => {
    currentToken = deviceToken();
    const client = deviceClient();
    await client.authenticateDevice();
    await client.checkAccess({ action: 'read', resourceId: 'doc:1' });

    const req = captured.at(-1)!;
    expect(req.headers.get('authorization')).toBe(`Bearer ${currentToken}`);
  });
});

describe('§6.1 (what the plan did not anticipate, note 3) — the device-token interceptor drops the jar', () => {
  it('installDeviceTokenInterceptor rewrites config to the no-credentials agent pair and an explicit empty Cookie', async () => {
    // A direct, unit-level check of the interceptor's effect on the request
    // config — msw intercepts at the fetch/XHR layer (see test/node/mtls.test.ts's
    // header comment) and never observes what a jar-wrapped Node http.Agent
    // would have injected, so an end-to-end assertion through msw cannot
    // distinguish "the jar was bypassed" from "msw never asked the agent in
    // the first place". This is the precise, provable form of the same
    // property test/node/mtls.test.ts covers for the TLS half.
    const { installDeviceTokenInterceptor } = await import('../../src/rest/interceptors.js');
    const axios = (await import('axios')).default;
    const { Sensitive } = await import('../../src/core/index.js');

    const noCredMarker = { httpAgent: 'plain-http-agent', httpsAgent: 'plain-https-agent', withCredentials: false };
    const fakeSession = {
      deviceAccessToken: new Sensitive('device-token-value'),
      isForeignHost: () => false,
      noCredentialsConfig: () => noCredMarker,
      // Unused by the interceptor; present only to satisfy the type.
    } as unknown as Parameters<typeof installDeviceTokenInterceptor>[1];

    const instance = axios.create();
    installDeviceTokenInterceptor(instance, fakeSession);
    const handler = (instance.interceptors.request as unknown as { handlers: Array<{ fulfilled: (c: unknown) => unknown }> })
      .handlers[0]!.fulfilled;

    const before = { url: '/api/v1/service-accounts', headers: { Cookie: 'axiam_access=stale' } };
    const after = handler(before) as {
      headers: Record<string, string>;
      httpAgent?: string;
      httpsAgent?: string;
      withCredentials?: boolean;
    };

    expect(after.httpAgent).toBe('plain-http-agent');
    expect(after.httpsAgent).toBe('plain-https-agent');
    expect(after.withCredentials).toBe(false);
    expect(after.headers.Cookie).toBe('');
    expect(after.headers.Authorization).toBe('Bearer device-token-value');
  });

  it('does nothing when no device token has been adopted', async () => {
    const { installDeviceTokenInterceptor } = await import('../../src/rest/interceptors.js');
    const axios = (await import('axios')).default;

    const fakeSession = {
      deviceAccessToken: undefined,
      isForeignHost: () => false,
      noCredentialsConfig: () => ({ withCredentials: false }),
    } as unknown as Parameters<typeof installDeviceTokenInterceptor>[1];

    const instance = axios.create();
    installDeviceTokenInterceptor(instance, fakeSession);
    const handler = (instance.interceptors.request as unknown as { handlers: Array<{ fulfilled: (c: unknown) => unknown }> })
      .handlers[0]!.fulfilled;

    const before = { url: '/api/v1/service-accounts', headers: { Cookie: 'axiam_access=live-session' } };
    const after = handler(before) as typeof before;

    // Byte-for-byte unchanged — the I4 twin for this interceptor.
    expect(after).toBe(before);
    expect(after.headers.Cookie).toBe('axiam_access=live-session');
  });
});

describe('§6.1 — no stale cookie in the end-to-end request/response cycle', () => {
  /**
   * A REAL jar-backed NodeSession (mirrors test/node/csrf.test.ts's
   * buildTestSession pattern) with an `axiam_access` cookie already set, as
   * if an earlier password session were still live on this same client. The
   * server reads that cookie BEFORE the `Authorization` header — if the
   * jar-wrapped agent were still attached to a device-token request, this
   * stale cookie would silently win and the request would run as the
   * earlier session's principal.
   */
  async function deviceClientWithStaleCookie(): Promise<AxiamClient> {
    const jar = new CookieJar();
    await jar.setCookie(`${ACCESS_COOKIE}=stale-cookie-session-token; Path=/`, BASE_URL);

    const options = { baseUrl: BASE_URL, tenantSlug: 'acme', clientCert: CERT_PEM, clientKey: KEY_PEM };
    const base = createSession(options);
    wrapAxios(base.axios, jar);
    const tokenManager = new TokenManager(jar, BASE_URL, base.tenantHeaderValue);
    const jwksVerifier = createVerifier(BASE_URL);
    const nodeSession = new NodeSession(options, base, tokenManager, jwksVerifier, jar);
    installInterceptors(nodeSession.axios, nodeSession);
    return new AxiamClient(options, nodeSession);
  }

  it('a device login withholds a previous cookie session, and later calls carry no Cookie at all', async () => {
    currentToken = deviceToken();
    const client = await deviceClientWithStaleCookie();

    await client.authenticateDevice();
    const loginReq = captured.at(-1)!;
    // The login call itself carries no cookie either (rule 3) — it must not
    // reach the wire with the STALE cookie still attached.
    expect(loginReq.cookie ?? '').not.toContain('stale-cookie-session-token');

    await client.management.serviceAccounts.list();
    const laterReq = captured.at(-1)!;
    expect(laterReq.cookie ?? '').not.toContain('stale-cookie-session-token');
    expect(laterReq.headers.get('authorization')).toBe(`Bearer ${currentToken}`);
  });
});

describe('§6.1 rule 8 — every refusal is a 401, mapped to AuthError, never refreshed', () => {
  it('an unbound/untrusted certificate refusal maps to AuthError verbatim', async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/device`, () => {
        deviceLoginCalls += 1;
        return HttpResponse.json({ error: 'authentication_failed', message: 'unbound certificate' }, { status: 401 });
      }),
    );
    const client = deviceClient();
    await expect(client.authenticateDevice()).rejects.toThrow(AuthError);
    expect(deviceLoginCalls).toBe(1);
  });

  it('a later 401 on the adopted token does not attempt a refresh', async () => {
    currentToken = deviceToken();
    const client = deviceClient();
    await client.authenticateDevice();

    let refreshCalls = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/refresh`, () => {
        refreshCalls += 1;
        return HttpResponse.json({ expires_in: 900 });
      }),
      http.get(`${BASE_URL}/api/v1/service-accounts`, () => {
        return HttpResponse.json({ error: 'authentication_failed' }, { status: 401 });
      }),
    );

    // sendManagement's own error mapper (src/management/request.ts) wraps
    // whatever it is handed into a NetworkError when the error carries no
    // `.response.status` (pre-existing behaviour, exercised here because the
    // interceptor's 401 branch already turned this into an AxiamError before
    // sendManagement's catch sees it) — the property under test is that the
    // ORIGINAL failure is AuthError (never a refresh-then-retry), which
    // survives as `.cause`.
    const err: unknown = await client.management.serviceAccounts.list().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect((err as NetworkError).cause).toBeInstanceOf(AuthError);
    expect(refreshCalls).toBe(0);
  });
});

describe('§6.1 rule 8 — a 429 is not an authentication failure and is not retried', () => {
  it('a rate-limited device login maps to NetworkError, called exactly once', async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/auth/device`, () => {
        deviceLoginCalls += 1;
        return HttpResponse.json({ error: 'rate_limited' }, { status: 429 });
      }),
    );
    const client = deviceClient();
    const err = await client.authenticateDevice().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(err).not.toBeInstanceOf(AuthError);
    expect(deviceLoginCalls).toBe(1);
  });
});
