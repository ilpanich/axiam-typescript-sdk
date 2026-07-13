// Error/edge branches of rest/auth.ts (login/verifyMfa/refresh/logout):
// HTTP-status -> taxonomy mapping (401 AuthError, 403 AuthzError), the
// NetworkError path when no response arrives, refresh() success, and
// logout()'s finally-clears-state guarantee. Complements login.test.ts,
// which only covers the happy 200/202 branches.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';
import { AuthError, AuthzError, NetworkError } from '../../src/core/index.js';

const BASE_URL = 'https://axiam-auth-errors.test';

const LOGIN = `${BASE_URL}/api/v1/auth/login`;
const MFA = `${BASE_URL}/api/v1/auth/mfa/verify`;
const REFRESH = `${BASE_URL}/api/v1/auth/refresh`;
const LOGOUT = `${BASE_URL}/api/v1/auth/logout`;

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function client(): AxiamClient {
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
}

describe('login() error branches', () => {
  // /auth/login is a SKIP_REFRESH url: the response interceptor pre-maps a
  // 401 to AuthError, which auth.ts (finding no axios `.response` on the
  // already-mapped error) then re-wraps as NetworkError('login request
  // failed'). 403/5xx are passed through raw and mapped by auth.ts itself.
  it('re-wraps a 401 (pre-mapped by the interceptor) as NetworkError', async () => {
    server.use(
      http.post(LOGIN, () => HttpResponse.json({ message: 'bad creds' }, { status: 401 })),
    );
    const err = await client().login('a@example.com', 'wrong').catch((e) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.message).toBe('login request failed');
  });

  it('maps a 403 response to AuthzError', async () => {
    server.use(http.post(LOGIN, () => HttpResponse.json({ message: 'denied' }, { status: 403 })));
    await expect(client().login('a@example.com', 'x')).rejects.toBeInstanceOf(AuthzError);
  });

  it('surfaces the server message on a mapped (403) error', async () => {
    server.use(
      http.post(LOGIN, () => HttpResponse.json({ message: 'account locked' }, { status: 403 })),
    );
    await expect(client().login('a@example.com', 'x')).rejects.toThrow('account locked');
  });

  it('wraps a transport failure (no response) in NetworkError', async () => {
    server.use(http.post(LOGIN, () => HttpResponse.error()));
    const err = await client()
      .login('a@example.com', 'x')
      .catch((e) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.message).toBe('login request failed');
  });
});

describe('verifyMfa() error branches', () => {
  it('maps a 401 response to AuthError', async () => {
    server.use(http.post(MFA, () => HttpResponse.json({ message: 'bad code' }, { status: 401 })));
    await expect(client().verifyMfa('challenge', '000000')).rejects.toBeInstanceOf(AuthError);
  });

  it('wraps a transport failure in NetworkError', async () => {
    server.use(http.post(MFA, () => HttpResponse.error()));
    const err = await client()
      .verifyMfa('challenge', '000000')
      .catch((e) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.message).toBe('verifyMfa request failed');
  });
});

describe('refresh()', () => {
  it('resolves on a 200 response', async () => {
    server.use(http.post(REFRESH, () => HttpResponse.json({ expires_in: 900 }, { status: 200 })));
    await expect(client().refresh()).resolves.toBeUndefined();
  });

  it('re-wraps a 401 on the refresh call (pre-mapped by the interceptor) as NetworkError', async () => {
    // /auth/refresh is a SKIP_REFRESH url — no retry loop; the interceptor
    // pre-maps the 401 and auth.ts re-wraps it as NetworkError.
    server.use(http.post(REFRESH, () => HttpResponse.json({}, { status: 401 })));
    const err = await client().refresh().catch((e) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.message).toBe('refresh request failed');
  });

  it('wraps a transport failure in NetworkError', async () => {
    server.use(http.post(REFRESH, () => HttpResponse.error()));
    const err = await client()
      .refresh()
      .catch((e) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.message).toBe('refresh request failed');
  });
});

describe('logout()', () => {
  it('clears auth + csrf state on a successful logout', async () => {
    server.use(http.post(LOGOUT, () => HttpResponse.json({}, { status: 204 })));
    const c = client();
    c.session.authenticated = true;
    c.session.csrfToken = 'csrf-abc';

    await c.logout();

    expect(c.session.authenticated).toBe(false);
    expect(c.session.csrfToken).toBeUndefined();
  });

  it('still clears state (finally) even when the request errors', async () => {
    server.use(http.post(LOGOUT, () => HttpResponse.json({ message: 'boom' }, { status: 500 })));
    const c = client();
    c.session.authenticated = true;
    c.session.csrfToken = 'csrf-abc';

    await expect(c.logout()).rejects.toBeInstanceOf(NetworkError);

    expect(c.session.authenticated).toBe(false);
    expect(c.session.csrfToken).toBeUndefined();
  });

  it('wraps a transport failure in NetworkError and clears state', async () => {
    server.use(http.post(LOGOUT, () => HttpResponse.error()));
    const c = client();
    c.session.authenticated = true;

    const err = await c.logout().catch((e) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.message).toBe('logout request failed');
    expect(c.session.authenticated).toBe(false);
  });
});
