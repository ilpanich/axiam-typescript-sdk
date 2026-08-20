// The OPAQUE HTTP paths (CONTRACT.md §23) — rest/opaque.ts.
//
// The protocol itself is `@axiam/opaque-wasm`'s and is proven in the AXIAM
// repository; `core/opaque.test.ts` covers the loader. What is left, and what
// this file asserts, is the layer this SDK actually owns: which endpoint, what
// body, and what a failure means.
//
// The WASM module is injected rather than `vi.mock`ed, because `core/opaque.ts`
// resolves it through a runtime specifier so an installation without the
// optional peer still loads — which also puts it out of `vi.mock`'s reach.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { AxiamClient } from '../../src/rest/client.js';
import { AuthError, NetworkError } from '../../src/core/index.js';
import {
  __resetOpaqueModuleForTests,
  __setOpaqueModuleForTests,
} from '../../src/core/opaque.js';

const BASE_URL = 'https://axiam-opaque.test';
const REGISTER_START = `${BASE_URL}/api/v1/auth/opaque/register/start`;
const LOGIN_START = `${BASE_URL}/api/v1/auth/opaque/login/start`;
const LOGIN_FINISH = `${BASE_URL}/api/v1/auth/opaque/login/finish`;

const PASSWORD = 'correct horse battery staple';

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  __resetOpaqueModuleForTests();
});
afterAll(() => server.close());

/** Fails the exchange for anything but PASSWORD, so the AuthError path is real. */
function installModule() {
  __setOpaqueModuleForTests({
    default: vi.fn(async () => undefined),
    opaqueAvailable: () => true,
    OpaqueKsf: {
      argon2id: () => ({ kind: 'argon2id' }),
      scrypt: () => ({ kind: 'scrypt' }),
    },
    OpaqueLogin: class {
      ke1 = 'aa'.repeat(96);
      constructor(private readonly password: string) {}
      finish(password: string) {
        if (password !== PASSWORD) throw new Error('envelope did not open');
        return { ke3: 'bb'.repeat(64), sessionKey: 'cc'.repeat(64), exportKey: 'dd'.repeat(64) };
      }
    },
    OpaqueRegistration: class {
      request = 'ee'.repeat(32);
      constructor(_password: string) {}
      finish() {
        return { record: 'ff'.repeat(192), exportKey: 'dd'.repeat(64) };
      }
    },
  });
}

beforeEach(() => {
  installModule();
});

function client(): AxiamClient {
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
}

const KSF_FIELDS = { ksf: 'argon2id', memory_kib: 8192, iterations: 1, parallelism: 1 };

function loginStartOk() {
  return http.post(LOGIN_START, () =>
    HttpResponse.json({
      opaque_session: 'sealed-login-session',
      ke2: '12'.repeat(320),
      suite: 'ristretto255_sha512',
      ...KSF_FIELDS,
    }),
  );
}

function registerStartOk() {
  return http.post(REGISTER_START, () =>
    HttpResponse.json({
      opaque_session: 'sealed-registration-session',
      registration_response: '34'.repeat(64),
      suite: 'ristretto255_sha512',
      ...KSF_FIELDS,
    }),
  );
}

describe('loginOpaque', () => {
  it('signs in and never puts the password on the wire', async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post(LOGIN_START, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({
          opaque_session: 'sealed-login-session',
          ke2: '12'.repeat(320),
          suite: 'ristretto255_sha512',
          ...KSF_FIELDS,
        });
      }),
      http.post(LOGIN_FINISH, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({
          user: { id: 'u1', username: 'alice', email: 'alice@example.com' },
          session_id: 's1',
          expires_in: 900,
        });
      }),
    );

    const result = await client().loginOpaque('alice', PASSWORD);
    expect(result.status).toBe('authenticated');

    // The property the whole protocol exists for, asserted over what the
    // server actually received rather than by reading the code.
    for (const body of bodies) {
      expect(JSON.stringify(body)).not.toContain(PASSWORD);
    }
    // And no stray `password` key from the shared login-body builder.
    expect(bodies[0]).not.toHaveProperty('password');
  });

  it('returns the same mfa_required shape the password path returns', async () => {
    server.use(
      loginStartOk(),
      http.post(LOGIN_FINISH, () =>
        HttpResponse.json(
          { challenge_token: 'chal-1', available_methods: ['totp'] },
          { status: 202 },
        ),
      ),
    );

    const result = await client().loginOpaque('alice', PASSWORD);
    expect(result).toMatchObject({
      status: 'mfa_required',
      mfaToken: 'chal-1',
      availableMethods: ['totp'],
    });
  });

  it('reports a disabled tenant as NetworkError, not AuthError', async () => {
    // Reporting this as a credential failure would send a user off to reset a
    // password that works, and would stop a caller falling back to login().
    server.use(http.post(LOGIN_START, () => new HttpResponse(null, { status: 404 })));

    await expect(client().loginOpaque('alice', PASSWORD)).rejects.toBeInstanceOf(NetworkError);
    await expect(client().loginOpaque('alice', PASSWORD)).rejects.toThrow(/use login\(\) instead/);
  });

  it('never reaches login/finish when the envelope fails', async () => {
    // §23.4 rule 7. Sending a KE3 the client could not derive would be sending
    // junk, and would leak that this client got that far.
    let finishCalls = 0;
    server.use(
      loginStartOk(),
      http.post(LOGIN_FINISH, () => {
        finishCalls += 1;
        return HttpResponse.json({});
      }),
    );

    await expect(client().loginOpaque('alice', 'the-wrong-password')).rejects.toBeInstanceOf(
      AuthError,
    );
    expect(finishCalls).toBe(0);
  });

  it('lets an unknown KSF propagate as NetworkError rather than a wrong password', async () => {
    let finishCalls = 0;
    server.use(
      http.post(LOGIN_START, () =>
        HttpResponse.json({
          opaque_session: 's',
          ke2: '12'.repeat(320),
          suite: 'ristretto255_sha512',
          ksf: 'bcrypt',
        }),
      ),
      http.post(LOGIN_FINISH, () => {
        finishCalls += 1;
        return HttpResponse.json({});
      }),
    );

    await expect(client().loginOpaque('alice', PASSWORD)).rejects.toThrow(/bcrypt/);
    await expect(client().loginOpaque('alice', PASSWORD)).rejects.toBeInstanceOf(NetworkError);
    expect(finishCalls).toBe(0);
  });

  it('maps a non-404 error from login/start through the shared taxonomy', async () => {
    server.use(http.post(LOGIN_START, () => new HttpResponse(null, { status: 500 })));

    await expect(client().loginOpaque('alice', PASSWORD)).rejects.toBeInstanceOf(Error);
    await expect(client().loginOpaque('alice', PASSWORD)).rejects.not.toThrow(
      /use login\(\) instead/,
    );
  });

  it('maps an error status from login/finish', async () => {
    server.use(
      loginStartOk(),
      http.post(LOGIN_FINISH, () => new HttpResponse(null, { status: 401 })),
    );

    await expect(client().loginOpaque('alice', PASSWORD)).rejects.toBeInstanceOf(Error);
  });

  it('refuses a closed client (§18.1 rule 4)', async () => {
    const c = client();
    await c.close();
    await expect(c.loginOpaque('alice', PASSWORD)).rejects.toBeInstanceOf(Error);
  });
});

describe('opaqueEnrollment', () => {
  it('produces a two-field record and echoes the session verbatim', async () => {
    server.use(registerStartOk());

    const enrollment = await client().opaqueEnrollment(PASSWORD);
    expect(enrollment).toEqual({
      opaque_session: 'sealed-registration-session',
      registration_record: 'ff'.repeat(192),
    });
  });

  it('sends the workspace but neither a username nor a password', async () => {
    // There is no identity argument by design: the record binds to a
    // credential identifier the server chooses.
    let body: Record<string, unknown> = {};
    server.use(
      http.post(REGISTER_START, async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({
          opaque_session: 's',
          registration_response: '34'.repeat(64),
          suite: 'ristretto255_sha512',
          ...KSF_FIELDS,
        });
      }),
    );

    await client().opaqueEnrollment(PASSWORD);

    expect(body).toHaveProperty('tenant_slug', 'acme');
    expect(body).toHaveProperty('registration_request');
    expect(body).not.toHaveProperty('password');
    expect(body).not.toHaveProperty('username_or_email');
    expect(JSON.stringify(body)).not.toContain(PASSWORD);
  });

  it('reports a disabled tenant as NetworkError', async () => {
    server.use(http.post(REGISTER_START, () => new HttpResponse(null, { status: 404 })));
    await expect(client().opaqueEnrollment(PASSWORD)).rejects.toBeInstanceOf(NetworkError);
  });

  it('maps a non-404 error through the shared taxonomy', async () => {
    server.use(http.post(REGISTER_START, () => new HttpResponse(null, { status: 403 })));
    await expect(client().opaqueEnrollment(PASSWORD)).rejects.toBeInstanceOf(Error);
  });

  it('refuses an unknown KSF on the path that writes a credential', async () => {
    // The same rule as on login, on the path that actually stores something:
    // enrolling under a substituted KSF would write a record the server can
    // never open.
    server.use(
      http.post(REGISTER_START, () =>
        HttpResponse.json({
          opaque_session: 's',
          registration_response: '34'.repeat(64),
          suite: 'ristretto255_sha512',
          ksf: 'bcrypt',
        }),
      ),
    );

    await expect(client().opaqueEnrollment(PASSWORD)).rejects.toThrow(/bcrypt/);
  });

  it('refuses a closed client', async () => {
    const c = client();
    await c.close();
    await expect(c.opaqueEnrollment(PASSWORD)).rejects.toBeInstanceOf(Error);
  });
});

describe('opaqueAvailable', () => {
  it('is true when the module is present', async () => {
    await expect(client().opaqueAvailable()).resolves.toBe(true);
  });

  it('is false when the optional peer is absent', async () => {
    __resetOpaqueModuleForTests();
    await expect(client().opaqueAvailable()).resolves.toBe(false);
  });
});
