// §25 account lifecycle and MFA enrolment — the CONTRACT.md §25.6 test set.
//
// The assertion worth reading is `keeps the secret out of every serialization
// surface`: it scans for the secret *value*, not the field name, which is what
// catches `totp_uri` — the field that actually reaches a log, because it is the
// one a caller passes to a QR renderer, and the one that silently contains the
// secret it sits next to.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';
import { AuthError, AuthzError, Sensitive } from '../../src/rest/index.js';

const BASE_URL = 'https://axiam.test';
const A = '/api/v1/auth';

const SECRET = 'JBSWY3DPEHPK3PXPSECRETVALUE';
const TOTP_URI = `otpauth://totp/AXIAM:alice@example.com?secret=${SECRET}&issuer=AXIAM`;
const SETUP_TOKEN = 'setup-token-value-do-not-log';
const RESET_TOKEN = 'reset-token-value-do-not-log';

let sent: Array<{ path: string; body: unknown; url: string }> = [];
let hits: Record<string, number> = {};
/** Swapped per test — the `login` handler's answer. */
let loginResponse: () => Response;

const enrollBody = { secret_base32: SECRET, totp_uri: TOTP_URI };

const server = setupServer(
  http.post(`${BASE_URL}${A}/login`, () => {
    hits.login = (hits.login ?? 0) + 1;
    return loginResponse();
  }),
  http.post(`${BASE_URL}${A}/mfa/enroll`, () => HttpResponse.json(enrollBody)),
  http.post(`${BASE_URL}${A}/mfa/confirm`, async ({ request }) => {
    const body = (await request.json()) as { totp_code: string };
    if (body.totp_code !== '123456') {
      return HttpResponse.json({ message: 'invalid code' }, { status: 401 });
    }
    return HttpResponse.json({ mfa_enabled: true });
  }),
  http.post(`${BASE_URL}${A}/mfa/setup/enroll`, async ({ request }) => {
    sent.push({ path: 'setup/enroll', body: await request.json(), url: request.url });
    return HttpResponse.json(enrollBody);
  }),
  http.post(`${BASE_URL}${A}/mfa/setup/confirm`, async ({ request }) => {
    sent.push({ path: 'setup/confirm', body: await request.json(), url: request.url });
    return HttpResponse.json({
      user: { id: 'u1', username: 'alice', email: 'alice@example.com' },
      session_id: 's1',
      expires_in: 900,
    });
  }),
  http.post(`${BASE_URL}${A}/verify-email`, async ({ request }) => {
    sent.push({ path: 'verify-email', body: await request.json(), url: request.url });
    return new HttpResponse(null, { status: 200 });
  }),
  http.post(`${BASE_URL}${A}/resend-verification`, async ({ request }) => {
    sent.push({ path: 'resend-verification', body: await request.json(), url: request.url });
    return new HttpResponse(null, { status: 200 });
  }),
  http.post(`${BASE_URL}${A}/reset`, async ({ request }) => {
    // Uniform 200 whether or not the address exists — the whole point.
    sent.push({ path: 'reset', body: await request.json(), url: request.url });
    return new HttpResponse(null, { status: 200 });
  }),
  http.post(`${BASE_URL}${A}/reset/confirm`, async ({ request }) => {
    sent.push({ path: 'reset/confirm', body: await request.json(), url: request.url });
    return new HttpResponse(null, { status: 200 });
  }),
  http.get(`${BASE_URL}${A}/reset/context`, ({ request }) => {
    sent.push({ path: 'reset/context', body: null, url: request.url });
    const token = new URL(request.url).searchParams.get('token');
    if (token !== RESET_TOKEN) return new HttpResponse(null, { status: 404 });
    return HttpResponse.json({ opaque: { mode: 'required', ksf: 'argon2id' } });
  }),
  http.post(`${BASE_URL}/api/v1/authz/check`, () => HttpResponse.json({ allowed: true })),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
beforeEach(() => {
  sent = [];
  hits = {};
  loginResponse = () =>
    HttpResponse.json(
      { mfa_setup_required: true, setup_token: SETUP_TOKEN },
      { status: 403 },
    );
});

function client(opts: Record<string, unknown> = {}): AxiamClient {
  return new AxiamClient({
    baseUrl: BASE_URL,
    tenantSlug: 'acme',
    orgSlug: 'globex',
    ...opts,
  } as never);
}

function bodyOf(path: string): Record<string, unknown> {
  const entry = sent.find((s) => s.path === path);
  expect(entry, `no request captured for ${path}`).toBeDefined();
  return entry!.body as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// §25.2 rule 1 — login's third outcome (the breaking change)
// ---------------------------------------------------------------------------

describe('§25.2 rule 1 — the mfa_setup_required outcome', () => {
  it('returns the setup branch rather than raising AuthzError', async () => {
    const result = await client().login('alice@example.com', 'pw');

    expect(result.status).toBe('mfa_setup_required');
    if (result.status !== 'mfa_setup_required') throw new Error('unreachable');
    expect(result.setupToken.expose()).toBe(SETUP_TOKEN);
  });

  it('still raises AuthzError for a 403 that is a genuine refusal', async () => {
    // Matched on the body's discriminant, not on the status: a real
    // authorization failure is also a 403 and must not be read as a setup
    // branch just because it shares a status code.
    loginResponse = () => HttpResponse.json({ message: 'tenant suspended' }, { status: 403 });
    await expect(client().login('alice@example.com', 'pw')).rejects.toBeInstanceOf(AuthzError);
  });

  it('does not leak the setup token through the result’s serialization', async () => {
    const result = await client().login('alice@example.com', 'pw');
    expect(JSON.stringify(result)).not.toContain(SETUP_TOKEN);
  });
});

// ---------------------------------------------------------------------------
// §25.2 — the two enrolment paths
// ---------------------------------------------------------------------------

describe('§25 MFA enrolment', () => {
  it('returns the secret and the URI from mfaEnroll', async () => {
    const enrolment = await client().mfaEnroll();
    expect(enrolment.secretBase32.expose()).toBe(SECRET);
    expect(enrolment.totpUri.expose()).toBe(TOTP_URI);
    expect(enrolment.totpUri.expose()).toContain(SECRET);
  });

  it('keeps the secret out of every serialization surface — scanned by value', async () => {
    const enrolment = await client().mfaEnroll();
    const surfaces = [
      JSON.stringify(enrolment),
      String(enrolment.secretBase32),
      String(enrolment.totpUri),
      `${enrolment.secretBase32}`,
      `${enrolment.totpUri}`,
    ].join('|');
    // Scanning for the VALUE, not the field name. `totp_uri` contains the
    // secret, so an SDK that wrapped only `secret_base32` fails right here.
    expect(surfaces).not.toContain(SECRET);
  });

  it('activates the factor on a correct code', async () => {
    await expect(client().mfaConfirm('123456')).resolves.toBe(true);
  });

  it('raises AuthError on a wrong code', async () => {
    await expect(client().mfaConfirm('000000')).rejects.toBeInstanceOf(AuthError);
  });

  it('does NOT clear the decision memo on mfaEnroll — the subject is unchanged', async () => {
    const c = client({ decisionMemoTtlMs: 60_000 });
    c.session.authenticated = true;
    await c.checkAccess({ action: 'read', resourceId: 'doc:1' });
    const before = c.decisionMemo.size;
    expect(before).toBeGreaterThan(0);

    await c.mfaEnroll();
    expect(c.decisionMemo.size).toBe(before);
  });

  it('DOES clear it on mfaSetupConfirm — that one completes a login', async () => {
    const c = client({ decisionMemoTtlMs: 60_000 });
    c.session.authenticated = true;
    await c.checkAccess({ action: 'read', resourceId: 'doc:1' });
    expect(c.decisionMemo.size).toBeGreaterThan(0);

    await c.mfaSetupConfirm(SETUP_TOKEN, '123456');
    expect(c.decisionMemo.size).toBe(0);
  });

  it('leaves the client authenticated after mfaSetupConfirm', async () => {
    const c = client();
    const result = await c.mfaSetupConfirm(new Sensitive(SETUP_TOKEN), '123456');

    expect(c.session.authenticated).toBe(true);
    expect(result.status).toBe('authenticated');
    expect(bodyOf('setup/confirm')).toEqual({ setup_token: SETUP_TOKEN, totp_code: '123456' });
  });

  it('drives the forced path end to end from the login outcome', async () => {
    const c = client();
    const login = await c.login('alice@example.com', 'pw');
    if (login.status !== 'mfa_setup_required') throw new Error('expected setup branch');

    const enrolment = await c.mfaSetupEnroll(login.setupToken);
    expect(enrolment.secretBase32.expose()).toBe(SECRET);
    expect(bodyOf('setup/enroll')).toEqual({ setup_token: SETUP_TOKEN });

    const done = await c.mfaSetupConfirm(login.setupToken, '123456');
    expect(done.status).toBe('authenticated');
  });
});

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

describe('§25 email verification', () => {
  it('sends the token and tenant in the body, not as query parameters', async () => {
    await client().verifyEmail(new Sensitive('verify-tok'), 'tenant-uuid');
    expect(bodyOf('verify-email')).toEqual({ token: 'verify-tok', tenant_id: 'tenant-uuid' });
    expect(sent.find((s) => s.path === 'verify-email')!.url).not.toContain('token=');
  });

  it('resends verification for an address', async () => {
    await client().resendVerification('alice@example.com', 'tenant-uuid');
    expect(bodyOf('resend-verification')).toEqual({
      email: 'alice@example.com',
      tenant_id: 'tenant-uuid',
    });
  });
});

// ---------------------------------------------------------------------------
// §25.4 — password reset
// ---------------------------------------------------------------------------

describe('§25.4 password reset', () => {
  it('resolves for an unknown address and exposes nothing distinguishing', async () => {
    // The uniform response is the whole mechanism; an SDK that surfaced a
    // "no such user" signal would rebuild the enumeration oracle it prevents.
    await expect(
      client().requestPasswordReset({ email: 'nobody@example.com' }),
    ).resolves.toBeUndefined();
  });

  it('fills the workspace from the client configuration', async () => {
    await client().requestPasswordReset({ email: 'alice@example.com' });
    expect(bodyOf('reset')).toEqual({
      email: 'alice@example.com',
      org_slug: 'globex',
      tenant_slug: 'acme',
    });
  });

  it('returns the OPAQUE policy from the reset context', async () => {
    const context = await client().passwordResetContext(RESET_TOKEN);
    expect(context.opaque).toEqual({ mode: 'required', ksf: 'argon2id' });
  });

  it('discloses no identity in the reset context', async () => {
    const context = await client().passwordResetContext(RESET_TOKEN);
    // Contract 1.26 removed the username. Assert the shape, so reintroducing
    // one downstream fails here rather than in a security review.
    expect(Object.keys(context)).toEqual(['opaque']);
  });

  it('maps an unknown, expired or consumed token to one indistinguishable failure', async () => {
    await expect(client().passwordResetContext('some-other-token')).rejects.toThrow();
  });

  it('sends the OPAQUE record when the tenant requires one', async () => {
    const c = client();
    const context = await c.passwordResetContext(RESET_TOKEN);
    expect(context.opaque).toBeDefined();

    await c.confirmPasswordReset({
      token: new Sensitive(RESET_TOKEN),
      newPassword: new Sensitive('new-password'),
      tenantId: 'tenant-uuid',
      opaque: { registration_record: 'abc' },
    });
    expect(bodyOf('reset/confirm').opaque).toEqual({ registration_record: 'abc' });
  });

  it('omits the opaque field entirely when there is none', async () => {
    await client().confirmPasswordReset({
      token: RESET_TOKEN,
      newPassword: 'new-password',
      tenantId: 'tenant-uuid',
    });
    expect(bodyOf('reset/confirm')).not.toHaveProperty('opaque');
  });
});
