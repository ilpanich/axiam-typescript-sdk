// §24 WebAuthn relying-party layer — the CONTRACT.md §24.8 test set.
//
// Every assertion here maps to a named requirement in §24.8. The ones worth
// reading twice are `does not retry the 503` (asserted on request count, not
// on the thrown type, because §24.4 rule 2 regresses the moment someone tidies
// a retry predicate) and `never parses the state token` (asserted by handing
// it a state token that is not a JWT at all).

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';
import { AuthError, AuthzError, Sensitive, webauthnRequestJson } from '../../src/rest/index.js';
import {
  ACCESS_TOKEN,
  AUTHENTICATION_RESPONSE,
  CHALLENGE_TOKEN,
  CREATION_CHALLENGE,
  CREDENTIAL_WIRE,
  DISCOVERABLE_CHALLENGE,
  LOGIN_WIRE,
  MINIMAL_CREATION_CHALLENGE,
  REFRESH_TOKEN,
  REGISTRATION_RESPONSE,
  REQUEST_CHALLENGE,
  STATE_TOKEN,
} from './webauthnFixtures.js';

const BASE_URL = 'https://axiam.test';
const W = '/api/v1/auth/webauthn';
const SETUP_TOKEN = 'setup-token-fixture-value-do-not-log';

const LOGIN_SUCCESS_WIRE = {
  user: { id: 'u1', username: 'alice', email: 'alice@example.com' },
  session_id: 's1',
  expires_in: 900,
};

/** Bodies the handlers captured, so a test can assert on what actually went out. */
let sent: Array<{ path: string; body: unknown }> = [];
/** Per-path request counts, for the retry assertions. */
let hits: Record<string, number> = {};

function record(path: string) {
  hits[path] = (hits[path] ?? 0) + 1;
}

/** Registration-start behaviour, swapped per test. */
let registerStart: () => Response = () =>
  HttpResponse.json({ challenge: CREATION_CHALLENGE, state_token: STATE_TOKEN });
/** Setup-register-start behaviour, swapped per test. */
let setupRegisterStart: () => Response = () =>
  HttpResponse.json({ challenge: CREATION_CHALLENGE, state_token: STATE_TOKEN });

const server = setupServer(
  http.post(`${BASE_URL}${W}/register/start`, () => {
    record('register/start');
    return registerStart();
  }),
  http.post(`${BASE_URL}${W}/register/finish`, async ({ request }) => {
    record('register/finish');
    sent.push({ path: 'register/finish', body: await request.json() });
    return HttpResponse.json(CREDENTIAL_WIRE, { status: 201 });
  }),
  http.post(`${BASE_URL}${W}/authenticate/start`, async ({ request }) => {
    record('authenticate/start');
    sent.push({ path: 'authenticate/start', body: await request.json() });
    return HttpResponse.json({ challenge: REQUEST_CHALLENGE, state_token: STATE_TOKEN });
  }),
  http.post(`${BASE_URL}${W}/authenticate/finish`, async ({ request }) => {
    record('authenticate/finish');
    sent.push({ path: 'authenticate/finish', body: await request.json() });
    return HttpResponse.json(LOGIN_WIRE);
  }),
  http.post(`${BASE_URL}${W}/authenticate/discoverable/start`, async ({ request }) => {
    record('discoverable/start');
    sent.push({ path: 'discoverable/start', body: await request.json() });
    return HttpResponse.json({ challenge: DISCOVERABLE_CHALLENGE, state_token: STATE_TOKEN });
  }),
  http.post(`${BASE_URL}${W}/authenticate/discoverable/finish`, async ({ request }) => {
    record('discoverable/finish');
    sent.push({ path: 'discoverable/finish', body: await request.json() });
    return HttpResponse.json(LOGIN_WIRE);
  }),
  http.post(`${BASE_URL}${W}/setup/register/start`, async ({ request }) => {
    record('setup/register/start');
    sent.push({ path: 'setup/register/start', body: await request.json() });
    return setupRegisterStart();
  }),
  http.post(`${BASE_URL}${W}/setup/register/finish`, async ({ request }) => {
    record('setup/register/finish');
    sent.push({ path: 'setup/register/finish', body: await request.json() });
    return HttpResponse.json(LOGIN_SUCCESS_WIRE);
  }),
  http.post(`${BASE_URL}/api/v1/authz/check`, () =>
    HttpResponse.json({ allowed: true, reason_code: 'allow' }),
  ),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
beforeEach(() => {
  sent = [];
  hits = {};
  registerStart = () =>
    HttpResponse.json({ challenge: CREATION_CHALLENGE, state_token: STATE_TOKEN });
  setupRegisterStart = () =>
    HttpResponse.json({ challenge: CREATION_CHALLENGE, state_token: STATE_TOKEN });
});

/** A client that believes it is signed in, which is what `register/*` needs. */
function signedInClient(): AxiamClient {
  const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'globex' });
  client.session.authenticated = true;
  return client;
}

function anonymousClient(): AxiamClient {
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'globex' });
}

function bodyOf(path: string): Record<string, unknown> {
  const entry = sent.find((s) => s.path === path);
  expect(entry, `no request captured for ${path}`).toBeDefined();
  return entry!.body as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// §24.0 — options and responses pass through untouched
// ---------------------------------------------------------------------------

describe('§24.0 pass-through', () => {
  it('hands back the server options structurally unchanged', async () => {
    const { challenge } = await signedInClient().webauthnRegisterStart();
    // Structural equality, not a spot-check of three fields: the failure mode
    // this guards is an SDK that quietly drops the one option it did not
    // recognize.
    expect(challenge).toEqual(CREATION_CHALLENGE);
  });

  it('synthesizes no field the server omitted', async () => {
    registerStart = () =>
      HttpResponse.json({ challenge: MINIMAL_CREATION_CHALLENGE, state_token: STATE_TOKEN });

    const { challenge } = await signedInClient().webauthnRegisterStart();
    expect(challenge.publicKey).not.toHaveProperty('authenticatorSelection');
    expect(challenge.publicKey).not.toHaveProperty('timeout');
    expect(challenge).toEqual(MINIMAL_CREATION_CHALLENGE);
  });

  it('sends the authenticator response back verbatim, unknown keys included', async () => {
    await signedInClient().webauthnRegisterFinish(
      STATE_TOKEN,
      'Alice’s laptop',
      REGISTRATION_RESPONSE,
    );
    expect(bodyOf('register/finish').response).toEqual(REGISTRATION_RESPONSE);
  });

  it('preserves the assertion response byte-for-byte', async () => {
    await anonymousClient().webauthnAuthenticateFinish(STATE_TOKEN, AUTHENTICATION_RESPONSE);
    expect(bodyOf('authenticate/finish').response).toEqual(AUTHENTICATION_RESPONSE);
  });
});

// ---------------------------------------------------------------------------
// §24.1 — auth requirements and workspace resolution
// ---------------------------------------------------------------------------

describe('§24.1 preconditions', () => {
  it('refuses register/start with no session and makes no wire call', async () => {
    await expect(anonymousClient().webauthnRegisterStart()).rejects.toBeInstanceOf(AuthError);
    // Asserted on the transport, not on the exception type alone.
    expect(hits['register/start']).toBeUndefined();
  });

  it('refuses register/finish with no session and makes no wire call', async () => {
    await expect(
      anonymousClient().webauthnRegisterFinish(STATE_TOKEN, 'x', REGISTRATION_RESPONSE),
    ).rejects.toBeInstanceOf(AuthError);
    expect(hits['register/finish']).toBeUndefined();
  });

  it('fills the discoverable workspace from the client, in slug form', async () => {
    await anonymousClient().webauthnDiscoverableStart();
    expect(bodyOf('discoverable/start')).toEqual({ org_slug: 'globex', tenant_slug: 'acme' });
  });

  it('lets the caller override the workspace', async () => {
    await anonymousClient().webauthnDiscoverableStart({
      orgId: '33333333-3333-3333-3333-333333333333',
      tenantSlug: 'other',
    });
    const body = bodyOf('discoverable/start');
    expect(body.org_id).toBe('33333333-3333-3333-3333-333333333333');
    expect(body.tenant_slug).toBe('other');
  });

  it('raises client-side when no organization can be resolved', async () => {
    const client = new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme' });
    await expect(client.webauthnDiscoverableStart()).rejects.toThrow(/organization/);
    expect(hits['discoverable/start']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// §24.2 — the two ceremonies are separate operations
// ---------------------------------------------------------------------------

describe('§24.2 two distinct flows', () => {
  it('sends the challenge token on the second-factor start and nothing else', async () => {
    await anonymousClient().webauthnAuthenticateStart(CHALLENGE_TOKEN);
    expect(bodyOf('authenticate/start')).toEqual({ challenge_token: CHALLENGE_TOKEN });
  });

  it('never sends a challenge token on the discoverable start', async () => {
    await anonymousClient().webauthnDiscoverableStart();
    expect(bodyOf('discoverable/start')).not.toHaveProperty('challenge_token');
  });

  it('reaches the discoverable endpoints, not the username-bound ones', async () => {
    const client = anonymousClient();
    const { stateToken } = await client.webauthnDiscoverableStart();
    await client.webauthnDiscoverableFinish(stateToken, AUTHENTICATION_RESPONSE);

    expect(hits['discoverable/start']).toBe(1);
    expect(hits['discoverable/finish']).toBe(1);
    expect(hits['authenticate/start']).toBeUndefined();
    expect(hits['authenticate/finish']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// §24.3 — credential adoption
// ---------------------------------------------------------------------------

describe('§24.3 adoption', () => {
  it('leaves the client authenticated after a second-factor sign-in', async () => {
    const client = anonymousClient();
    expect(client.session.authenticated).toBe(false);

    const result = await client.webauthnAuthenticateFinish(STATE_TOKEN, AUTHENTICATION_RESPONSE);

    // The client's own state — not merely that a token came back. §24.3 rule 1
    // exists because returning a token set without adopting it would make this
    // the one way to log in that does not log you in.
    expect(client.session.authenticated).toBe(true);
    expect(result.accessToken.expose()).toBe(ACCESS_TOKEN);
    expect(result.refreshToken.expose()).toBe(REFRESH_TOKEN);
    expect(result.expiresIn).toBe(900);
  });

  it('leaves the client authenticated after a discoverable sign-in', async () => {
    const client = anonymousClient();
    await client.webauthnDiscoverableFinish(STATE_TOKEN, AUTHENTICATION_RESPONSE);
    expect(client.session.authenticated).toBe(true);
  });

  it('clears the decision memo, because the subject changed', async () => {
    const client = new AxiamClient({
      baseUrl: BASE_URL,
      tenantSlug: 'acme',
      orgSlug: 'globex',
      decisionMemoTtlMs: 60_000,
    });
    client.session.authenticated = true;
    await client.checkAccess({ action: 'read', resourceId: 'doc:1' });
    expect(client.decisionMemo.size).toBeGreaterThan(0);

    await client.webauthnAuthenticateFinish(STATE_TOKEN, AUTHENTICATION_RESPONSE);
    expect(client.decisionMemo.size).toBe(0);
  });

  it('adopts nothing on register/finish — the caller was already signed in', async () => {
    const client = signedInClient();
    const credential = await client.webauthnRegisterFinish(
      STATE_TOKEN,
      'Alice’s laptop',
      REGISTRATION_RESPONSE,
    );
    expect(credential.credentialId).toBe(CREDENTIAL_WIRE.credential_id);
    expect(credential.name).toBe(CREDENTIAL_WIRE.name);
    expect(credential.credentialType).toBe('passkey');
    expect(credential.lastUsedAt).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// §24.4 — error taxonomy
// ---------------------------------------------------------------------------

describe('§24.4 errors', () => {
  it('does NOT retry the 503 from register/start', async () => {
    registerStart = () =>
      HttpResponse.json({ message: 'FIDO metadata unavailable' }, { status: 503 });

    await expect(signedInClient().webauthnRegisterStart()).rejects.toThrow();
    // §24.4 rule 2. Asserted on the request count rather than on the thrown
    // type: a 503 is a server *configuration* state here, retrying changes
    // nothing, and this regresses silently the moment the retry predicate is
    // tidied.
    expect(hits['register/start']).toBe(1);
  });

  it('surfaces the attestation policy message from a 403 verbatim', async () => {
    const message =
      'this security key is not FIDO certified and the tenant policy requires certification';
    server.use(
      http.post(`${BASE_URL}${W}/register/finish`, () =>
        HttpResponse.json({ message }, { status: 403 }),
      ),
    );

    await expect(
      signedInClient().webauthnRegisterFinish(STATE_TOKEN, 'key', REGISTRATION_RESPONSE),
    ).rejects.toMatchObject({ message });
  });

  it('maps a 403 to the authorization branch of the taxonomy', async () => {
    server.use(
      http.post(`${BASE_URL}${W}/register/finish`, () =>
        HttpResponse.json({ message: 'denied' }, { status: 403 }),
      ),
    );
    await expect(
      signedInClient().webauthnRegisterFinish(STATE_TOKEN, 'key', REGISTRATION_RESPONSE),
    ).rejects.toBeInstanceOf(AuthzError);
  });

  it('maps a failed assertion to the authentication branch', async () => {
    server.use(
      http.post(`${BASE_URL}${W}/authenticate/finish`, () =>
        HttpResponse.json({ message: 'assertion failed' }, { status: 401 }),
      ),
    );
    await expect(
      anonymousClient().webauthnAuthenticateFinish(STATE_TOKEN, AUTHENTICATION_RESPONSE),
    ).rejects.toBeInstanceOf(AuthError);
  });
});

// ---------------------------------------------------------------------------
// §24.5 — the state token is opaque, and sensitive
// ---------------------------------------------------------------------------

describe('§24.5 sensitivity', () => {
  it('never parses the state token', async () => {
    // Not a JWT, not three dot-separated segments, not base64 anything. If the
    // SDK decoded state tokens at all, this would fail — which is exactly the
    // assertion §24.8 asks for.
    const notAJwt = 'this-is-not-a-jwt-and-never-will-be';
    await anonymousClient().webauthnAuthenticateFinish(notAJwt, AUTHENTICATION_RESPONSE);
    expect(bodyOf('authenticate/finish').state_token).toBe(notAJwt);
  });

  it('wraps the state token so it cannot be logged by accident', async () => {
    const { stateToken } = await signedInClient().webauthnRegisterStart();
    expect(stateToken).toBeInstanceOf(Sensitive);
    expect(String(stateToken)).not.toContain(STATE_TOKEN);
    expect(JSON.stringify({ stateToken })).not.toContain(STATE_TOKEN);
  });

  it('keeps both returned tokens out of every serialization surface', async () => {
    const result = await anonymousClient().webauthnAuthenticateFinish(
      STATE_TOKEN,
      AUTHENTICATION_RESPONSE,
    );
    const serialized = `${JSON.stringify(result)}${String(result.accessToken)}${String(
      result.refreshToken,
    )}`;
    expect(serialized).not.toContain(ACCESS_TOKEN);
    expect(serialized).not.toContain(REFRESH_TOKEN);
  });

  it('accepts a Sensitive state token as readily as a bare string', async () => {
    await anonymousClient().webauthnAuthenticateFinish(
      new Sensitive(STATE_TOKEN),
      AUTHENTICATION_RESPONSE,
    );
    expect(bodyOf('authenticate/finish').state_token).toBe(STATE_TOKEN);
  });
});

// ---------------------------------------------------------------------------
// §24.6a — the JSON bridge
// ---------------------------------------------------------------------------

describe('§24.6a JSON bridge', () => {
  it('round-trips a creation challenge through its platform JSON form', async () => {
    const { challenge } = await signedInClient().webauthnRegisterStart();
    // This is the string an Android app hands to
    // CreatePublicKeyCredentialRequest, and a browser to
    // PublicKeyCredential.parseCreationOptionsFromJSON.
    expect(JSON.parse(webauthnRequestJson(challenge))).toEqual(CREATION_CHALLENGE.publicKey);
  });

  it('round-trips a request challenge, empty allowCredentials included', async () => {
    const { challenge } = await anonymousClient().webauthnDiscoverableStart();
    const parsed = JSON.parse(webauthnRequestJson(challenge));
    expect(parsed).toEqual(DISCOVERABLE_CHALLENGE.publicKey);
    expect(parsed.allowCredentials).toEqual([]);
  });

  it('omits the publicKey wrapper the platform JSON APIs do not want', async () => {
    const { challenge } = await signedInClient().webauthnRegisterStart();
    expect(JSON.parse(webauthnRequestJson(challenge))).not.toHaveProperty('publicKey');
  });

  it('accepts a platform response JSON string on register/finish, unaltered', async () => {
    await signedInClient().webauthnRegisterFinish(
      STATE_TOKEN,
      'Alice’s laptop',
      JSON.stringify(REGISTRATION_RESPONSE),
    );
    expect(bodyOf('register/finish').response).toEqual(REGISTRATION_RESPONSE);
  });

  it('accepts a platform response JSON string on authenticate/finish', async () => {
    await anonymousClient().webauthnAuthenticateFinish(
      STATE_TOKEN,
      JSON.stringify(AUTHENTICATION_RESPONSE),
    );
    expect(bodyOf('authenticate/finish').response).toEqual(AUTHENTICATION_RESPONSE);
  });

  it('rejects a malformed response string before making a wire call', async () => {
    await expect(
      anonymousClient().webauthnAuthenticateFinish(STATE_TOKEN, '{not json'),
    ).rejects.toBeInstanceOf(TypeError);
    expect(hits['authenticate/finish']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// §24.1/§24.8 (contract 1.45) — setup/register/*, the WebAuthn twin of
// mfa_setup_enroll/mfa_setup_confirm. No session is required OR permitted:
// see test/node/webauthnSetupRegister.test.ts for the "carries no session
// credential" and CSRF-adoption assertions, which need a real jar/server.
// ---------------------------------------------------------------------------

describe('§24.1 setup/register/* — no session required', () => {
  it('starts with an anonymous client — no session needed, unlike register/start', async () => {
    const { challenge, stateToken } = await anonymousClient().webauthnSetupRegisterStart(
      SETUP_TOKEN,
    );
    expect(challenge).toEqual(CREATION_CHALLENGE);
    expect(stateToken).toBeInstanceOf(Sensitive);
    expect(bodyOf('setup/register/start')).toEqual({ setup_token: SETUP_TOKEN });
  });

  it('finishes with an anonymous client and leaves it authenticated (§24.3 rule 1, mirrored)', async () => {
    const client = anonymousClient();
    expect(client.session.authenticated).toBe(false);

    const result = await client.webauthnSetupRegisterFinish(
      SETUP_TOKEN,
      STATE_TOKEN,
      'Alice’s security key',
      REGISTRATION_RESPONSE,
    );

    expect(client.session.authenticated).toBe(true);
    expect(result.status).toBe('authenticated');
    if (result.status === 'authenticated') {
      expect(result.sessionId).toBe(LOGIN_SUCCESS_WIRE.session_id);
      expect(result.expiresIn).toBe(LOGIN_SUCCESS_WIRE.expires_in);
    }
  });

  it('sends the setup token, state token, credential name and response verbatim', async () => {
    await anonymousClient().webauthnSetupRegisterFinish(
      SETUP_TOKEN,
      STATE_TOKEN,
      'Alice’s security key',
      REGISTRATION_RESPONSE,
    );
    const body = bodyOf('setup/register/finish');
    expect(body).toMatchObject({
      setup_token: SETUP_TOKEN,
      state_token: STATE_TOKEN,
      credential_name: 'Alice’s security key',
    });
    expect(body.response).toEqual(REGISTRATION_RESPONSE);
  });

  it('accepts a platform response JSON string, unaltered (§24.6a)', async () => {
    await anonymousClient().webauthnSetupRegisterFinish(
      SETUP_TOKEN,
      STATE_TOKEN,
      'key',
      JSON.stringify(REGISTRATION_RESPONSE),
    );
    expect(bodyOf('setup/register/finish').response).toEqual(REGISTRATION_RESPONSE);
  });

  it('clears the decision memo — this completes a login, like mfaSetupConfirm', async () => {
    const client = new AxiamClient({
      baseUrl: BASE_URL,
      tenantSlug: 'acme',
      orgSlug: 'globex',
      decisionMemoTtlMs: 60_000,
    });
    await client.checkAccess({ action: 'read', resourceId: 'doc:1' });
    expect(client.decisionMemo.size).toBeGreaterThan(0);

    await client.webauthnSetupRegisterFinish(SETUP_TOKEN, STATE_TOKEN, 'key', REGISTRATION_RESPONSE);
    expect(client.decisionMemo.size).toBe(0);
  });

  it('never parses the setup token or the state token', async () => {
    const notAJwt = 'this-is-not-a-jwt-and-never-will-be';
    await anonymousClient().webauthnSetupRegisterFinish(
      notAJwt,
      notAJwt,
      'key',
      REGISTRATION_RESPONSE,
    );
    const body = bodyOf('setup/register/finish');
    expect(body.setup_token).toBe(notAJwt);
    expect(body.state_token).toBe(notAJwt);
  });

  it('wraps the setup token and the returned state token so neither can be logged by accident', async () => {
    const { stateToken } = await anonymousClient().webauthnSetupRegisterStart(
      new Sensitive(SETUP_TOKEN),
    );
    expect(stateToken).toBeInstanceOf(Sensitive);
    expect(String(stateToken)).not.toContain(STATE_TOKEN);
    expect(JSON.stringify({ stateToken })).not.toContain(STATE_TOKEN);
  });

  it('does NOT retry the 503 from setup/register/start (§24.4 rule 2)', async () => {
    setupRegisterStart = () =>
      HttpResponse.json({ message: 'FIDO metadata unavailable' }, { status: 503 });

    await expect(anonymousClient().webauthnSetupRegisterStart(SETUP_TOKEN)).rejects.toThrow();
    expect(hits['setup/register/start']).toBe(1);
  });

  it('maps a 401 (invalid/expired/wrong-purpose setup token) to the authentication branch', async () => {
    server.use(
      http.post(`${BASE_URL}${W}/setup/register/start`, () =>
        HttpResponse.json({ message: 'invalid or expired setup token' }, { status: 401 }),
      ),
    );
    await expect(
      anonymousClient().webauthnSetupRegisterStart(SETUP_TOKEN),
    ).rejects.toBeInstanceOf(AuthError);
  });

  it('surfaces a 400 (account already has a factor) — the same answer mfa_setup_enroll gives', async () => {
    const message = 'this account already has a second factor configured';
    server.use(
      http.post(`${BASE_URL}${W}/setup/register/start`, () =>
        HttpResponse.json({ message }, { status: 400 }),
      ),
    );
    await expect(
      anonymousClient().webauthnSetupRegisterStart(SETUP_TOKEN),
    ).rejects.toMatchObject({ message });
  });

  it('surfaces a 403 (attestation policy) message verbatim on finish', async () => {
    const message = 'this security key is not FIDO certified and the tenant policy requires certification';
    server.use(
      http.post(`${BASE_URL}${W}/setup/register/finish`, () =>
        HttpResponse.json({ message }, { status: 403 }),
      ),
    );
    await expect(
      anonymousClient().webauthnSetupRegisterFinish(SETUP_TOKEN, STATE_TOKEN, 'key', REGISTRATION_RESPONSE),
    ).rejects.toMatchObject({ message });
    await expect(
      anonymousClient().webauthnSetupRegisterFinish(SETUP_TOKEN, STATE_TOKEN, 'key', REGISTRATION_RESPONSE),
    ).rejects.toBeInstanceOf(AuthzError);
  });
});
