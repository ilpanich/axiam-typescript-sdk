// oidcRefresh, loginClientCredentials, introspect, revoke
// (CONTRACT.md §12.1, §12.3 rules 3–4, §9).

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { AuthError, NetworkError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import { createOidcClient, DISCOVERY_PATH } from '../../src/node/oidc.js';
import { createNodeClient, createNodeSession } from '../../src/node/session.js';
import {
  BASE_URL,
  CLIENT_ID,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  discoveryDocument,
  discoveryHandler,
  generateSigningKey,
  INTROSPECT_ENDPOINT,
  ISSUER,
  jwksHandler,
  ORG_ID,
  REVOKE_ENDPOINT,
  signIdToken,
  TENANT_ID,
  tokenHandler,
  tokenResponse,
  TOKEN_ENDPOINT,
} from './oidcTestKit.js';

const server = createServer();

beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe('oidcRefresh (§12.1, §9)', () => {
  it('posts a refresh_token grant with the documented field set', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ refresh_token: 'rotated-refresh' }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.oidcRefresh({ refreshToken: new Sensitive('old-refresh'), scope: 'openid' });

    const form = state.tokenForms[0];
    expect(form.get('grant_type')).toBe('refresh_token');
    expect(form.get('refresh_token')).toBe('old-refresh');
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('client_secret')).toBe(CLIENT_SECRET);
    expect(form.get('scope')).toBe('openid');
    expect([...form.keys()].sort()).toEqual([
      'client_id',
      'client_secret',
      'grant_type',
      'refresh_token',
      'scope',
    ]);
    expect(state.tokenTenantIds[0]).toBe(TENANT_ID);
    expect(tokens.refreshToken?.expose()).toBe('rotated-refresh');
  });

  // Contract 1.60 §12.1: the server intersects the grant with the client's
  // current registration, so a refresh may answer a narrower scope — and no
  // ID token once `openid` is gone. The result carries the response's scope.
  it("takes the refresh response's scope as the token's scope, never the original grant's", async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ scope: 'profile' }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.oidcRefresh({ refreshToken: 'r', scope: 'openid profile email' });

    expect(state.tokenForms[0].get('scope')).toBe('openid profile email');
    expect(tokens.scope).toBe('profile');
    expect(tokens.idToken).toBeUndefined();
    expect(tokens.idClaims).toBeUndefined();
  });

  it('omits scope when the caller does not narrow it', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.oidcRefresh({ refreshToken: 'r' });

    expect(state.tokenForms[0].has('scope')).toBe(false);
  });

  it('collapses concurrent refreshes into ONE token request and shares the result (§9 rules 1–2)', async () => {
    const state = createMockState();
    let tokenCalls = 0;
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async () => {
        tokenCalls += 1;
        await new Promise((resolve) => setTimeout(resolve, 20));
        return HttpResponse.json(tokenResponse({ access_token: `access-${tokenCalls}` }));
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    // Warm the discovery cache so all five callers race on the refresh alone.
    await oidc.oidcDiscover();

    const results = await Promise.all(
      Array.from({ length: 5 }, () => oidc.oidcRefresh({ refreshToken: 'r' })),
    );

    expect(tokenCalls).toBe(1);
    for (const tokens of results) {
      expect(tokens.accessToken.expose()).toBe('access-1');
    }
  });

  // CONTRACT.md §9 rule 2 / 6d (#177): the single-flight is keyed PER refresh token. A caller holding a
  // different token is not part of the burst and must never receive another grant's token set.
  it('gives a DIFFERENT refresh token its own wire call and its own token set (#177)', async () => {
    const state = createMockState();
    const presented: Array<string | null> = [];
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        const rt = new URLSearchParams(await request.text()).get('refresh_token');
        presented.push(rt);
        await new Promise((resolve) => setTimeout(resolve, 30));
        return HttpResponse.json(tokenResponse({ access_token: `access-for-${rt}` }));
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcDiscover();

    const [a1, b, a2] = await Promise.all([
      oidc.oidcRefresh({ refreshToken: 'token-A' }),
      oidc.oidcRefresh({ refreshToken: new Sensitive('token-B') }),
      oidc.oidcRefresh({ refreshToken: 'token-A' }), // same token: joins A
    ]);

    expect(a1.accessToken.expose()).toBe('access-for-token-A');
    expect(b.accessToken.expose()).toBe('access-for-token-B');
    expect(a2).toBe(a1);
    expect([...presented].sort()).toEqual(['token-A', 'token-B']); // 2 wire calls, A once
  });

  it('default tenant explicit / upper-case / omitted in ONE burst → one wire call; same token, other tenant → own call and own outcome (#177)', async () => {
    const HEX = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
    const OTHER = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff';
    const state = createMockState();
    const wire: Array<{ rt: string | null; tenant: string | null }> = [];
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        const tenant = new URL(request.url).searchParams.get('tenant_id');
        wire.push({ rt: new URLSearchParams(await request.text()).get('refresh_token'), tenant });
        await new Promise((resolve) => setTimeout(resolve, 20));
        return HttpResponse.json(tokenResponse({ access_token: `access-${tenant}` }));
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET, tenantId: HEX });
    await oidc.oidcDiscover();
    const burst = await Promise.all([
      oidc.oidcRefresh({ refreshToken: 'secret-rt', tenantId: HEX }),
      oidc.oidcRefresh({ refreshToken: 'secret-rt', tenantId: HEX.toUpperCase() }),
      oidc.oidcRefresh({ refreshToken: 'secret-rt' }),
      oidc.oidcRefresh({ refreshToken: 'secret-rt', scope: 'openid' }), // scope is not part of the key
      oidc.oidcRefresh({ refreshToken: 'secret-rt', tenantId: OTHER }),
    ]);
    expect(wire).toHaveLength(2); // HEX once, OTHER once
    expect(wire.map((w) => w.tenant).sort()).toEqual([HEX, OTHER]);
    for (const r of burst.slice(0, 4)) expect(r.accessToken.expose()).toBe(`access-${HEX}`);
    expect(burst[4]?.accessToken.expose()).toBe(`access-${OTHER}`);
  });

  it('vacates the slot once settled, and no raw token reaches an error (#177)', async () => {
    const state = createMockState();
    const presented: Array<string | null> = [];
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        presented.push(new URLSearchParams(await request.text()).get('refresh_token'));
        return HttpResponse.json(tokenResponse());
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcRefresh({ refreshToken: 'secret-rt', tenantId: TENANT_ID });
    // After full vacate the same token starts a fresh wire call.
    await oidc.oidcRefresh({ refreshToken: 'secret-rt', tenantId: TENANT_ID });
    expect(presented).toHaveLength(2);
    // No raw token reaches an error message.
    server.use(http.post(TOKEN_ENDPOINT, () => HttpResponse.json({ error: 'invalid_grant' }, { status: 400 })));
    const err = await oidc.oidcRefresh({ refreshToken: 'secret-rt' }).catch((e: unknown) => e);
    expect(String((err as Error).message)).not.toContain('secret-rt');
  });

  // Contract 1.65 §9 ("A replayed refresh token ends the session"): the 1.65 port
  // CONFIRMS the existing single-flight rules against `invalid_grant`. With the
  // default `revoke_session` a second presentation of a rotated token costs the
  // user their session, so N-1 replays must never happen.
  it('answers a burst of N>=5 refreshes with ONE wire call and ONE shared invalid_grant, and never re-presents the spent token (§9, contract 1.65)', async () => {
    const state = createMockState();
    const presented: (string | null)[] = [];
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        presented.push(new URLSearchParams(await request.text()).get('refresh_token'));
        await new Promise((resolve) => setTimeout(resolve, 20));
        return HttpResponse.json(
          { error: 'invalid_grant', error_description: 'the refresh token is not valid' },
          { status: 400 },
        );
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcDiscover();

    const settled = await Promise.allSettled(
      Array.from({ length: 8 }, () => oidc.oidcRefresh({ refreshToken: new Sensitive('spent-refresh') })),
    );

    expect(presented).toEqual(['spent-refresh']);
    const reasons = settled.map((r) => (r.status === 'rejected' ? r.reason : undefined));
    for (const reason of reasons) {
      expect(reason).toBeInstanceOf(OAuthProtocolError);
      expect(reason).toMatchObject({ error: 'invalid_grant' });
    }
    // Every waiter received the one error the single wire call produced.
    expect(new Set(reasons).size).toBe(1);

    // Nothing retries on its own afterwards: no further request carries the spent token.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(presented).toEqual(['spent-refresh']);
  });

  it('allows a fresh refresh after the previous one settled (not a permanent lock)', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.oidcRefresh({ refreshToken: 'r1' });
    await oidc.oidcRefresh({ refreshToken: 'r2' });

    expect(state.tokenCalls).toBe(2);
    expect(state.tokenForms.map((f) => f.get('refresh_token'))).toEqual(['r1', 'r2']);
  });

  it('validates an id_token in the refresh response but skips the nonce rule (§12.4 rule 6)', async () => {
    const key = await generateSigningKey('refresh-kid');
    // No nonce claim at all — legal for a refresh-issued ID token.
    const idToken = await signIdToken(key, { nonce: null });
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ id_token: idToken }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.oidcRefresh({ refreshToken: 'r' });

    expect(tokens.idClaims?.iss).toBe(ISSUER);
    expect(tokens.idClaims?.nonce).toBeUndefined();
  });

  it('still enforces rules 1–5 on a refresh-issued id_token', async () => {
    const key = await generateSigningKey('refresh-kid-bad');
    const idToken = await signIdToken(key, { nonce: null, issuer: 'https://evil.example' });
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ id_token: idToken }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.oidcRefresh({ refreshToken: 'r' })).rejects.toMatchObject({
      reason: 'invalid_issuer',
    });
  });

  it('is not blocked by the §1 cookie-session refresh holding the session guard', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcDiscover();
    let release: (() => void) | undefined;
    const sessionRefresh = session.refreshGuard(() => new Promise<void>((resolve) => { release = resolve; }));
    await expect(oidc.oidcRefresh({ refreshToken: 'r' })).resolves.toMatchObject({ tokenType: 'Bearer' });
    expect(state.tokenCalls).toBe(1);
    release?.();
    await sessionRefresh;
  });

  // Rule 7 (clarifications 3-4): flights of different tokens are independent and concurrent.
  it('starts B\'s wire call while A\'s is still held on the wire (asserted on the transport)', async () => {
    const state = createMockState();
    const started: Array<string | null> = [];
    let releaseA: (() => void) | undefined;
    const aHeld = new Promise<void>((r) => { releaseA = r; });
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        const rt = new URLSearchParams(await request.text()).get('refresh_token');
        started.push(rt);
        if (rt === 'token-A') await aHeld;
        return HttpResponse.json(tokenResponse({ access_token: `access-for-${rt}` }));
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcDiscover();
    const a = oidc.oidcRefresh({ refreshToken: 'token-A' });
    await vi.waitFor(() => expect(started).toEqual(['token-A']));
    const b = oidc.oidcRefresh({ refreshToken: 'token-B' });
    await vi.waitFor(() => expect(started).toEqual(['token-A', 'token-B'])); // B reached the wire, A still held
    await expect(b).resolves.toMatchObject({ accessToken: expect.anything() });
    expect((await b).accessToken.expose()).toBe('access-for-token-B');
    releaseA?.();
    expect((await a).accessToken.expose()).toBe('access-for-token-A');
  });

  it('A failing does not reject B: B is still sent and gets its own result', async () => {
    const state = createMockState();
    const started: Array<string | null> = [];
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        const rt = new URLSearchParams(await request.text()).get('refresh_token');
        started.push(rt);
        await new Promise((r) => setTimeout(r, 20));
        if (rt === 'token-A') return HttpResponse.json({ error: 'invalid_grant' }, { status: 400 });
        return HttpResponse.json(tokenResponse({ access_token: 'access-B' }));
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcDiscover();
    const [a, b] = await Promise.allSettled([
      oidc.oidcRefresh({ refreshToken: 'token-A' }),
      oidc.oidcRefresh({ refreshToken: 'token-B' }),
    ]);
    expect(a.status).toBe('rejected');
    expect(b.status === 'fulfilled' && b.value.accessToken.expose()).toBe('access-B');
    expect([...started].sort()).toEqual(['token-A', 'token-B']);
  });

  it('20 concurrent distinct-token refreshes all complete with their own results, and the slots are removed', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        const rt = new URLSearchParams(await request.text()).get('refresh_token');
        await new Promise((r) => setTimeout(r, 20));
        return HttpResponse.json(tokenResponse({ access_token: `access-for-${rt}` }));
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcDiscover();
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => oidc.oidcRefresh({ refreshToken: `tok-${i}` })));
    results.forEach((r, i) => expect(r.accessToken.expose()).toBe(`access-for-tok-${i}`));
    expect(oidc._pendingRefreshSlots()).toBe(0);
  });

  // The publish is synchronous in oidcRefresh and the vacate is the flight's first settle reaction, so no
  // caller can observe a settled-but-published slot: the window is atomic. B is presented at the earliest
  // reachable instant after A's outcome is published (inside A's own continuation).
  it('a different token presented the moment A settles gets its own flight; the slot is gone (#177)', async () => {
    const state = createMockState();
    const presented: Array<string | null> = [];
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        const rt = new URLSearchParams(await request.text()).get('refresh_token');
        presented.push(rt);
        return HttpResponse.json(tokenResponse({ access_token: `access-for-${rt}` }));
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcDiscover();
    const a = await oidc.oidcRefresh({ refreshToken: 'token-A' });
    const bPromise = oidc.oidcRefresh({ refreshToken: 'token-B' }); // right after A's outcome
    const sameAgain = oidc.oidcRefresh({ refreshToken: 'token-A' }); // same token after vacate: fresh call
    expect(oidc._pendingRefreshSlots()).toBe(2);
    expect((await bPromise).accessToken.expose()).toBe('access-for-token-B');
    await sameAgain;
    expect(a.accessToken.expose()).toBe('access-for-token-A');
    expect(presented).toEqual(['token-A', 'token-B', 'token-A']);
    expect(oidc._pendingRefreshSlots()).toBe(0);
  });

  it('resolves the tenant ONCE: a hex-letter tenant in upper case goes on the wire lower-case', async () => {
    const state = createMockState();
    const tenants: Array<string | null> = [];
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        tenants.push(new URL(request.url).searchParams.get('tenant_id'));
        return HttpResponse.json(tokenResponse());
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await oidc.oidcDiscover();
    await oidc.oidcRefresh({ refreshToken: 'r', tenantId: 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE' });
    expect(tenants).toEqual(['aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee']);
  });

  it('an unresolvable tenant fails at once: no slot, no token call', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });
    await expect(oidc.oidcRefresh({ refreshToken: 'r', tenantId: 'not-a-uuid' })).rejects.toBeInstanceOf(AuthError);
    expect(oidc._pendingRefreshSlots()).toBe(0);
    expect(state.tokenCalls).toBe(0);
  });

  it('maps a 400 invalid_grant to OAuthProtocolError without entering a refresh loop', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () =>
        HttpResponse.json(
          { error: 'invalid_grant', error_description: 'refresh token revoked' },
          { status: 400 },
        ),
      ),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const error = await oidc.oidcRefresh({ refreshToken: 'r' }).then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(OAuthProtocolError);
    expect((error as OAuthProtocolError).message).toBe('invalid_grant: refresh token revoked');
    // Exactly one attempt — no silent retry.
    expect(state.tokenCalls).toBe(1);
  });
});

describe('loginClientCredentials (§12.1)', () => {
  it('posts a client_credentials grant with only the documented fields', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ scope: 'authz:check' }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.loginClientCredentials({ scope: 'authz:check' });

    const form = state.tokenForms[0];
    expect(form.get('grant_type')).toBe('client_credentials');
    expect(form.get('client_id')).toBe(CLIENT_ID);
    expect(form.get('client_secret')).toBe(CLIENT_SECRET);
    expect([...form.keys()].sort()).toEqual(['client_id', 'client_secret', 'grant_type', 'scope']);
    expect(state.tokenTenantIds[0]).toBe(TENANT_ID);
    expect(tokens.accessToken.expose()).toBe('access-token-value');
    expect(tokens.idToken).toBeUndefined();
    expect(tokens.idClaims).toBeUndefined();
    expect(tokens.scope).toBe('authz:check');
  });

  it('works with no arguments at all and omits an unrequested scope', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials();

    expect(state.tokenForms[0].has('scope')).toBe(false);
  });

  it('raises AuthError client-side for a public client (no clientSecret)', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    await expect(oidc.loginClientCredentials()).rejects.toThrow(/confidential-client credentials/);
    expect(state.tokenCalls).toBe(0);
  });

  it('optionally adopts the token as the session bearer credential, but never for /oauth2/*', async () => {
    const state = createMockState();
    let protectedAuthHeader: string | null = null;
    let tokenEndpointAuthHeader: string | null | undefined;
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        tokenEndpointAuthHeader = request.headers.get('authorization');
        return HttpResponse.json(tokenResponse({ access_token: 'm2m-access-token' }));
      }),
      http.get(`${BASE_URL}/api/v1/protected`, ({ request }) => {
        protectedAuthHeader = request.headers.get('authorization');
        return HttpResponse.json({ ok: true });
      }),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials({ adoptAsCredential: true });
    await session.axios.get('/api/v1/protected');

    expect(protectedAuthHeader).toBe('Bearer m2m-access-token');
    // The client authenticates itself in the FORM body at /oauth2/* (§12.1
    // note 3) — no Authorization header is added there.
    expect(tokenEndpointAuthHeader).toBeNull();
  });

  // CONTRACT 1.52 N4.4 (C-12): "Any later session-establishing call
  // replaces it [the device credential] ... client-credentials adoption
  // ..." Before this fix, `loginClientCredentials({ adoptAsCredential:
  // true })` never touched `session.deviceAccessToken`, so a client that
  // had previously called authenticateDevice() and then adopted
  // client-credentials kept riding the STALE device token on every later
  // same-origin request — installDeviceTokenInterceptor sends it
  // unconditionally whenever `deviceAccessToken` is set, ahead of the
  // client-credentials interceptor's own Authorization header.
  it('CONTRACT 1.52 N4.4 (C-12) — adopting client-credentials clears a previously-adopted device credential', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => HttpResponse.json(tokenResponse({ access_token: 'm2m-access-token' }))),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    session.deviceAccessToken = new Sensitive('stale-device-token');

    await oidc.loginClientCredentials({ adoptAsCredential: true });

    expect(session.deviceAccessToken).toBeUndefined();
  });

  // I4 twin: a client with no device credential is unaffected.
  it('twin (I4): a client with no device credential is unaffected by adoption', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => HttpResponse.json(tokenResponse({ access_token: 'm2m-access-token' }))),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    expect(session.deviceAccessToken).toBeUndefined();

    await oidc.loginClientCredentials({ adoptAsCredential: true });

    expect(session.deviceAccessToken).toBeUndefined();
  });

  // CONTRACT 1.52 N5.5 (C-12): "Those that carry none reset the gate to
  // unknown: WebAuthn authentication, the SSO completions, the device
  // login, and client-credentials adoption." Before this fix,
  // `#adoptCredential` never touched `session.principalScope`, so a client
  // that had completed an ordinary login (recording, say,
  // `organizationLevel: false`) and then adopted client-credentials as a
  // secondary/service identity kept `actingTenant()` gating on the STALE
  // human principal's report instead of treating the new credential's
  // reach as unknown (server decides).
  it('CONTRACT 1.52 N5.5 (C-12) — adopting client-credentials resets the acting-tenant gate to unknown', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => HttpResponse.json(tokenResponse({ access_token: 'm2m-access-token' }))),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    // A stale report from an earlier, unrelated login on this session.
    session.principalScope = { organizationLevel: false };

    await oidc.loginClientCredentials({ adoptAsCredential: true });

    expect(session.principalScope).toBeUndefined();
  });

  // I4 twin: adopting with no prior principalScope is unaffected — still
  // undefined afterward, exactly as before this fix.
  it('twin (I4): adopting client-credentials with no prior principalScope is unaffected', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => HttpResponse.json(tokenResponse({ access_token: 'm2m-access-token' }))),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    expect(session.principalScope).toBeUndefined();

    await oidc.loginClientCredentials({ adoptAsCredential: true });

    expect(session.principalScope).toBeUndefined();
  });

  it('does not touch the session credential unless adoption was requested', async () => {
    const state = createMockState();
    let protectedAuthHeader: string | null = null;
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse())),
      http.get(`${BASE_URL}/api/v1/protected`, ({ request }) => {
        protectedAuthHeader = request.headers.get('authorization');
        return HttpResponse.json({ ok: true });
      }),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials();
    await session.axios.get('/api/v1/protected');

    expect(protectedAuthHeader).toBeNull();
  });
});

describe('introspect (§12.1, RFC 7662)', () => {
  it('posts a form body to the introspection endpoint and maps the response', async () => {
    const state = createMockState();
    let captured: URLSearchParams | undefined;
    let tenantIdQuery: string | null = null;
    server.use(
      discoveryHandler(state),
      http.post(INTROSPECT_ENDPOINT, async ({ request }) => {
        tenantIdQuery = new URL(request.url).searchParams.get('tenant_id');
        captured = new URLSearchParams(await request.text());
        return HttpResponse.json({
          active: true,
          sub: 'user-9',
          client_id: CLIENT_ID,
          scope: 'openid profile',
          token_type: 'Bearer',
          exp: 1_800_000_900,
          iat: 1_800_000_000,
        });
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const result = await oidc.introspect({
      token: new Sensitive('token-to-check'),
      tokenTypeHint: 'access_token',
    });

    expect(tenantIdQuery).toBe(TENANT_ID);
    expect(captured?.get('token')).toBe('token-to-check');
    expect(captured?.get('client_id')).toBe(CLIENT_ID);
    expect(captured?.get('client_secret')).toBe(CLIENT_SECRET);
    expect(captured?.get('token_type_hint')).toBe('access_token');
    expect(result).toEqual({
      active: true,
      sub: 'user-9',
      clientId: CLIENT_ID,
      scope: 'openid profile',
      tokenType: 'Bearer',
      exp: 1_800_000_900,
      iat: 1_800_000_000,
    });
  });

  it('returns { active: false } with no metadata for an inactive token', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(INTROSPECT_ENDPOINT, () => HttpResponse.json({ active: false, sub: null, exp: null })),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.introspect({ token: 'unknown' })).resolves.toEqual({ active: false });
  });

  it('omits token_type_hint when the caller does not supply one', async () => {
    const state = createMockState();
    let captured: URLSearchParams | undefined;
    server.use(
      discoveryHandler(state),
      http.post(INTROSPECT_ENDPOINT, async ({ request }) => {
        captured = new URLSearchParams(await request.text());
        return HttpResponse.json({ active: true });
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.introspect({ token: 't' });

    expect(captured?.has('token_type_hint')).toBe(false);
  });

  it('a 401 becomes OAuthProtocolError and does NOT trigger the §9 refresh guard', async () => {
    const state = createMockState();
    let sessionRefreshCalls = 0;
    server.use(
      discoveryHandler(state),
      http.post(`${BASE_URL}/api/v1/auth/refresh`, () => {
        sessionRefreshCalls += 1;
        return HttpResponse.json({ expires_in: 900 });
      }),
      http.post(INTROSPECT_ENDPOINT, () =>
        HttpResponse.json(
          { error: 'invalid_client', error_description: 'client authentication failed' },
          { status: 401 },
        ),
      ),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });
    // The refresh interceptor only fires for an authenticated session, so make
    // the test hostile: pretend we are logged in.
    session.authenticated = true;

    const error = await oidc.introspect({ token: 't' }).then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(OAuthProtocolError);
    expect(error).toBeInstanceOf(AuthError);
    expect((error as OAuthProtocolError).error).toBe('invalid_client');
    expect((error as OAuthProtocolError).message).toBe('invalid_client: client authentication failed');
    // §12.3 rule 3: a client-credential failure is not a session expiry.
    expect(sessionRefreshCalls).toBe(0);
  });

  it('raises AuthError client-side for a public client', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    await expect(oidc.introspect({ token: 't' })).rejects.toThrow(/confidential-client credentials/);
  });
});

describe('revoke (§12.1, RFC 7009)', () => {
  it('posts a form body to the revocation endpoint and resolves with no value', async () => {
    const state = createMockState();
    let captured: URLSearchParams | undefined;
    let tenantIdQuery: string | null = null;
    server.use(
      discoveryHandler(state),
      http.post(REVOKE_ENDPOINT, async ({ request }) => {
        tenantIdQuery = new URL(request.url).searchParams.get('tenant_id');
        captured = new URLSearchParams(await request.text());
        return new HttpResponse(null, { status: 200 });
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(
      oidc.revoke({ token: new Sensitive('token-to-revoke'), tokenTypeHint: 'refresh_token' }),
    ).resolves.toBeUndefined();

    expect(tenantIdQuery).toBe(TENANT_ID);
    expect(captured?.get('token')).toBe('token-to-revoke');
    expect(captured?.get('client_secret')).toBe(CLIENT_SECRET);
    expect(captured?.get('token_type_hint')).toBe('refresh_token');
  });

  it('is idempotent: a 200 for an unknown/already-revoked token is success', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      // RFC 7009: the server answers 200 for tokens it has never seen.
      http.post(REVOKE_ENDPOINT, () => new HttpResponse(null, { status: 200 })),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.revoke({ token: 'never-existed' })).resolves.toBeUndefined();
    await expect(oidc.revoke({ token: 'never-existed' })).resolves.toBeUndefined();
    await expect(oidc.revoke({ token: 'never-existed' })).resolves.toBeUndefined();
  });

  it('surfaces a 401 as OAuthProtocolError', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(REVOKE_ENDPOINT, () =>
        HttpResponse.json({ error: 'invalid_client', error_description: 'bad secret' }, { status: 401 }),
      ),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.revoke({ token: 't' })).rejects.toBeInstanceOf(OAuthProtocolError);
  });

  it('surfaces a transport failure as NetworkError', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(REVOKE_ENDPOINT, () => HttpResponse.json({ oops: true }, { status: 500 })),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.revoke({ token: 't' })).rejects.toBeInstanceOf(NetworkError);
  });

  it('raises AuthError client-side for a public client', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    await expect(oidc.revoke({ token: 't' })).rejects.toThrow(/confidential-client credentials/);
  });
});

describe('transport, caching and interceptor paths', () => {
  it('surfaces a connection failure (no HTTP response at all) as NetworkError', async () => {
    server.use(http.get(`${BASE_URL}${DISCOVERY_PATH}`, () => HttpResponse.error()));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const error = await oidc.oidcDiscover().then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(NetworkError);
    expect((error as NetworkError).message).toBe('oidc discovery request failed');
  });

  it('does not invent a message from a non-object error body', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, () => new HttpResponse('gateway exploded', { status: 502 })),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const error = await oidc.loginClientCredentials().then(
      () => undefined,
      (err: unknown) => err,
    );

    expect(error).toBeInstanceOf(NetworkError);
    expect((error as NetworkError).message).toBe('token request failed');
  });

  it('reuses one JWKS verifier (and its cached key set) across exchanges', async () => {
    const key = await generateSigningKey('reuse-kid');
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, async () =>
        HttpResponse.json(tokenResponse({ id_token: await signIdToken(key, { nonce: 'n' }) })),
      ),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.oidcExchange({ code: 'c1', codeVerifier: 'v', redirectUri: 'https://app/cb', nonce: 'n' });
    await oidc.oidcExchange({ code: 'c2', codeVerifier: 'v', redirectUri: 'https://app/cb', nonce: 'n' });

    expect(state.tokenCalls).toBe(2);
    // One JWKS fetch for two validations: the verifier — and jose's key-set
    // cache inside it — is built once per jwks_uri, not per call.
    expect(state.jwksCalls).toBe(1);
  });

  it('installs the credential-adoption interceptor only once across repeated adoptions', async () => {
    const state = createMockState();
    const authHeaders: (string | null)[] = [];
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ access_token: 'm2m-token' }))),
      http.get(`${BASE_URL}/api/v1/protected`, ({ request }) => {
        authHeaders.push(request.headers.get('authorization'));
        return HttpResponse.json({ ok: true });
      }),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials({ adoptAsCredential: true });
    await oidc.loginClientCredentials({ adoptAsCredential: true });
    await session.axios.get('/api/v1/protected');

    // A single header, not a duplicated one — the interceptor was not stacked.
    expect(authHeaders).toEqual(['Bearer m2m-token']);
  });

  it('honours a narrowed clockSkewSec when validating an id_token', async () => {
    const key = await generateSigningKey('skew-kid');
    // Expired 30 s ago: inside the default 60 s allowance, outside a 5 s one.
    const idToken = await signIdToken(key, { nonce: null, expiresInSec: -30 });
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ id_token: idToken }))),
    );

    const lenient = createClient({ clientSecret: CLIENT_SECRET });
    await expect(lenient.oidc.oidcRefresh({ refreshToken: 'r' })).resolves.toMatchObject({
      tokenType: 'Bearer',
    });

    const strict = createClient({ clientSecret: CLIENT_SECRET, clockSkewSec: 5 });
    await expect(strict.oidc.oidcRefresh({ refreshToken: 'r' })).rejects.toMatchObject({
      reason: 'token_expired',
    });
  });

  it('rejects a malformed id_token that is not a well-formed JWS', async () => {
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      tokenHandler(state, () => HttpResponse.json(tokenResponse({ id_token: 'not-a-jwt-at-all' }))),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await expect(oidc.oidcRefresh({ refreshToken: 'r' })).rejects.toMatchObject({
      reason: 'invalid_alg',
    });
  });

  it('a 401 from /oauth2/introspect on a fully-wired client stays out of the §9 guard', async () => {
    // The realistic wiring: an AxiamClient installs the CSRF + reactive
    // 401->refresh interceptors on the session, and the OidcClient shares it.
    const state = createMockState();
    let sessionRefreshCalls = 0;
    server.use(
      discoveryHandler(state),
      http.post(`${BASE_URL}/api/v1/auth/refresh`, () => {
        sessionRefreshCalls += 1;
        return HttpResponse.json({ expires_in: 900 });
      }),
      http.post(INTROSPECT_ENDPOINT, () =>
        HttpResponse.json(
          { error: 'invalid_client', error_description: 'client authentication failed' },
          { status: 401 },
        ),
      ),
    );
    const client = createNodeClient({ baseUrl: BASE_URL, tenantId: TENANT_ID, orgId: ORG_ID });
    client.session.authenticated = true;
    const oidc = createOidcClient(client.session, {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
    });

    const error = await oidc.introspect({ token: 't' }).then(
      () => undefined,
      (err: unknown) => err,
    );

    // The interceptor mapped it (SKIP_REFRESH covers /oauth2/*) and the OIDC
    // layer passed the already-mapped AxiamError straight through.
    expect(error).toBeInstanceOf(OAuthProtocolError);
    expect((error as OAuthProtocolError).message).toBe('invalid_client: client authentication failed');
    expect(sessionRefreshCalls).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// §12.1 note 2 / §12.3 rule 4 — tenant_id is SET on the advertised endpoint,
// never appended to it.
// ---------------------------------------------------------------------------

describe('tenant_id on a discovery-advertised endpoint', () => {
  // Contract 1.42 made this reachable: the discovery document now publishes
  // `?tenant_id=<uuid>` inside the token / revocation / introspection / device
  // / PAR / end-session URLs whenever the discovery request named a tenant, or
  // the deployment sets `oauth2_default_tenant_id`. An SDK that *appends* its
  // own copy sends `?tenant_id=A&tenant_id=B`, and which one the server reads
  // is then a coin toss. `#endpointUrl` uses `URLSearchParams.set`, which
  // replaces every existing occurrence of the key and leaves the others alone
  // — this locks that in against a refactor to string concatenation.
  it('replaces a tenant_id the OP already advertised, and keeps other query parameters', async () => {
    const advertised = '99999999-9999-9999-9999-999999999999';
    const seen: string[][] = [];
    const others: (string | null)[] = [];
    server.use(
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        const url = new URL(request.url);
        seen.push(url.searchParams.getAll('tenant_id'));
        others.push(url.searchParams.get('deployment'));
        return HttpResponse.json(tokenResponse());
      }),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.loginClientCredentials({
      configuration: discoveryDocument({
        token_endpoint: `${TOKEN_ENDPOINT}?tenant_id=${advertised}&deployment=eu-1`,
      }),
    });

    // Exactly one, and it is the resolved value — what the caller actually
    // authenticated against wins over whatever the document happened to carry.
    expect(seen[0]).toEqual([TENANT_ID]);
    // RFC 6749 §3.2: the endpoint's own query component survives.
    expect(others[0]).toBe('eu-1');
  });
});
