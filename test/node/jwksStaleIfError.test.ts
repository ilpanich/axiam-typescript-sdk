// CONTRACT.md §12.4 rule 2, "Stale-if-error, bounded" and its conformance test (contract 1.69; D-10),
// against the §10 access-token verifier, which every path reusing the JWKS cache shares. The clock is
// mocked (Date only: the fetch timeout and MSW keep real timers), never slept.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type CryptoKey } from 'jose';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';

const BASE_URL = 'https://axiam-jwks-stale.test';
const TENANT = 'tenant-stale';
const T0 = Date.parse('2026-11-27T12:00:00.000Z');
const TTL = 300;

async function keyPair(kid: string): Promise<{ jwk: JWK; privateKey: CryptoKey }> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const jwk = await exportJWK(publicKey);
  jwk.kid = kid;
  jwk.alg = 'EdDSA';
  return { jwk, privateKey };
}
const token = (privateKey: CryptoKey, kid: string): Promise<string> =>
  new SignJWT({ tenant_id: TENANT })
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'at+jwt' })
    .setSubject('user-stale')
    .setIssuer('axiam')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);

describe('§12.4 rule 2 — bounded stale-if-error (conformance)', () => {
  const server = setupServer();
  beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(T0);
  });
  afterEach(() => {
    server.resetHandlers();
    vi.useRealTimers();
  });
  afterAll(() => server.close());

  const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 40)); // a usable held set does not wait for its refresh
  const at = (secondsAfterT0: number): void => void vi.setSystemTime(T0 + secondsAfterT0 * 1000);

  async function setup(failure: () => Response = () => HttpResponse.error() as unknown as Response) {
    const held = await keyPair('kid-held');
    const stranger = await keyPair('kid-stranger');
    const state = { fetches: 0, mode: 'ok' as 'ok' | 'fail' | 'empty' | 'notModified', conditional: [] as Array<string | null> };
    server.use(
      http.get(`${BASE_URL}${JWKS_PATH}`, ({ request }) => {
        state.fetches += 1;
        state.conditional.push(request.headers.get('if-none-match'));
        if (state.mode === 'fail') return failure();
        if (state.mode === 'empty') return HttpResponse.json({ keys: [] });
        if (state.mode === 'notModified') return new HttpResponse(null, { status: 304 });
        return HttpResponse.json({ keys: [held.jwk] }, { headers: { etag: '"v1"' } });
      }),
    );
    const verifier = createVerifier(BASE_URL);
    const heldToken = await token(held.privateKey, 'kid-held');
    const strangerToken = await token(stranger.privateKey, 'kid-stranger');
    const ok = async (t: string) => {
      try {
        return await verifier.verifyAccessToken(t, { expectedTenantId: TENANT });
      } finally {
        await settle();
      }
    };
    expect((await ok(heldToken)).sub).toBe('user-stale'); // fills the cache at t0
    expect(state.fetches).toBe(1);
    return { state, ok, heldToken, strangerToken };
  }

  it.each([
    ['a transport error', () => HttpResponse.error() as unknown as Response],
    ['a 500', () => new HttpResponse('boom', { status: 500 })],
    ['a body that is not a JWKS document', () => new HttpResponse('<html>', { status: 200 })],
    ['{"keys":[{}]}', () => HttpResponse.json({ keys: [{}] })],
    ['{"keys":[null]}', () => HttpResponse.json({ keys: [null] })],
    ['a 204', () => new HttpResponse(null, { status: 204 })],
  ])('every later fetch fails with %s: held kid accepted at TTL+1 s and TTL+250 s, unknown kid refused, held kid refused at TTL+301 s, recovers after one fetch', async (_l, failure) => {
    const { state, ok, heldToken, strangerToken } = await setup(failure);
    state.mode = 'fail';

    at(TTL + 1);
    expect((await ok(heldToken)).sub).toBe('user-stale');
    expect(state.fetches).toBe(2); // one failed refresh attempted

    at(TTL + 250);
    await expect(ok(strangerToken)).rejects.toThrow(); // unknown kid: refresh fails, token refused
    expect(state.fetches).toBe(3); // and that failed attempt was made, once
    expect((await ok(heldToken)).sub).toBe('user-stale'); // held kid still accepted
    expect(state.fetches).toBe(3);

    at(TTL + 301);
    await expect(ok(heldToken)).rejects.toThrow(/unavailable/); // past TTL + 300 s of the last SUCCESSFUL fetch

    // the server serves the set again; past the window, one fetch and the held kid is accepted
    state.mode = 'ok';
    at(TTL + 301 + 61);
    const before = state.fetches;
    expect((await ok(heldToken)).sub).toBe('user-stale');
    expect(state.fetches - before).toBe(1);
  });

  it('an EMPTY key set is a failed refresh: the held kid is still accepted at TTL+1 s and the set is not replaced', async () => {
    const { state, ok, heldToken } = await setup();
    state.mode = 'empty';
    at(TTL + 1);
    expect((await ok(heldToken)).sub).toBe('user-stale');
    expect(state.fetches).toBe(2);
    // not moved: the empty answer did not restart the anchor, so the bound still runs from t0
    at(TTL + 301);
    await expect(ok(heldToken)).rejects.toThrow();
  });

  it('a failed unknown-kid refresh never opens, restarts or extends the stale window', async () => {
    const { state, ok, heldToken, strangerToken } = await setup();
    state.mode = 'fail';
    at(TTL + 100);
    await expect(ok(strangerToken)).rejects.toThrow();
    at(TTL + 299);
    await expect(ok(strangerToken)).rejects.toThrow();
    expect((await ok(heldToken)).sub).toBe('user-stale');
    at(TTL + 301);
    await expect(ok(heldToken)).rejects.toThrow();
  });

  it('a 304 to the conditional refresh is a success: it re-confirms the held set and moves the anchor', async () => {
    const { state, ok, heldToken } = await setup();
    state.mode = 'notModified';
    at(TTL + 1);
    expect((await ok(heldToken)).sub).toBe('user-stale');
    expect(state.conditional[1]).toBe('"v1"'); // If-None-Match with the held set's ETag
    // every later fetch fails; without the 304 the bound (t0 + 600 s) would already have passed
    state.mode = 'fail';
    at(TTL + 301 + 60);
    expect((await ok(heldToken)).sub).toBe('user-stale');
  });

  it('the TTL is the advertised max-age, clamped to 300 s', async () => {
    const held = await keyPair('kid-held');
    let fetches = 0;
    let maxAge = 3600;
    server.use(
      http.get(`${BASE_URL}${JWKS_PATH}`, () => {
        fetches += 1;
        return HttpResponse.json({ keys: [held.jwk] }, { headers: { 'cache-control': `public, max-age=${maxAge}` } });
      }),
    );
    const verifier = createVerifier(BASE_URL);
    const t = await token(held.privateKey, 'kid-held');
    const v = async () => { await verifier.verifyAccessToken(t, { expectedTenantId: TENANT }); await settle(); };
    await v();
    at(TTL - 1);
    await v();
    expect(fetches).toBe(1); // within the TTL: no fetch
    at(TTL + 1);
    await v();
    expect(fetches).toBe(2); // 3600 s advertised, 300 s honoured

    maxAge = 100; // a smaller one is honoured
    at(TTL + 1 + TTL + 1); // 301 s after the second fetch
    await v();
    expect(fetches).toBe(3); // refreshed; this response advertised max-age=100
    at(TTL + 1 + TTL + 1 + 99);
    await v();
    expect(fetches).toBe(3); // 99 s: still within the 100 s advertised
    at(TTL + 1 + TTL + 1 + 101);
    await v();
    expect(fetches).toBe(4); // 101 s: past it
  });

  it('a cold cache with a failing endpoint costs one fetch per window, not one per token', async () => {
    const held = await keyPair('kid-held');
    let fetches = 0;
    server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => { fetches += 1; return new HttpResponse('x', { status: 500 }); }));
    const verifier = createVerifier(BASE_URL);
    const t = await token(held.privateKey, 'kid-held');
    for (let i = 0; i < 20; i += 1) {
      await expect(verifier.verifyAccessToken(t, { expectedTenantId: TENANT })).rejects.toThrow();
    }
    expect(fetches).toBe(1);
  });

  it('an ETag with a control character or over 256 bytes is not echoed; a clock moving backwards makes the set due, not fresh', async () => {
    const held = await keyPair('kid-held');
    const seen: Array<string | null> = [];
    let etag = 'x'.repeat(300);
    server.use(
      http.get(`${BASE_URL}${JWKS_PATH}`, ({ request }) => {
        seen.push(request.headers.get('if-none-match'));
        return HttpResponse.json({ keys: [held.jwk] }, { headers: { etag } });
      }),
    );
    const verifier = createVerifier(BASE_URL);
    const t = await token(held.privateKey, 'kid-held');
    const v = async () => { await verifier.verifyAccessToken(t, { expectedTenantId: TENANT }); await settle(); };
    await v();
    at(TTL + 1);
    await v();
    expect(seen).toEqual([null, null]); // 300-byte ETag never stored
    etag = '"ok"';
    at(2 * TTL + 100);
    await v();
    at(2 * TTL + 100 - 200); // clock moved backwards: negative age, refresh due
    await v();
    expect(seen.length).toBe(4);
    expect(seen[3]).toBe('"ok"');
  });

  it('entries are taken one by one: junk beside a valid JWK is skipped; an RSA-only set is a success (pinned)', async () => {
    const held = await keyPair('kid-held');
    const stranger = await keyPair('kid-stranger');
    let body: unknown = { keys: [null, {}, held.jwk, 7] };
    server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json(body as never)));
    const verifier = createVerifier(BASE_URL);
    const ok = async (t: string) => verifier.verifyAccessToken(t, { expectedTenantId: TENANT });
    expect((await ok(await token(held.privateKey, 'kid-held'))).sub).toBe('user-stale');
    // a fresh verifier served only an RSA JWK: the set is adopted (success), the kid is simply unknown
    body = { keys: [{ kty: 'RSA', kid: 'rsa', n: 'AQAB', e: 'AQAB' }] };
    const v2 = createVerifier(BASE_URL);
    // adopted: the refusal is the no-matching-key one, not the generic "unavailable"
    await expect(v2.verifyAccessToken(await token(stranger.privateKey, 'kid-stranger'), { expectedTenantId: TENANT })).rejects.toMatchObject({ code: 'ERR_JWKS_NO_MATCHING_KEY' });
    body = { keys: [held.jwk] };
    at(30); // inside the window: the RSA-only answer was a success, not a failure that reopens fetching
    await expect(v2.verifyAccessToken(await token(held.privateKey, 'kid-held'), { expectedTenantId: TENANT })).rejects.toMatchObject({ code: 'ERR_JWKS_NO_MATCHING_KEY' });
  });

  it('a clock stepped back: refresh due, and held keys are not trusted while the age is negative', async () => {
    const { state, ok, heldToken } = await setup();
    state.mode = 'fail';
    at(-120);
    await expect(ok(heldToken)).rejects.toThrow(/unavailable/);
  });

  it('a usable held set never waits for an in-flight refresh that hangs', async () => {
    const { state, ok, heldToken } = await setup();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    server.use(http.get(`${BASE_URL}${JWKS_PATH}`, async () => { state.fetches += 1; await gate; return new HttpResponse('x', { status: 500 }); }));
    at(TTL + 1);
    const outcome = await Promise.race([ok(heldToken).then(() => 'accepted'), new Promise((r) => setTimeout(() => r('waited'), 1500))]);
    release();
    expect(outcome).toBe('accepted');
  });
});
