// CONTRACT.md §12.4 rule 2, "Conformance test for the window" (contract 1.68;
// C5; review gate TYP-R1-3), against the §10 access-token verifier
// (`createVerifier` / `verifyAccessToken`), which every path that verifies an
// AXIAM access token reuses:
//
// - against a counting mock server and a WARM cache, 50 tokens each carrying
//   a different unknown `kid`, presented within one window, cause at most one
//   JWKS fetch, and every one is rejected;
// - then, with the clock moved past the window (mocked, never slept) and the
//   server serving a rotated set, a token with the new `kid` is accepted after
//   exactly one fetch — so the rule is not "fixed" into "never re-fetch".
//
// The §10 verifier is bound to a JWKS URI directly; it reads no discovery
// document, so the rule's discovery-cache clause has nothing to count here.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type CryptoKey } from 'jose';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';

const BASE_URL = 'https://axiam-jwks-window.test';
const TENANT = 'tenant-window';

async function keyPair(kid: string): Promise<{ jwk: JWK; privateKey: CryptoKey }> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const jwk = await exportJWK(publicKey);
  jwk.kid = kid;
  jwk.alg = 'EdDSA';
  return { jwk, privateKey };
}

function accessToken(privateKey: CryptoKey, kid: string): Promise<string> {
  return new SignJWT({ tenant_id: TENANT })
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'at+jwt' })
    .setSubject('user-window')
    .setIssuer('axiam')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);
}

describe('§12.4 rule 2 — the unknown-kid re-fetch window (conformance)', () => {
  const server = setupServer();
  beforeAll(() => server.listen({ onUnhandledFrame: 'error' }));
  afterEach(() => {
    server.resetHandlers();
    vi.useRealTimers();
  });
  afterAll(() => server.close());

  it('50 unknown kids in one window cost at most one fetch and are all rejected; past the window a rotated kid is accepted after one fetch', async () => {
    // Only Date is mocked: jose's cooldown reads Date.now(), while its fetch
    // timeout and MSW keep real timers.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-11-22T12:00:00.000Z'));

    const served = await keyPair('kid-served');
    const rotated = await keyPair('kid-rotated');
    let keys: JWK[] = [served.jwk];
    let fetches = 0;
    server.use(
      http.get(`${BASE_URL}${JWKS_PATH}`, () => {
        fetches += 1;
        return HttpResponse.json({ keys });
      }),
    );

    const verifier = createVerifier(BASE_URL);

    // Warm the cache: one token with the served kid.
    const warm = await verifier.verifyAccessToken(await accessToken(served.privateKey, 'kid-served'), {
      expectedTenantId: TENANT,
    });
    expect(warm.sub).toBe('user-window');
    expect(fetches).toBe(1);

    // 50 tokens, each with a different unknown kid, within one window (the
    // clock is held still; they are presented one after another).
    const stranger = await keyPair('unused');
    let rejected = 0;
    for (let i = 0; i < 50; i += 1) {
      const token = await accessToken(stranger.privateKey, `kid-unknown-${i}`);
      await expect(verifier.verifyAccessToken(token, { expectedTenantId: TENANT })).rejects.toThrow();
      rejected += 1;
    }
    expect(rejected).toBe(50);
    expect(fetches - 1).toBeLessThanOrEqual(1);
    const afterBurst = fetches;

    // Past the window (61 s covers any window of the rule's 30–60 s), the
    // server rotates its set: the new kid is accepted after one fetch.
    vi.setSystemTime(new Date('2026-11-22T12:01:01.000Z'));
    keys = [served.jwk, rotated.jwk];
    const claims = await verifier.verifyAccessToken(await accessToken(rotated.privateKey, 'kid-rotated'), {
      expectedTenantId: TENANT,
    });
    expect(claims.sub).toBe('user-window');
    expect(fetches - afterBurst).toBe(1);
  });
});
