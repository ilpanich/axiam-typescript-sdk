// SA-20 ride-along hardening, each pinned on its own:
//
// 1. A non-finite ID-token clock skew is refused (`node/oidcIdToken.ts`). NaN
//    survived the [0, 60] clamp (`Math.min(Math.max(NaN, 0), 60)` is NaN), and
//    every comparison against NaN is false, so `exp`/`iat` stopped expiring.
// 2. `MemoryOidcStateStore` is capped, so an unauthenticated login route cannot
//    grow it without bound inside the 10-minute TTL.
// 3. `SharedSession.isForeignHost` compares the origin, not the host, so a
//    same-host URL on another scheme (`http://` against an `https://` base) is
//    foreign and never receives the tenant header or the CSRF token.

import { describe, expect, it } from 'vitest';
import { Sensitive } from '../../src/core/index.js';
import { checkIdTokenClaims, resolveClockSkewSec } from '../../src/node/oidcIdToken.js';
import { MemoryOidcStateStore, OIDC_STATE_MAX_ENTRIES } from '../../src/node/oidcState.js';
import { createSession } from '../../src/rest/session.js';
import { createClient } from './oidcTestKit.js';

describe('ID-token clock skew must be finite', () => {
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    'resolveClockSkewSec(%s) is refused',
    (value) => {
      expect(() => resolveClockSkewSec(value)).toThrow();
    },
  );

  it('finite values are still clamped into [0, 60], not refused (§12.4 rule 5)', () => {
    expect(resolveClockSkewSec(undefined)).toBe(60);
    expect(resolveClockSkewSec(30)).toBe(30);
    expect(resolveClockSkewSec(3600)).toBe(60);
    expect(resolveClockSkewSec(-5)).toBe(0);
  });

  it('an expired ID token is never accepted under a NaN skew', () => {
    const nowSec = Math.floor(Date.now() / 1000);
    expect(() =>
      checkIdTokenClaims(
        { iss: 'https://iss', aud: 'rp', sub: 'u', nonce: 'n', iat: nowSec - 7200, exp: nowSec - 3600 },
        { issuer: 'https://iss', clientId: 'rp', nonce: 'n', clockSkewSec: Number.NaN },
      ),
    ).toThrow();
  });

  it('an OidcClient configured with a NaN clockSkewSec is refused at construction', () => {
    expect(() => createClient({ clockSkewSec: Number.NaN })).toThrow();
  });
});

describe('MemoryOidcStateStore is bounded', () => {
  const entry = (state: string) => ({
    state,
    nonce: `${state}-n`,
    codeVerifier: new Sensitive('v'),
    redirectUri: 'https://app.example.com/cb',
  });

  it('never holds more than its configured maximum, evicting the oldest entry first', async () => {
    const store = new MemoryOidcStateStore(undefined, 3);
    for (const s of ['a', 'b', 'c', 'd']) await store.save(entry(s));
    expect(store.size).toBe(3);
    expect(await store.consume('a')).toBeUndefined();
    expect((await store.consume('d'))?.state).toBe('d');
  });

  it('has a finite default cap', async () => {
    expect(Number.isFinite(OIDC_STATE_MAX_ENTRIES)).toBe(true);
    const store = new MemoryOidcStateStore();
    for (let i = 0; i <= OIDC_STATE_MAX_ENTRIES; i += 1) await store.save(entry(`s${i}`));
    expect(store.size).toBe(OIDC_STATE_MAX_ENTRIES);
  });
});

describe('SharedSession.isForeignHost compares the origin', () => {
  const session = createSession({ baseUrl: 'https://axiam-origin.test', tenantSlug: 'acme' });

  it('the same host over plain http is foreign', () => {
    expect(session.isForeignHost('http://axiam-origin.test/api/v1/users')).toBe(true);
  });

  it('the same origin with an explicit default port is not foreign', () => {
    expect(session.isForeignHost('https://axiam-origin.test:443/api/v1/users')).toBe(false);
  });
});
