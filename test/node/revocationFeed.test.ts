// CONTRACT.md §10.4 — the optional session-revocation feed (contract 1.44,
// AXIAM threats T-39 and T-143).
//
// Two properties, and the second is what makes the feature safe to ship. A
// revoked `sid` is rejected AFTER ONE POLL and not before, which pins that the
// guard reads a cached set rather than fetching per request. And a guard with
// the feature OFF, or with it on and the feed unreachable, behaves
// byte-for-byte as it does today — asserted by counting fetches, so "does not
// fetch" is proven rather than claimed.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/index.js';
import { createVerifier, JWKS_PATH } from '../../src/node/jwks.js';
import { RevocationFeed } from '../../src/node/revocationFeed.js';
import { authenticateRequest, type VerifiableSession } from '../../src/middleware/verifyCore.js';

const BASE_URL = 'https://axiam-104.test';
const FEED_PATH = '/oauth2/revocations';
const KID = 'sec-104-kid';
const TENANT = 'tenant-alpha';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const now = () => Math.floor(Date.now() / 1000);

async function serveJwks(): Promise<CryptoKey> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const jwk = await exportJWK(publicKey);
  jwk.kid = KID;
  jwk.alg = 'EdDSA';
  server.use(http.get(`${BASE_URL}${JWKS_PATH}`, () => HttpResponse.json({ keys: [jwk] })));
  return privateKey;
}

function sign(key: CryptoKey, payload: JWTPayload): Promise<string> {
  return new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', kid: KID }).sign(key);
}

/** A token satisfying every §10.1 rule, naming `sid`. */
function tokenPayload(sid?: string): JWTPayload {
  return {
    sub: 'user-1',
    tenant_id: TENANT,
    iss: 'https://iam.example.com',
    aud: 'axiam:user',
    scope: 'read',
    exp: now() + 3600,
    jti: 'jti-1',
    ...(sid === undefined ? {} : { sid }),
  };
}

/** Serve the feed, counting fetches. The counter proves the poll interval. */
function serveFeed(body: unknown): { fetches: () => number } {
  let count = 0;
  server.use(
    http.get(`${BASE_URL}${FEED_PATH}`, () => {
      count += 1;
      return HttpResponse.json(body as Record<string, unknown>);
    }),
  );
  return { fetches: () => count };
}

function feedDocument(revokedSids: string[]) {
  return {
    alg: 'SHA-256',
    issued_at: now(),
    ttl: 900,
    revoked: revokedSids.map((s) => RevocationFeed.entryFor(s)),
  };
}

function session(overrides: Partial<VerifiableSession> = {}): VerifiableSession {
  return {
    jwksVerifier: createVerifier(BASE_URL),
    tenantHeaderValue: TENANT,
    ...overrides,
  };
}

function withFeed(overrides: Partial<VerifiableSession> = {}): VerifiableSession {
  return session({
    revocationFeed: new RevocationFeed(BASE_URL),
    ...overrides,
  });
}

describe('CONTRACT.md §10.4 the session-revocation feed', () => {
  it('computes the entry the server publishes', () => {
    // The wire format, pinned against the server's own vector. Eleven SDKs
    // compute this independently; a change here is a change every one of them
    // silently stops matching, which presents as "revocation stopped working"
    // with nothing failing.
    const entry = RevocationFeed.entryFor('6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b');
    expect(entry).toBe('i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ');
    expect(entry).toHaveLength(43);
    expect(entry).not.toMatch(/[+/=]/);
  });

  it('hashes the claim as read, never a normalised UUID', () => {
    // Parsing and re-rendering would make the answer depend on this SDK's
    // parser rather than on the feed.
    expect(RevocationFeed.entryFor('6F3E0A5C-1B2D-4E8F-9A7B-0C1D2E3F4A5B')).not.toBe(
      RevocationFeed.entryFor('6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b'),
    );
  });

  it('rejects a session the feed lists', async () => {
    const key = await serveJwks();
    serveFeed(feedDocument(['session-revoked']));
    const token = await sign(key, tokenPayload('session-revoked'));

    await expect(authenticateRequest(withFeed(), token)).rejects.toBeInstanceOf(AuthError);
  });

  it('admits a session the feed does not list', async () => {
    const key = await serveJwks();
    serveFeed(feedDocument(['someone-else']));
    const token = await sign(key, tokenPayload('session-live'));

    await expect(authenticateRequest(withFeed(), token)).resolves.toMatchObject({
      userId: 'user-1',
    });
  });

  it('polls on an interval and never per request (§10.4 rule 2)', async () => {
    const key = await serveJwks();
    const feed = serveFeed(feedDocument([]));
    const s = withFeed();

    for (let i = 0; i < 10; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await authenticateRequest(s, await sign(key, tokenPayload(`session-${i}`)));
    }

    expect(feed.fetches()).toBe(1);
  });

  it('never matches a token with no sid (§10.4 rule 6)', async () => {
    const key = await serveJwks();
    // The feed lists the token's own `jti`, so an implementation that fell
    // back to it would reject here.
    serveFeed(feedDocument(['jti-1']));
    const token = await sign(key, tokenPayload(undefined));

    await expect(authenticateRequest(withFeed(), token)).resolves.toMatchObject({
      userId: 'user-1',
    });
  });

  it('with the feature off, fetches nothing and rejects nothing', async () => {
    // I4 twin. The default guard is unchanged by contract 1.44, and the
    // endpoint is never touched — counted, because "does not fetch" is the
    // claim and only a counter proves it.
    const key = await serveJwks();
    const feed = serveFeed(feedDocument(['session-revoked']));
    const token = await sign(key, tokenPayload('session-revoked'));

    await expect(authenticateRequest(session(), token)).resolves.toMatchObject({
      userId: 'user-1',
    });
    expect(feed.fetches()).toBe(0);
  });

  it('treats an unreachable feed as no feed at all (§10.4 rule 3)', async () => {
    // The load-bearing rule. NOT "as an empty list" — an empty list asserts
    // that nothing has been revoked, which is a guard silently honouring none.
    const key = await serveJwks();
    server.use(http.get(`${BASE_URL}${FEED_PATH}`, () => new HttpResponse(null, { status: 503 })));
    const token = await sign(key, tokenPayload('session-live'));

    await expect(authenticateRequest(withFeed(), token)).resolves.toMatchObject({
      userId: 'user-1',
    });
  });

  it('treats an unknown alg as no feed at all', async () => {
    const key = await serveJwks();
    serveFeed({
      alg: 'BLAKE3',
      issued_at: now(),
      ttl: 900,
      revoked: [RevocationFeed.entryFor('session-revoked')],
    });
    const token = await sign(key, tokenPayload('session-revoked'));

    await expect(authenticateRequest(withFeed(), token)).resolves.toMatchObject({
      userId: 'user-1',
    });
  });

  it('treats an unparseable document as no feed at all', async () => {
    const key = await serveJwks();
    server.use(
      http.get(`${BASE_URL}${FEED_PATH}`, () => HttpResponse.text('<html>not found</html>')),
    );
    const token = await sign(key, tokenPayload('session-live'));

    await expect(authenticateRequest(withFeed(), token)).resolves.toMatchObject({
      userId: 'user-1',
    });
  });
});
