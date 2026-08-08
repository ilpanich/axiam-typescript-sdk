// RP-initiated and back-channel logout — CONTRACT.md §12.7.
//
// The §12.7.6 required tests. The `verifyLogoutToken` half carries the
// security weight: its input arrives unsolicited, from the network, and
// instructs the RP to terminate a session — so each rejection test names the
// attack it prevents rather than merely asserting an error.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AuthError, Sensitive } from '../../src/core/index.js';
import {
  BASE_URL,
  CLIENT_ID,
  createClient,
  createMockState,
  createServer,
  discoveryDocumentWithoutOptionalEndpoints,
  discoveryHandler,
  generateSigningKey,
  ISSUER,
  jwksHandler,
  LOGOUT_JTI,
  LOGOUT_SID,
  signIdToken,
  signLogoutToken,
  type SigningKey,
} from './oidcTestKit.js';

const ID_TOKEN = 'the-users-id-token';

const server = createServer();
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' });
});
afterEach(() => {
  server.resetHandlers();
});
afterAll(() => {
  server.close();
});

function queryOf(url: string): URLSearchParams {
  return new URL(url).searchParams;
}

/** Mount discovery only — enough for `logoutUrl`, which does no other I/O. */
function mountDiscovery(): void {
  server.use(discoveryHandler(createMockState()));
}

/** Mount discovery + a JWKS publishing `key`. */
async function mountLogoutFixture(kid = 'logout-key'): Promise<SigningKey> {
  const key = await generateSigningKey(kid);
  server.use(discoveryHandler(createMockState()), jwksHandler(createMockState(), [key.jwk]));
  return key;
}

// ---------------------------------------------------------------------------
// §12.7.2 logoutUrl
// ---------------------------------------------------------------------------

describe('logoutUrl (§12.7.2)', () => {
  it('uses the discovered endpoint rather than concatenating onto the issuer', async () => {
    mountDiscovery();
    const { oidc } = createClient();

    const url = await oidc.logoutUrl({ idToken: new Sensitive(ID_TOKEN) });

    // Rule 1. The fixture's issuer is deliberately a DIFFERENT origin from the
    // server, so a naive `${issuer}/oauth2/end_session` would point at the
    // wrong host — exactly how concatenation breaks against a non-AXIAM OP.
    expect(url.startsWith(BASE_URL)).toBe(true);
    expect(url.startsWith(ISSUER)).toBe(false);
    expect(url).toContain('/oauth2/end_session');
  });

  it('carries the hint and omits what was not supplied', async () => {
    mountDiscovery();
    const { oidc } = createClient();

    const bare = queryOf(await oidc.logoutUrl({ idToken: ID_TOKEN }));
    expect(bare.get('id_token_hint')).toBe(ID_TOKEN);
    expect(bare.get('post_logout_redirect_uri')).toBeNull();
    expect(bare.get('state')).toBeNull();

    const full = queryOf(
      await oidc.logoutUrl({
        idToken: ID_TOKEN,
        postLogoutRedirectUri: 'https://app.example.com/bye',
        state: 'caller-generated-state',
      }),
    );
    expect(full.get('post_logout_redirect_uri')).toBe('https://app.example.com/bye');
    // Rule 2: passed through unmodified — the SDK never invents one, because
    // the value only means something to the caller.
    expect(full.get('state')).toBe('caller-generated-state');
  });

  it('does not pre-validate the redirect against a local list', async () => {
    mountDiscovery();
    const { oidc } = createClient();

    // Rule 3: the allow-list lives in the client's server-side registration. A
    // client-side copy would drift and reject a URI an operator had just
    // registered, so an arbitrary URI must pass through.
    const url = await oidc.logoutUrl({
      idToken: ID_TOKEN,
      postLogoutRedirectUri: 'https://somewhere-else.example/x',
    });

    expect(queryOf(url).get('post_logout_redirect_uri')).toBe('https://somewhere-else.example/x');
  });

  it('errors when the server advertises no end_session_endpoint', async () => {
    server.use(discoveryHandler(createMockState(), discoveryDocumentWithoutOptionalEndpoints()));
    const { oidc } = createClient();

    await expect(oidc.logoutUrl({ idToken: ID_TOKEN })).rejects.toThrow(AuthError);
    await expect(oidc.logoutUrl({ idToken: ID_TOKEN })).rejects.toThrow(/end_session_endpoint/);
  });
});

// ---------------------------------------------------------------------------
// §12.7.3 verifyLogoutToken
// ---------------------------------------------------------------------------

describe('verifyLogoutToken (§12.7.3)', () => {
  it('verifies a valid token and surfaces sid, sub and jti', async () => {
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key);
    const { oidc } = createClient();

    const verified = await oidc.verifyLogoutToken(token);

    // Not a bare boolean: the RP has to know WHICH session to end, and a
    // verifier that only says "valid" forces the caller to re-parse the token
    // themselves with none of these checks.
    expect(verified.sid).toBe(LOGOUT_SID);
    expect(verified.sub).toBe('user-1');
    expect(verified.jti).toBe(LOGOUT_JTI);
  });

  it('rejects an ID token replayed as a logout token', async () => {
    // The attack rules 3 and 4 exist to stop, asserted with a real,
    // otherwise-valid ID token rather than a synthetic mutation: correctly
    // signed by a published key, right issuer and audience, unexpired. Only
    // the missing `events` and the present `nonce` distinguish it.
    const key = await mountLogoutFixture();
    const idToken = await signIdToken(key);
    const { oidc } = createClient();

    await expect(oidc.verifyLogoutToken(idToken)).rejects.toThrow(AuthError);
  });

  it('rejects a token with no events member', async () => {
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key, { omitEvents: true });
    const { oidc } = createClient();

    await expect(oidc.verifyLogoutToken(token)).rejects.toThrow(/events/);
  });

  it('rejects a token carrying some other event', async () => {
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key, { wrongEvent: true });
    const { oidc } = createClient();

    await expect(oidc.verifyLogoutToken(token)).rejects.toThrow(AuthError);
  });

  it('rejects a nonce rather than ignoring it', async () => {
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key, { nonce: 'n-0S6_WzA2Mj' });
    const { oidc } = createClient();

    await expect(oidc.verifyLogoutToken(token)).rejects.toThrow(/nonce/);
  });

  it('rejects a token naming neither sid nor sub', async () => {
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key, { sid: null, omitSub: true });
    const { oidc } = createClient();

    await expect(oidc.verifyLogoutToken(token)).rejects.toThrow(AuthError);
  });

  it('accepts sub alone but prefers sid when present', async () => {
    const key = await mountLogoutFixture();
    const { oidc } = createClient();

    const subOnly = await signLogoutToken(key, { sid: null });
    const first = await oidc.verifyLogoutToken(subOnly);
    expect(first.sid).toBeUndefined();
    expect(first.sub).toBe('user-1');

    // With `sid` present the RP must end THAT session only — falling back to
    // "every session for sub" is over-reach the server itself refuses.
    const both = await oidc.verifyLogoutToken(await signLogoutToken(key));
    expect(both.sid).toBe(LOGOUT_SID);
  });

  it('rejects a token minted for another client', async () => {
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key, { audience: 'some-other-rp' });
    const { oidc } = createClient();

    await expect(oidc.verifyLogoutToken(token)).rejects.toThrow(/audience/);
    expect(CLIENT_ID).not.toBe('some-other-rp');
  });

  it('rejects a token from another issuer', async () => {
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key, { issuer: 'https://evil.example.com' });
    const { oidc } = createClient();

    await expect(oidc.verifyLogoutToken(token)).rejects.toThrow(/issuer/);
  });

  it('rejects a token signed by an unpublished key', async () => {
    await mountLogoutFixture();
    const rogue = await generateSigningKey('rogue-key');
    const token = await signLogoutToken(rogue);
    const { oidc } = createClient();

    // The signature is what makes the token a statement rather than a request.
    await expect(oidc.verifyLogoutToken(token)).rejects.toThrow();
  });

  it('rejects a token with no kid header', async () => {
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key, { omitKid: true });
    const { oidc } = createClient();

    // Same discipline as §12.4 rule 2: no "the only key" fallback, so key
    // rotation cannot be defeated by omitting the header.
    await expect(oidc.verifyLogoutToken(token)).rejects.toThrow(/kid/);
  });

  it('rejects an expired token', async () => {
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key, { expiresInSec: -600, issuedAtSec: 1 });
    const { oidc } = createClient();

    // A long-lived logout token is a replayable session-termination command.
    await expect(oidc.verifyLogoutToken(token)).rejects.toThrow();
  });

  it('verifies the same token twice without raising', async () => {
    // Rule 7. Delivery is at-least-once with retry, so a valid token
    // legitimately arrives twice — that is a retry, not an attack. An SDK that
    // dedupped internally would have no durable store and would silently drop
    // a real second logout after a restart, so `jti` is surfaced for the RP to
    // dedup on and never consumed here.
    const key = await mountLogoutFixture();
    const token = await signLogoutToken(key);
    const { oidc } = createClient();

    const first = await oidc.verifyLogoutToken(token);
    const second = await oidc.verifyLogoutToken(token);

    expect(second).toEqual(first);
    expect(first.jti).toBe(LOGOUT_JTI);
  });

  it('never echoes the token on failure', async () => {
    await mountLogoutFixture();
    const rogue = await generateSigningKey('rogue-key');
    const token = await signLogoutToken(rogue);
    const { oidc } = createClient();

    const err = await oidc.verifyLogoutToken(token).catch((e: unknown) => e);
    const rendered = `${String(err)}${(err as Error).stack ?? ''}`;
    expect(rendered).not.toContain(token);
  });
});
