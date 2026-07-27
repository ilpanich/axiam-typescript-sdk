// Sensitive<T> coverage of the five §12.5 secret fields, across all three
// JavaScript stringification surfaces: toString(), JSON.stringify() and
// console.log/util.inspect (CONTRACT.md §7, §12.3 rule 2, §12.5).

import { inspect } from 'node:util';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { HttpResponse } from 'msw';
import { REDACTED, Sensitive } from '../../src/core/index.js';
import {
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  discoveryHandler,
  generateSigningKey,
  jwksHandler,
  REDIRECT_URI,
  signIdToken,
  tokenHandler,
  tokenResponse,
} from './oidcTestKit.js';
import { MemoryOidcStateStore } from '../../src/node/oidcState.js';
import { discoveryDocument } from './oidcTestKit.js';

const NONCE = 'nonce-for-redaction-test';
const server = createServer();

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/** Every way a value can leak into a log line or a diagnostic dump. */
function stringificationsOf(value: unknown): string[] {
  return [String(value), JSON.stringify(value) ?? '', inspect(value, { depth: 5 })];
}

describe('OidcTokenSet redaction (§12.5)', () => {
  it('redacts accessToken, refreshToken and idToken across toString/JSON/inspect', async () => {
    const key = await generateSigningKey('redaction-kid');
    const idToken = await signIdToken(key, { nonce: NONCE });
    const state = createMockState();
    server.use(
      discoveryHandler(state),
      jwksHandler(state, [key.jwk]),
      tokenHandler(state, () =>
        HttpResponse.json(
          tokenResponse({
            access_token: 'SECRET-ACCESS',
            refresh_token: 'SECRET-REFRESH',
            id_token: idToken,
          }),
        ),
      ),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.oidcExchange({
      code: 'c',
      codeVerifier: 'SECRET-VERIFIER',
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
    });

    for (const rendered of stringificationsOf(tokens)) {
      expect(rendered).not.toContain('SECRET-ACCESS');
      expect(rendered).not.toContain('SECRET-REFRESH');
      expect(rendered).not.toContain(idToken);
    }
    // Each wrapper individually redacts too.
    expect(String(tokens.accessToken)).toBe(REDACTED);
    expect(JSON.stringify(tokens.refreshToken)).toBe(`"${REDACTED}"`);
    expect(inspect(tokens.idToken)).toBe(REDACTED);
    // …and the raw values are still reachable for SDK-internal use.
    expect(tokens.accessToken.expose()).toBe('SECRET-ACCESS');
  });

  it('leaves the non-secret fields readable (§12.3 rule 2)', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state), tokenHandler(state, () => HttpResponse.json(tokenResponse())));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const tokens = await oidc.loginClientCredentials();
    const serialized = JSON.stringify(tokens);

    expect(serialized).toContain('Bearer');
    expect(serialized).toContain('900');
  });
});

describe('AuthorizationRequest redaction (§12.5)', () => {
  it('redacts the code verifier but exposes state and nonce as plain strings', () => {
    const { oidc } = createClient();
    const request = oidc.oidcBegin({ configuration: discoveryDocument(), redirectUri: REDIRECT_URI });

    for (const rendered of stringificationsOf(request)) {
      expect(rendered).not.toContain(request.codeVerifier.expose());
    }
    // state/nonce are NOT secrets — they must remain plainly visible, since a
    // caller has to compare them and they travel in the browser's URL bar.
    expect(JSON.stringify(request)).toContain(request.state);
    expect(JSON.stringify(request)).toContain(request.nonce);
    expect(typeof request.state).toBe('string');
    expect(typeof request.nonce).toBe('string');
  });
});

describe('client secret and verifier redaction (§12.5)', () => {
  it('never leaks a Sensitive-wrapped client secret through a stringification', () => {
    const secret = new Sensitive('SUPER-SECRET-CLIENT-SECRET');
    for (const rendered of stringificationsOf({ clientSecret: secret })) {
      expect(rendered).not.toContain('SUPER-SECRET-CLIENT-SECRET');
    }
  });

  it('keeps the verifier redacted while parked in a state store', async () => {
    const store = new MemoryOidcStateStore();
    const { oidc } = createClient();
    const request = oidc.oidcBegin({ configuration: discoveryDocument(), redirectUri: REDIRECT_URI });
    await store.save({
      state: request.state,
      nonce: request.nonce,
      codeVerifier: request.codeVerifier,
      redirectUri: REDIRECT_URI,
    });

    const consumed = await store.consume(request.state);
    for (const rendered of stringificationsOf(consumed)) {
      expect(rendered).not.toContain(request.codeVerifier.expose());
    }
  });

  it('keeps the secret out of an OidcClient instance dump', async () => {
    const state = createMockState();
    server.use(discoveryHandler(state));
    const { oidc } = createClient({ clientSecret: 'SECRET-IN-OPTIONS' });

    // Private class fields (#options) are not reachable from inspect/JSON at
    // all, so no configuration value can leak through a diagnostic dump.
    for (const rendered of stringificationsOf(oidc)) {
      expect(rendered).not.toContain('SECRET-IN-OPTIONS');
    }
  });
});
