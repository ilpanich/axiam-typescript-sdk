// oidcBegin: authorization-request construction (CONTRACT.md §12.1 rules 1–5).
// Pure local computation — these tests make no HTTP request at all, which is
// itself the assertion for "no network I/O".

import { describe, expect, it } from 'vitest';
import { Sensitive } from '../../src/core/index.js';
import { computeCodeChallenge } from '../../src/node/oidcPkce.js';
import { CLIENT_ID, createClient, discoveryDocument, REDIRECT_URI } from './oidcTestKit.js';

/** Parse an authorization URL into its query parameters. */
function queryOf(url: string): URLSearchParams {
  return new URL(url).searchParams;
}

describe('oidcBegin (§12.1)', () => {
  it('builds the URL from the discovery document with exactly the eight mandated parameters', () => {
    const { oidc } = createClient();
    const configuration = discoveryDocument();

    const request = oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI });
    const url = new URL(request.url);
    const query = url.searchParams;

    expect(`${url.origin}${url.pathname}`).toBe(configuration.authorization_endpoint);
    expect([...query.keys()].sort()).toEqual([
      'client_id',
      'code_challenge',
      'code_challenge_method',
      'nonce',
      'redirect_uri',
      'response_type',
      'scope',
      'state',
    ]);
    expect(query.get('response_type')).toBe('code');
    expect(query.get('client_id')).toBe(CLIENT_ID);
    expect(query.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(query.get('state')).toBe(request.state);
    expect(query.get('nonce')).toBe(request.nonce);
  });

  it('always sends code_challenge_method=S256 and the challenge derived from the verifier', () => {
    const { oidc } = createClient();
    const request = oidc.oidcBegin({ configuration: discoveryDocument(), redirectUri: REDIRECT_URI });
    const query = queryOf(request.url);

    expect(query.get('code_challenge_method')).toBe('S256');
    expect(query.get('code_challenge')).toBe(computeCodeChallenge(request.codeVerifier.expose()));
    // The verifier itself never appears in the URL.
    expect(request.url).not.toContain(request.codeVerifier.expose());
  });

  it('never emits code_challenge_method=plain, whatever the caller asks for', () => {
    const { oidc } = createClient();
    // `code_challenge_method` is one of the eight reserved parameters, so an
    // attempt to downgrade to `plain` is rejected outright rather than honoured.
    expect(() =>
      oidc.oidcBegin({
        configuration: discoveryDocument(),
        redirectUri: REDIRECT_URI,
        extraParams: { code_challenge_method: 'plain' },
      }),
    ).toThrow(/may not override/i);
  });

  it('adds the openid scope when the caller omits it, and does not duplicate it', () => {
    const { oidc } = createClient();
    const configuration = discoveryDocument();

    expect(queryOf(oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI }).url).get('scope')).toBe(
      'openid',
    );
    expect(
      queryOf(oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI, scope: 'profile email' }).url).get(
        'scope',
      ),
    ).toBe('openid profile email');
    expect(
      queryOf(
        oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI, scope: ['openid', 'profile'] }).url,
      ).get('scope'),
    ).toBe('openid profile');
    expect(
      queryOf(
        oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI, scope: 'openid openid profile' }).url,
      ).get('scope'),
    ).toBe('openid profile');
  });

  it('percent-encodes the scope separator as %20 rather than +', () => {
    const { oidc } = createClient();
    const request = oidc.oidcBegin({
      configuration: discoveryDocument(),
      redirectUri: REDIRECT_URI,
      scope: 'openid profile',
    });

    expect(request.url).toContain('scope=openid%20profile');
    expect(request.url).not.toContain('scope=openid+profile');
  });

  it('accepts extra caller-supplied parameters and preserves ones already on the endpoint', () => {
    const { oidc } = createClient();
    const configuration = discoveryDocument({
      authorization_endpoint: 'https://axiam-oidc.test/oauth2/authorize?tenant_hint=acme',
    });

    const query = queryOf(
      oidc.oidcBegin({
        configuration,
        redirectUri: REDIRECT_URI,
        extraParams: { prompt: 'login', login_hint: 'user@example.com' },
      }).url,
    );

    expect(query.get('prompt')).toBe('login');
    expect(query.get('login_hint')).toBe('user@example.com');
    expect(query.get('tenant_hint')).toBe('acme');
    expect(query.get('response_type')).toBe('code');
  });

  it.each([
    'response_type',
    'client_id',
    'redirect_uri',
    'scope',
    'state',
    'nonce',
    'code_challenge',
    'code_challenge_method',
  ])('rejects an extraParams override of the SDK-owned "%s" parameter', (name) => {
    const { oidc } = createClient();
    expect(() =>
      oidc.oidcBegin({
        configuration: discoveryDocument(),
        redirectUri: REDIRECT_URI,
        extraParams: { [name]: 'attacker-value' },
      }),
    ).toThrow(/CONTRACT.md §12.1 rule 5/);
  });

  it('returns state/nonce as plain strings with >= 128 bits of entropy (§12.3 rule 2)', () => {
    const { oidc } = createClient();
    const request = oidc.oidcBegin({ configuration: discoveryDocument(), redirectUri: REDIRECT_URI });

    expect(typeof request.state).toBe('string');
    expect(typeof request.nonce).toBe('string');
    expect(Buffer.from(request.state, 'base64url').length * 8).toBeGreaterThanOrEqual(128);
    expect(Buffer.from(request.nonce, 'base64url').length * 8).toBeGreaterThanOrEqual(128);
    expect(request.state).not.toContain('=');
    expect(request.nonce).not.toContain('=');
    // The verifier, by contrast, is Sensitive-wrapped (§12.5).
    expect(request.codeVerifier).toBeInstanceOf(Sensitive);
  });

  it('generates a fresh state, nonce and verifier on every call (no reuse, nothing stored)', () => {
    const { oidc } = createClient();
    const configuration = discoveryDocument();
    const requests = Array.from({ length: 25 }, () =>
      oidc.oidcBegin({ configuration, redirectUri: REDIRECT_URI }),
    );

    expect(new Set(requests.map((r) => r.state)).size).toBe(25);
    expect(new Set(requests.map((r) => r.nonce)).size).toBe(25);
    expect(new Set(requests.map((r) => r.codeVerifier.expose())).size).toBe(25);
    // state and nonce are independently generated, never the same value.
    for (const request of requests) {
      expect(request.state).not.toBe(request.nonce);
    }
  });
});
