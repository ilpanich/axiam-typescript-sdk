// Token Exchange (RFC 8693) — CONTRACT.md §15.
//
// Most of §15 is a list of things an SDK must *not* helpfully do, so most of
// these tests assert an absence: no defaulted `actorToken`, no auto-narrow
// after `invalid_scope`, no synthesised refresh token, no adoption.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { AuthError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import { JWT_TOKEN_TYPE } from '../../src/node/oidc.js';
import {
  BASE_URL,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  discoveryHandler,
  TOKEN_ENDPOINT,
} from './oidcTestKit.js';

const SUBJECT_TOKEN = 'subject-token-value';
const ACTOR_TOKEN = 'actor-token-value';
const ISSUED_TOKEN = 'issued-narrow-token';

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

function exchangeResponse(overrides: Record<string, unknown> = {}): Response {
  return HttpResponse.json({
    access_token: ISSUED_TOKEN,
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: 300,
    scope: 'orders:read',
    ...overrides,
  });
}

function oauthError(code: string): Response {
  return HttpResponse.json(
    { error: code, error_description: `${code} description` },
    { status: 400 },
  );
}

/** Mount discovery + a token endpoint, capturing every form body. */
function mountExchange(responder: () => Response): { forms: URLSearchParams[] } {
  const state = createMockState();
  const forms: URLSearchParams[] = [];
  server.use(
    discoveryHandler(state),
    http.post(TOKEN_ENDPOINT, async ({ request }) => {
      forms.push(new URLSearchParams(await request.text()));
      return responder();
    }),
  );
  return { forms };
}

describe('tokenExchange wire shape (§15.1)', () => {
  it('sends the RFC 8693 grant and authenticates as a confidential client', async () => {
    const { forms } = mountExchange(() => exchangeResponse());
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const result = await oidc.tokenExchange({
      subjectToken: new Sensitive(SUBJECT_TOKEN),
      scopes: ['orders:read', 'orders:write'],
      audience: 'orders-service',
    });

    const form = forms[0]!;
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(form.get('subject_token')).toBe(SUBJECT_TOKEN);
    expect(form.get('subject_token_type')).toBe('urn:ietf:params:oauth:token-type:access_token');
    expect(form.get('scope')).toBe('orders:read orders:write');
    expect(form.get('audience')).toBe('orders-service');
    expect(form.get('client_secret')).toBe(CLIENT_SECRET);

    expect(result.accessToken.expose()).toBe(ISSUED_TOKEN);
    // §15.2 rule 6: surfaced, not dropped.
    expect(result.issuedTokenType).toBe('urn:ietf:params:oauth:token-type:access_token');
  });

  it('fails client-side, with no wire call, for a public client', async () => {
    const state = createMockState();
    // No token-endpoint handler: reaching the wire would fail the test with an
    // unhandled-request error.
    server.use(discoveryHandler(state));
    const { oidc } = createClient();

    await expect(
      oidc.tokenExchange({ subjectToken: SUBJECT_TOKEN }),
    ).rejects.toThrow(AuthError);
  });
});

describe('delegation vs impersonation (§15.2 rule 1)', () => {
  it('sends no actor_token when none was given, and never defaults one', async () => {
    const { forms } = mountExchange(() => exchangeResponse());
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.tokenExchange({ subjectToken: SUBJECT_TOKEN });

    // Passing no actor token asks for IMPERSONATION. An SDK that helpfully
    // substituted its own session token would silently turn that into a
    // delegation — a different operation with different risk.
    expect(forms[0]!.get('actor_token')).toBeNull();
    expect(forms[0]!.get('actor_token_type')).toBeNull();
  });

  it('sends actor_token and its type as a pair', async () => {
    const { forms } = mountExchange(() => exchangeResponse());
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc.tokenExchange({
      subjectToken: SUBJECT_TOKEN,
      actorToken: new Sensitive(ACTOR_TOKEN),
    });

    expect(forms[0]!.get('actor_token')).toBe(ACTOR_TOKEN);
    // RFC 8693 §2.1 requires the pair; the type alone is a malformed request.
    expect(forms[0]!.get('actor_token_type')).toBe(
      'urn:ietf:params:oauth:token-type:access_token',
    );
  });
});

describe('refusals surface unchanged (§15.2 rules 2-3, §15.3)', () => {
  it('does not retry invalid_scope with fewer scopes', async () => {
    const { forms } = mountExchange(() => oauthError('invalid_scope'));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const err = await oidc
      .tokenExchange({ subjectToken: SUBJECT_TOKEN, scopes: ['orders:read', 'orders:admin'] })
      .catch((e: unknown) => e);

    expect((err as OAuthProtocolError).error).toBe('invalid_scope');
    // The server refuses rather than silently narrowing precisely so the
    // caller finds out HERE. Auto-narrowing and re-sending would hide it.
    expect(forms).toHaveLength(1);
  });

  it('surfaces unauthorized_client verbatim without downgrading to delegation', async () => {
    const { forms } = mountExchange(() => oauthError('unauthorized_client'));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const err = await oidc
      .tokenExchange({ subjectToken: SUBJECT_TOKEN })
      .catch((e: unknown) => e);

    expect((err as OAuthProtocolError).error).toBe('unauthorized_client');
    expect(forms).toHaveLength(1);
    expect(forms[0]!.get('actor_token')).toBeNull();
  });

  it.each([
    'invalid_request',
    'invalid_grant',
    'invalid_scope',
    'invalid_target',
    'unauthorized_client',
    'invalid_client',
  ])('passes %s through as an OAuthProtocolError', async (code) => {
    // Including cross-tenant, which the server deliberately collapses into
    // `invalid_grant` — the SDK must not re-derive the distinction it withheld.
    mountExchange(() => oauthError(code));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const err = await oidc
      .tokenExchange({ subjectToken: SUBJECT_TOKEN })
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe(code);
    expect(err).toBeInstanceOf(AuthError);
  });
});

describe('what the result is, and is not (§15.2 rules 4-7)', () => {
  it('cannot surface a refresh token even when the wire sends one', async () => {
    // Deliberately hostile fixture: RFC 8693 issues no refresh token, so the
    // result type has no field for one and there is nothing to synthesise.
    mountExchange(() => exchangeResponse({ refresh_token: 'should-not-exist' }));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const result = await oidc.tokenExchange({ subjectToken: SUBJECT_TOKEN });

    expect(JSON.stringify(result)).not.toContain('should-not-exist');
    expect('refreshToken' in result).toBe(false);
  });

  it('reports the granted scope, which may be narrower than requested', async () => {
    mountExchange(() => exchangeResponse({ scope: 'orders:read' }));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const result = await oidc.tokenExchange({
      subjectToken: SUBJECT_TOKEN,
      scopes: ['orders:read', 'orders:write'],
    });

    // §15.2 rule 7 — applications must be able to read what they actually got.
    expect(result.scope).toBe('orders:read');
  });

  it('redacts the issued token', async () => {
    mountExchange(() => exchangeResponse());
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const result = await oidc.tokenExchange({ subjectToken: SUBJECT_TOKEN });

    expect(result.accessToken).toBeInstanceOf(Sensitive);
    expect(String(result.accessToken)).not.toContain(ISSUED_TOKEN);
  });

  it('never echoes the subject or actor token on failure', async () => {
    // §15.5 calls this out specifically: an exchange failure is exactly when a
    // naive implementation logs the request body.
    mountExchange(() => oauthError('invalid_grant'));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const err = await oidc
      .tokenExchange({
        subjectToken: SUBJECT_TOKEN,
        actorToken: ACTOR_TOKEN,
      })
      .catch((e: unknown) => e);

    const rendered = `${String(err)}${(err as Error).stack ?? ''}`;
    expect(rendered).not.toContain(SUBJECT_TOKEN);
    expect(rendered).not.toContain(ACTOR_TOKEN);
  });
});

// ---------------------------------------------------------------------------
// §15.7 — external-IdP subject tokens (X4)
//
// No new operation: the same `tokenExchange` carries a partner IdP's token.
// What changes is which subject tokens the server accepts and what its
// refusals mean, so these tests are about not getting in the way of either.
// ---------------------------------------------------------------------------

/**
 * A token minted by a partner's IdP. Opaque to the SDK — deliberately not a
 * well-formed JWT, because nothing here may decode it.
 */
const EXTERNAL_SUBJECT_TOKEN = 'partner-idp-subject-token';

/**
 * The one normative `error_description` (§15.7). It means "fix the AXIAM trust
 * configuration", not "fix your token".
 */
const ISSUER_NOT_CONFIGURED = "the subject token's issuer is not configured for token exchange";

function oauthErrorWithDescription(code: string, description: string): Response {
  return HttpResponse.json({ error: code, error_description: description }, { status: 400 });
}

describe('external-IdP subject tokens (§15.7)', () => {
  it('sends the caller-named subject_token_type and surfaces the result unchanged', async () => {
    const { forms } = mountExchange(() => exchangeResponse({ scope: 'read:orders' }));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const result = await oidc.tokenExchange({
      subjectToken: new Sensitive(EXTERNAL_SUBJECT_TOKEN),
      subjectTokenType: JWT_TOKEN_TYPE,
      scopes: ['read:orders'],
      audience: 'https://orders.internal',
    });

    const form = forms[0]!;
    // The caller named …:jwt, so …:jwt goes on the wire.
    expect(form.get('subject_token_type')).toBe('urn:ietf:params:oauth:token-type:jwt');
    expect(form.get('subject_token')).toBe(EXTERNAL_SUBJECT_TOKEN);
    // Delegation across a trust boundary is unsupported; nothing may add one.
    expect(form.get('actor_token')).toBeNull();

    // The cross-domain path is not a different result shape, and §15.2
    // rules 6-7 still hold.
    expect(result.accessToken.expose()).toBe(ISSUED_TOKEN);
    expect(result.issuedTokenType).toBe('urn:ietf:params:oauth:token-type:access_token');
    expect(result.scope).toBe('read:orders');
  });

  it('never infers subject_token_type from the token itself', async () => {
    const { forms } = mountExchange(() => exchangeResponse());
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    // A subject token that *looks* exactly like a JWT. An SDK that sniffed the
    // token would send …:jwt here; §15.7 says it must not look, so the
    // caller's silence still means the §15.1 same-domain default.
    await oidc.tokenExchange({
      subjectToken: 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig',
    });

    expect(forms[0]!.get('subject_token_type')).toBe(
      'urn:ietf:params:oauth:token-type:access_token',
    );
  });

  it('surfaces invalid_request for an actor_token, with no retry and no rewriting', async () => {
    const { forms } = mountExchange(() =>
      oauthErrorWithDescription(
        'invalid_request',
        'actor_token is not supported for an external subject token',
      ),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const err = await oidc
      .tokenExchange({
        subjectToken: EXTERNAL_SUBJECT_TOKEN,
        subjectTokenType: JWT_TOKEN_TYPE,
        actorToken: ACTOR_TOKEN,
      })
      .catch((e: unknown) => e);

    expect((err as OAuthProtocolError).error).toBe('invalid_request');
    // No retry, and no rewriting. Dropping the actor token and re-sending
    // would turn a delegation the caller asked for into an impersonation they
    // did not.
    expect(forms).toHaveLength(1);
    expect(forms[0]!.get('actor_token')).toBe(ACTOR_TOKEN);
    expect(forms[0]!.get('subject_token_type')).toBe('urn:ietf:params:oauth:token-type:jwt');
  });

  it.each([
    'urn:ietf:params:oauth:token-type:refresh_token',
    'urn:ietf:params:oauth:token-type:id_token',
  ])('never retries the refused type %s as a different one', async (refused) => {
    // A refresh token is a re-authentication credential and an ID token is an
    // assertion to a client about a login; neither is a bearer credential for
    // an API, so both are refused BY NAME. Retrying as …:jwt would present one
    // as if it were.
    const { forms } = mountExchange(() =>
      oauthErrorWithDescription('invalid_request', `unsupported subject_token_type ${refused}`),
    );
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    await oidc
      .tokenExchange({ subjectToken: EXTERNAL_SUBJECT_TOKEN, subjectTokenType: refused })
      .catch(() => undefined);

    expect(forms).toHaveLength(1);
    expect(forms[0]!.get('subject_token_type')).toBe(refused);
  });

  it('passes the "issuer is not configured" description through intact', async () => {
    mountExchange(() => oauthErrorWithDescription('invalid_grant', ISSUER_NOT_CONFIGURED));
    const { oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const err = await oidc
      .tokenExchange({
        subjectToken: EXTERNAL_SUBJECT_TOKEN,
        subjectTokenType: JWT_TOKEN_TYPE,
      })
      .catch((e: unknown) => e);

    expect((err as OAuthProtocolError).error).toBe('invalid_grant');
    // This is the ONLY distinguishable external failure, and the whole point
    // of it is that an integrator can tell "fix the AXIAM trust config" from
    // "fix your token". Truncating or rewording it destroys that.
    expect((err as OAuthProtocolError).errorDescription).toBe(ISSUER_NOT_CONFIGURED);
  });

  it('never re-exchanges a token it just obtained', async () => {
    // Tokens minted from an external subject token carry `ext_exchange`, and
    // BOTH exchange paths refuse a subject token bearing it: exchanges do not
    // compose. The SDK's part is to never feed a result back in by itself.
    const state = createMockState();
    const forms: URLSearchParams[] = [];
    let protectedAuthHeader: string | null = null;
    server.use(
      discoveryHandler(state),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        forms.push(new URLSearchParams(await request.text()));
        return exchangeResponse();
      }),
      http.get(`${BASE_URL}/api/v1/protected`, ({ request }) => {
        protectedAuthHeader = request.headers.get('authorization');
        return HttpResponse.json({ ok: true });
      }),
    );
    const { session, oidc } = createClient({ clientSecret: CLIENT_SECRET });

    const result = await oidc.tokenExchange({
      subjectToken: EXTERNAL_SUBJECT_TOKEN,
      subjectTokenType: JWT_TOKEN_TYPE,
    });
    await session.axios.get('/api/v1/protected');

    // Exactly one exchange happened: nothing looped the result back in.
    expect(forms).toHaveLength(1);
    expect(result.accessToken.expose()).toBe(ISSUED_TOKEN);
    // §15.2 rule 5 restated for the cross-domain path: had the result been
    // adopted, every later call would carry it — and the next exchange would
    // carry it as a *subject* token, which is exactly the re-exchange §15.7
    // forbids, arrived at by accident rather than by decision.
    expect(protectedAuthHeader).toBeNull();
  });
});
