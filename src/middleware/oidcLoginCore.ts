// Shared "Login with AXIAM" core (CONTRACT.md §12) — the ONE
// begin/complete + state-store + error-mapping path both the Express
// `oidcLoginHandlers` and the Fastify `oidcLoginPlugin` call, mirroring how
// `authzCore.ts` is the one §11 path and `verifyCore.ts` the one §10 path.
//
// This module is framework-agnostic on purpose: it takes plain values in and
// returns a discriminated `OidcLoginOutcome` out, so each adapter only has to
// translate an outcome into that framework's redirect/JSON response. It
// performs no token extraction, sets no cookie, and touches no `req`/`reply`
// object.
//
// The state store is what makes the two HTTP requests of a redirect flow into
// one login: `oidcBegin` produces `state`/`nonce`/`code_verifier` in the
// login request, and only `state` survives the round trip through the IdP, so
// the other two must be parked somewhere the callback request can reach
// (§12.3 rule 1 — the SDK itself stores nothing).

import { AuthError, NetworkError } from '../core/index.js';
import type { OidcClient } from '../node/oidc.js';
import type { OidcStateEntry, OidcStateStore } from '../node/oidcState.js';
import type { OidcTokenSet } from '../node/oidcTypes.js';
import type { AuthzLogger, ErrorBody } from './authzCore.js';

/** Configuration shared by the login and callback handlers (CONTRACT.md §12). */
export interface OidcLoginOptions {
  /** The relying-party client driving the flow (built with `createOidcClient`). */
  client: OidcClient;
  /**
   * Where in-flight login state is parked between the login redirect and the
   * callback. {@link MemoryOidcStateStore} is a ready single-process
   * implementation; a multi-instance deployment needs a shared one.
   */
  store: OidcStateStore;
  /**
   * The relying party's redirect URI — must be the public URL of the callback
   * route, and is replayed verbatim on the token exchange (the server compares
   * the two).
   */
  redirectUri: string;
  /** Requested scope. `openid` is added automatically when absent (§12.1 rule 4). */
  scope?: string | string[];
  /** Where to send the browser after a successful login. Falls back to the `returnTo` captured at login time, then to a JSON summary. */
  successRedirect?: string;
  /**
   * Called with the validated token set once the exchange succeeds — the hook
   * where an application establishes its OWN session (sign a cookie, write a
   * session row, …). The SDK deliberately does not do this for you: what a
   * session means is the application's decision.
   *
   * Receives the consumed state entry too, so `returnTo` and any other
   * application data captured at login time is available.
   */
  onSuccess?: (tokens: OidcTokenSet, entry: OidcStateEntry) => void | Promise<void>;
  /** Debug-only logger. Receives failure reasons, never token material, `state`, `nonce` or the verifier. */
  logger?: AuthzLogger;
}

/**
 * What a login/callback handler should do next — one arm per response shape.
 * Adapters translate this into their framework's API and add nothing of their
 * own, so Express and Fastify cannot drift.
 */
export type OidcLoginOutcome =
  | {
      /** Send a 302 to {@link url}. */
      kind: 'redirect';
      /** Target of the redirect: the IdP authorization URL, or the post-login destination. */
      url: string;
    }
  | {
      /** Reply `200` with {@link body} — the fallback when no post-login redirect is configured. */
      kind: 'json';
      /** A token-free summary of the established login. */
      body: OidcLoginSuccessBody;
    }
  | {
      /** Reply {@link status} with the standardized `{ error, message }` body. */
      kind: 'error';
      /** HTTP status: 400 malformed callback, 401 authentication failure, 503 AXIAM unreachable. */
      status: number;
      /** Standardized error body (§10/§11 shape). */
      body: ErrorBody;
    };

/** The token-free success summary returned when no post-login redirect is configured. */
export interface OidcLoginSuccessBody {
  /** Always `true` — the ID token validated and the login completed. */
  authenticated: true;
  /** The authenticated subject from the validated ID token, when the server issued one. */
  sub?: string;
  /** Access-token lifetime in seconds, for a caller sizing its own session. */
  expiresIn: number;
}

/** The callback query parameters the flow reads (RFC 6749 §4.1.2 / §4.1.2.1). */
export interface OidcCallbackQuery {
  /** The `state` the IdP echoed back — matched against the stored entry. */
  state?: string;
  /** The authorization code, on success. */
  code?: string;
  /** An RFC 6749 error code, when the IdP refused instead of issuing a code. */
  error?: string;
  /** The IdP's description of {@link error}. */
  error_description?: string;
}

function authenticationFailedBody(message: string): ErrorBody {
  return { error: 'authentication_failed', message };
}

function invalidRequestBody(message: string): ErrorBody {
  return { error: 'invalid_request', message };
}

function unavailableBody(message: string): ErrorBody {
  return { error: 'oidc_unavailable', message };
}

/**
 * Step 1 — build the authorization request, park its state, and hand back the
 * redirect (CONTRACT.md §12.1 `oidc_begin`).
 *
 * Discovery is fetched through `oidcDiscover`, so its per-origin cache and
 * single-flight de-duplication apply and a busy login route does not hammer
 * the discovery endpoint (§12.3 rule 6).
 *
 * @param options the shared login configuration.
 * @param returnTo optional application destination to restore after login;
 *   stored with the state entry and used as the post-login redirect when
 *   `successRedirect` is unset.
 */
export async function beginOidcLogin(
  options: OidcLoginOptions,
  returnTo?: string,
): Promise<OidcLoginOutcome> {
  try {
    const configuration = await options.client.oidcDiscover();
    const request = options.client.oidcBegin({
      configuration,
      redirectUri: options.redirectUri,
      ...(options.scope !== undefined ? { scope: options.scope } : {}),
    });
    await options.store.save({
      state: request.state,
      nonce: request.nonce,
      codeVerifier: request.codeVerifier,
      redirectUri: options.redirectUri,
      ...(returnTo !== undefined ? { returnTo } : {}),
    });
    return { kind: 'redirect', url: request.url };
  } catch (err) {
    // A login route that cannot reach AXIAM must fail closed with 503 rather
    // than redirect the browser somewhere half-built.
    options.logger?.debug('axiam_sdk.oidc', 'oidc login could not be started', {
      reason: err instanceof Error ? err.message : 'unknown',
    });
    return { kind: 'error', status: 503, body: unavailableBody('could not start the OIDC login flow') };
  }
}

/**
 * Step 2 — validate the callback, consume the stored state, exchange the code,
 * and hand back the post-login response (CONTRACT.md §12.1 `oidc_exchange`).
 *
 * Failure mapping:
 * - IdP returned `error=…` instead of a code → `401 authentication_failed`;
 * - `state` or `code` missing → `400 invalid_request`;
 * - `state` unknown, already consumed, or expired → `401 authentication_failed`
 *   (all three are deliberately indistinguishable to the client);
 * - any §12.4 ID-token failure or `OAuthProtocolError` (an `AuthError`
 *   sub-type) → `401 authentication_failed`;
 * - `NetworkError` → `503 oidc_unavailable`, never a silent success.
 */
export async function completeOidcLogin(
  options: OidcLoginOptions,
  query: OidcCallbackQuery,
): Promise<OidcLoginOutcome> {
  if (query.error) {
    options.logger?.debug('axiam_sdk.oidc', 'idp returned an authorization error', { error: query.error });
    return {
      kind: 'error',
      status: 401,
      body: authenticationFailedBody(
        query.error_description ? `${query.error}: ${query.error_description}` : query.error,
      ),
    };
  }
  if (!query.state || !query.code) {
    return {
      kind: 'error',
      status: 400,
      body: invalidRequestBody('callback is missing the state or code query parameter'),
    };
  }

  // Single-use consume (§12.3 rule 1): a replayed callback finds nothing.
  const entry = await options.store.consume(query.state);
  if (!entry) {
    options.logger?.debug('axiam_sdk.oidc', 'no stored login state for the callback state');
    return {
      kind: 'error',
      status: 401,
      body: authenticationFailedBody('unknown, expired, or already-used login state'),
    };
  }

  let tokens: OidcTokenSet;
  try {
    tokens = await options.client.oidcExchange({
      code: query.code,
      codeVerifier: entry.codeVerifier,
      nonce: entry.nonce,
      redirectUri: entry.redirectUri,
    });
  } catch (err) {
    if (err instanceof NetworkError) {
      options.logger?.debug('axiam_sdk.oidc', 'token exchange transport failure');
      return { kind: 'error', status: 503, body: unavailableBody('the AXIAM token endpoint is unreachable') };
    }
    // AuthError (including OAuthProtocolError and every §12.4 reason code) and
    // anything unexpected: a login that cannot be proven is a failed login.
    const reason = err instanceof AuthError ? err.message : 'token exchange failed';
    options.logger?.debug('axiam_sdk.oidc', 'token exchange failed', { reason });
    return { kind: 'error', status: 401, body: authenticationFailedBody(reason) };
  }

  await options.onSuccess?.(tokens, entry);

  const destination = options.successRedirect ?? entry.returnTo;
  if (destination) {
    return { kind: 'redirect', url: destination };
  }
  return {
    kind: 'json',
    body: {
      authenticated: true,
      ...(typeof tokens.idClaims?.sub === 'string' ? { sub: tokens.idClaims.sub } : {}),
      expiresIn: tokens.expiresIn,
    },
  };
}
