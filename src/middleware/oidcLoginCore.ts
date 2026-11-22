// Shared "Login with AXIAM" core (CONTRACT.md §12) — the ONE
// begin/complete + state-store + error-mapping path both the Express
// `oidcLoginHandlers` and the Fastify `oidcLoginPlugin` call, mirroring how
// `authzCore.ts` is the one §11 path and `verifyCore.ts` the one §10 path.
//
// This module is framework-agnostic on purpose: it takes plain values in and
// returns a discriminated `OidcLoginOutcome` out, so each adapter only has to
// translate an outcome into that framework's redirect/JSON response. It
// performs no token extraction and touches no `req`/`reply` object.
//
// The browser binding (CONTRACT.md §12.8 rule 1, contract 1.68; C7) is the one
// piece of cookie state the flow needs, and rule 1 (f) puts it here without
// breaking that rule: `beginOidcLogin` RETURNS the `Set-Cookie` value to send,
// and `completeOidcLogin` TAKES the presented cookie value as a parameter. The
// adapters do the cookie I/O and nothing else. See
// `docs/login-glue-binding.md` for the design and the order of the checks.
//
// The state store is what makes the two HTTP requests of a redirect flow into
// one login: `oidcBegin` produces `state`/`nonce`/`code_verifier` in the
// login request, and only `state` survives the round trip through the IdP, so
// the other two must be parked somewhere the callback request can reach
// (§12.3 rule 1 — the SDK itself stores nothing).

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { AuthError, NetworkError } from '../core/index.js';
import type { OidcClient } from '../node/oidc.js';
import { OIDC_STATE_TTL_MS, type OidcStateEntry, type OidcStateStore } from '../node/oidcState.js';
import type { OidcTokenSet } from '../node/oidcTypes.js';
import type { AuthzLogger, ErrorBody } from './authzCore.js';

/**
 * Configuration shared by the login and callback handlers (CONTRACT.md §12).
 *
 * @typeParam TRequest - the framework's request type, handed to
 *   {@link OidcLoginOptions.onSuccess} (§12.8 rule 2). Express's
 *   `oidcLoginHandlers` fixes it to Express's `Request`, Fastify's
 *   `oidcLoginPlugin` to `FastifyRequest`. A plain `OidcLoginOptions` (the
 *   default, `unknown`) is accepted by both.
 */
export interface OidcLoginOptions<TRequest = unknown> {
  /** The relying-party client driving the flow (built with `createOidcClient`). */
  client: OidcClient;
  /**
   * Where in-flight login state is parked between the login redirect and the
   * callback. {@link MemoryOidcStateStore} is a ready single-process
   * implementation; a multi-instance deployment needs a shared one, and that
   * store MUST persist and return {@link OidcStateEntry.bindingDigest}
   * unchanged (§12.3 rule 1) or every callback is refused.
   */
  store: OidcStateStore;
  /**
   * The relying party's redirect URI — must be the public URL of the callback
   * route, and is replayed verbatim on the token exchange (the server compares
   * the two).
   *
   * It also selects the browser-binding cookie's name (§12.8 rule 1 (b)):
   * `__Host-axiam_oidc_bind` everywhere, except `axiam_oidc_bind` (without
   * `Secure`) when it is plain `http:` on a loopback host (`localhost`,
   * `127.0.0.1`, `[::1]`), where a browser would not store a `Secure` cookie.
   */
  redirectUri: string;
  /** Requested scope. `openid` is added automatically when absent (§12.1 rule 4). */
  scope?: string | string[];
  /**
   * Where to send the browser after a successful login. Falls back to the
   * `returnTo` captured at login time — only when it passes the §12.8 rule 3
   * check — then to a JSON summary.
   */
  successRedirect?: string;
  /**
   * Optional widening of the `returnTo` rule (CONTRACT.md §12.8 rule 3).
   *
   * By default a `returnTo` is followed only when it is a same-origin relative
   * path ({@link isSafeReturnTo}). This predicate is consulted — at login and
   * again before the redirect — **only** for a value the default rule refuses,
   * and the value is honoured only when it returns `true`: for example an
   * allowlist of the application's other origins. Never pass a predicate that
   * accepts arbitrary absolute URLs; that reopens the open redirect.
   */
  allowReturnTo?: (value: string) => boolean;
  /**
   * Called with the validated token set once the exchange succeeds — the hook
   * where an application establishes its OWN session (sign a cookie, write a
   * session row, …). The SDK deliberately does not do this for you: what a
   * session means is the application's decision.
   *
   * Receives the consumed state entry too, so `returnTo` and any other
   * application data captured at login time is available, and (contract 1.68,
   * §12.8 rule 2) the framework request that completed the sign-in, so the
   * session can be created on it without ambient context. It runs only after
   * the browser binding and every §12.4 ID-token check have passed.
   */
  onSuccess?: (tokens: OidcTokenSet, entry: OidcStateEntry, request: TRequest) => void | Promise<void>;
  /** Debug-only logger. Receives failure reasons, never token material, `state`, `nonce`, the verifier or the binding cookie. */
  logger?: AuthzLogger;
}

/**
 * What the callback adapter hands {@link completeOidcLogin} besides the query:
 * the request-side inputs the framework-neutral core cannot read itself
 * (CONTRACT.md §12.8 rule 1 (f)).
 */
export interface OidcCallbackContext<TRequest = unknown> {
  /**
   * The value of the browser-binding cookie the callback request presented —
   * the cookie named by {@link oidcBindingCookieName} for the configured
   * `redirectUri`, and only that name. Absent means no cookie: the callback is
   * refused with the uniform 401.
   */
  bindingCookie?: string;
  /** The framework request, passed through to `onSuccess` (§12.8 rule 2). */
  request?: TRequest;
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
      /** A complete `Set-Cookie` header value the adapter MUST send with this response (§12.8 rule 1). */
      setCookie?: string;
    }
  | {
      /** Reply `200` with {@link body} — the fallback when no post-login redirect is configured. */
      kind: 'json';
      /** A token-free summary of the established login. */
      body: OidcLoginSuccessBody;
      /** A complete `Set-Cookie` header value the adapter MUST send with this response (§12.8 rule 1). */
      setCookie?: string;
    }
  | {
      /** Reply {@link status} with the standardized `{ error, message }` body. */
      kind: 'error';
      /** HTTP status: 400 malformed callback, 401 authentication failure, 503 AXIAM unreachable. */
      status: number;
      /** Standardized error body (§10/§11 shape). */
      body: ErrorBody;
      /** A complete `Set-Cookie` header value the adapter MUST send with this response (§12.8 rule 1). */
      setCookie?: string;
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
 * The browser-binding cookie name on every `https:` redirect URI, and on plain
 * HTTP to any host that is not loopback (CONTRACT.md §12.8 rule 1 (a)).
 */
export const OIDC_BINDING_COOKIE_NAME = '__Host-axiam_oidc_bind';

/**
 * The browser-binding cookie name used ONLY for a plain-HTTP loopback
 * `redirectUri` (`http://localhost`, `http://127.0.0.1`, `http://[::1]`), where
 * a browser will not store the `Secure` cookie the `__Host-` prefix requires
 * (CONTRACT.md §12.8 rule 1 (b)). Never selected off loopback.
 */
export const OIDC_BINDING_COOKIE_NAME_LOOPBACK = 'axiam_oidc_bind';

/** The uniform refusal: unknown, expired, consumed state and every binding failure (§12.8 rule 1 (c)). */
const UNIFORM_STATE_FAILURE = 'unknown, expired, or already-used login state';

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Whether `redirectUri` is plain HTTP to a loopback host — the one case §12.8 rule 1 (b) relaxes. */
function isPlainHttpLoopback(redirectUri: string): boolean {
  try {
    const url = new URL(redirectUri);
    return url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
  } catch {
    // An unparseable redirect URI is not loopback: fall to the strict name.
    return false;
  }
}

/**
 * The browser-binding cookie name for `redirectUri` (CONTRACT.md §12.8 rule 1
 * (b)): {@link OIDC_BINDING_COOKIE_NAME_LOOPBACK} for plain HTTP on a loopback
 * host, {@link OIDC_BINDING_COOKIE_NAME} everywhere else. The login sets, and
 * the callback reads, the name this returns — and only that name.
 */
export function oidcBindingCookieName(redirectUri: string): string {
  return isPlainHttpLoopback(redirectUri) ? OIDC_BINDING_COOKIE_NAME_LOOPBACK : OIDC_BINDING_COOKIE_NAME;
}

/** `Set-Cookie` attributes shared by the set and the clear, so the two always match. */
function bindingCookieAttributes(redirectUri: string): string {
  return isPlainHttpLoopback(redirectUri) ? 'Path=/; HttpOnly; SameSite=Lax' : 'Path=/; HttpOnly; Secure; SameSite=Lax';
}

/** Max-Age of the binding cookie: the store's maximum TTL (§12.8 rule 1 (a) — at most 600 s). */
const BINDING_COOKIE_MAX_AGE_SEC = Math.floor(OIDC_STATE_TTL_MS / 1000);

function setBindingCookie(redirectUri: string, value: string): string {
  return `${oidcBindingCookieName(redirectUri)}=${value}; ${bindingCookieAttributes(redirectUri)}; Max-Age=${BINDING_COOKIE_MAX_AGE_SEC}`;
}

/** The clearing `Set-Cookie` every callback response carries (§12.8 rule 1 (d)). */
function clearBindingCookie(redirectUri: string): string {
  return `${oidcBindingCookieName(redirectUri)}=; ${bindingCookieAttributes(redirectUri)}; Max-Age=0`;
}

/** SHA-256 (lower-case hex) of the ASCII bytes of the cookie value as set (§12.8 rule 1 (a)). */
function bindingDigest(value: string): string {
  return createHash('sha256').update(value, 'ascii').digest('hex');
}

/**
 * Constant-time comparison of the presented cookie's digest with the entry's
 * (§12.8 rule 1 (c)). A missing cookie, a missing or ill-typed digest, or a
 * difference all return `false`.
 */
function bindingMatches(entry: OidcStateEntry, presented: string | undefined): boolean {
  const stored = (entry as { bindingDigest?: unknown }).bindingDigest;
  if (typeof presented !== 'string' || presented.length === 0 || typeof stored !== 'string') {
    return false;
  }
  const expected = Buffer.from(bindingDigest(presented), 'utf8');
  const actual = Buffer.from(stored, 'utf8');
  // Both sides are 64 hex digits for a genuine entry; a length mismatch is a
  // malformed entry, not a secret, and timingSafeEqual requires equal lengths.
  if (expected.length !== actual.length) {
    return false;
  }
  return timingSafeEqual(expected, actual);
}

/**
 * The default `returnTo` rule (CONTRACT.md §12.8 rule 3; C6): `true` only for
 * a same-origin relative path — it starts with a single `/`, does not start
 * with `//` or `/\`, and contains no `\` anywhere and no control character
 * (U+0000–U+001F, U+007F). Absolute URLs (`https://…`), scheme-relative ones
 * (`//host/…`) and backslash forms (`/\host`, `/a\b`) are all refused.
 *
 * Both framework adapters reach it through {@link beginOidcLogin} (which drops
 * a refused value before storing) and {@link completeOidcLogin} (which checks
 * the stored value again before redirecting), so Express and Fastify share one
 * implementation.
 */
export function isSafeReturnTo(value: string): boolean {
  if (value.length === 0 || value[0] !== '/') {
    return false;
  }
  if (value.startsWith('//') || value.startsWith('/\\')) {
    return false;
  }
  return !/[\\\u0000-\u001f\u007f]/.test(value);
}

/** Apply the default rule, then — only for a value it refuses — the integrator's predicate (§12.8 rule 3). */
function acceptedReturnTo(value: unknown, allowReturnTo: ((value: string) => boolean) | undefined): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  if (isSafeReturnTo(value)) {
    return value;
  }
  if (allowReturnTo !== undefined) {
    try {
      if (allowReturnTo(value) === true) {
        return value;
      }
    } catch {
      // A predicate that throws accepts nothing.
    }
  }
  return undefined;
}

/**
 * Step 1 — build the authorization request, park its state, and hand back the
 * redirect (CONTRACT.md §12.1 `oidc_begin`).
 *
 * Discovery is fetched through `oidcDiscover`, so its per-origin cache and
 * single-flight de-duplication apply and a busy login route does not hammer
 * the discovery endpoint (§12.3 rule 6).
 *
 * **Browser binding (contract 1.68, §12.8 rule 1 (a)).** Every login draws a
 * fresh 32-byte CSPRNG value, stores its SHA-256 on the entry as
 * {@link OidcStateEntry.bindingDigest}, and returns the value in the redirect
 * outcome's `setCookie`, which the adapter MUST send. A cookie the request
 * already presents is never reused.
 *
 * @param options the shared login configuration.
 * @param returnTo optional application destination to restore after login.
 *   Stored only when it passes {@link isSafeReturnTo} (or
 *   {@link OidcLoginOptions.allowReturnTo}); any other value is dropped, as if
 *   none had been given (§12.8 rule 3).
 */
export async function beginOidcLogin<TRequest = unknown>(
  options: OidcLoginOptions<TRequest>,
  returnTo?: string,
): Promise<OidcLoginOutcome> {
  try {
    const configuration = await options.client.oidcDiscover();
    const request = options.client.oidcBegin({
      configuration,
      redirectUri: options.redirectUri,
      ...(options.scope !== undefined ? { scope: options.scope } : {}),
    });
    const safeReturnTo = acceptedReturnTo(returnTo, options.allowReturnTo);
    if (returnTo !== undefined && safeReturnTo === undefined) {
      options.logger?.debug('axiam_sdk.oidc', 'dropped a returnTo that is not a same-origin relative path');
    }
    const binding = randomBytes(32).toString('base64url');
    await options.store.save({
      state: request.state,
      nonce: request.nonce,
      codeVerifier: request.codeVerifier,
      redirectUri: options.redirectUri,
      ...(safeReturnTo !== undefined ? { returnTo: safeReturnTo } : {}),
      bindingDigest: bindingDigest(binding),
    });
    return { kind: 'redirect', url: request.url, setCookie: setBindingCookie(options.redirectUri, binding) };
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
 * Step 2 — validate the callback, consume the stored state, check the browser
 * binding, exchange the code, and hand back the post-login response
 * (CONTRACT.md §12.1 `oidc_exchange`, §12.8).
 *
 * Order (§12.8 rule 1 (c)): the entry is consumed FIRST, so `state` stays
 * single-use whatever happens next; then the presented binding cookie's
 * SHA-256 is compared in constant time with the entry's digest; only then is
 * the code exchanged and `onSuccess` called. Every outcome carries a
 * `setCookie` that clears the binding cookie (rule 1 (d)).
 *
 * Failure mapping:
 * - IdP returned `error=…` instead of a code → `401 authentication_failed`;
 * - `state` or `code` missing → `400 invalid_request`;
 * - `state` unknown, already consumed, or expired; no binding cookie; an entry
 *   with no `bindingDigest`; or a different cookie → `401
 *   authentication_failed` with ONE body, so the refusal does not say which
 *   check failed, and with no request to the token endpoint;
 * - any §12.4 ID-token failure or `OAuthProtocolError` (an `AuthError`
 *   sub-type) → `401 authentication_failed`;
 * - `NetworkError` → `503 oidc_unavailable`, never a silent success.
 *
 * @param context the presented binding cookie and the framework request. A
 *   caller that passes no `bindingCookie` has every callback refused (rule 1
 *   (f)).
 */
export async function completeOidcLogin<TRequest = unknown>(
  options: OidcLoginOptions<TRequest>,
  query: OidcCallbackQuery,
  context: OidcCallbackContext<TRequest> = {},
): Promise<OidcLoginOutcome> {
  const setCookie = clearBindingCookie(options.redirectUri);

  if (query.error) {
    options.logger?.debug('axiam_sdk.oidc', 'idp returned an authorization error', { error: query.error });
    return {
      kind: 'error',
      status: 401,
      body: authenticationFailedBody(
        query.error_description ? `${query.error}: ${query.error_description}` : query.error,
      ),
      setCookie,
    };
  }
  if (!query.state || !query.code) {
    return {
      kind: 'error',
      status: 400,
      body: invalidRequestBody('callback is missing the state or code query parameter'),
      setCookie,
    };
  }

  // Single-use consume (§12.3 rule 1), and FIRST (§12.8 rule 1 (c)): a
  // replayed callback finds nothing, and a callback refused below for its
  // binding has still spent the state.
  const entry = await options.store.consume(query.state);
  if (!entry) {
    options.logger?.debug('axiam_sdk.oidc', 'no stored login state for the callback state');
    return { kind: 'error', status: 401, body: authenticationFailedBody(UNIFORM_STATE_FAILURE), setCookie };
  }
  if (!bindingMatches(entry, context.bindingCookie)) {
    // Login CSRF (C7): this request is not from the browser that started the
    // login. Same status and body as an unknown state; the code is NOT
    // exchanged and onSuccess is NOT called. Neither value is logged.
    options.logger?.debug('axiam_sdk.oidc', 'login state is not bound to this browser');
    return { kind: 'error', status: 401, body: authenticationFailedBody(UNIFORM_STATE_FAILURE), setCookie };
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
      return {
        kind: 'error',
        status: 503,
        body: unavailableBody('the AXIAM token endpoint is unreachable'),
        setCookie,
      };
    }
    // AuthError (including OAuthProtocolError and every §12.4 reason code) and
    // anything unexpected: a login that cannot be proven is a failed login.
    const reason = err instanceof AuthError ? err.message : 'token exchange failed';
    options.logger?.debug('axiam_sdk.oidc', 'token exchange failed', { reason });
    return { kind: 'error', status: 401, body: authenticationFailedBody(reason), setCookie };
  }

  await options.onSuccess?.(tokens, entry, context.request as TRequest);

  // §12.8 rule 3: the stored value is checked again — a caller-supplied store
  // or an entry written by older glue may hold anything.
  const destination = options.successRedirect ?? acceptedReturnTo(entry.returnTo, options.allowReturnTo);
  if (destination) {
    return { kind: 'redirect', url: destination, setCookie };
  }
  return {
    kind: 'json',
    body: {
      authenticated: true,
      ...(typeof tokens.idClaims?.sub === 'string' ? { sub: tokens.idClaims.sub } : {}),
      expiresIn: tokens.expiresIn,
    },
    setCookie,
  };
}
