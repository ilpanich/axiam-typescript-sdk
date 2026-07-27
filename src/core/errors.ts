// AxiamError taxonomy (CONTRACT.md §2, D-16).
//
// Three concrete TOP-LEVEL error types: AuthError, AuthzError, NetworkError,
// all extending the abstract AxiamError base. §2 additionally permits
// language-idiomatic SUB-TYPES of those three (they never replace them):
// this module ships one, `OAuthProtocolError extends AuthError`, mandated by
// §12.3 rule 3 for `OAuth2ErrorResponse` bodies returned by `/oauth2/*`.
// `instanceof AuthError` therefore still matches every authentication
// failure, including OAuth2 protocol errors — that backward compatibility is
// what makes contract 1.4 additive rather than breaking.
//
// No error message or field may embed a raw token string, client secret, or
// code verifier (D-16, §12.3 rule 3). The prototype chain is fixed up
// manually in each constructor so `instanceof` works reliably across the
// transpiled CJS+ESM outputs (a well-known TS-to-ES5/ES2022-target caveat
// when extending built-ins like Error).

/**
 * Base class of every error this SDK throws (CONTRACT.md §2).
 *
 * Catch this to handle any AXIAM failure uniformly; catch one of the three
 * concrete subclasses — {@link AuthError}, {@link AuthzError},
 * {@link NetworkError} — to distinguish authentication, authorization and
 * transport failures.
 */
export abstract class AxiamError extends Error {
  protected constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Authentication failure (CONTRACT.md §2): wrong credentials, an expired
 * session, a failed MFA challenge, a `401` on refresh, or a failed ID-token
 * validation.
 */
export class AuthError extends AxiamError {
  /**
   * Optional stable, machine-readable reason code for the failure.
   *
   * Populated by the CONTRACT.md §12.4 ID-token validation checklist with
   * one of the seven codes §12.3 rule 3 enumerates (see
   * {@link IdTokenFailureReason}); `undefined` for every other `AuthError`.
   * It is a *code*, never free text, so callers can branch on it without
   * parsing `message`.
   */
  readonly reason?: string;

  constructor(message: string, reason?: string) {
    super(message);
    this.name = 'AuthError';
    this.reason = reason;
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}

/**
 * The seven stable reason codes CONTRACT.md §12.3 rule 3 defines for
 * ID-token validation failures, one per §12.4 rule. Surfaced on
 * {@link AuthError.reason}.
 */
export type IdTokenFailureReason =
  | 'invalid_alg'
  | 'unknown_kid'
  | 'invalid_signature'
  | 'invalid_issuer'
  | 'invalid_audience'
  | 'token_expired'
  | 'nonce_mismatch';

/**
 * An RFC 6749 protocol error returned by an `/oauth2/*` endpoint as an
 * `OAuth2ErrorResponse` body (CONTRACT.md §2 sub-type table, §12.3 rule 3).
 *
 * @remarks
 * A **sub-type of {@link AuthError}**, not a replacement for it: existing
 * `catch (e) { if (e instanceof AuthError) … }` code keeps working unchanged.
 * Raised for a `400` from `POST /oauth2/token` (e.g. `invalid_grant`) and for
 * a `401` from `POST /oauth2/introspect` / `POST /oauth2/revoke` (client
 * authentication failed) — neither of which may collapse into the generic
 * §2 `400 → NetworkError` / `401 → AuthError` rows.
 *
 * `message` is always exactly `"<error>: <error_description>"`, built from
 * the two wire fields, which are also exposed individually.
 *
 * @example
 * ```ts
 * try {
 *   await oidc.oidcExchange({ code, codeVerifier, nonce, redirectUri });
 * } catch (err) {
 *   if (err instanceof OAuthProtocolError && err.error === 'invalid_grant') {
 *     // the authorization code was replayed, expired, or bound to another client
 *   }
 * }
 * ```
 */
export class OAuthProtocolError extends AuthError {
  /** The RFC 6749 `error` code (e.g. `"invalid_grant"`, `"invalid_client"`, `"unsupported_grant_type"`). */
  readonly error: string;
  /** The server's human-readable `error_description`. Never contains token material. */
  readonly errorDescription: string;

  constructor(error: string, errorDescription: string) {
    super(`${error}: ${errorDescription}`);
    this.name = 'OAuthProtocolError';
    this.error = error;
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, OAuthProtocolError.prototype);
  }
}

/**
 * Authorization failure (CONTRACT.md §2): the caller is authenticated but
 * lacks permission for the requested operation (`403`, or `409` for a
 * resource-level denial).
 */
export class AuthzError extends AxiamError {
  /** The denied action, when the server reported it. */
  readonly action?: string;
  /** The resource the denied action targeted, when the server reported it. */
  readonly resourceId?: string;

  constructor(message: string, action?: string, resourceId?: string) {
    super(message);
    this.name = 'AuthzError';
    this.action = action;
    this.resourceId = resourceId;
    Object.setPrototypeOf(this, AuthzError.prototype);
  }
}

/**
 * Transport-level failure (CONTRACT.md §2): connection refused, timeout, TLS
 * or DNS error, a malformed request (`400`), rate limiting (`429`), or a `5xx`
 * server error.
 */
export class NetworkError extends AxiamError {
  /** The underlying transport error, with every non-allowlisted response header redacted (§2, X-3). */
  readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'NetworkError';
    this.cause = cause;
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}
