// login/verifyMfa/refresh/logout over REST (D-18, §1).
//
// Mirrors the Rust SDK's src/rest/auth.rs's request/response shapes exactly
// (mirror only, no server crate dependency). Tokens are delivered
// exclusively via Set-Cookie — LoginResult deliberately carries no session
// token field anywhere in the public API (T-17-07).

import { AuthError, AxiamError, mapHttpStatusToError, NetworkError, Sensitive, sanitizeAxiosError } from '../core/index.js';
import type { AxiamClient } from './client.js';
import type {
  AxiamUserInfo,
  LoginResult,
  LoginSuccessResponseWire,
  LoginUserInfoWire,
  MfaRequiredResponseWire,
  MfaSetupRequiredResponseWire,
  RefreshSuccessResponseWire,
} from './types.js';

const LOGIN_PATH = '/api/v1/auth/login';
const MFA_VERIFY_PATH = '/api/v1/auth/mfa/verify';
const REFRESH_PATH = '/api/v1/auth/refresh';
const LOGOUT_PATH = '/api/v1/auth/logout';

interface MfaVerifyRequestBody {
  challenge_token: string;
  totp_code: string;
}

/**
 * Map the wire user object onto {@link AxiamUserInfo}.
 *
 * Shared by the three response paths that complete a login — password,
 * OPAQUE, and the account-lifecycle flows — which previously each carried
 * their own copy of this mapping and a comment saying "same reading as
 * `auth.ts`". Contract 1.34 turned that duplication into a hazard: five more
 * fields, and a copy that forwards three of them is a bug nothing catches.
 */
export function userInfoFromWire(user: LoginUserInfoWire): AxiamUserInfo {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    // §5.2: derived server-side and response-only. `?? false` is what makes a
    // pre-1.31 server's silence mean "no cross-tenant action", rather than
    // `undefined` leaking into a truthiness check somewhere downstream.
    organizationLevel: user.organization_level ?? false,
    tenantId: user.tenant_id,
    // §5.2.2 rule 1: absent means equal. A server older than contract 1.34
    // omits this and cannot switch the acting tenant either, so falling back
    // to `tenant_id` is not a guess — it is the only value it could have had.
    principalTenantId: user.principal_tenant_id ?? user.tenant_id,
    principalTenantSlug: user.principal_tenant_slug ?? undefined,
    orgId: user.org_id ?? undefined,
    // §5.2.3: absent means unrestricted, and `null` from the server means the
    // same thing — neither should surface as an empty list, which would read
    // as "reaches nothing".
    reachableTenantIds: user.reachable_tenant_ids ?? undefined,
  };
}

function loginSuccessToResult(wire: LoginSuccessResponseWire, client?: AxiamClient): LoginResult {
  const user = userInfoFromWire(wire.user);
  // §5.2.2: remember where this principal lives, so a later
  // `opaqueEnrollmentForSelf` seals against the account's own tenant without
  // a second round trip.
  if (client && user.principalTenantId) {
    client.session.resolvedPrincipalTenantId = user.principalTenantId;
  }
  if (client) recordPrincipalScope(client, user);
  return {
    status: 'authenticated',
    user,
    sessionId: wire.session_id,
    expiresIn: wire.expires_in,
  };
}

/**
 * Remember what a completed login reported about the principal's reach
 * (CONTRACT.md §5.2 / §5.2.3, contract 1.51), so `AxiamClient.actingTenant()`
 * can gate on it.
 *
 * Called for every session-establishing response that carries a
 * `LoginUserInfo`: password login, `verifyMfa`, OPAQUE login, the two
 * WebAuthn login ceremonies, and `mfaSetupConfirm`. All five decode the
 * identical wire shape through {@link userInfoFromWire}, so all five report
 * exactly what the server said — a deliberately more precise choice than
 * treating them as "unknown" (see the C-12 note in the PR/CHANGELOG): this
 * SDK's `userInfoFromWire` already gives every one of them a real
 * `organizationLevel`/`reachableTenantIds`, so reading the real values is no
 * more work than discarding them would be.
 *
 * NOT called by `authenticateDevice()` (§6.1): a device token is a
 * service-account credential with no `LoginUserInfo` behind it, so that path
 * explicitly resets this to `undefined` instead — "the server said nothing",
 * on which `actingTenant()` has nothing to gate.
 *
 * @internal
 */
export function recordPrincipalScope(client: AxiamClient, user: AxiamUserInfo): void {
  client.session.principalScope = {
    organizationLevel: user.organizationLevel,
    reachableTenantIds: user.reachableTenantIds,
  };
}

function mfaRequiredToResult(wire: MfaRequiredResponseWire): LoginResult {
  return {
    status: 'mfa_required',
    mfaToken: wire.challenge_token,
    availableMethods: wire.available_methods,
  };
}

/**
 * CONTRACT.md §25.2 rule 1 — the `403 mfa_setup_required` branch of `login`.
 *
 * The server answers `403` when the tenant requires MFA and the account has
 * none, and hands back the token to fix it. Mapping that through §2 to
 * `AuthzError` told the caller they lacked permission to log in, when what the
 * server said was recoverable and came with the means to recover. It is an
 * outcome, so it is returned rather than thrown.
 *
 * Matched on the body's own discriminant, not on the status alone: a genuine
 * authorization refusal is also a `403`, and only one of the two carries a
 * `setup_token`.
 *
 * Exported so `loginOpaque` shares it — that endpoint answers the identical
 * `403`, and a second copy of this check is a second place for the two to
 * disagree about what a setup branch looks like.
 *
 * @internal
 */
export function mfaSetupRequired(err: unknown): LoginResult | undefined {
  if (extractAxiosStatus(err) !== 403) return undefined;
  const body = extractAxiosData<Partial<MfaSetupRequiredResponseWire>>(err);
  if (body?.mfa_setup_required !== true || typeof body.setup_token !== 'string') {
    return undefined;
  }
  return { status: 'mfa_setup_required', setupToken: new Sensitive(body.setup_token) };
}

function extractErrorMessage(err: unknown): string {
  if (err && typeof err === 'object' && 'message' in err && typeof (err as { message?: unknown }).message === 'string') {
    return (err as { message: string }).message;
  }
  return 'request failed';
}

/**
 * `POST /api/v1/auth/login` (§1).
 *
 * On a 200 response returns the authenticated branch of the LoginResult
 * discriminated union; on the MFA-required response (202) returns the
 * mfa_required branch (mfaToken sourced from the wire challenge_token).
 */
export async function login(client: AxiamClient, email: string, password: string): Promise<LoginResult> {
  // §18.1 rule 4: use-after-close is an error, not a reconnect.
  client.ensureOpen();
  // §17.1 rule 9: entries are keyed by subject, not session, so any credential
  // change must drop them — otherwise a re-authentication as a different
  // principal inherits the previous one's decisions.
  client.decisionMemo.clear();
  // §6.1 rules 6-10 (contract 1.51): a password login fully replaces
  // whatever credential this client held, including a device token adopted
  // by an earlier authenticateDevice() call on the same client.
  client.session.deviceAccessToken = undefined;
  // The server resolves the workspace from the login body (org + tenant), not
  // the X-Tenant-ID header, so tenant/org context must travel here (§5).
  const body = client.session.buildLoginBody(email, password);

  try {
    // axios treats any 2xx (including 202 MFA-required) as a resolved
    // response, not a thrown error — branch on the actual status here.
    const response = await client.session.axios.post<LoginSuccessResponseWire | MfaRequiredResponseWire>(
      LOGIN_PATH,
      body,
    );
    if (response.status === 202) {
      return mfaRequiredToResult(response.data as MfaRequiredResponseWire);
    }
    client.session.authenticated = true;
    // CR-01/D-05: sync the Node persona's csrfToken (and cached access token)
    // from the jar now that the session cookie(s) have landed. No-op for the
    // browser SharedSession, which has no onAuthenticated implementation.
    await client.session.onAuthenticated?.();
    return loginSuccessToResult(response.data as LoginSuccessResponseWire, client);
  } catch (err) {
    // §25.2 rule 1: a recoverable, guided state, not a refusal. Checked
    // before the guard below because a 403 is never pre-mapped: the response
    // interceptor pre-maps only 401 on a SKIP_REFRESH url, so an
    // `mfa_setup_required` 403 still arrives here as a raw AxiosError.
    const setup = mfaSetupRequired(err);
    if (setup) return setup;

    // Already an SDK error: the response interceptor mapped it. LOGIN_PATH is
    // a SKIP_REFRESH url, so a 401 here has ALREADY become an AuthError
    // before this catch runs. Such an error carries no axios `.response`, so
    // `extractAxiosStatus` below reports undefined and the final line used to
    // bury the AuthError inside a NetworkError — reporting wrong credentials
    // as a transport failure, and inconsistently with verifyMfa(), whose path
    // is not SKIP_REFRESH and so maps the identical 401 straight to AuthError.
    // Rethrowing unchanged is also what §23.4 rule 7's OPAQUE fallback needs:
    // it delegates to login() and returns that call's outcome verbatim.
    if (err instanceof AxiamError) throw err;

    const status = extractAxiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, extractErrorMessage(extractAxiosData(err)) ?? 'login failed', {
        cause: err,
      });
    }
    throw new NetworkError('login request failed', sanitizeAxiosError(err));
  }
}

/**
 * `POST /api/v1/auth/mfa/verify` (§1).
 *
 * Completes the two-phase flow started by login() when status was
 * 'mfa_required', using the caller-supplied mfaToken (the challenge token
 * returned from that prior login() call).
 */
export async function verifyMfa(client: AxiamClient, mfaToken: string, code: string): Promise<LoginResult> {
  // §18.1 rule 4: use-after-close is an error, not a reconnect.
  client.ensureOpen();
  // §17.1 rule 9: entries are keyed by subject, not session, so any credential
  // change must drop them — otherwise a re-authentication as a different
  // principal inherits the previous one's decisions.
  client.decisionMemo.clear();
  client.session.deviceAccessToken = undefined;
  const body: MfaVerifyRequestBody = { challenge_token: mfaToken, totp_code: code };

  try {
    const response = await client.session.axios.post<LoginSuccessResponseWire>(MFA_VERIFY_PATH, body);
    client.session.authenticated = true;
    // CR-01/D-05: same post-authentication sync as login()'s 200 branch.
    await client.session.onAuthenticated?.();
    return loginSuccessToResult(response.data, client);
  } catch (err) {
    // Already mapped by the response interceptor — rethrow rather than bury
    // it in a NetworkError. MFA_VERIFY_PATH is not a SKIP_REFRESH url, so
    // nothing pre-maps a 401 here today; the guard keeps this path correct if
    // that list ever grows, and identical to its three siblings.
    if (err instanceof AxiamError) throw err;

    const status = extractAxiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, extractErrorMessage(extractAxiosData(err)) ?? 'verifyMfa failed', {
        cause: err,
      });
    }
    throw new NetworkError('verifyMfa request failed', sanitizeAxiosError(err));
  }
}

/**
 * `POST /api/v1/auth/refresh` (§1).
 *
 * Callers typically do not invoke this directly — the response interceptor
 * (interceptors.ts) drives it reactively via the single-flight guard on a
 * 401 (D-07). Exposed as a public method for explicit proactive refresh.
 */
export async function refresh(client: AxiamClient): Promise<void> {
  // §18.1 rule 4: use-after-close is an error, not a reconnect.
  client.ensureOpen();
  // §17.1 rule 9: entries are keyed by subject, not session, so any credential
  // change must drop them — otherwise a re-authentication as a different
  // principal inherits the previous one's decisions.
  client.decisionMemo.clear();
  try {
    await client.session.axios.post<RefreshSuccessResponseWire>(REFRESH_PATH, client.session.buildRefreshBody(), {
      headers: client.actingTenantHeaders(),
    });
    // H8 fix (SDK bench harness validation): a successful refresh rotates
    // the `axiam_csrf` cookie (new random token, CONTRACT.md §3) the same
    // way login does, but — unlike login/verifyMfa just below, which both
    // call `onAuthenticated?.()` — this path never resynced the Node
    // persona's in-memory `session.csrfToken` (only NodeSession.doRefresh
    // did that, and doRefresh is wired to gRPC's callWithRefresh only, never
    // to this REST path). Every REST call after the FIRST refresh() then
    // echoed a now-stale X-CSRF-Token and failed with 403 "CSRF validation
    // failed" — refresh() effectively broke the session after one use.
    // `onAuthenticated` is exactly the right hook to reuse: same
    // access/csrf resync as login, it's a no-op on the browser persona
    // (undefined there), and Node's implementation is idempotent.
    await client.session.onAuthenticated?.();
  } catch (err) {
    // REFRESH_PATH is a SKIP_REFRESH url, so a 401 here is already an
    // AuthError by the time this catch runs. §9.3 wants exactly that error
    // surfaced, not a NetworkError wrapping it.
    if (err instanceof AxiamError) throw err;

    const status = extractAxiosStatus(err);
    if (status !== undefined) {
      // §9.3: 401 on the refresh call itself is AuthError, no retry loop.
      throw mapHttpStatusToError(status, extractErrorMessage(extractAxiosData(err)) ?? 'refresh failed', {
        cause: err,
      });
    }
    throw new NetworkError('refresh request failed', sanitizeAxiosError(err));
  }
}

/**
 * `POST /api/v1/auth/logout` (§1).
 *
 * Clears session csrf/auth state regardless of the response outcome once
 * the request has been sent successfully.
 */
export async function logout(client: AxiamClient): Promise<void> {
  // §18.1 rule 4: use-after-close is an error, not a reconnect.
  client.ensureOpen();
  // §17.1 rule 9: entries are keyed by subject, not session, so any credential
  // change must drop them — otherwise a re-authentication as a different
  // principal inherits the previous one's decisions.
  client.decisionMemo.clear();
  try {
    await client.session.axios.post(LOGOUT_PATH, {}, { headers: client.actingTenantHeaders() });
  } catch (err) {
    // LOGOUT_PATH is a SKIP_REFRESH url — same pre-mapping as login/refresh.
    // The `finally` below still clears session state either way.
    if (err instanceof AxiamError) throw err;

    const status = extractAxiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, extractErrorMessage(extractAxiosData(err)) ?? 'logout failed', {
        cause: err,
      });
    }
    throw new NetworkError('logout request failed', sanitizeAxiosError(err));
  } finally {
    client.session.authenticated = false;
    client.session.csrfToken = undefined;
    // §5.2 rule 1 (C-12): logout forgets what the previous session reported.
    // A later re-login as a different principal must not have
    // `actingTenant()` gate on the outgoing principal's reach.
    client.session.principalScope = undefined;
    // §6.1 rules 6-10 (contract 1.51): forget an adopted device token too.
    client.session.deviceAccessToken = undefined;
  }
}

// ---------------------------------------------------------------------------
// §6.1 rules 6-10 (contract 1.51) — authenticateDevice(), the mTLS device
// login. `POST /api/v1/auth/device`, no request body.
// ---------------------------------------------------------------------------

const DEVICE_LOGIN_PATH = '/api/v1/auth/device';

interface DeviceLoginResponseWire {
  access_token: string;
  token_type: string;
  expires_in: number;
}

/** The outcome of {@link AxiamClient.authenticateDevice} — CONTRACT.md §6.1 rule 6. */
export interface DeviceToken {
  /** The minted access token. Secret material (§7) — never logged/serialized. */
  accessToken: Sensitive<string>;
  /** Always `"Bearer"`. */
  tokenType: string;
  /** Access-token lifetime in seconds from the time of this response (server default 900). */
  expiresIn: number;
}

/**
 * `POST /api/v1/auth/device` (§6.1 rules 6–10, contract 1.51) — authenticate
 * an IoT device or service account by the mutual-TLS identity this client was
 * built with.
 *
 * No request body; the server derives identity entirely from the client
 * certificate presented during the TLS handshake. Adopts the returned token
 * as this client's credential exactly as a completed `login()` is adopted —
 * every subsequent same-origin REST request carries it as
 * `Authorization: Bearer`.
 *
 * **There is no refresh token** (server decision, D-6 of the dogfooding
 * remediation plan). A device re-authenticates by calling this operation
 * again, which costs one TLS handshake; a later `401` on the adopted token is
 * surfaced as `AuthError` without a refresh attempt (rule 6,
 * `rest/interceptors.ts`'s reactive-refresh guard checks
 * `session.deviceAccessToken` for exactly this).
 *
 * @throws {AuthError} client-side, with **zero wire calls**, when this client
 * was not built with a client certificate (rule 7) — going to the wire would
 * only earn the same `401` the server already knows it would give, turning a
 * configuration mistake into an authentication failure. Also thrown (this
 * time from the server's `401`) for an unknown, untrusted, expired, revoked
 * or unbound certificate, and for a `Server`-type certificate (rule 8) — the
 * message is the server's, surfaced verbatim.
 * @throws {NetworkError} on a `429` (the route is rate-limited per client IP;
 * §16 governs, and this is not an authentication failure, rule 8) or any
 * other transport failure. Never retried — this call is not routed through
 * §16's retry runner, the same way `login()` is not.
 */
export async function authenticateDevice(client: AxiamClient): Promise<DeviceToken> {
  // §18.1 rule 4: use-after-close is an error, not a reconnect.
  client.ensureOpen();
  // Rule 7: reachable only on a client configured with a certificate. Elsewhere
  // the call MUST fail client-side, with zero wire calls.
  if (!client.session.presentsClientCertificate) {
    throw new AuthError(
      'authenticateDevice() requires a client configured with clientCert/clientKey ' +
        '(CONTRACT.md §6.1 rule 7); this client has neither',
    );
  }
  // §17.1 rule 9: this is a credential change, exactly as login() is.
  client.decisionMemo.clear();
  // A fresh call gets a fresh credential — this client's PREVIOUS device
  // token (if any) must not linger and be sent alongside this attempt, or a
  // failure below would leave a stale one still adopted.
  client.session.deviceAccessToken = undefined;

  try {
    const response = await client.session.axios.post<DeviceLoginResponseWire>(
      DEVICE_LOGIN_PATH,
      undefined,
      // "What the plan did not anticipate" note 3: this LOGIN call itself
      // must not carry a stale cookie from an earlier session either — the
      // server would read that cookie before deciding this is a device
      // login. noCredentialsConfig() keeps the mTLS client certificate on
      // the connection (it is TLS-configured, not TLS-disabled) while
      // dropping the cookie jar.
      client.session.noCredentialsConfig(),
    );
    const accessToken = new Sensitive(response.data.access_token);
    client.session.deviceAccessToken = accessToken;
    client.session.authenticated = true;
    // §6.1: a device token carries no LoginUserInfo. actingTenant() has
    // nothing to gate on and sends the header regardless (§5.2 rule 1).
    client.session.principalScope = undefined;
    return {
      accessToken,
      tokenType: response.data.token_type,
      expiresIn: response.data.expires_in,
    };
  } catch (err) {
    // Rule 8: every refusal is a 401, mapped to AuthError and surfaced
    // verbatim — this IS the login, so it MUST NOT enter the §9 refresh
    // guard. `DEVICE_LOGIN_PATH` is in `SKIP_REFRESH` (CONTRACT 1.52 N4.5,
    // C-12) precisely so this holds even when `session.authenticated` is
    // already true from an EARLIER cookie session on this same client — a
    // case this comment used to (wrongly) say could not happen. A 429 maps
    // to NetworkError through the same §2 mapping every other REST call
    // uses.
    if (err instanceof AxiamError) throw err;
    const status = extractAxiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(
        status,
        extractErrorMessage(extractAxiosData(err)) ?? 'authenticateDevice failed',
        { cause: err },
      );
    }
    throw new NetworkError('authenticateDevice request failed', sanitizeAxiosError(err));
  }
}

// ---------------------------------------------------------------------------
// axios error helpers (kept local — core stays dependency-free of axios)
// ---------------------------------------------------------------------------

function extractAxiosStatus(err: unknown): number | undefined {
  if (err && typeof err === 'object' && 'response' in err) {
    const response = (err as { response?: { status?: number } }).response;
    return response?.status;
  }
  return undefined;
}

function extractAxiosData<T>(err: unknown): T | undefined {
  if (err && typeof err === 'object' && 'response' in err) {
    const response = (err as { response?: { data?: T } }).response;
    return response?.data;
  }
  return undefined;
}
