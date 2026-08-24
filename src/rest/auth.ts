// login/verifyMfa/refresh/logout over REST (D-18, §1).
//
// Mirrors the Rust SDK's src/rest/auth.rs's request/response shapes exactly
// (mirror only, no server crate dependency). Tokens are delivered
// exclusively via Set-Cookie — LoginResult deliberately carries no session
// token field anywhere in the public API (T-17-07).

import { AxiamError, mapHttpStatusToError, NetworkError, Sensitive, sanitizeAxiosError } from '../core/index.js';
import type { AxiamClient } from './client.js';
import type {
  LoginResult,
  LoginSuccessResponseWire,
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

function loginSuccessToResult(wire: LoginSuccessResponseWire): LoginResult {
  return {
    status: 'authenticated',
    user: { id: wire.user.id, username: wire.user.username, email: wire.user.email },
    sessionId: wire.session_id,
    expiresIn: wire.expires_in,
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
    return loginSuccessToResult(response.data as LoginSuccessResponseWire);
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
  const body: MfaVerifyRequestBody = { challenge_token: mfaToken, totp_code: code };

  try {
    const response = await client.session.axios.post<LoginSuccessResponseWire>(MFA_VERIFY_PATH, body);
    client.session.authenticated = true;
    // CR-01/D-05: same post-authentication sync as login()'s 200 branch.
    await client.session.onAuthenticated?.();
    return loginSuccessToResult(response.data);
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
    await client.session.axios.post<RefreshSuccessResponseWire>(REFRESH_PATH, client.session.buildRefreshBody());
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
    await client.session.axios.post(LOGOUT_PATH, {});
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
