// Account lifecycle and MFA enrolment (CONTRACT.md §25).
//
// §1 locked the middle of an account's life — login, verifyMfa, refresh,
// logout all assume an account that already exists, is verified, and already
// has its second factor. These nine operations are how an account gets into
// that state. None of them is new server surface; all nine have been live and
// unreachable-from-an-SDK since before §1 was written, which meant every
// application hand-rolled a POST against a path this SDK also knew.

import { mapHttpStatusToError, NetworkError, Sensitive, sanitizeAxiosError } from '../core/index.js';
import type { AxiamClient } from './client.js';
import { userInfoFromWire } from './auth.js';
import type { LoginResult, LoginSuccessResponseWire } from './types.js';

const MFA_ENROLL = '/api/v1/auth/mfa/enroll';
const MFA_CONFIRM = '/api/v1/auth/mfa/confirm';
const MFA_SETUP_ENROLL = '/api/v1/auth/mfa/setup/enroll';
const MFA_SETUP_CONFIRM = '/api/v1/auth/mfa/setup/confirm';
const VERIFY_EMAIL = '/api/v1/auth/verify-email';
const RESEND_VERIFICATION = '/api/v1/auth/resend-verification';
const RESEND_OWN_VERIFICATION = '/api/v1/users/me/resend-verification';
const RESET_REQUEST = '/api/v1/auth/reset';
const RESET_CONFIRM = '/api/v1/auth/reset/confirm';
const RESET_CONTEXT = '/api/v1/auth/reset/context';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * A TOTP enrolment offer. **The factor is not active yet** — it becomes active
 * when `AxiamClient.mfaConfirm` accepts a code derived from this secret (§25.2
 * rule 4).
 *
 * Both fields are `Sensitive`, and `totpUri` is the one that matters: it is
 * `otpauth://totp/...?secret=<secretBase32>`, so it *contains* the secret. An
 * SDK that wrapped the secret and left the URI bare would have wrapped nothing
 * — the URI is the field that actually reaches a log, because it is the field
 * a caller passes to a QR renderer (§25.3).
 */
export interface MfaEnrollment {
  /** The shared TOTP secret, base32. Anyone holding it can generate valid codes indefinitely. */
  secretBase32: Sensitive<string>;
  /** `otpauth://totp/…?secret=…` — what a QR renderer takes. It *contains* `secretBase32`. */
  totpUri: Sensitive<string>;
}

/**
 * The effective OPAQUE policy for the account a reset token belongs to (§25.4).
 *
 * Discloses no identity. Contract 1.26 removed the username from this response
 * when OPAQUE replaced SRP — an unauthenticated endpoint that confirms which
 * account a token belongs to is an oracle worth not having.
 */
export interface PasswordResetContext {
  /** The tenant's OPAQUE parameters, when it has OPAQUE enabled. Absent means plaintext is accepted. */
  opaque?: Record<string, unknown>;
}

/** The workspace a password-reset request names. Slugs are accepted, as on `login`. */
export interface PasswordResetRequest {
  /** The address to send the reset mail to. */
  email: string;
  /** Organization slug. Defaults to the client's own configuration. */
  orgSlug?: string;
  /** Tenant UUID. Defaults to the client's own configuration. */
  tenantId?: string;
  /** Tenant slug. Defaults to the client's own configuration. */
  tenantSlug?: string;
}

/** Everything `confirmPasswordReset` needs. */
export interface PasswordResetConfirmation {
  /** The single-use token from the reset mail. */
  token: Sensitive<string> | string;
  /** The new password. */
  newPassword: Sensitive<string> | string;
  /** The tenant the account belongs to. A UUID — this is a body field, not a query parameter. */
  tenantId: string;
  /**
   * The §23 registration record, for a tenant whose `AxiamClient.passwordResetContext`
   * says it requires one. Sending a plaintext `newPassword` to a tenant in
   * `opaque_mode: required` is refused, and refused late (§25.4 rule 1).
   */
  opaque?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

interface MfaEnrollWire {
  secret_base32: string;
  totp_uri: string;
}
interface MfaConfirmWire {
  mfa_enabled: boolean;
}
interface ResetContextWire {
  opaque?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Voluntary MFA enrolment, by a signed-in user (§25.2)
// ---------------------------------------------------------------------------

/**
 * `POST /api/v1/auth/mfa/enroll` (§25.1) — start voluntary TOTP enrolment.
 *
 * Requires a session and changes nothing about it. In particular this does
 * **not** clear the §17 decision memo: the subject has not changed, and
 * discarding a warm memo on an unrelated profile action costs a round trip on
 * every check that follows (§25.2 rule 3).
 */
export async function mfaEnroll(client: AxiamClient): Promise<MfaEnrollment> {
  client.ensureOpen();
  const wire = await post<MfaEnrollWire>(client, MFA_ENROLL, {}, 'mfaEnroll');
  return {
    secretBase32: new Sensitive(wire.secret_base32),
    totpUri: new Sensitive(wire.totp_uri),
  };
}

/**
 * `POST /api/v1/auth/mfa/confirm` (§25.1) — activate the factor
 * {@link mfaEnroll} offered, by proving a code derived from its secret.
 */
export async function mfaConfirm(client: AxiamClient, totpCode: string): Promise<boolean> {
  client.ensureOpen();
  const wire = await post<MfaConfirmWire>(
    client,
    MFA_CONFIRM,
    { totp_code: totpCode },
    'mfaConfirm',
  );
  return wire.mfa_enabled;
}

// ---------------------------------------------------------------------------
// Forced MFA enrolment, during login (§25.2)
// ---------------------------------------------------------------------------

/**
 * `POST /api/v1/auth/mfa/setup/enroll` (§25.1) — start the enrolment a
 * `login()` demanded.
 *
 * Reached when `login()` returns the `mfa_setup_required` outcome: the tenant
 * requires MFA and this account has none. There is no session yet — the setup
 * token *is* the credential.
 */
export async function mfaSetupEnroll(
  client: AxiamClient,
  setupToken: Sensitive<string> | string,
): Promise<MfaEnrollment> {
  client.ensureOpen();
  const wire = await post<MfaEnrollWire>(
    client,
    MFA_SETUP_ENROLL,
    { setup_token: expose(setupToken) },
    'mfaSetupEnroll',
  );
  return {
    secretBase32: new Sensitive(wire.secret_base32),
    totpUri: new Sensitive(wire.totp_uri),
  };
}

/**
 * `POST /api/v1/auth/mfa/setup/confirm` (§25.1) — finish forced enrolment and,
 * with it, the login that was interrupted.
 *
 * Adopts credentials exactly as `login()` does, because it *is* the completion
 * of a login (§25.2 rule 2).
 */
export async function mfaSetupConfirm(
  client: AxiamClient,
  setupToken: Sensitive<string> | string,
  totpCode: string,
): Promise<LoginResult> {
  client.ensureOpen();
  // §17.1 rule 9: the subject changes here, unlike on `mfaEnroll`.
  client.decisionMemo.clear();

  const wire = await post<LoginSuccessResponseWire>(
    client,
    MFA_SETUP_CONFIRM,
    { setup_token: expose(setupToken), totp_code: totpCode },
    'mfaSetupConfirm',
  );

  client.session.authenticated = true;
  await client.session.onAuthenticated?.();

  return {
    status: 'authenticated',
    user: userInfoFromWire(wire.user),
    sessionId: wire.session_id,
    expiresIn: wire.expires_in,
  };
}

// ---------------------------------------------------------------------------
// Email verification (§25.1)
// ---------------------------------------------------------------------------

/** `POST /api/v1/auth/verify-email` (§25.1). Unauthenticated — the user may have no session yet. */
export async function verifyEmail(
  client: AxiamClient,
  token: Sensitive<string> | string,
  tenantId: string,
): Promise<void> {
  client.ensureOpen();
  await post<void>(
    client,
    VERIFY_EMAIL,
    { token: expose(token), tenant_id: tenantId },
    'verifyEmail',
  );
}

/**
 * `POST /api/v1/auth/resend-verification` (§25.1) — the **unauthenticated**
 * resend, for a caller with no session.
 *
 * **Resolves whatever the outcome.** The address may not exist, may already be
 * verified, or may be over the daily limit, and this answers identically in all
 * of them, because it takes an address from an anonymous caller and anything
 * else is an oracle for which addresses have accounts (§25.7).
 *
 * A caller that *is* signed in wants {@link resendOwnVerification}, which says
 * which of those happened. Do not reach for this one because it is the name you
 * already knew.
 */
export async function resendVerification(
  client: AxiamClient,
  email: string,
  tenantId: string,
): Promise<void> {
  client.ensureOpen();
  await post<void>(
    client,
    RESEND_VERIFICATION,
    { email, tenant_id: tenantId },
    'resendVerification',
  );
}

/**
 * `POST /api/v1/users/me/resend-verification` (§25.1, §25.7) — resend the
 * **signed-in caller's own** verification mail, and say what happened.
 *
 * Takes no address. The server reads it off the caller's own record, and this
 * signature deliberately offers no way to name a different one: a parameter
 * here would let an authenticated session mail an arbitrary address.
 *
 * Unlike {@link resendVerification} this reports the outcome, because the
 * caller is signed in to the account it is asking about and none of the
 * outcomes tells it anything it did not already know:
 *
 * - resolves — a token was minted and the mail **enqueued**. Delivery is
 *   asynchronous and can still fail at the provider; a queue that accepts
 *   everything in front of one that rejects it looks exactly like this working.
 * - `ConflictError` (from `409`) — already verified, or the account is in a
 *   state that must not be sent a live token.
 * - `NetworkError` (from `429`) — the daily resend limit.
 *
 * §25.7 rule 2 forbids falling back to the unauthenticated endpoint on either
 * of those, and this SDK does not: the fallback would turn both failures back
 * into a resolved promise and restore the bug this operation exists to fix,
 * with an extra round-trip.
 */
export async function resendOwnVerification(client: AxiamClient): Promise<void> {
  client.ensureOpen();
  await post<void>(client, RESEND_OWN_VERIFICATION, {}, 'resendOwnVerification');
}

// ---------------------------------------------------------------------------
// Password reset (§25.4)
// ---------------------------------------------------------------------------

/**
 * `POST /api/v1/auth/reset` (§25.1) — ask for a reset mail.
 *
 * **Resolves whether or not the address exists**, and this SDK exposes no way
 * to tell the two apart. That is not an omission to improve on: a client that
 * surfaced a "no such user" state — even one inferred from timing — would turn
 * the endpoint into the enumeration oracle its uniform response exists to
 * prevent (§25.4).
 */
export async function requestPasswordReset(
  client: AxiamClient,
  request: PasswordResetRequest,
): Promise<void> {
  client.ensureOpen();
  const body: Record<string, string> = { email: request.email };
  const orgSlug = request.orgSlug ?? client.session.orgSlug;
  const tenantId = request.tenantId ?? client.session.tenantId;
  const tenantSlug = request.tenantSlug ?? client.session.tenantSlug;
  if (orgSlug) body.org_slug = orgSlug;
  if (tenantId) body.tenant_id = tenantId;
  if (tenantSlug) body.tenant_slug = tenantSlug;

  await post<void>(client, RESET_REQUEST, body, 'requestPasswordReset');
}

/**
 * `GET /api/v1/auth/reset/context` (§25.1) — the OPAQUE policy for the account
 * a reset token belongs to.
 *
 * Call this before {@link confirmPasswordReset} on any tenant that might have
 * §23 enabled: the client has to build a registration record, and building one
 * needs parameters it cannot know before it has a token to ask with.
 *
 * `404` means unknown, expired **or** already-consumed, deliberately without
 * distinguishing them; this SDK does not distinguish them either (§25.4 rule 3).
 */
export async function passwordResetContext(
  client: AxiamClient,
  token: Sensitive<string> | string,
): Promise<PasswordResetContext> {
  client.ensureOpen();
  const url = `${RESET_CONTEXT}?token=${encodeURIComponent(expose(token))}`;
  try {
    const response = await client.session.axios.get<ResetContextWire>(url);
    return response.data?.opaque ? { opaque: response.data.opaque } : {};
  } catch (err) {
    throw toTaxonomyError(err, 'passwordResetContext');
  }
}

/** `POST /api/v1/auth/reset/confirm` (§25.1) — set the new password. */
export async function confirmPasswordReset(
  client: AxiamClient,
  confirmation: PasswordResetConfirmation,
): Promise<void> {
  client.ensureOpen();
  const body: Record<string, unknown> = {
    token: expose(confirmation.token),
    new_password: expose(confirmation.newPassword),
    tenant_id: confirmation.tenantId,
  };
  if (confirmation.opaque) body.opaque = confirmation.opaque;

  await post<void>(client, RESET_CONFIRM, body, 'confirmPasswordReset');
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function expose(value: Sensitive<string> | string): string {
  return typeof value === 'string' ? value : value.expose();
}

async function post<T>(
  client: AxiamClient,
  path: string,
  body: unknown,
  operation: string,
): Promise<T> {
  try {
    const response = await client.session.axios.post<T>(path, body);
    return response.data;
  } catch (err) {
    throw toTaxonomyError(err, operation);
  }
}

function toTaxonomyError(err: unknown, operation: string): Error {
  if (err && typeof err === 'object' && 'response' in err) {
    const response = (err as { response?: { status?: number; data?: unknown } }).response;
    if (response?.status !== undefined) {
      return mapHttpStatusToError(response.status, serverMessage(response.data) ?? `${operation} failed`, {
        cause: err,
      });
    }
  }
  return new NetworkError(`${operation} request failed`, sanitizeAxiosError(err));
}

function serverMessage(data: unknown): string | undefined {
  if (typeof data === 'string' && data.length > 0) return data;
  if (data && typeof data === 'object' && 'message' in data) {
    const message = (data as { message?: unknown }).message;
    if (typeof message === 'string' && message.length > 0) return message;
  }
  return undefined;
}
