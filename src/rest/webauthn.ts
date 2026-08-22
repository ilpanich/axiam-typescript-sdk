// WebAuthn / passkeys — the relying-party layer (CONTRACT.md §24.1–§24.5).
//
// Six wire operations. None of them touches an authenticator: that is §24.6,
// which lives in `axiam-sdk/browser` because it needs a DOM. These six are the
// half of a ceremony that talks to AXIAM, and they work identically in Node —
// a service completing a ceremony its native client ran is the relying party
// here, exactly as a browser is.
//
// The rule everything below obeys is §24.0: the server chooses every option
// and verifies every response, so this module carries both through untouched.
// It does not default a field, does not normalize one, and does not re-encode
// a buffer.

import { mapHttpStatusToError, NetworkError, Sensitive, sanitizeAxiosError } from '../core/index.js';
import type { AxiamClient } from './client.js';
import type {
  WebauthnAuthenticationResponse,
  WebauthnCreationChallenge,
  WebauthnCredential,
  WebauthnRegistrationResponse,
  WebauthnRequestChallenge,
  WebauthnWorkspace,
} from './webauthnTypes.js';

const REGISTER_START = '/api/v1/auth/webauthn/register/start';
const REGISTER_FINISH = '/api/v1/auth/webauthn/register/finish';
const AUTH_START = '/api/v1/auth/webauthn/authenticate/start';
const AUTH_FINISH = '/api/v1/auth/webauthn/authenticate/finish';
const DISCOVERABLE_START = '/api/v1/auth/webauthn/authenticate/discoverable/start';
const DISCOVERABLE_FINISH = '/api/v1/auth/webauthn/authenticate/discoverable/finish';

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

/**
 * A started ceremony: the server's challenge, plus the state token that binds
 * a response to it.
 *
 * `stateToken` is `Sensitive` (§24.5) — it is a bearer credential for the
 * length of the ceremony, and one that leaks inside that window is a ceremony
 * an attacker can try to complete. Pass it straight back to the matching
 * `*Finish` call; the SDK never decodes it and neither should a caller.
 */
export interface WebauthnRegistrationChallenge {
  /** The server's options. Hand them to the authenticator unchanged (§24.0). */
  challenge: WebauthnCreationChallenge;
  /** Binds the authenticator's answer to this challenge. Pass it back to `webauthnRegisterFinish`. */
  stateToken: Sensitive<string>;
}

/** A started authentication ceremony (both the second-factor and discoverable forms). */
export interface WebauthnAuthenticationChallenge {
  /** The server's options. Hand them to the authenticator unchanged (§24.0). */
  challenge: WebauthnRequestChallenge;
  /** Binds the authenticator's answer to this challenge. Pass it back to the matching `*Finish`. */
  stateToken: Sensitive<string>;
}

/**
 * The outcome of a completed passkey sign-in.
 *
 * The client is **already authenticated** when this resolves (§24.3 rule 1) —
 * the tokens are returned as well because a caller may want to hand them
 * onward, not because adoption is optional.
 */
export interface WebauthnLoginResult {
  /** The new access token. Already adopted by this client (§24.3 rule 1). */
  accessToken: Sensitive<string>;
  /** The session refresh token — refreshed through `refresh()`, not `oidcRefresh` (§24.3 rule 5). */
  refreshToken: Sensitive<string>;
  /** Opaque identifier for the session just created. */
  sessionId: string;
  /** Access-token lifetime in seconds, from the time of this response. */
  expiresIn: number;
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

interface StartRegistrationWire {
  challenge: WebauthnCreationChallenge;
  state_token: string;
}
interface StartAuthenticationWire {
  challenge: WebauthnRequestChallenge;
  state_token: string;
}
interface CredentialWire {
  id: string;
  credential_id: string;
  name: string;
  credential_type: string;
  created_at: string;
  last_used_at?: string | null;
}
interface WebauthnLoginWire {
  access_token: string;
  refresh_token: string;
  session_id: string;
  expires_in: number;
}

// ---------------------------------------------------------------------------
// Registration — requires an authenticated session (§24.1)
// ---------------------------------------------------------------------------

/**
 * `POST /api/v1/auth/webauthn/register/start` (§24.1).
 *
 * Enrolling a passkey is something a signed-in user does to their own account,
 * so this requires a session and fails **client-side with no wire call** when
 * there is none.
 *
 * A `503` here means the tenant's attestation policy requires attestation and
 * the FIDO metadata service has no usable snapshot. That is a server
 * configuration state, not a transient failure, so it is surfaced as a
 * `AxiamError` and — per §24.4 rule 2 — deliberately **not** retried.
 */
export async function webauthnRegisterStart(
  client: AxiamClient,
): Promise<WebauthnRegistrationChallenge> {
  client.ensureOpen();
  requireSession(client, 'webauthnRegisterStart');

  const wire = await post<StartRegistrationWire>(client, REGISTER_START, {}, 'webauthnRegisterStart');
  return { challenge: wire.challenge, stateToken: new Sensitive(wire.state_token) };
}

/**
 * `POST /api/v1/auth/webauthn/register/finish` (§24.1).
 *
 * `response` goes to the server exactly as the authenticator produced it
 * (§24.0 rule 3).
 *
 * A `403` is the tenant's attestation policy refusing **this authenticator** —
 * an AAGUID that is not allow-listed, a missing FIDO certification, a revoked
 * status. It is not a permission problem with the user, and the server's
 * message is surfaced verbatim (§24.4 rule 1) because it is the only way the
 * person holding the key learns that a different one would work.
 */
export async function webauthnRegisterFinish(
  client: AxiamClient,
  stateToken: Sensitive<string> | string,
  credentialName: string,
  response: WebauthnRegistrationResponse | string,
): Promise<WebauthnCredential> {
  client.ensureOpen();
  requireSession(client, 'webauthnRegisterFinish');

  const wire = await post<CredentialWire>(
    client,
    REGISTER_FINISH,
    {
      state_token: expose(stateToken),
      credential_name: credentialName,
      response: asResponse(response, 'webauthnRegisterFinish'),
    },
    'webauthnRegisterFinish',
  );

  return {
    id: wire.id,
    credentialId: wire.credential_id,
    name: wire.name,
    credentialType: wire.credential_type,
    createdAt: wire.created_at,
    ...(wire.last_used_at ? { lastUsedAt: wire.last_used_at } : {}),
  };
}

// ---------------------------------------------------------------------------
// Authentication as a second factor (§24.2)
// ---------------------------------------------------------------------------

/**
 * `POST /api/v1/auth/webauthn/authenticate/start` (§24.1).
 *
 * The **second-factor** ceremony: it continues a `login()` that answered
 * `mfa_required` and listed `"webauthn"` among its methods. `challengeToken`
 * is that result's `mfaToken`.
 *
 * This is a different flow from {@link webauthnDiscoverableStart}, not the
 * same one with an optional argument — see §24.2 for why they cannot be
 * merged.
 */
export async function webauthnAuthenticateStart(
  client: AxiamClient,
  challengeToken: Sensitive<string> | string,
): Promise<WebauthnAuthenticationChallenge> {
  client.ensureOpen();
  const wire = await post<StartAuthenticationWire>(
    client,
    AUTH_START,
    { challenge_token: expose(challengeToken) },
    'webauthnAuthenticateStart',
  );
  return { challenge: wire.challenge, stateToken: new Sensitive(wire.state_token) };
}

/** `POST /api/v1/auth/webauthn/authenticate/finish` (§24.1). Adopts the session (§24.3). */
export async function webauthnAuthenticateFinish(
  client: AxiamClient,
  stateToken: Sensitive<string> | string,
  response: WebauthnAuthenticationResponse | string,
): Promise<WebauthnLoginResult> {
  return finishSignIn(client, AUTH_FINISH, stateToken, response, 'webauthnAuthenticateFinish');
}

// ---------------------------------------------------------------------------
// Usernameless (discoverable) authentication (§24.2)
// ---------------------------------------------------------------------------

/**
 * `POST /api/v1/auth/webauthn/authenticate/discoverable/start` (§24.1).
 *
 * The **primary-factor** ceremony: nothing precedes it, the server sends an
 * empty `allowCredentials`, and the assertion itself identifies the user.
 *
 * The workspace still has to be named — a discoverable credential is resolved
 * inside one tenant's isolation boundary — but the SDK fills it from its own
 * configured identity, and this endpoint accepts slugs, so a slug-only client
 * can run the ceremony.
 */
export async function webauthnDiscoverableStart(
  client: AxiamClient,
  workspace?: WebauthnWorkspace,
): Promise<WebauthnAuthenticationChallenge> {
  client.ensureOpen();

  const body = resolveWorkspace(client, workspace);
  const wire = await post<StartAuthenticationWire>(
    client,
    DISCOVERABLE_START,
    body,
    'webauthnDiscoverableStart',
  );
  return { challenge: wire.challenge, stateToken: new Sensitive(wire.state_token) };
}

/**
 * `POST /api/v1/auth/webauthn/authenticate/discoverable/finish` (§24.1).
 * Adopts the session (§24.3).
 *
 * Unlike its username-bound twin this fires the server's `login.post_auth`
 * reactor hook (§22.5): there was no password step for the event to have been
 * fired at.
 */
export async function webauthnDiscoverableFinish(
  client: AxiamClient,
  stateToken: Sensitive<string> | string,
  response: WebauthnAuthenticationResponse | string,
): Promise<WebauthnLoginResult> {
  return finishSignIn(
    client,
    DISCOVERABLE_FINISH,
    stateToken,
    response,
    'webauthnDiscoverableFinish',
  );
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/**
 * The shared tail of both authentication ceremonies.
 *
 * §24.3 rule 1: a completed passkey sign-in leaves the client authenticated,
 * in exactly the state `login()` leaves it. This is not §14.3's "MAY adopt"
 * posture — `deviceLogin` mints tokens a caller may want to route elsewhere,
 * and this is the SDK's own primary authentication. Returning a token set
 * without adopting it would make `webauthnLogin()` the one way to log in that
 * does not log you in.
 */
async function finishSignIn(
  client: AxiamClient,
  path: string,
  stateToken: Sensitive<string> | string,
  response: WebauthnAuthenticationResponse | string,
  operation: string,
): Promise<WebauthnLoginResult> {
  client.ensureOpen();
  // §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and this
  // call changes the subject.
  client.decisionMemo.clear();

  const wire = await post<WebauthnLoginWire>(
    client,
    path,
    { state_token: expose(stateToken), response: asResponse(response, operation) },
    operation,
  );

  client.session.authenticated = true;
  // Syncs the Node persona's csrfToken (and cached access token) out of the
  // jar. Load-bearing since the server started setting the cookie triple on
  // these two endpoints: without it the first state-changing call after a
  // passkey sign-in echoes no `X-CSRF-Token` and is refused (§24.3 rule 2).
  await client.session.onAuthenticated?.();

  return {
    accessToken: new Sensitive(wire.access_token),
    refreshToken: new Sensitive(wire.refresh_token),
    sessionId: wire.session_id,
    expiresIn: wire.expires_in,
  };
}

/**
 * §24.1: `register/*` needs a session, and the failure is raised client-side
 * with no wire call — the same shape §1.1 rule 3 requires of `getUserInfo`.
 */
function requireSession(client: AxiamClient, operation: string): void {
  if (!client.session.authenticated) {
    throw mapHttpStatusToError(
      401,
      `${operation} requires an authenticated session: enrol a passkey while signed in ` +
        '(CONTRACT.md §24.1).',
    );
  }
}

/**
 * Fill the discoverable ceremony's workspace from the client's own configured
 * identity when the caller passed none.
 *
 * Only the fields that actually have a value are emitted: the server takes
 * either form for either level, and sending `null` for the ones it does not
 * have would be indistinguishable from asking it to resolve nothing.
 */
function resolveWorkspace(
  client: AxiamClient,
  workspace: WebauthnWorkspace | undefined,
): Record<string, string> {
  const merged: WebauthnWorkspace = {
    orgId: workspace?.orgId ?? client.session.orgId,
    orgSlug: workspace?.orgSlug ?? client.session.orgSlug,
    tenantId: workspace?.tenantId ?? client.session.tenantId,
    tenantSlug: workspace?.tenantSlug ?? client.session.tenantSlug,
  };

  const body: Record<string, string> = {};
  if (merged.orgId) body.org_id = merged.orgId;
  if (merged.orgSlug) body.org_slug = merged.orgSlug;
  if (merged.tenantId) body.tenant_id = merged.tenantId;
  if (merged.tenantSlug) body.tenant_slug = merged.tenantSlug;

  if (!body.org_id && !body.org_slug) {
    throw mapHttpStatusToError(
      400,
      'webauthnDiscoverableStart needs an organization: construct the client with an org, or pass ' +
        'one in the workspace argument (CONTRACT.md §24.1).',
    );
  }
  if (!body.tenant_id && !body.tenant_slug) {
    throw mapHttpStatusToError(
      400,
      'webauthnDiscoverableStart needs a tenant: construct the client with one, or pass it in the ' +
        'workspace argument (CONTRACT.md §24.1).',
    );
  }
  return body;
}

function expose(token: Sensitive<string> | string): string {
  return typeof token === 'string' ? token : token.expose();
}

/**
 * Accept either the typed response or the platform's own JSON string (§24.6a
 * rule 2).
 *
 * Android's Credential Manager hands back `registrationResponseJson` /
 * `authenticationResponseJson`, and a browser hands back `credential.toJSON()`.
 * Requiring a caller to destructure one of those into a typed value that this
 * SDK immediately re-serializes is three chances to corrupt a signed buffer in
 * service of nothing — so the string is taken directly.
 *
 * Parsing is value-preserving: every field in these messages is a string or a
 * plain object, so what reaches the server is what the authenticator produced.
 * Key order can differ, which JSON does not ascribe meaning to and the server
 * does not read.
 */
function asResponse<T>(response: T | string, operation: string): T {
  if (typeof response !== 'string') return response;
  try {
    return JSON.parse(response) as T;
  } catch (err) {
    throw new TypeError(
      `${operation}: the authenticator response string is not valid JSON. Pass the platform's ` +
        'response JSON verbatim (CONTRACT.md §24.6a).',
      { cause: err },
    );
  }
}

/**
 * The challenge in the JSON form every platform authenticator API takes
 * (§24.6a rule 1).
 *
 * This is the string an Android app passes to
 * `CreatePublicKeyCredentialRequest` or `GetPublicKeyCredentialOption`, and the
 * value a browser passes to `PublicKeyCredential.parseCreationOptionsFromJSON()`.
 * It is the inner options object — the `publicKey` wrapper is what the DOM's
 * `CredentialCreationOptions` adds, and the platform JSON APIs do not want it.
 *
 * Pure local computation, no I/O. Nothing is defaulted, dropped or reordered on
 * the way through (§24.0).
 */
export function webauthnRequestJson(
  challenge: WebauthnCreationChallenge | WebauthnRequestChallenge,
): string {
  return JSON.stringify(challenge.publicKey);
}

/**
 * POST a JSON body and map failures through the §2 taxonomy.
 *
 * Not routed through §16's retry helper, and that is deliberate for the whole
 * section: five of the six operations are ceremony steps that consume
 * server-side state, and the sixth (`register/start`) has the `503` §24.4
 * rule 2 forbids retrying. There is nothing here a bounded retry could help.
 */
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
    const status = axiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, serverMessage(err) ?? `${operation} failed`, { cause: err });
    }
    throw new NetworkError(`${operation} request failed`, sanitizeAxiosError(err));
  }
}

function axiosStatus(err: unknown): number | undefined {
  if (err && typeof err === 'object' && 'response' in err) {
    return (err as { response?: { status?: number } }).response?.status;
  }
  return undefined;
}

/**
 * The server's own message, kept verbatim.
 *
 * §24.4 rule 1 turns on this: a `403` from `register/finish` names which
 * attestation rule refused the authenticator, and replacing it with a generic
 * string throws away the only actionable part of the response.
 */
function serverMessage(err: unknown): string | undefined {
  if (!err || typeof err !== 'object' || !('response' in err)) return undefined;
  const data = (err as { response?: { data?: unknown } }).response?.data;
  if (typeof data === 'string' && data.length > 0) return data;
  if (data && typeof data === 'object' && 'message' in data) {
    const message = (data as { message?: unknown }).message;
    if (typeof message === 'string' && message.length > 0) return message;
  }
  return undefined;
}
