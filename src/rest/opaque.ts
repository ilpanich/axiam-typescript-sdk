// loginOpaque / opaqueEnrollment — the OPAQUE (RFC 9807) login path
// (CONTRACT.md §23).
//
// A sibling of `login`, not a replacement. It establishes the same fact — this
// principal knows the password — by a route that never puts the password on the
// wire, and returns the **same** `LoginResult`, so an application can switch a
// tenant to OPAQUE without touching its own code.
//
// The protocol lives in `core/opaque.ts`, which is a loader around the one
// shared implementation and performs no I/O; this module is the HTTP calls and
// the policy around them.

import { NetworkError, mapHttpStatusToError, sanitizeAxiosError } from '../core/index.js';
import {
  OpaqueUnavailableError,
  startLogin,
  startRegistration,
  type OpaqueKsfFields,
} from '../core/opaque.js';
import type { AxiamClient } from './client.js';
import type { LoginResult, LoginSuccessResponseWire, MfaRequiredResponseWire } from './types.js';

const OPAQUE_REGISTER_START_PATH = '/api/v1/auth/opaque/register/start';
const OPAQUE_LOGIN_START_PATH = '/api/v1/auth/opaque/login/start';
const OPAQUE_LOGIN_FINISH_PATH = '/api/v1/auth/opaque/login/finish';

interface LoginStartWire extends OpaqueKsfFields {
  opaque_session: string;
  ke2: string;
  suite: string;
}

interface RegisterStartWire extends OpaqueKsfFields {
  opaque_session: string;
  registration_response: string;
  suite: string;
}

/**
 * A completed enrolment, to send with any request that sets a password.
 *
 * Two fields, where the SRP verifier it replaces had seven. The server chose
 * the credential identifier, the ciphersuite and the costs and sealed them into
 * `opaque_session` — which is why a client cannot name any of them, and why it
 * cannot enrol a record against somebody else's account.
 */
export interface OpaqueEnrollment {
  opaque_session: string;
  registration_record: string;
}

function axiosStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } })?.response?.status;
}

function axiosMessage(err: unknown): string {
  return (err as { message?: string })?.message ?? 'request failed';
}

/**
 * Perform a full OPAQUE login (CONTRACT.md §23).
 *
 * Returns the same `LoginResult` as `login`, including the MFA-challenge case,
 * so a caller needs one result handler for both.
 *
 * ## What this does that `login` does not
 *
 * The password never leaves this process. What crosses the wire is a blinded
 * group element and a MAC, neither useful without the account's record **and**
 * the tenant's OPRF seed — so a TLS-terminating proxy, an accidentally verbose
 * request log or a heap dump on the server cannot capture a plaintext password,
 * because the server never has one. It also means a stolen record database is
 * not offline-crackable on its own, which is the property SRP could not offer.
 *
 * It does **not** protect against a compromised AXIAM server, and in a browser
 * it does not protect against AXIAM serving malicious JavaScript.
 *
 * ## What a caller no longer has to do
 *
 * Under SRP this returned only after verifying the server's `M2`, and §23.3
 * rule 6 had to mandate that in capitals because skipping it kept only the half
 * of the protocol that authenticates the client. RFC 9807's AKE authenticates
 * the server during the handshake — opening `KE2` *is* the proof that the
 * server holds the record — so there is no separate check and no way to omit
 * one.
 *
 * ## Errors
 *
 * - `NetworkError` when the tenant has OPAQUE disabled (`404` — a property of
 *   the tenant, not of any user), when `@axiam/opaque-wasm` is not installed,
 *   and when the server names a KSF this SDK cannot perform. These are
 *   configuration or client-side faults, deliberately **not** `AuthError`:
 *   reporting them as a credential failure would send a user off to reset a
 *   password that works, and would stop a caller falling back to `login()`.
 * - `AuthError` for a wrong password, an account that does not exist, and a
 *   server that does not hold the record — indistinguishable by design.
 *   **Nothing is sent to `login/finish` in that case** (§23.4 rule 7), and a
 *   caller must not retry over `login()`: that would hand the plaintext to a
 *   server that just failed to prove itself.
 *
 * ## Cost
 *
 * Runs the tenant's key-stretching function: Argon2id at 19 MiB by default,
 * tens to hundreds of milliseconds of synchronous work. That cost is the point
 * — it is what makes a stolen record expensive to attack even by someone
 * holding the OPRF seed. In a browser, consider a Web Worker.
 */
export async function loginOpaque(
  client: AxiamClient,
  usernameOrEmail: string,
  password: string,
): Promise<LoginResult> {
  // §18.1 rule 4: use-after-close is an error, not a reconnect.
  client.ensureOpen();
  // §17.1 rule 9: entries are keyed by subject, so any credential change must
  // drop them, or a re-authentication as a different principal inherits the
  // previous one's decisions.
  client.decisionMemo.clear();

  const exchange = await startLogin(password);

  // Reuses the login body builder so tenant/org resolution cannot drift between
  // the two login paths. The password field is deleted rather than sent — it
  // has no business on this request, and this is the assertion the tests make.
  const body: Record<string, string> = {
    ...client.session.buildLoginBody(usernameOrEmail, ''),
    ke1: exchange.ke1,
  };
  delete body.password;

  let started: LoginStartWire;
  try {
    const response = await client.session.axios.post<LoginStartWire>(
      OPAQUE_LOGIN_START_PATH,
      body,
    );
    started = response.data;
  } catch (err) {
    const status = axiosStatus(err);
    if (status === 404) {
      throw new NetworkError(
        'this tenant does not offer OPAQUE (opaque_mode is disabled); use login() instead',
      );
    }
    if (status !== undefined) {
      throw mapHttpStatusToError(status, axiosMessage(err), { cause: err });
    }
    throw new NetworkError('OPAQUE login/start request failed', sanitizeAxiosError(err));
  }

  // The whole of the client's authentication check. A failure covers both
  // halves of the mutual authentication — the envelope only opens under the
  // right password, and KE2's MAC only verifies if the server holds the record
  // — and nothing further may be sent.
  //
  // A KSF the SDK cannot perform throws `NetworkError` from `buildKsf` and is
  // deliberately allowed to propagate rather than being flattened into an
  // authentication failure.
  let ke3: string;
  try {
    ke3 = exchange.finish(started.ke2, started);
  } catch (err) {
    if (err instanceof NetworkError) throw err;
    throw mapHttpStatusToError(401, 'invalid credentials', { cause: err });
  }

  let response;
  try {
    response = await client.session.axios.post<LoginSuccessResponseWire | MfaRequiredResponseWire>(
      OPAQUE_LOGIN_FINISH_PATH,
      { opaque_session: started.opaque_session, ke3 },
    );
  } catch (err) {
    const status = axiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, axiosMessage(err), { cause: err });
    }
    throw new NetworkError('OPAQUE login/finish request failed', sanitizeAxiosError(err));
  }

  if (response.status === 202) {
    const wire = response.data as MfaRequiredResponseWire;
    return {
      status: 'mfa_required',
      mfaToken: wire.challenge_token,
      availableMethods: wire.available_methods,
    };
  }

  const wire = response.data as LoginSuccessResponseWire;
  client.session.authenticated = true;
  await client.session.onAuthenticated?.();
  return {
    status: 'authenticated',
    user: { id: wire.user.id, username: wire.user.username, email: wire.user.email },
    sessionId: wire.session_id,
    expiresIn: wire.expires_in,
  };
}

/**
 * Build a registration record for `password`, to send with any request that
 * sets one (user creation, change-password, reset completion).
 *
 * This performs a `register/start` round trip, which the SRP verifier it
 * replaces did not need: OPAQUE's envelope is sealed under the server's
 * oblivious PRF, so there is no offline computation that produces a valid
 * record.
 *
 * Note the absence of an `identity` argument. The SRP version required the
 * account's canonical username, and passing an email produced a verifier no
 * login could ever satisfy. A record binds to a credential identifier the
 * server chooses, so there is nothing here to get wrong — and a later rename
 * cannot invalidate it.
 */
export async function opaqueEnrollment(
  client: AxiamClient,
  password: string,
): Promise<OpaqueEnrollment> {
  client.ensureOpen();

  const exchange = await startRegistration(password);

  const body: Record<string, string> = {
    ...client.session.buildLoginBody('', ''),
    registration_request: exchange.request,
  };
  delete body.password;
  delete body.username_or_email;

  let started: RegisterStartWire;
  try {
    const response = await client.session.axios.post<RegisterStartWire>(
      OPAQUE_REGISTER_START_PATH,
      body,
    );
    started = response.data;
  } catch (err) {
    const status = axiosStatus(err);
    if (status === 404) {
      throw new NetworkError('this tenant does not offer OPAQUE (opaque_mode is disabled)');
    }
    if (status !== undefined) {
      throw mapHttpStatusToError(status, axiosMessage(err), { cause: err });
    }
    throw new NetworkError('OPAQUE register/start request failed', sanitizeAxiosError(err));
  }

  return {
    opaque_session: started.opaque_session,
    registration_record: exchange.finish(started.registration_response, started),
  };
}

export { OpaqueUnavailableError };
export { opaqueAvailable } from '../core/opaque.js';
