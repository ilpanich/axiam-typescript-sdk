// loginSrp / srpEnrollment — the SRP-6a login path (CONTRACT.md §23).
//
// A sibling of `login`, not a replacement. It establishes the same fact — this
// principal knows the password — by a route that never puts the password on the
// wire, and returns the **same** `LoginResult`, so an application can switch a
// tenant to SRP without touching its own code.
//
// The protocol arithmetic lives in `core/srp.ts` and performs no I/O; this
// module is the two HTTP calls and the policy around them.

import {
  AuthError,
  NetworkError,
  mapHttpStatusToError,
  sanitizeAxiosError,
} from '../core/index.js';
import {
  beginClientSession,
  computeVerifier,
  deriveX,
  generateSalt,
  parseGroup,
  verifyServerProof,
  type SrpClientSession,
  type SrpGroupName,
} from '../core/srp.js';
import type { AxiamClient } from './client.js';
import type { LoginResult, LoginSuccessResponseWire, MfaRequiredResponseWire } from './types.js';

const SRP_CHALLENGE_PATH = '/api/v1/auth/srp/challenge';
const SRP_VERIFY_PATH = '/api/v1/auth/srp/verify';

/**
 * The group an exchange opens in before the server has named one.
 *
 * The challenge response names the group, but `A` has to be computed *before*
 * that response exists — so the first attempt guesses, and the exchange
 * restarts if the server names another. The guess is AXIAM's default, so the
 * restart is the exceptional path rather than the normal one.
 */
const OPENING_GROUP: SrpGroupName = 'rfc5054_4096';

/** Server response to `POST /api/v1/auth/srp/challenge`. */
interface SrpChallengeWire {
  srp_session: string;
  /**
   * The canonical identity to feed into the KDF — the server's answer, not the
   * user's input. A user may sign in with a username or an email while only one
   * of the two is bound into `x`.
   */
  identity: string;
  salt: string;
  group: string;
  kdf: string;
  memory_kib?: number;
  iterations: number;
  parallelism?: number;
  b_pub: string;
}

type SrpVerifyWire = (LoginSuccessResponseWire | MfaRequiredResponseWire) & {
  server_proof?: string;
};

/** The verifier and its parameters, for any endpoint that sets a password. */
export interface SrpEnrollment {
  group: string;
  kdf: string;
  memory_kib?: number;
  iterations: number;
  parallelism?: number;
  salt: string;
  verifier: string;
}

/** Options for {@link srpEnrollment}. */
export interface SrpEnrollmentOptions {
  /**
   * The account's **username** — the canonical identity the challenge endpoint
   * hands back. Passing an email produces a verifier no login can ever satisfy.
   */
  identity: string;
  password: string;
  /** From the tenant's policy (`GET /api/v1/auth/me`, or the reset context). */
  group: string;
  kdf: string;
  iterations?: number;
  memoryKib?: number;
  parallelism?: number;
}

function axiosStatus(err: unknown): number | undefined {
  const response = (err as { response?: { status?: number } } | undefined)?.response;
  return response?.status;
}

function axiosMessage(err: unknown): string {
  const data = (err as { response?: { data?: { message?: string } } } | undefined)?.response?.data;
  return data?.message ?? 'request failed';
}

/**
 * `POST /api/v1/auth/srp/challenge` + `/verify` — SRP-6a login (§23).
 *
 * Returns the same `LoginResult` as `login`, including the `mfa_required`
 * branch, so a caller needs one result handler for both.
 *
 * ## What this does that `login` does not
 *
 * The password never leaves this process. What crosses the wire is `A` and a
 * proof, neither of which is useful without the account's verifier — so a
 * TLS-terminating proxy, an accidentally verbose request log, or a heap dump on
 * the server cannot capture a plaintext password, because the server never has
 * one. It does **not** protect against a compromised AXIAM server.
 *
 * ## Errors
 *
 * - `NetworkError` when the tenant has SRP disabled (404), or when this SDK
 *   cannot perform the group or KDF the server named. These are client-side
 *   faults, deliberately not `AuthError`: reporting them as a credential
 *   failure would send a user off to reset a password that works.
 * - `AuthError` for a wrong password, and for a server whose `M2` does not
 *   verify — in the latter case no session is returned, because an endpoint
 *   that cannot prove it holds the verifier is not the server it claims to be.
 *
 * ## Cost
 *
 * Runs the tenant's KDF: Argon2id at 19 MiB by default, tens to hundreds of
 * milliseconds of synchronous work. That cost is the point. In a browser,
 * consider a Web Worker.
 */
export async function loginSrp(
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

  let { session, challenge } = await requestChallenge(client, usernameOrEmail, OPENING_GROUP);

  // The server named a group other than the one `A` was computed in, so the
  // exchange has to restart. Rare — the opening guess is AXIAM's own default —
  // but a tenant on a narrower group must work rather than fail.
  const group = parseGroup(challenge.group);
  if (group !== OPENING_GROUP) {
    ({ session, challenge } = await requestChallenge(client, usernameOrEmail, group));
  }

  // `challenge.identity`, never `usernameOrEmail` (§23.3 rule 2).
  const x = await deriveX(challenge.identity, password, challenge.salt, {
    kdf: challenge.kdf,
    iterations: challenge.iterations,
    memoryKib: challenge.memory_kib,
    parallelism: challenge.parallelism,
  });
  const { clientProof, expectedServerProof } = await session.finish({
    identity: challenge.identity,
    saltHex: challenge.salt,
    serverPublicHex: challenge.b_pub,
    x,
  });

  let response;
  try {
    response = await client.session.axios.post<SrpVerifyWire>(SRP_VERIFY_PATH, {
      srp_session: challenge.srp_session,
      client_proof: clientProof,
    });
  } catch (err) {
    const status = axiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, axiosMessage(err), { cause: err });
    }
    throw new NetworkError('SRP verify request failed', sanitizeAxiosError(err));
  }

  // Mutual authentication (§23.3 rule 6), checked BEFORE anything from the
  // response is stored or reported. A rogue server that cannot prove itself
  // must not get the chance to collect an MFA code either.
  if (!verifyServerProof(expectedServerProof, response.data.server_proof)) {
    throw new AuthError('SRP: the server failed to prove it holds this account\'s verifier');
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

async function requestChallenge(
  client: AxiamClient,
  usernameOrEmail: string,
  group: SrpGroupName,
): Promise<{ session: SrpClientSession; challenge: SrpChallengeWire }> {
  const session = await beginClientSession(group);
  // Reuses the login body builder so tenant/org resolution cannot drift
  // between the two login paths. The password field is replaced rather than
  // sent — it has no business on this request.
  const body: Record<string, string> = {
    ...client.session.buildLoginBody(usernameOrEmail, ''),
    client_public: session.clientPublic,
  };
  delete body.password;

  try {
    const response = await client.session.axios.post<SrpChallengeWire>(SRP_CHALLENGE_PATH, body);
    return { session, challenge: response.data };
  } catch (err) {
    // 404 is a property of the tenant ("SRP is off here"), not of the user, and
    // not a credential failure — so a caller can fall back to `login()` without
    // mistaking it for a bad password.
    if (axiosStatus(err) === 404) {
      throw new NetworkError(
        'this tenant does not offer Secure Remote Password (srp_mode is disabled); use login() instead',
      );
    }
    const status = axiosStatus(err);
    if (status !== undefined) {
      throw mapHttpStatusToError(status, axiosMessage(err), { cause: err });
    }
    throw new NetworkError('SRP challenge request failed', sanitizeAxiosError(err));
  }
}

/**
 * Compute a verifier for `password`, to send with any request that sets one
 * (user creation, change-password, reset completion).
 *
 * The server cannot compute this — it never sees the plaintext — so it has to
 * arrive with the request or not at all. The salt is 32 fresh bytes from the
 * platform CSPRNG (§23.3 rule 11).
 */
export async function srpEnrollment(options: SrpEnrollmentOptions): Promise<SrpEnrollment> {
  const group = parseGroup(options.group);
  const kdf = options.kdf === 'pbkdf2_sha256' ? 'pbkdf2_sha256' : 'argon2id';
  const iterations = options.iterations ?? (kdf === 'argon2id' ? 2 : 600_000);
  const memoryKib = kdf === 'argon2id' ? (options.memoryKib ?? 19456) : undefined;
  const parallelism = kdf === 'argon2id' ? (options.parallelism ?? 1) : undefined;

  const salt = generateSalt();
  const x = await deriveX(options.identity, options.password, salt, {
    kdf,
    iterations,
    memoryKib,
    parallelism,
  });

  return {
    group,
    kdf,
    ...(memoryKib !== undefined ? { memory_kib: memoryKib } : {}),
    iterations,
    ...(parallelism !== undefined ? { parallelism } : {}),
    salt,
    verifier: await computeVerifier(group, x),
  };
}

/**
 * Whether this SDK build can perform SRP.
 *
 * Always `true` for TypeScript: `BigInt` is native and both KDFs are available
 * (`hash-wasm` for Argon2id, WebCrypto for PBKDF2). It exists because §23.1
 * puts it in the locked method vocabulary for every SDK, and in PHP — which
 * needs `ext-gmp` or `ext-bcmath` and is guaranteed neither — it genuinely
 * answers `false`.
 */
export function srpAvailable(): boolean {
  return typeof globalThis.crypto?.subtle?.digest === 'function' && typeof BigInt === 'function';
}
