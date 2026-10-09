// The SSF receiver helper — CONTRACT.md §32.7 (contract 1.56).
//
// AXIAM is a Shared Signals Framework transmitter: it sends CAEP and RISC
// security events as Security Event Tokens (RFC 8417) to the relying parties a
// tenant administrator registered (the §27 `ssf` namespace, `client.ssf`).
// This module is for the **relying party** that receives them — a different
// audience from that namespace:
//
//   * `SsfReceiver.verifySet` verifies one compact SET — pushed to your
//     endpoint (RFC 8935) or returned by a poll — in the contract's fixed
//     order, refusing at the first failure with a `SetRefusedError` whose
//     `reason` names the step;
//   * `SsfReceiver.poll` calls the stream's poll endpoint (RFC 8936), verifies
//     every returned SET and hands back the verified and the refused apart.
//
// Neither transmits, signs or registers anything, and neither trusts a key it
// did not fetch from the configured JWKS: no `jwk` or `x5c` header member is
// honoured (§32.9).
//
// Node-only (`axiam-sdk/node`): signatures are checked with `node:crypto`'s
// Ed25519, and the poll and JWKS fetches use the Node persona's TLS agents.

import { createPublicKey, verify as verifySignature, type KeyObject } from 'node:crypto';
import type { AxiosResponse } from 'axios';
import { AuthError, mapHttpStatusToError, NetworkError, type AxiamError } from '../core/index.js';
import type { Sensitive } from '../core/index.js';
import { ConflictError, NotFoundError, ValidationError, parseFieldErrors } from '../management/errors.js';
import { bareRequest, retryableNetworkError, statusIsRetryable } from '../rest/bareTransport.js';
import type { AxiamClient } from '../rest/client.js';
import { withRetry } from '../rest/retry.js';

/**
 * The replay window's floor and default: seven days, the transmitter's buffer
 * retention (§32.6). A window shorter than that would forget a `jti` the
 * transmitter can still re-send.
 */
export const MIN_REPLAY_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/** Forced JWKS refetches (on an unknown `kid`) happen at most this often (§32.7 step 4). */
export const JWKS_REFETCH_INTERVAL_MS = 60_000;

/**
 * The six event types AXIAM transmits, plus the two SSF stream events
 * (§32.6). Event types are open: a SET whose type is not among these still
 * verifies, and {@link SecurityEvent.eventType} carries it verbatim.
 */
export const SSF_EVENT_TYPES = {
  /** CAEP session revoked. */
  SESSION_REVOKED: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  /** CAEP credential change. */
  CREDENTIAL_CHANGE: 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
  /** CAEP assurance level change. */
  ASSURANCE_LEVEL_CHANGE: 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',
  /** RISC account disabled. */
  ACCOUNT_DISABLED: 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
  /** RISC account enabled. */
  ACCOUNT_ENABLED: 'https://schemas.openid.net/secevent/risc/event-type/account-enabled',
  /** RISC account purged. */
  ACCOUNT_PURGED: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
  /** SSF verification. */
  VERIFICATION: 'https://schemas.openid.net/secevent/ssf/event-type/verification',
  /** SSF stream updated. */
  STREAM_UPDATED: 'https://schemas.openid.net/secevent/ssf/event-type/stream-updated',
} as const;

/**
 * Why `verifySet` refused a SET (§32.7), one code per step:
 *
 * - `malformed` — not three base64url parts decoding to a JSON header and payload (step 1);
 * - `invalid_type` — the header `typ` is not `secevent+jwt` / `application/secevent+jwt` (step 2);
 * - `invalid_key` — `alg` not `EdDSA`, no key for `kid` after one refetch, or a bad signature (steps 3–5);
 * - `invalid_issuer` — `iss` is not the configured issuer (step 6);
 * - `invalid_audience` — `aud` does not name the configured audience (step 7);
 * - `invalid_request` — `exp` or `sub` present, `jti` / `iat` / `sub_id` absent, or `events` not exactly one member (step 8);
 * - `replayed` — the `jti` was already seen inside the replay window (step 9).
 */
export type SetFailureReason =
  | 'malformed'
  | 'invalid_type'
  | 'invalid_key'
  | 'invalid_issuer'
  | 'invalid_audience'
  | 'invalid_request'
  | 'replayed';

/**
 * The RFC 8935 §2.4 `err` value to answer a push with (`400 {"err": …}`), or to
 * send in a poll's `setErrs`.
 *
 * The reason itself where RFC 8935 defines it (`invalid_key`,
 * `invalid_issuer`, `invalid_audience`, `invalid_request`), and
 * `invalid_request` for `malformed`, `invalid_type` and `replayed`, which it
 * does not — so only RFC-defined codes reach the wire. (§32.7 says the codes
 * "match RFC 8935" and names only `replayed` as mapped; `malformed` and
 * `invalid_type` are not RFC 8935 codes either, and this SDK maps them the same
 * way — the conservative reading.)
 */
export function pushErrorCode(reason: SetFailureReason): string {
  return reason === 'malformed' || reason === 'invalid_type' || reason === 'replayed'
    ? 'invalid_request'
    : reason;
}

/** An RFC 8936 `setErrs` entry. */
export interface SetErr {
  /** The RFC 8935 §2.4 code. */
  err: string;
  /** Optional text. AXIAM never stores it (§32.6). */
  description?: string;
}

/** The `setErrs` entry for a refusal: `{ err: pushErrorCode(reason) }`. */
export function setErrFromReason(reason: SetFailureReason, description?: string): SetErr {
  return { err: pushErrorCode(reason), ...(description !== undefined ? { description } : {}) };
}

/**
 * The `AuthError` `verifySet` raises for a refused SET (§32.7), with the
 * refusal's {@link SetFailureReason} on {@link SetRefusedError.reason}.
 *
 * A JWKS fetch failure is **not** one of these: it is a `NetworkError`, and not
 * a verdict on the SET.
 */
export class SetRefusedError extends AuthError {
  /** Which verification step refused the SET. */
  declare readonly reason: SetFailureReason;

  constructor(reason: SetFailureReason, detail: string) {
    super(`SET refused (${reason}): ${detail} (CONTRACT.md §32.7)`, reason);
    this.name = 'SetRefusedError';
    Object.setPrototypeOf(this, SetRefusedError.prototype);
  }
}

/**
 * Remembers the `jti`s already accepted, for step 9.
 *
 * Pluggable so a receiver running several instances can share one store
 * (§32.7). {@link MemoryReplayStore} is the default.
 */
export interface ReplayStore {
  /**
   * Record `jti` for `windowMs` and return `true`, or return `false` without
   * recording when it is already held. Must be atomic: two concurrent calls
   * with one `jti` must not both see `true`.
   */
  checkAndRecord(jti: string, windowMs: number): boolean | Promise<boolean>;
}

/** The in-memory {@link ReplayStore}: one process, lost on restart; entries expire after their window. */
export class MemoryReplayStore implements ReplayStore {
  readonly #seen = new Map<string, number>();
  readonly #now: () => number;

  /** @param now the clock, injectable for tests; defaults to `Date.now`. */
  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  /** {@inheritDoc ReplayStore.checkAndRecord} */
  checkAndRecord(jti: string, windowMs: number): boolean {
    const now = this.#now();
    for (const [key, expires] of this.#seen) {
      if (expires <= now) this.#seen.delete(key);
    }
    if (this.#seen.has(jti)) return false;
    this.#seen.set(jti, now + windowMs);
    return true;
  }
}

/** Supplies the bearer {@link SsfReceiver.poll} presents: a client-credentials token with `ssf.manage` (e.g. `OidcClient.loginClientCredentials`). Called once per poll. */
export type AccessTokenProvider = () => Promise<Sensitive<string> | string>;

/**
 * Configuration for an {@link SsfReceiver} (§32.7: `{ issuer, audience,
 * jwks_uri | discovery_url, access_token_provider }`).
 */
export interface SsfReceiverConfig {
  /** The transmitter's issuer — compared to `iss` exactly. */
  issuer: string;
  /** This receiver's audience — the stream's `audience`. */
  audience: string;
  /** The JWKS URL itself (AXIAM: `{issuer}/oauth2/jwks`). Exactly one of this and `discoveryUrl`. */
  jwksUri?: string;
  /**
   * The transmitter's SSF configuration document
   * (`/.well-known/ssf-configuration…`): its `jwks_uri` is used, and its
   * `issuer` must equal {@link SsfReceiverConfig.issuer}.
   */
  discoveryUrl?: string;
  /** The bearer for {@link SsfReceiver.poll}; omit for a push-only receiver. */
  accessTokenProvider?: AccessTokenProvider;
  /** How long a `jti` is remembered, in ms. Default **and floor**: {@link MIN_REPLAY_WINDOW_MS}. */
  replayWindowMs?: number;
  /** Where accepted `jti`s are kept; defaults to a {@link MemoryReplayStore}. */
  replayStore?: ReplayStore;
}

/** A verified Security Event Token (§32.7's result). */
export interface SecurityEvent {
  /** The SET's unique id. */
  jti: string;
  /** When it was issued, seconds since the epoch. */
  iat: number;
  /** The issuer, equal to the configured one. */
  iss: string;
  /** The audience as sent: one string, or an array containing yours. */
  aud: string | string[];
  /** The transaction id shared by every SET one operation produced. */
  txn?: string;
  /** The single `events` key — an event-type URI, see {@link SSF_EVENT_TYPES}. */
  eventType: string;
  /** That event's object, opaque to the helper. */
  event: unknown;
  /** The RFC 9493 subject identifier, opaque to the helper. */
  subId: Record<string, unknown>;
}

/** Arguments to {@link SsfReceiver.poll}. Every member is passed through as given; an unset one is not sent. */
export interface SsfPollOptions {
  /** `maxEvents` — the server clamps it to 100; `0` acknowledges and returns nothing. */
  maxEvents?: number;
  /** `returnImmediately` — without it the server long-polls up to 30 s. */
  returnImmediately?: boolean;
  /** `ack` — the `jti`s you **processed** since the last poll. */
  ack?: string[];
  /** `setErrs` — the `jti`s you refuse, each with its code ({@link setErrFromReason}). */
  setErrs?: Record<string, SetErr>;
}

/** One SET a poll returned and the helper refused. */
export interface RefusedSet {
  /** The key the transmitter returned the SET under. */
  jti: string;
  /** Why it was refused. Pass `setErrFromReason(reason)` for it in the next poll's `setErrs`. */
  reason: SetFailureReason;
}

/** What {@link SsfReceiver.poll} returns. */
export interface SsfPollResult {
  /** The SETs that verified, in the order the transmitter's map listed them. */
  events: SecurityEvent[];
  /** Whether the transmitter holds more. */
  moreAvailable: boolean;
  /** The SETs that did not verify. */
  refused: RefusedSet[];
  /**
   * The `jti`s of SETs this poll could not judge — the JWKS or discovery
   * fetch failed, or the replay store could not answer (§34.2 P1, P3). They
   * are in neither `events` nor `refused` and were **not** recorded:
   * acknowledge them not, refuse them not, and the transmitter offers them
   * again. Empty when every SET was judged.
   */
  unjudged: string[];
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const B64URL = /^[A-Za-z0-9_-]*$/;

function refuseConfig(field: string, message: string): never {
  throw new ValidationError('ssf.receiver', 400, `ssf.receiver: ${field}: ${message} (CONTRACT.md §32.7)`, [
    { field, message },
  ]);
}

/** `https`, or `http` on a loopback host only (§6). */
function secureUrl(label: string, raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new NetworkError(`${label} is not an absolute URL`);
  }
  if (url.protocol === 'https:') return raw;
  if (url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname.toLowerCase())) return raw;
  throw new NetworkError(`${label} must be https (http only on a loopback host) (CONTRACT.md §6)`);
}

function decodeJsonObject(part: string): Record<string, unknown> | undefined {
  if (!B64URL.test(part)) return undefined;
  try {
    const value: unknown = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * The SSF receiver helper (CONTRACT.md §32.7) — `verifySet` and `poll`.
 *
 * @remarks
 * Built over an {@link AxiamClient}: its §6 TLS configuration fetches the
 * JWKS, and its base URL is the transmitter root `poll` calls. Both requests
 * go out on a session-free transport — no SDK cookie, access token or CSRF
 * header, no redirects.
 *
 * @example
 * ```ts
 * const receiver = new SsfReceiver(client, {
 *   issuer: 'https://iam.example.com/t/<tenant>',
 *   audience: 'https://rp.example.com',
 *   jwksUri: 'https://iam.example.com/oauth2/jwks',
 *   accessTokenProvider: async () => (await oidc.loginClientCredentials({ scope: 'ssf.manage' })).accessToken,
 * });
 *
 * // push (RFC 8935): answer 202, or 400 {"err": …} on a refusal
 * try {
 *   const event = await receiver.verifySet(body);
 *   handle(event);
 *   res.status(202).end();
 * } catch (e) {
 *   if (e instanceof SetRefusedError) res.status(400).json(setErrFromReason(e.reason));
 *   else throw e; // NetworkError: the JWKS could not be fetched — not a verdict
 * }
 * ```
 */
export class SsfReceiver {
  readonly #client: AxiamClient;
  readonly #issuer: string;
  readonly #audience: string;
  readonly #jwksUri: string | undefined;
  readonly #discoveryUrl: string | undefined;
  readonly #tokenProvider: AccessTokenProvider | undefined;
  readonly #replayWindowMs: number;
  readonly #replayStore: ReplayStore;
  readonly #now: () => number;
  #resolvedJwksUri: Promise<string> | undefined;
  #keys: Map<string, Record<string, unknown>> | undefined;
  #fetching: Promise<void> | undefined;
  #lastForcedRefetch: number | undefined;

  /**
   * @param client the client whose TLS policy and base URL the helper uses.
   * @param config issuer, audience, key source, poll credential, replay window and store.
   * @param now the clock for the forced-refetch interval; injectable for tests.
   * @throws ValidationError (local, no I/O) when the replay window is below
   * seven days, `issuer` or `audience` is empty, or not exactly one of
   * `jwksUri` / `discoveryUrl` is given.
   */
  constructor(client: AxiamClient, config: SsfReceiverConfig, now: () => number = Date.now) {
    const window = config.replayWindowMs ?? MIN_REPLAY_WINDOW_MS;
    if (!(window >= MIN_REPLAY_WINDOW_MS)) {
      refuseConfig('replayWindowMs', "must be at least seven days, the transmitter's buffer retention");
    }
    if (!config.issuer) refuseConfig('issuer', 'is required');
    if (!config.audience) refuseConfig('audience', 'is required');
    if ((config.jwksUri === undefined) === (config.discoveryUrl === undefined)) {
      refuseConfig('jwksUri', 'set exactly one of jwksUri and discoveryUrl');
    }
    this.#client = client;
    this.#issuer = config.issuer;
    this.#audience = config.audience;
    this.#jwksUri = config.jwksUri;
    this.#discoveryUrl = config.discoveryUrl;
    this.#tokenProvider = config.accessTokenProvider;
    this.#replayWindowMs = window;
    this.#replayStore = config.replayStore ?? new MemoryReplayStore();
    this.#now = now;
  }

  /**
   * Verify one compact SET (§32.7), in this order, refusing at the first
   * failure with a {@link SetRefusedError} whose `reason` is in brackets:
   *
   * 1. three base64url parts, a JSON-object header and payload [`malformed`];
   * 2. `typ` `secevent+jwt` or `application/secevent+jwt`, any case [`invalid_type`];
   * 3. `alg` exactly `EdDSA` [`invalid_key`];
   * 4. the `kid` in the configured JWKS — on a miss, one refetch, at most once a minute [`invalid_key`];
   * 5. the Ed25519 signature [`invalid_key`];
   * 6. `iss` equal to the configured issuer [`invalid_issuer`];
   * 7. `aud` equal to, or an array containing, the audience [`invalid_audience`];
   * 8. no `exp`, no `sub`; a non-empty `jti`, a numeric `iat`, an object `sub_id`; exactly one `events` member [`invalid_request`];
   * 9. a `jti` not seen within the replay window [`replayed`] — recorded only once 1–8 passed.
   *
   * **A SET that verifies has been recorded**: verifying it again is
   * `replayed`. Acknowledge a polled SET once you have processed it.
   *
   * @throws SetRefusedError on a refusal; NetworkError when the JWKS (or the
   * discovery document) could not be fetched — which is not a verdict.
   */
  verifySet(set: string): Promise<SecurityEvent> {
    return this.#verify(set, undefined);
  }

  /**
   * Poll the stream's RFC 8936 endpoint, `{baseUrl}/ssf/v1/poll/{streamId}`,
   * with a bearer from the configured `accessTokenProvider`, and verify every
   * returned SET.
   *
   * @remarks
   * `ack` and `setErrs` are sent exactly as given, and only the members you
   * set (`{}` when none). **Nothing is acknowledged on your behalf**:
   * acknowledge, on the next call, the `jti`s you processed, and pass each
   * refused one in `setErrs` (`setErrFromReason(r.reason)`). A SET you neither
   * acknowledge nor refuse is re-offered and — having been recorded when it
   * verified — then reads as `replayed`.
   *
   * Retried per §16 on a transport failure, `408`, `429` or `5xx`; never on
   * another `4xx` (`400` is a `ValidationError`, `404` a `NotFoundError`). A
   * SET whose verified `jti` differs from the key it was returned under is
   * refused `invalid_request`; a non-string SET `malformed`.
   *
   * **A SET it cannot judge is never recorded** (contract 1.59, §34.2 P1). A
   * JWKS or discovery fetch that fails, or a replay store that throws, is no
   * verdict: that SET goes in neither `events` nor `refused` but in
   * `unjudged`, its `jti` unrecorded, so the transmitter offers it again. The
   * SETs judged before and after it are returned as usual — the ones in
   * `events` are recorded and must be processed and acknowledged, or they are
   * lost. When the poll accepted no SET at all, nothing was recorded and the
   * first such failure is thrown instead (a `NetworkError` for a failed fetch).
   *
   * @throws AuthError (local, no request) when no `accessTokenProvider` was configured.
   */
  async poll(streamId: string, options: SsfPollOptions = {}): Promise<SsfPollResult> {
    const operation = 'ssf.poll';
    this.#client.ensureOpen();
    if (!this.#tokenProvider) {
      throw new AuthError(
        'ssf.poll needs an accessTokenProvider (a client-credentials token with ssf.manage) (CONTRACT.md §32.7)',
      );
    }
    const base = new URL(this.#client.session.baseUrl);
    // Trailing slashes trimmed with a loop rather than /\/+$/, which is
    // polynomial on a path of many '/' (CodeQL js/polynomial-redos).
    let prefix = base.pathname;
    while (prefix.endsWith('/')) prefix = prefix.slice(0, -1);
    base.pathname = `${prefix}/ssf/v1/poll/${encodeURIComponent(streamId)}`;
    base.search = '';
    base.hash = '';
    const body: Record<string, unknown> = {};
    if (options.maxEvents !== undefined) body.maxEvents = options.maxEvents;
    if (options.returnImmediately !== undefined) body.returnImmediately = options.returnImmediately;
    if (options.ack !== undefined) body.ack = options.ack;
    if (options.setErrs !== undefined) body.setErrs = options.setErrs;
    const provided = await this.#tokenProvider();
    const token = typeof provided === 'string' ? provided : provided.expose();

    const outcome = await withRetry<{ reply?: unknown; error?: AxiamError }>(
      async () => {
        const response = await bareRequest(this.#client.session, operation, {
          method: 'POST',
          url: base.toString(),
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          data: JSON.stringify(body),
        });
        if (response.status >= 200 && response.status < 300) return { reply: response.data };
        const error = mapPollError(operation, response);
        if (statusIsRetryable(response.status)) throw retryableNetworkError(error.message, response);
        return { error };
      },
      this.#client.retryOptions(operation),
    );
    if (outcome.error) throw outcome.error;

    let reply = outcome.reply;
    if (typeof reply === 'string') {
      try {
        reply = JSON.parse(reply);
      } catch {
        throw new NetworkError('ssf.poll: the response is not JSON');
      }
    }
    const record = isPlainObject(reply) ? reply : {};
    const result: SsfPollResult = {
      events: [],
      moreAvailable: record.moreAvailable === true,
      refused: [],
      unjudged: [],
    };
    let firstFailure: { error: unknown } | undefined;
    const sets = isPlainObject(record.sets) ? record.sets : {};
    for (const [jti, set] of Object.entries(sets)) {
      if (typeof set !== 'string') {
        result.refused.push({ jti, reason: 'malformed' });
        continue;
      }
      try {
        result.events.push(await this.#verify(set, jti));
      } catch (err) {
        if (err instanceof SetRefusedError) {
          result.refused.push({ jti, reason: err.reason });
        } else {
          // §34.2 P1: no verdict, so not recorded (#verify records only after
          // steps 1 – 8 passed and the store answered). Keep judging the rest:
          // a SET already accepted in this batch is recorded and must be
          // returned, never dropped by a throw.
          result.unjudged.push(jti);
          firstFailure ??= { error: err };
        }
      }
    }
    // Nothing accepted means nothing recorded: raising loses no event.
    if (firstFailure && result.events.length === 0) throw firstFailure.error;
    return result;
  }

  async #verify(set: string, expectedJti: string | undefined): Promise<SecurityEvent> {
    // 1.
    const parts = typeof set === 'string' ? set.split('.') : [];
    if (parts.length !== 3 || !B64URL.test(parts[2]!)) {
      throw new SetRefusedError('malformed', 'not three base64url parts');
    }
    const header = decodeJsonObject(parts[0]!);
    const claims = decodeJsonObject(parts[1]!);
    if (!header || !claims) {
      throw new SetRefusedError('malformed', 'the header or payload is not a JSON object');
    }
    // 2.
    const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
    if (typ !== 'secevent+jwt' && typ !== 'application/secevent+jwt') {
      throw new SetRefusedError('invalid_type', 'typ is not secevent+jwt');
    }
    // 3.
    if (header.alg !== 'EdDSA') {
      throw new SetRefusedError('invalid_key', 'alg is not EdDSA');
    }
    // 4. (`jwk` / `x5c` header members are never consulted.)
    if (typeof header.kid !== 'string' || header.kid === '') {
      throw new SetRefusedError('invalid_key', 'no kid');
    }
    const jwk = await this.#keyFor(header.kid);
    if (!jwk) {
      throw new SetRefusedError('invalid_key', 'no key for the kid in the JWKS');
    }
    // 5.
    let key: KeyObject;
    try {
      key = createPublicKey({ key: jwk as never, format: 'jwk' });
    } catch {
      throw new SetRefusedError('invalid_key', 'the JWKS key is not usable');
    }
    let valid = false;
    try {
      valid =
        key.asymmetricKeyType === 'ed25519' &&
        verifySignature(null, Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), key, Buffer.from(parts[2]!, 'base64url'));
    } catch {
      valid = false;
    }
    if (!valid) {
      throw new SetRefusedError('invalid_key', 'the signature does not verify');
    }
    // 6.
    if (claims.iss !== this.#issuer) {
      throw new SetRefusedError('invalid_issuer', 'iss is not the configured issuer');
    }
    // 7.
    const aud = claims.aud;
    const audOk =
      (typeof aud === 'string' && aud === this.#audience) ||
      (Array.isArray(aud) && aud.some((a) => a === this.#audience));
    if (!audOk) {
      throw new SetRefusedError('invalid_audience', 'aud does not name this receiver');
    }
    // 8.
    if ('exp' in claims || 'sub' in claims) {
      throw new SetRefusedError('invalid_request', 'a SET carries no exp and no sub');
    }
    const jti = claims.jti;
    if (typeof jti !== 'string' || jti === '') {
      throw new SetRefusedError('invalid_request', 'no jti');
    }
    if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) {
      throw new SetRefusedError('invalid_request', 'no numeric iat');
    }
    if (!isPlainObject(claims.sub_id)) {
      throw new SetRefusedError('invalid_request', 'no sub_id object');
    }
    const events = claims.events;
    if (!isPlainObject(events) || Object.keys(events).length !== 1) {
      throw new SetRefusedError('invalid_request', 'events must have exactly one member');
    }
    if (expectedJti !== undefined && expectedJti !== jti) {
      throw new SetRefusedError('invalid_request', 'the poll key is not the SET jti');
    }
    const [eventType, event] = Object.entries(events)[0]!;
    // 9.
    if (!(await this.#replayStore.checkAndRecord(jti, this.#replayWindowMs))) {
      throw new SetRefusedError('replayed', 'jti already seen');
    }
    return {
      jti,
      iat: claims.iat,
      iss: claims.iss as string,
      aud: aud as string | string[],
      ...(typeof claims.txn === 'string' ? { txn: claims.txn } : {}),
      eventType,
      event,
      subId: claims.sub_id,
    };
  }

  /** The JWK for `kid`: fetched once, refetched once on a miss, forced refetches at most once a minute. */
  async #keyFor(kid: string): Promise<Record<string, unknown> | undefined> {
    if (this.#keys === undefined) await this.#fetchKeys();
    let jwk = this.#keys?.get(kid);
    if (jwk) return jwk;
    const now = this.#now();
    if (this.#lastForcedRefetch === undefined || now - this.#lastForcedRefetch >= JWKS_REFETCH_INTERVAL_MS) {
      this.#lastForcedRefetch = now;
      await this.#fetchKeys();
      jwk = this.#keys?.get(kid);
    }
    return jwk;
  }

  /** Single-flight JWKS fetch over the session-free transport (§6 TLS policy). */
  #fetchKeys(): Promise<void> {
    this.#fetching ??= (async () => {
      try {
        const uri = await this.#jwksUriResolved();
        const response = await bareRequest(this.#client.session, 'ssf.jwks', {
          method: 'GET',
          url: uri,
          headers: { Accept: 'application/json' },
        });
        if (response.status < 200 || response.status >= 300) {
          throw mapHttpStatusToError(response.status, `SSF JWKS fetch answered HTTP ${response.status}`);
        }
        const doc = parseJson(response.data);
        const keys = isPlainObject(doc) && Array.isArray(doc.keys) ? doc.keys : undefined;
        if (!keys) throw new NetworkError('the SSF JWKS is not a JWK Set');
        const map = new Map<string, Record<string, unknown>>();
        for (const k of keys) {
          if (isPlainObject(k) && typeof k.kid === 'string') map.set(k.kid, k);
        }
        this.#keys = map;
      } finally {
        this.#fetching = undefined;
      }
    })();
    return this.#fetching;
  }

  #jwksUriResolved(): Promise<string> {
    if (this.#jwksUri !== undefined) return Promise.resolve(secureUrl('jwksUri', this.#jwksUri));
    this.#resolvedJwksUri ??= (async () => {
      const url = secureUrl('discoveryUrl', this.#discoveryUrl!);
      const response = await bareRequest(this.#client.session, 'ssf.discovery', {
        method: 'GET',
        url,
        headers: { Accept: 'application/json' },
      });
      if (response.status < 200 || response.status >= 300) {
        throw mapHttpStatusToError(response.status, `SSF configuration answered HTTP ${response.status}`);
      }
      const doc = parseJson(response.data);
      if (!isPlainObject(doc) || doc.issuer !== this.#issuer) {
        throw new NetworkError("the SSF configuration's issuer is not the configured issuer");
      }
      if (typeof doc.jwks_uri !== 'string') {
        throw new NetworkError('the SSF configuration carries no jwks_uri');
      }
      return secureUrl('jwks_uri', doc.jwks_uri);
    })().catch((err: unknown) => {
      this.#resolvedJwksUri = undefined;
      throw err;
    });
    return this.#resolvedJwksUri;
  }
}

function parseJson(data: unknown): unknown {
  if (typeof data !== 'string') return data;
  try {
    return JSON.parse(data);
  } catch {
    throw new NetworkError('expected a JSON document');
  }
}

/** Map a non-2xx poll answer like the management surface (§27.4 rule 7). */
function mapPollError(operation: string, response: AxiosResponse): AxiamError {
  const body = parseJsonQuiet(response.data);
  const message =
    isPlainObject(body) && typeof (body.message ?? body.error) === 'string'
      ? `${operation}: ${String(body.message ?? body.error)}`
      : `${operation}: HTTP ${response.status}`;
  if (response.status === 404) return new NotFoundError(operation, message);
  if (response.status === 409) return new ConflictError(operation, message);
  if (response.status === 400 || response.status === 422) {
    return new ValidationError(operation, response.status, message, parseFieldErrors(body));
  }
  return mapHttpStatusToError(response.status, message);
}

function parseJsonQuiet(data: unknown): unknown {
  try {
    return parseJson(data);
  } catch {
    return undefined;
  }
}
