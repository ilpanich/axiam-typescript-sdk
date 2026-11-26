// The AMQP authorization requester (CONTRACT.md §8, "Signed authorization
// responses", contract 1.68; N2, D-9).
//
// Publishes a signed `AuthzRequest` on `axiam.authz.request` (default
// exchange) with `reply_to` naming a PRIVATE queue — exclusive, auto-delete,
// broker-named (`amq.gen-…`) — and accepts an answer only when
// `AuthzResponseVerifier` verifies it as the server's signed response to THAT
// request: tenant subkey, own `tenant_id`, and the request's `correlation_id`
// and `nonce`. A forged or mismatched response is nacked without requeue and
// the caller keeps waiting for the genuine answer, until the timeout.
//
// The same rule as the verifier: verify the received bytes and deliver the
// same bytes. Mirrors the Go SDK's `amqp/authz_requester.go`.

import { createHmac, randomUUID } from 'node:crypto';
import amqp from 'amqplib';
import type { ConsumeMessage } from 'amqplib';
import { NetworkError, type Sensitive } from '../core/index.js';
import { AuthzResponseVerifier, type AuthzResponseVerifierOptions } from './authzResponse.js';
import type { ConsumeLogger } from './consumer.js';
import { buildAmqpConnectOptions, type AmqpTlsOptions } from './transport.js';

/** The queue the server consumes `AuthzRequest` from (CONTRACT.md §8). */
export const AUTHZ_REQUEST_QUEUE = 'axiam.authz.request';

/** The signing-key version requests are sent under; the response carries none (§8). */
const AUTHZ_KEY_VERSION = 2;

/** Default bound on one {@link AuthzRequester.check}, in milliseconds. */
export const DEFAULT_AUTHZ_TIMEOUT_MS = 10_000;

/** Prefix of the server's own queues; the server does not honour such a `reply_to` (§8 rule 5). */
const SERVER_QUEUE_PREFIX = 'axiam.';

/** A lone (unpaired) UTF-16 surrogate, which serde_json cannot represent. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** The largest delay `setTimeout` honours; Node runs anything larger (or `NaN`, `≤ 0`) after 1 ms. */
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

/**
 * Refuse a `timeoutMs` that `setTimeout` would silently turn into "time out
 * at once" (non-finite, not positive, or above 2³¹−1 ms), so the
 * misconfiguration is visible at construction instead of failing every check.
 */
function assertTimeout(timeoutMs: number | undefined): void {
  if (timeoutMs === undefined) return;
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new RangeError(`axiam: authz requester timeoutMs must be a finite number in (0, ${MAX_TIMEOUT_MS}]`);
  }
}

/** Thrown by {@link AuthzRequester.check} once the requester is closed or its reply queue went away. */
export class AuthzRequesterClosedError extends Error {
  constructor() {
    super('axiam: authz requester is closed');
    this.name = 'AuthzRequesterClosedError';
  }
}

/** A verified answer to one `AuthzRequest`. */
export interface AuthzDecision {
  /** The decision; `true` only for a response that verified. */
  allowed: boolean;
  /** The server's human-readable reason, when it gave one. */
  reason?: string;
  /** `allowed`, `no_grant`, `denied_by_rule`, `tenant_suspended`, or a code this SDK does not know (verbatim). */
  reasonCode?: string;
}

/** One authorization question (CONTRACT.md §8 `AuthzRequest`). */
export interface AuthzCheckInput {
  /** The subject (user or service account) UUID. */
  subjectId: string;
  /** The action, e.g. `documents:read`. */
  action: string;
  /** The resource UUID. */
  resourceId: string;
  /** Optional sub-resource scope. */
  scope?: string;
  /** Aborts the wait (the request stays published; its answer is then dropped). */
  signal?: AbortSignal;
}

/**
 * The subset of an amqplib `Channel` the requester uses. A real `Channel`
 * satisfies it; tests supply a fake.
 */
export interface AuthzRequesterChannel {
  /** `channel.assertQueue('', { exclusive: true, autoDelete: true, durable: false })` — a broker-named private queue. */
  assertQueue(
    queue: string,
    options: { exclusive: boolean; autoDelete: boolean; durable: boolean },
  ): Promise<{ queue: string }>;
  /** `channel.consume(queue, onMessage, { noAck: false, exclusive: true })`. */
  consume(
    queue: string,
    onMessage: (msg: ConsumeMessage | null) => void,
    options: { noAck: boolean; exclusive: boolean },
  ): Promise<{ consumerTag: string }>;
  /** `channel.sendToQueue(queue, content, options)` — a publish on the default exchange. */
  sendToQueue(
    queue: string,
    content: Buffer,
    options: { correlationId: string; replyTo: string; contentType: string },
  ): boolean;
  /** `channel.ack(msg)`. */
  ack(msg: ConsumeMessage): void;
  /** `channel.nack(msg, allUpTo, requeue)`. */
  nack(msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void;
  /** `channel.cancel(consumerTag)`; optional. */
  cancel?(consumerTag: string): Promise<unknown>;
}

/** Configuration for {@link createAuthzRequester}. */
export interface AuthzRequesterOptions {
  /** The requester's OWN tenant (UUID); the only tenant an answer is accepted for. */
  tenantId: string;
  /** The tenant's HKDF-derived AMQP subkey for `key_version` 2 (§8.1, provisioned out of band) — never the master key. */
  subkey: Sensitive<Buffer>;
  /**
   * Bound on each {@link AuthzRequester.check}, in milliseconds. Defaults to
   * {@link DEFAULT_AUTHZ_TIMEOUT_MS}. A value that is not finite, not
   * positive, or above 2³¹−1 is refused with a `RangeError` when the
   * requester is created.
   */
  timeoutMs?: number;
  /** Security-event logger. Never receives a signature value or the key. */
  logger?: ConsumeLogger;
  /** Clock for `issued_at`; injectable for tests. */
  now?: () => Date;
}

/** The fields of a request, for {@link buildAuthzRequest}. */
export interface AuthzRequestFields {
  /** Request correlation id (UUID). */
  correlationId: string;
  /** The requester's tenant (UUID). */
  tenantId: string;
  /** Subject UUID. */
  subjectId: string;
  /** Action. */
  action: string;
  /** Resource UUID. */
  resourceId: string;
  /** Optional scope. */
  scope?: string;
  /** Fresh per-request nonce (UUID). */
  nonce: string;
  /** Send time. */
  issuedAt: Date;
}

function normalizeUuid(value: string, what: string): string {
  if (!UUID_RE.test(value)) {
    throw new TypeError(`axiam: ${what} is not a UUID`);
  }
  return value.toLowerCase();
}

/**
 * Serialize and sign an `AuthzRequest` exactly as the server verifies it
 * (CONTRACT.md §8 v2): compact JSON in the fixed field order
 * `correlation_id, tenant_id, subject_id, action, resource_id, scope?,
 * key_version, nonce, issued_at`, then `,"hmac_signature":"<hex>"` appended as
 * the trailing member. `JSON.stringify` escapes strings as serde_json does
 * (`"`, `\`, the short escapes, other controls as lower-case `\u00XX`; all
 * else raw), so the bytes match — except for a lone surrogate, which serde
 * cannot represent and is refused.
 *
 * @throws TypeError on a non-UUID id or an action/scope that is not well-formed UTF-16.
 */
export function buildAuthzRequest(subkey: Buffer, fields: AuthzRequestFields): Buffer {
  for (const s of [fields.action, ...(fields.scope !== undefined ? [fields.scope] : [])]) {
    if (typeof s !== 'string' || LONE_SURROGATE.test(s)) {
      throw new TypeError('axiam: action and scope must be well-formed strings');
    }
  }
  const body: Record<string, unknown> = {
    correlation_id: normalizeUuid(fields.correlationId, 'correlation_id'),
    tenant_id: normalizeUuid(fields.tenantId, 'tenant_id'),
    subject_id: normalizeUuid(fields.subjectId, 'subject_id'),
    action: fields.action,
    resource_id: normalizeUuid(fields.resourceId, 'resource_id'),
  };
  if (fields.scope !== undefined) body.scope = fields.scope;
  body.key_version = AUTHZ_KEY_VERSION;
  body.nonce = normalizeUuid(fields.nonce, 'nonce');
  // RFC 3339, second precision, UTC — the server's own format.
  body.issued_at = fields.issuedAt.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const canonical = JSON.stringify(body);
  const signature = createHmac('sha256', subkey).update(Buffer.from(canonical, 'utf8')).digest('hex');
  return Buffer.from(`${canonical.slice(0, -1)},"hmac_signature":"${signature}"}`, 'utf8');
}

interface Pending {
  resolve(decision: AuthzDecision): void;
  reject(err: Error): void;
}

/**
 * Publishes `AuthzRequest` messages and verifies their answers. Many checks
 * may be outstanding at once. Build it with {@link createAuthzRequester} or
 * {@link connectAuthzRequester}.
 *
 * The AMQP authorization requester requires an AXIAM server of 1.68 or later
 * (contract 1.68). Such a server signs every authorization response with the
 * tenant's AMQP subkey and answers on the requester's private `reply_to`
 * queue. A server older than 1.68 ignores `reply_to` and answers, unsigned,
 * only on the shared `axiam.authz.response` queue, which this requester never
 * reads: against it every check times out. There is no option to accept
 * unsigned responses (CONTRACT.md §8, contract 1.69): no AXIAM server sends
 * one to a reply queue, so an unsigned response can only have been published
 * by someone else, and it is discarded and logged. During a rolling upgrade
 * from a pre-1.68 server, use REST or gRPC authorization until every replica
 * runs 1.68 or later.
 */
export class AuthzRequester {
  readonly #channel: AuthzRequesterChannel;
  readonly #options: AuthzRequesterOptions;
  readonly #tenantId: string;
  readonly #replyTo: string;
  readonly #verifier: AuthzResponseVerifier;
  readonly #pending = new Map<string, Pending>();
  #consumerTag: string | undefined;
  #closed = false;
  #onClose: (() => Promise<void>) | undefined;

  /** @internal Use {@link createAuthzRequester}. */
  constructor(channel: AuthzRequesterChannel, options: AuthzRequesterOptions, tenantId: string, replyTo: string) {
    this.#channel = channel;
    this.#options = options;
    this.#tenantId = tenantId;
    this.#replyTo = replyTo;
    this.#verifier = new AuthzResponseVerifier({
      subkey: options.subkey,
      tenantId,
      replyQueue: replyTo,
      ...(options.logger !== undefined ? { logger: options.logger } : {}),
    });
  }

  /** The private reply queue every request names in `reply_to`. */
  get replyTo(): string {
    return this.#replyTo;
  }

  /** Number of checks still awaiting an answer. */
  get pending(): number {
    return this.#pending.size;
  }

  /** @internal Start consuming the reply queue. */
  async start(onClose?: () => Promise<void>): Promise<void> {
    this.#onClose = onClose;
    const { consumerTag } = await this.#channel.consume(this.#replyTo, (msg) => this.#handle(msg), {
      noAck: false,
      exclusive: true,
    });
    this.#consumerTag = consumerTag;
  }

  /**
   * Ask whether `subjectId` may perform `action` on `resourceId` and wait for
   * the verified answer. A response that fails verification or binding is
   * discarded and the check keeps waiting for the genuine one: a failed
   * verification is never an allow and never completes the request.
   *
   * @throws AuthzRequesterClosedError once {@link close} was called or the reply queue went away.
   * @throws NetworkError on a publish failure or when no verified answer arrives in time.
   */
  async check(input: AuthzCheckInput): Promise<AuthzDecision> {
    if (this.#closed) {
      throw new AuthzRequesterClosedError();
    }
    const correlationId = randomUUID(); // CSPRNG: unpredictable
    const nonce = randomUUID();
    const body = buildAuthzRequest(this.#options.subkey.expose(), {
      correlationId,
      tenantId: this.#tenantId,
      subjectId: input.subjectId,
      action: input.action,
      resourceId: input.resourceId,
      ...(input.scope !== undefined ? { scope: input.scope } : {}),
      nonce,
      issuedAt: (this.#options.now ?? (() => new Date()))(),
    });

    return new Promise<AuthzDecision>((resolve, reject) => {
      const timeoutMs = this.#options.timeoutMs ?? DEFAULT_AUTHZ_TIMEOUT_MS;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const onAbort = () => finish(() => reject(new NetworkError('axiam: authz check aborted')));
      const finish = (settle: () => void) => {
        if (timer !== undefined) clearTimeout(timer);
        input.signal?.removeEventListener('abort', onAbort);
        this.#pending.delete(correlationId);
        this.#verifier.forget(correlationId);
        settle();
      };

      this.#pending.set(correlationId, {
        resolve: (d) => finish(() => resolve(d)),
        reject: (e) => finish(() => reject(e)),
      });
      this.#verifier.expect({ correlation_id: correlationId, nonce, tenant_id: this.#tenantId });

      timer = setTimeout(
        () => finish(() => reject(new NetworkError('axiam: no verified authz answer before the timeout'))),
        timeoutMs,
      );
      if (input.signal) {
        if (input.signal.aborted) {
          onAbort();
          return;
        }
        input.signal.addEventListener('abort', onAbort, { once: true });
      }

      try {
        this.#channel.sendToQueue(AUTHZ_REQUEST_QUEUE, body, {
          correlationId,
          replyTo: this.#replyTo,
          contentType: 'application/json',
        });
      } catch (err) {
        finish(() => reject(new NetworkError('axiam: failed to publish authz request', err)));
      }
    });
  }

  /**
   * Stop accepting answers: every outstanding and later check rejects with
   * {@link AuthzRequesterClosedError}. The reply queue is exclusive and
   * auto-delete, so the broker removes it with its consumer. Idempotent.
   */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    for (const p of [...this.#pending.values()]) {
      p.reject(new AuthzRequesterClosedError());
    }
    if (this.#consumerTag !== undefined && this.#channel.cancel) {
      try {
        await this.#channel.cancel(this.#consumerTag);
      } catch {
        // The channel may already be gone; nothing left to release.
      }
    }
    await this.#onClose?.();
  }

  #handle(msg: ConsumeMessage | null): void {
    if (msg === null) {
      // The broker cancelled the consumer: the reply queue is gone.
      void this.close();
      return;
    }
    // Acks an accepted answer, nacks (no requeue) and logs anything else; on
    // acceptance the verifier has already retired the request.
    const verdict = this.#verifier.settle(this.#channel, msg);
    if (!verdict.accepted) {
      return;
    }
    const pending = this.#pending.get(verdict.response.correlation_id);
    pending?.resolve({
      allowed: verdict.response.allowed,
      ...(verdict.response.reason !== undefined ? { reason: verdict.response.reason } : {}),
      ...(verdict.response.reason_code !== undefined ? { reasonCode: verdict.response.reason_code } : {}),
    });
  }
}

/**
 * Open a private reply queue on `channel` and return a requester for
 * `options.tenantId` (CONTRACT.md §8, contract 1.68).
 *
 * The reply queue is declared with an EMPTY name (the broker names it
 * `amq.gen-…`), `exclusive`, `autoDelete` and non-durable, and consumed
 * exclusively with manual acknowledgement. A returned name that is empty or
 * starts with `axiam.` is refused: the server would answer such a request on
 * the shared `axiam.authz.response` queue (§8 rule 5).
 *
 * The caller owns `channel` and its connection, and therefore their error
 * handling: attach `'error'` listeners to both (an amqplib connection or
 * channel that emits `'error'` with no listener throws an uncaught exception
 * and ends the process), and call {@link AuthzRequester.close} when either
 * closes, so outstanding checks are released at once instead of waiting for
 * their timeout. {@link connectAuthzRequester} does both itself.
 *
 * @throws TypeError on a non-UUID tenant or an empty subkey; RangeError on an
 *   invalid `timeoutMs`; Error on a non-private reply queue.
 */
export async function createAuthzRequester(
  channel: AuthzRequesterChannel,
  options: AuthzRequesterOptions,
): Promise<AuthzRequester> {
  return createOn(channel, options);
}

async function createOn(
  channel: AuthzRequesterChannel,
  options: AuthzRequesterOptions,
  onClose?: () => Promise<void>,
): Promise<AuthzRequester> {
  const tenantId = normalizeUuid(options.tenantId, 'authz requester tenant_id');
  if (options.subkey.expose().length === 0) {
    throw new TypeError('axiam: authz requester needs the tenant subkey');
  }
  assertTimeout(options.timeoutMs);
  const { queue } = await channel.assertQueue('', { exclusive: true, autoDelete: true, durable: false });
  if (typeof queue !== 'string' || queue.length === 0 || queue.startsWith(SERVER_QUEUE_PREFIX)) {
    throw new Error(`axiam: authz reply queue ${JSON.stringify(queue)} is not a private queue`);
  }
  const requester = new AuthzRequester(channel, options, tenantId, queue);
  await requester.start(onClose);
  return requester;
}

/**
 * Connect to the broker at `amqpUrl` (MUST be `amqps://`, CONTRACT.md §8b) and
 * return a requester on its own channel; {@link AuthzRequester.close} also
 * closes that connection.
 *
 * The connection and channel are private to the requester, so it handles
 * their events itself: an `'error'` on either (a socket error, a missed
 * heartbeat, a channel-level exception) is logged through `options.logger`
 * — the error's message only, never the URL's credentials or a key (a
 * socket error's message can name the broker host and port) — instead of
 * escaping as an uncaught exception, and a `'close'` of either closes the requester:
 * every outstanding check rejects at once with
 * {@link AuthzRequesterClosedError}, and so does every later one. Reconnect
 * by building a new requester.
 */
export async function connectAuthzRequester(
  amqpUrl: string,
  options: AuthzRequesterOptions & { tls?: AmqpTlsOptions },
): Promise<AuthzRequester> {
  const socketOptions = buildAmqpConnectOptions(amqpUrl, options.tls, 'connectAuthzRequester() amqpUrl');
  const connection = await amqp.connect(amqpUrl, socketOptions);
  // Listen from the start: an 'error' with no listener throws out of
  // amqplib's socket handler and takes the whole process down.
  let requester: AuthzRequester | undefined;
  let gone = false;
  const onError = (source: 'connection' | 'channel') => (err: unknown) => {
    options.logger?.warn('axiam_sdk.amqp', `AMQP authz requester ${source} error`, {
      timestamp: new Date().toISOString(),
      reason: err instanceof Error ? err.message : 'unknown',
    });
  };
  const onGone = () => {
    gone = true;
    void requester?.close();
  };
  connection.on('error', onError('connection'));
  connection.on('close', onGone);
  try {
    const channel = await connection.createChannel();
    channel.on('error', onError('channel'));
    channel.on('close', onGone);
    requester = await createOn(channel as unknown as AuthzRequesterChannel, options, async () => {
      try {
        await connection.close();
      } catch {
        // already closed
      }
    });
    if (gone) {
      // Closed while the reply queue was being set up.
      await requester.close();
    }
    return requester;
  } catch (err) {
    await connection.close().catch(() => undefined);
    throw err;
  }
}
