// `reactorServe` — the SDK reactor runtime (CONTRACT.md §22.10).
//
// One helper. It connects (TLS per §8b and §6), consumes the SERVER-DECLARED
// queue, and for each delivery: verifies §8 v2 (`key_version`, MAC, freshness,
// nonce), decodes the event, dispatches to a user-supplied handler, then signs
// and publishes the reply. It drains in-flight events on shutdown per §18.
//
// ## The four rules on the helper itself (§22.10)
//
//  1. It declares no topology. There is no `assertQueue`, `assertExchange` or
//     `bindQueue` anywhere in this module, and the channel seam it is written
//     against (`ReactorChannel`) exposes no such operation — so the rule is
//     structural rather than remembered. A reactor that can bind is a reactor
//     that can bind itself to `*.token.pre_issue`.
//  2. It fails closed on its own errors. A handler that throws, a payload that
//     will not decode, a window that has already closed — every one of them
//     produces NO REPLY, letting the server's `failure_policy` decide.
//     Answering `allow` on behalf of a handler that crashed would override the
//     operator's `fail_closed` setting from inside the library.
//  3. It does not filter a patch. A handler's patch is published exactly as
//     returned, forbidden keys and all (§22.4 rule 1).
//  4. It honours `timeout_ms`. The handler runs under the event's own window,
//     and a reply whose window has closed is abandoned rather than published
//     late.

import amqp from 'amqplib';
import type { Channel, ConsumeMessage } from 'amqplib';
import type { Sensitive } from '../../core/index.js';
import { TelemetryDispatcher, type TelemetryHook } from '../../core/index.js';
import { InMemoryNonceStore, type NonceStore } from '../consumer.js';
import { buildAmqpConnectOptions, type AmqpTlsOptions } from '../transport.js';
import {
  REACTOR_FRESHNESS_SKEW_MS,
  buildReactorReply,
  reactorQueueName,
  signReactorReply,
  verifyEvent,
  type ReactorEvent,
} from './protocol.js';
import { REACTOR_EVENTS, eventSpec, type ReactorMode } from './registry.js';

/** Telemetry operation name for one reactor dispatch (§19.1). */
const TELEMETRY_OPERATION = 'reactorDispatch';

// ---------------------------------------------------------------------------
// The handler's answer
// ---------------------------------------------------------------------------

/**
 * What a handler decided about one event (CONTRACT.md §22.10).
 *
 * Three answers plus one absence. `allow`, `deny` and `mutate` are the three the
 * wire carries; `abstain` is the *absence* of a reply, which the server resolves
 * through the registration's `failure_policy` (§22.8) exactly as it resolves a
 * timeout.
 *
 * Build one with {@link allow}, {@link requireStepUp}, {@link deny} or
 * {@link mutate} rather than by hand.
 */
export type ReactorDecision =
  | {
      readonly kind: 'allow';
      /**
       * Proceed **only after step-up authentication**. `login.post_auth` only —
       * it is not a separate decision value, and sending it on any other event
       * is refused (§22.4 rule 3).
       */
      readonly requireMfa: boolean;
    }
  | {
      readonly kind: 'deny';
      /**
       * Audited reason. A deny with no reason still denies; the server
       * substitutes `"denied by reactor"` when it is absent.
       */
      readonly reason?: string;
    }
  | {
      readonly kind: 'mutate';
      /**
       * The fields to set — a flat `string → string` map. Published
       * **unfiltered**: one forbidden key rejects the whole patch server-side,
       * and pruning it here would leave you believing a field was set when it
       * was dropped (§22.4 rule 1). Check it yourself with `patchFieldAllowed`
       * if you want to know before you send.
       */
      readonly patch: Record<string, string>;
    }
  | {
      /**
       * Publish nothing at all.
       *
       * The right answer when the window has already closed (§22.3: shed load
       * rather than answer into a closed window) or when the handler cannot
       * decide. It is **not** a quiet `allow`: the server applies the
       * registration's `failure_policy`, which for every event except
       * `token.pre_issue` defaults to `fail_closed`.
       */
      readonly kind: 'abstain';
    };

/** Proceed unchanged. */
export function allow(): ReactorDecision {
  return { kind: 'allow', requireMfa: false };
}

/** Proceed, but demand step-up authentication first. `login.post_auth` only. */
export function requireStepUp(): ReactorDecision {
  return { kind: 'allow', requireMfa: true };
}

/**
 * Refuse. Pass a reason for the audit trail; omitting it still denies, and the
 * audit record reads `"denied by reactor"`.
 */
export function deny(reason?: string): ReactorDecision {
  return reason === undefined ? { kind: 'deny' } : { kind: 'deny', reason };
}

/** Proceed, applying a patch. */
export function mutate(patch: Record<string, string>): ReactorDecision {
  return { kind: 'mutate', patch };
}

/** Publish nothing; let the registration's `failure_policy` decide. */
export function abstain(): ReactorDecision {
  return { kind: 'abstain' };
}

/**
 * A reactor handler: one function from a verified event to one of three answers
 * (CONTRACT.md §22.10).
 */
export type ReactorHandler = (event: ReactorEvent) => ReactorDecision | Promise<ReactorDecision>;

// ---------------------------------------------------------------------------
// The channel seam
// ---------------------------------------------------------------------------

/**
 * The operations one reactor delivery needs — **and no others**.
 *
 * There is deliberately no `assertQueue`, `assertExchange` or `bindQueue` here:
 * §22.1's "actors consume; they never declare topology" is enforced by the
 * seam's shape, so it cannot be violated by a later edit that forgets the rule.
 * `amqplib`'s `Channel` satisfies it structurally; tests provide a recording
 * fake that never touches a broker.
 */
export interface ReactorChannel {
  /** `channel.ack(msg)` — `allUpTo` intentionally omitted/false. */
  ack(msg: ConsumeMessage): void;
  /** `channel.nack(msg, allUpTo, requeue)` — positional booleans. */
  nack(msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void;
  /** Publish the signed reply to the `reply_to` queue, echoing the correlation id. */
  sendToQueue(
    queue: string,
    content: Buffer,
    options?: { correlationId?: string; contentType?: string },
  ): boolean;
}

/** Where this runtime writes its security events. */
export interface ReactorLogger {
  warn(event: string, message: string, context?: Record<string, unknown>): void;
}

// ---------------------------------------------------------------------------
// Per-delivery dispatch
// ---------------------------------------------------------------------------

/** Everything one dispatch needs that does not come from the delivery. */
export interface ReactorDispatchContext {
  /** The tenant's HKDF-derived AMQP subkey. */
  readonly signingKey: Buffer;
  /** The tenant this reactor is registered in. */
  readonly tenantId: string;
  /** `intercept` (answers) or `listen` (observes, publishes nothing). */
  readonly mode: ReactorMode;
  /** `issued_at` acceptance window, in milliseconds. */
  readonly skewMs: number;
  /** Shared across every delivery on one consumer, or replay dedup does nothing. */
  readonly nonceStore: NonceStore;
  readonly logger?: ReactorLogger;
  readonly telemetry?: TelemetryDispatcher;
}

/**
 * Verify one delivery, dispatch it to `handler`, and publish the answer.
 *
 * Every path that cannot produce a **usable** reply publishes nothing at all,
 * which is what hands the decision to the registration's `failure_policy`
 * (§22.8) rather than to this library.
 *
 * Exported because it is the separately-testable unit backing
 * {@link reactorServe}'s per-message loop, mirroring the §8 consumer's
 * `verifyAndDispatch`.
 */
export async function dispatchReactorDelivery(
  channel: ReactorChannel,
  msg: ConsumeMessage,
  ctx: ReactorDispatchContext,
  handler: ReactorHandler,
): Promise<void> {
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(msg.content.toString('utf8')) as Record<string, unknown>;
  } catch {
    reject(channel, msg, ctx, 'malformed', 'reactor delivery body failed JSON parse');
    return;
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    reject(channel, msg, ctx, 'malformed', 'reactor delivery body is not a JSON object');
    return;
  }

  // §22.3, in order: key_version, MAC, freshness. Only then is anything in the
  // payload looked at.
  const verified = verifyEvent(body, ctx.signingKey, Date.now(), ctx.skewMs);
  if (!verified.ok) {
    reject(channel, msg, ctx, verified.rejection, 'reactor event failed §8 v2 verification');
    return;
  }
  const event = verified.event;

  // The fourth §22.3 check: the nonce seen-set.
  if (ctx.nonceStore.checkAndRecord(event.nonce, ctx.skewMs * 2)) {
    reject(channel, msg, ctx, 'replayed_nonce', 'reactor event nonce was already seen');
    return;
  }

  // A queue is per-tenant and the subkey is per-tenant, so this can only fire on
  // a misconfiguration — but a reactor answering for a tenant it was not
  // configured as is exactly the confusion §22.1 refuses to allow.
  if (event.tenant_id !== ctx.tenantId) {
    reject(
      channel,
      msg,
      ctx,
      'malformed',
      'reactor event names a different tenant than this reactor is configured for',
    );
    return;
  }

  const startedAt = Date.now();
  const deadline = startedAt + event.timeout_ms;
  const eventLabel = registryLabel(event.event);
  ctx.telemetry?.emit({
    type: 'requestStart',
    operation: TELEMETRY_OPERATION,
    method: 'AMQP',
    pathTemplate: eventLabel,
    attempt: 1,
  });

  // §22.10 rules 2 and 4 together: the handler runs inside the window the server
  // declared, and a throw is caught rather than propagated — both resolve to *no
  // reply*, never to a synthesized `allow`.
  let decision: ReactorDecision | undefined;
  try {
    decision = await withDeadline(handler(event), event.timeout_ms);
  } catch (err) {
    ctx.logger?.warn(
      'axiam_sdk.reactor',
      'reactor handler threw or outran timeout_ms; publishing no reply so the registration’s failure_policy decides',
      {
        event: event.event,
        correlationId: event.correlation_id,
        timeoutMs: event.timeout_ms,
        error: err instanceof Error ? err.message : String(err),
      },
    );
  }

  ctx.telemetry?.emit({
    type: 'requestEnd',
    operation: TELEMETRY_OPERATION,
    method: 'AMQP',
    pathTemplate: eventLabel,
    attempt: 1,
    durationMs: Date.now() - startedAt,
    outcome: decision === undefined ? 'failure' : 'success',
  });

  // A listener never publishes: the server does not wait for it and does not
  // read a reply, so anything it sent would be noise on a queue nobody is
  // draining (§22.5).
  if (ctx.mode === 'listen') {
    channel.ack(msg);
    return;
  }

  if (decision !== undefined) {
    publishAnswer(channel, msg, ctx, event, decision, deadline);
  }

  // The event verified and was consumed. Acking is what keeps `last_seen_at`
  // moving — a heartbeat derived from real work (§22.9) — and requeueing an
  // event whose correlation is already spent would only re-run a handler against
  // a window that has closed.
  channel.ack(msg);
}

/** Build, sign and publish the reply for `decision`, or publish nothing and say why. */
function publishAnswer(
  channel: ReactorChannel,
  msg: ConsumeMessage,
  ctx: ReactorDispatchContext,
  event: ReactorEvent,
  decision: ReactorDecision,
  deadlineMs: number,
): void {
  if (decision.kind === 'abstain') {
    return;
  }

  let requireMfa = false;
  let reason: string | undefined;
  let patch: Record<string, string> | undefined;
  let wire: 'allow' | 'deny' | 'mutate';

  if (decision.kind === 'allow') {
    wire = 'allow';
    requireMfa = decision.requireMfa;
  } else if (decision.kind === 'deny') {
    wire = 'deny';
    reason = decision.reason;
  } else {
    wire = 'mutate';
    patch = decision.patch;
    if (Object.keys(patch).length === 0) {
      // `mutate` with an empty patch is `malformed_mutation` server-side (§22.4
      // row 10). Refusing it here is not filtering — no field is being dropped,
      // the reply has no content to carry.
      ctx.logger?.warn(
        'axiam_sdk.reactor',
        'handler returned a mutation with an empty patch (malformed_mutation); publishing no reply',
        { event: event.event, correlationId: event.correlation_id },
      );
      return;
    }
  }

  // §22.4 row 7 / rule 3: `require_mfa` rides on `allow`, on `login.post_auth`,
  // and nowhere else. §22.13 allows an SDK to refuse this client-side; doing so
  // puts the mistake in the reactor author's log instead of only in the server's
  // audit trail.
  if (requireMfa && event.event !== REACTOR_EVENTS.LOGIN_POST_AUTH) {
    ctx.logger?.warn(
      'axiam_sdk.reactor',
      'require_mfa is only valid on login.post_auth (require_mfa_not_supported); publishing no reply',
      { event: event.event, correlationId: event.correlation_id },
    );
    return;
  }

  const reply = signReactorReply(
    buildReactorReply(event, { decision: wire, reason, patch, requireMfa }),
    ctx.signingKey,
  );

  // §22.3 / §22.10 rule 4: a late reply is discarded, and the CPU spent
  // producing it was spent for nothing. Do not spend the network on it too.
  if (Date.now() >= deadlineMs) {
    ctx.logger?.warn(
      'axiam_sdk.reactor',
      'the event’s window closed before the reply was ready; not publishing',
      {
        event: event.event,
        correlationId: event.correlation_id,
        timeoutMs: event.timeout_ms,
      },
    );
    return;
  }

  const replyTo = msg.properties.replyTo;
  if (typeof replyTo !== 'string' || replyTo.length === 0) {
    ctx.logger?.warn(
      'axiam_sdk.reactor',
      'delivery carried no reply_to property; nowhere to publish the reply',
      { correlationId: event.correlation_id },
    );
    return;
  }

  // The AMQP property is the RPC convention; what the server AUTHENTICATES is
  // the correlation_id inside the signed body, which `buildReactorReply` copied
  // from the event.
  const propertyCorrelation =
    typeof msg.properties.correlationId === 'string'
      ? msg.properties.correlationId
      : event.correlation_id;

  channel.sendToQueue(replyTo, Buffer.from(JSON.stringify(reply), 'utf8'), {
    correlationId: propertyCorrelation,
    contentType: 'application/json',
  });
}

/**
 * Nack without requeue and log the reason. The reason never carries the signing
 * key, and never the received or expected MAC.
 */
function reject(
  channel: ReactorChannel,
  msg: ConsumeMessage,
  ctx: ReactorDispatchContext,
  rejection: string,
  message: string,
): void {
  ctx.logger?.warn('axiam_sdk.security', `${message}; nacking without requeue`, {
    timestamp: new Date().toISOString(),
    rejection,
    exchange: msg.fields.exchange,
    routingKey: msg.fields.routingKey,
  });
  channel.nack(msg, false, false);
}

/**
 * Map a wire event name onto the registry's own string, so a telemetry label can
 * never be an attacker-chosen string or a cardinality bomb.
 */
function registryLabel(name: string): string {
  return eventSpec(name)?.name ?? 'unknown_event';
}

/**
 * Settle `work`, or reject once `timeoutMs` has elapsed.
 *
 * The timer is always cleared — a pending `setTimeout` would keep a Node process
 * alive past the shutdown §18 promises is deterministic.
 */
function withDeadline<T>(work: T | Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject_) => {
    const timer = setTimeout(() => {
      reject_(new Error(`reactor handler exceeded timeout_ms=${timeoutMs}`));
    }, Math.max(timeoutMs, 0));
    Promise.resolve(work).then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject_(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

// ---------------------------------------------------------------------------
// reactorServe
// ---------------------------------------------------------------------------

/** How to reach the broker and which reactor this process is (§22.1, §22.9). */
export interface ReactorConfig {
  /**
   * Broker URL. Must be `amqps://` (§8b rules 1 and 5) — there is no
   * verification-skip switch and no plaintext fallback, and this is now
   * *enforced* before the socket opens rather than merely stated here.
   */
  readonly amqpUrl: string;
  /**
   * TLS material for {@link amqpUrl} (§8b).
   *
   * Optional. With none supplied the broker is verified against Node's bundled
   * roots, which is correct for a publicly-issued broker certificate. Set
   * {@link AmqpTlsOptions.caCert} for a privately-issued one — the common case
   * for an in-cluster broker, and why §8b rule 2 is a MUST — and
   * `clientCert`/`clientKey` together for mutual TLS toward the broker
   * (rule 3).
   */
  readonly tls?: AmqpTlsOptions;
  /** The tenant this reactor is registered in. */
  readonly tenantId: string;
  /**
   * This reactor's registration id, from `POST /api/v1/reactors` (§22.9).
   *
   * It names the **one** queue this process may consume. Passing another
   * reactor's id is not a supported way to share a runtime: §22.1 forbids
   * deriving a queue name for a reactor other than the one you are.
   */
  readonly reactorId: string;
  /**
   * The tenant's HKDF-derived AMQP subkey (§8 v2, §22.2) — **not** the master
   * key. Obtain it from the AXIAM management API for this tenant; hard-coding
   * one is prohibited. Wrapped in `Sensitive` (§22.12) so it cannot be logged,
   * printed or serialized by accident.
   */
  readonly signingKey: Sensitive<Buffer>;
  /**
   * `intercept` (default) or `listen`.
   *
   * In `listen` mode the runtime publishes **nothing**: a listener cannot affect
   * any outcome, and §22.5 requires the handler be written idempotently because
   * a redelivery after a broker hiccup is normal.
   */
  readonly mode?: ReactorMode;
  /**
   * Override the ±300 s `issued_at` acceptance window. The same window, doubled,
   * bounds how long a `nonce` is remembered for replay detection.
   */
  readonly skewMs?: number;
  /** Nonce dedup store. One is created and shared across the consumer by default. */
  readonly nonceStore?: NonceStore;
  readonly logger?: ReactorLogger;
  /**
   * A §19 telemetry hook. One `requestStart`/`requestEnd` pair is emitted per
   * dispatch, with the registry event name as the path template — a bounded
   * label set, never a correlation id.
   */
  readonly telemetryHook?: TelemetryHook;
  /**
   * Deterministic shutdown (§18). Aborting it cancels the consumer, waits for
   * every in-flight dispatch to finish — handler, signature and publish — and
   * only then closes the channel and connection. Shutdown drains rather than
   * truncates.
   */
  readonly signal?: AbortSignal;
}

/**
 * Run a reactor: consume the server-declared queue, answer every event
 * (CONTRACT.md §22.10).
 *
 * `handler` is called **only** with an event whose `key_version`, MAC, freshness
 * and nonce have all passed. It returns one of {@link ReactorDecision}'s three
 * answers, or {@link abstain} to publish nothing.
 *
 * Resolves when `signal` aborts (after the drain) or when the broker closes the
 * connection.
 *
 * @example
 * ```ts
 * import { Sensitive } from 'axiam-sdk/amqp';
 * import { REACTOR_EVENTS, allow, deny, mutate, reactorServe } from 'axiam-sdk/amqp';
 *
 * await reactorServe(
 *   {
 *     amqpUrl: 'amqps://reactor:secret@broker.example.com:5671',
 *     tenantId: '11111111-1111-1111-1111-111111111111',
 *     reactorId: '99999999-9999-9999-9999-999999999999',
 *     signingKey: new Sensitive(subkey),
 *   },
 *   (event) => {
 *     if (event.event === REACTOR_EVENTS.TOKEN_PRE_ISSUE) {
 *       return mutate({ 'ext.cost_center': '42' });
 *     }
 *     if (event.event === REACTOR_EVENTS.LOGIN_POST_AUTH && fromEmbargoedRegion(event)) {
 *       return deny('embargoed region');
 *     }
 *     return allow();
 *   },
 * );
 * ```
 *
 * ## Security
 *
 * The `payload`, `patch`, `reason` and `decision` are tenant business data:
 * readable by design (a handler that cannot inspect the event cannot decide
 * anything) but **not** logged at info level by this runtime, and they should not
 * be logged at info level by yours either (§22.12). The signing key is
 * `Sensitive` and never appears in a log line or an error payload.
 */
export async function reactorServe(config: ReactorConfig, handler: ReactorHandler): Promise<void> {
  const queue = reactorQueueName(config.tenantId, config.reactorId);
  const skewMs = config.skewMs ?? REACTOR_FRESHNESS_SKEW_MS;
  const ctx: ReactorDispatchContext = {
    signingKey: config.signingKey.expose(),
    tenantId: config.tenantId,
    mode: config.mode ?? 'intercept',
    skewMs,
    // One store shared across every delivery on this consumer — a fresh store
    // per message would defeat replay dedup entirely.
    nonceStore: config.nonceStore ?? new InMemoryNonceStore(),
    logger: config.logger,
    telemetry: config.telemetryHook ? new TelemetryDispatcher(config.telemetryHook) : undefined,
  };

  // §8b: a reactor connects across a trust boundary, and its reply is an
  // instruction to allow, deny or rewrite a token. Validated before dialling —
  // a plaintext URL or half a client identity is a configuration fault, and
  // discovering it as a connect-time network error tells nobody what to fix.
  const socketOptions = buildAmqpConnectOptions(
    config.amqpUrl,
    config.tls,
    'reactorServe() amqpUrl',
  );
  const connection = await amqp.connect(config.amqpUrl, socketOptions);
  const channel: Channel = await connection.createChannel();

  // NOTE: there is no assertQueue / assertExchange / bindQueue here, and there
  // must never be one. §22.1: the server declares the exchange, the queue and
  // the bindings; actors consume.
  const inFlight = new Set<Promise<void>>();
  let stopped = false;

  const { consumerTag } = await channel.consume(queue, (msg) => {
    if (!msg) return;
    // A delivery that arrives after the signal is nacked back rather than
    // half-processed: §18's drain covers what is already in flight, not what
    // the broker pushed afterwards.
    if (stopped) {
      channel.nack(msg, false, true);
      return;
    }
    const work = dispatchReactorDelivery(channel, msg, ctx, handler).finally(() => {
      inFlight.delete(work);
    });
    inFlight.add(work);
  });

  const closed = new Promise<void>((resolve) => {
    connection.on('close', () => resolve());
  });

  const aborted = config.signal
    ? new Promise<void>((resolve) => {
        const signal = config.signal as AbortSignal;
        if (signal.aborted) {
          resolve();
          return;
        }
        signal.addEventListener('abort', () => resolve(), { once: true });
      })
    : new Promise<void>(() => {
        /* never resolves; only the connection closing ends the run */
      });

  await Promise.race([closed, aborted]);
  stopped = true;

  // Drain (§18): stop taking new deliveries, then let every dispatch already
  // running finish — handler, signature, publish — before tearing down.
  try {
    await channel.cancel(consumerTag);
  } catch {
    // The channel may already be gone if the connection closed on us; the
    // drain below is what matters.
  }
  await Promise.allSettled([...inFlight]);
  try {
    await channel.close();
    await connection.close();
  } catch {
    // Idempotent teardown: closing an already-closed channel or connection is
    // the state the caller asked for, not an error to surface.
  }
}
