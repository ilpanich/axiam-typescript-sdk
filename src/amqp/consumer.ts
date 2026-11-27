// Closure-handler AMQP consumer (D-12, CONTRACT.md §8.3g/§8.4).
//
// The SDK owns the full ack/nack loop. Every delivery is HMAC-verified
// (CONTRACT.md §8) BEFORE the caller-supplied handler is ever invoked. The
// consumer is typed (D-9): it is configured with the ONE signed type it
// consumes and accepts that type's layout only. On any refusal (a body that is
// not one well-formed JSON object starting with `{` — a byte-order mark is
// refused, never stripped — a missing signature (no lenient mode, §8 rule 3), a
// layout that is not the configured type's, a signature mismatch, a verified
// body that does not decode, or a failed v2 gate) the delivery is nacked
// WITHOUT requeue and ONE event is logged (D-8): timestamp, exchange, routing
// key, the consumer's own tenant and a closed reason — never a signature, a
// nonce, a key or any member of the body. Only a verified delivery reaches the
// handler, and only then is it acked.
//
// NEW-4 (CONTRACT.md §8 "v2 — Replay Protection", hard cutover): once the
// HMAC verifies, the delivery is ADDITIONALLY rejected (same nack-without-
// requeue path) when `key_version < 2`, `issued_at` falls outside the
// ±skew freshness window, or `nonce` has already been seen. Because this
// module verifies over the received bytes (the body minus its trailing
// `hmac_signature` member; axiam#882), `nonce`/`issued_at` are already
// covered by the HMAC bytes with no canonicalization change — only the three
// validation gates below are new.
//
// This is the TS port of the already-tested Rust `verify_and_dispatch`/
// `consume` (the Rust SDK's src/amqp/consumer.rs).

import amqp from 'amqplib';
import type { Channel, ConsumeMessage } from 'amqplib';
import type { Sensitive } from '../core/index.js';
import { decodeUtf8Strict, verifyPayload } from './hmac.js';
import { buildAmqpConnectOptions, type AmqpTlsOptions } from './transport.js';

/**
 * Default freshness skew for `issued_at` acceptance (NEW-4): a message is
 * accepted only when its `issued_at` lies within ±5 minutes of the
 * verifier's clock, matching the server's
 * `DEFAULT_FRESHNESS_SKEW_SECS = 300` / `AXIAM__AMQP__REPLAY_SKEW_SECS`
 * (CONTRACT.md §8 v2).
 */
export const DEFAULT_REPLAY_SKEW_MS = 5 * 60 * 1000;

/**
 * Nonce replay-dedup store (NEW-4). `checkAndRecord` returns `true` when
 * `nonce` has already been recorded and its dedup entry has not yet
 * expired (i.e. this delivery is a replay); otherwise it records the nonce
 * with the given TTL and returns `false`.
 */
export interface NonceStore {
  checkAndRecord(nonce: string, ttlMs: number): boolean;
}

/**
 * Default in-memory nonce dedup store (NEW-4). Naturally bounded: each
 * entry expires after `ttlMs` (the caller passes 2x the freshness skew, so
 * a nonce can never still be "fresh" once its dedup entry has lapsed) and
 * expired entries are pruned opportunistically on each check — no
 * background timer and no unbounded growth under sustained traffic.
 *
 * Share ONE instance across every delivery from the same consumer (as
 * `consume()` does by default) — a fresh store per call provides no
 * cross-message replay protection.
 */
export class InMemoryNonceStore implements NonceStore {
  private readonly seenUntilMs = new Map<string, number>();

  checkAndRecord(nonce: string, ttlMs: number): boolean {
    const now = Date.now();
    this.prune(now);
    const expiry = this.seenUntilMs.get(nonce);
    if (expiry !== undefined && expiry > now) {
      return true;
    }
    this.seenUntilMs.set(nonce, now + ttlMs);
    return false;
  }

  private prune(now: number): void {
    for (const [nonce, expiry] of this.seenUntilMs) {
      if (expiry <= now) this.seenUntilMs.delete(nonce);
    }
  }
}

/** The two signed event types an event consumer can be configured for (CONTRACT.md §8 step 2c, D-9). */
export type EventType = 'AuthzRequest' | 'AuditEventMessage';

/** The closed vocabulary of the discard event's `reason` (CONTRACT.md §8 rule 4, D-8). */
export type EventDiscardReason = 'malformed' | 'unsigned' | 'signature' | 'key_version' | 'stale' | 'replay';

const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

type MemberKind = 'uuid' | 'string' | 'json' | 'u8' | 'timestamp';

/**
 * Step 2f decode: the verified canonical bytes decode into the configured
 * type, member by member, as the server's struct does (`Uuid`, `String`,
 * `u8`, `DateTime<Utc>`, `serde_json::Value`).
 */
function decodesAs(kinds: Readonly<Record<string, MemberKind>>, body: Record<string, unknown>): boolean {
  for (const [name, value] of Object.entries(body)) {
    switch (kinds[name]) {
      case 'uuid':
        if (typeof value !== 'string' || !UUID.test(value)) return false;
        break;
      case 'string':
        if (typeof value !== 'string') return false;
        break;
      case 'u8':
        if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 255) return false;
        break;
      case 'timestamp':
        if (typeof value !== 'string' || !RFC3339.test(value) || Number.isNaN(Date.parse(value))) return false;
        break;
      case 'json':
        if (value === null) return false; // an omitted member, never `null` (§8 wire form)
        break;
      default:
        return false;
    }
  }
  return true;
}

/** The members of each type, in declaration order (CONTRACT.md §8 "Exact signed field order"); a name ending in `?` is optional. */
interface EventSpec {
  readonly layout: readonly string[];
  readonly kinds: Readonly<Record<string, MemberKind>>;
}
const EVENT_SPECS: Readonly<Record<EventType, EventSpec>> = {
  AuthzRequest: {
    layout: ['correlation_id', 'tenant_id', 'subject_id', 'action', 'resource_id', 'scope?', 'key_version', 'nonce', 'issued_at'],
    kinds: {
      correlation_id: 'uuid',
      tenant_id: 'uuid',
      subject_id: 'uuid',
      action: 'string',
      resource_id: 'uuid',
      scope: 'string',
      key_version: 'u8',
      nonce: 'uuid',
      issued_at: 'timestamp',
    },
  },
  AuditEventMessage: {
    layout: [
      'tenant_id',
      'actor_id',
      'actor_type',
      'action',
      'resource_id?',
      'outcome',
      'ip_address?',
      'metadata?',
      'key_version',
      'nonce',
      'issued_at',
    ],
    kinds: {
      tenant_id: 'uuid',
      actor_id: 'uuid',
      actor_type: 'string',
      action: 'string',
      resource_id: 'uuid',
      outcome: 'string',
      ip_address: 'string',
      metadata: 'json',
      key_version: 'u8',
      nonce: 'uuid',
      issued_at: 'timestamp',
    },
  },
};

/**
 * Gates (6)–(8), checked only AFTER the HMAC verified and the body decoded.
 * Returns the failing gate's reason, or `undefined` when all three pass; the
 * nonce is recorded last, so a body refused at (6) or (7) leaves none behind.
 * `ttlMs` for the nonce store is 2x `skewMs` — the freshness window plus a
 * margin so a nonce cannot be replayed the instant its dedup entry expires
 * while `issued_at` might still (barely) be judged fresh by a differently-
 * skewed verifier.
 */
function checkReplayProtection(
  body: Record<string, unknown>,
  skewMs: number,
  nonceStore: NonceStore,
): 'key_version' | 'stale' | 'replay' | undefined {
  if ((body.key_version as number) < 2) return 'key_version';
  if (Math.abs(Date.now() - Date.parse(body.issued_at as string)) > skewMs) return 'stale';
  if (nonceStore.checkAndRecord(body.nonce as string, skewMs * 2)) return 'replay';
  return undefined;
}

/**
 * Minimal seam over the channel operations this module needs
 * (ack/nack/consume). `amqplib`'s `Channel` implements this directly;
 * tests provide a recording fake that never touches a live broker, so the
 * security-sensitive nack-without-requeue behavior can be asserted without
 * a running RabbitMQ instance.
 */
export interface ConsumeChannel {
  consume(
    queue: string,
    onMessage: (msg: ConsumeMessage | null) => void | Promise<void>,
  ): Promise<unknown>;
  /** `channel.ack(msg, allUpTo?)` — allUpTo intentionally omitted/false here. */
  ack(msg: ConsumeMessage): void;
  /** `channel.nack(msg, allUpTo, requeue)` — positional booleans (Pitfall 4). */
  nack(msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void;
}

export interface ConsumeLogger {
  warn(event: string, message: string, context?: Record<string, unknown>): void;
}

export interface ConsumeOptions {
  /**
   * The consumer's OWN tenant: the tenant whose signing subkey `signingKey`
   * is (CONTRACT.md §8 rule 1). Every discard event names it as `tenantId`;
   * a `tenant_id` read from a message body is never logged (D-8).
   */
  tenantId: string;
  /**
   * The ONE signed type this consumer consumes (CONTRACT.md §8 step 2c, D-9).
   * A body with the layout of any other signed type — the other event type, an
   * `AuthzResponse`, a reactor message — is refused as `malformed` before the
   * HMAC is computed. An application consuming both types runs two consumers.
   */
  eventType: EventType;
  logger?: ConsumeLogger;
  /**
   * Freshness skew window for `issued_at` validation (NEW-4), in
   * milliseconds. Defaults to {@link DEFAULT_REPLAY_SKEW_MS} (5 minutes),
   * matching the server default (CONTRACT.md §8 v2).
   */
  skewMs?: number;
  /**
   * Nonce replay-dedup store (NEW-4). Defaults to a fresh
   * `InMemoryNonceStore` per call when omitted — `consume()` creates and
   * shares ONE store across every delivery on that connection by default;
   * callers invoking `verifyAndDispatch` directly across multiple messages
   * must pass the same store explicitly for dedup to take effect.
   */
  nonceStore?: NonceStore;
  /**
   * TLS material for the `amqps://` broker connection (CONTRACT.md §8b).
   *
   * Optional, and omitting it does not weaken anything: the URL must be
   * `amqps://` either way, and with no material supplied the broker is verified
   * against Node's bundled roots. Set {@link AmqpTlsOptions.caCert} when the
   * broker certificate comes from a private CA — the common case for an
   * in-cluster broker, and the reason §8b rule 2 is a MUST.
   */
  tls?: AmqpTlsOptions;
}

/** `,"hmac_signature":"<64 hex>"}` at the very end of the body, nothing after it (CONTRACT.md §8 step 2b). */
const TRAILING_SIGNATURE = /,"hmac_signature":"([0-9a-fA-F]{64})"\}$/;

/** Whether `names` (top-level member names, in wire order) fit `layout` exactly. */
function matchesSignedLayout(names: readonly string[], layout: readonly string[]): boolean {
  let i = 0;
  for (const declared of layout) {
    const optional = declared.endsWith('?');
    const name = optional ? declared.slice(0, -1) : declared;
    if (i < names.length && names[i] === name) i += 1;
    else if (!optional) return false;
  }
  return i === names.length;
}

/**
 * A configuration fault, found before any delivery is read: the consumer needs
 * its own tenant (D-8) and the one type it consumes (D-9).
 */
function assertConsumeConfig(options: ConsumeOptions, where: string): void {
  if (typeof options?.tenantId !== 'string' || options.tenantId === '') {
    throw new TypeError(`${where}: options.tenantId (the consumer's own tenant) is required`);
  }
  if (!Object.prototype.hasOwnProperty.call(EVENT_SPECS, options.eventType)) {
    throw new TypeError(`${where}: options.eventType must be 'AuthzRequest' or 'AuditEventMessage'`);
  }
}

/**
 * Whether any JSON object in `text` (already known to be well-formed JSON)
 * repeats a key. Keys are compared after unescaping, so `"a"` and `"\u0061"`
 * are the same key.
 */
function hasDuplicateKey(text: string): boolean {
  const stack: Array<Set<string> | null> = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < n && text[j] !== '"') {
        j += text[j] === '\\' ? 2 : 1;
      }
      const raw = text.slice(i, j + 1);
      i = j + 1;
      const top = stack[stack.length - 1];
      if (top !== undefined && top !== null) {
        let k = i;
        while (k < n && /\s/.test(text[k])) k += 1;
        if (text[k] === ':') {
          const key = JSON.parse(raw) as string;
          if (top.has(key)) return true;
          top.add(key);
        }
      }
      continue;
    }
    if (c === '{') stack.push(new Set());
    else if (c === '[') stack.push(null);
    else if (c === '}' || c === ']') stack.pop();
    i += 1;
  }
  return false;
}

/**
 * Verify a single delivery's HMAC signature (CONTRACT.md §8 steps a-g) and,
 * only on success, invoke `handler` with the parsed body (hmac_signature
 * removed) before acking. On any failure the delivery is nacked without
 * requeue and a security event is emitted that never contains the HMAC
 * value or the signing key.
 *
 * Exported (not just used internally) so it is the same separately-testable
 * unit backing `consume`'s per-message loop, mirroring the Rust SDK's
 * `verify_and_dispatch`.
 */
export async function verifyAndDispatch(
  channel: ConsumeChannel,
  msg: ConsumeMessage,
  signingKey: Buffer,
  handler: (event: Record<string, unknown>) => Promise<void>,
  options: ConsumeOptions,
): Promise<void> {
  assertConsumeConfig(options, 'verifyAndDispatch()');
  const { logger } = options;
  const spec = EVENT_SPECS[options.eventType];

  // CONTRACT.md §8 step 2 / axiam#882: verify over the RECEIVED bytes — the body
  // with its trailing `,"hmac_signature":"<hex>"}` member removed — never over a
  // re-serialization, which disagrees with serde_json on floats (`1.0`),
  // integer-like keys (reordered) and large integers. The handler is given the
  // value decoded from those same verified bytes, so what is verified and what
  // is delivered cannot differ.
  //
  // Every discard is ONE call of `refuse` (D-8): nack first (a logger that
  // throws must not leave the delivery unacked), then exactly the five members
  // of the event — the tenant is this consumer's own, never read from the body.
  const refuse = (reason: EventDiscardReason): void => {
    try {
      // channel.nack(msg, /* allUpTo */ false, /* requeue */ false)
      channel.nack(msg, false, false);
    } catch {
      // channel already closed: nothing more can be done for this delivery
    }
    try {
      logger?.warn('axiam_sdk.security', `AMQP event discarded (${reason})`, {
        timestamp: new Date().toISOString(),
        exchange: msg.fields.exchange,
        routingKey: msg.fields.routingKey,
        tenantId: options.tenantId,
        reason,
      });
    } catch {
      // an integrator logger's failure is not the delivery's problem
    }
  };

  // (1) one JSON object whose FIRST BYTE is its opening `{` (a byte-order mark,
  // whitespace or any other prefix is refused, never stripped; D-10), nothing
  // after its `}`. Invalid UTF-8 is refused rather than decoded to U+FFFD, which
  // would make the handler's value differ from the bytes.
  let text: string;
  try {
    text = decodeUtf8Strict(msg.content);
  } catch {
    refuse('malformed');
    return;
  }
  let whole: unknown;
  try {
    whole = JSON.parse(text);
  } catch {
    whole = undefined;
  }
  if (
    typeof whole !== 'object' ||
    whole === null ||
    Array.isArray(whole) ||
    !text.startsWith('{') ||
    !text.endsWith('}')
  ) {
    refuse('malformed');
    return;
  }

  // (2) no top-level `hmac_signature` member: unsigned, whatever else is wrong
  // (§8 rule 3: there is no lenient mode).
  if (!Object.prototype.hasOwnProperty.call(whole, 'hmac_signature')) {
    refuse('unsigned');
    return;
  }

  // (3) everything else steps 2a-2c refuse: a repeated member at any depth, a
  // signature that is not the trailing 64-hex member (null, non-string, not
  // last), and a layout that is not the configured type's.
  if (hasDuplicateKey(text)) {
    refuse('malformed');
    return;
  }
  const trailing = TRAILING_SIGNATURE.exec(msg.content.toString('latin1'));
  const sig = (whole as Record<string, unknown>).hmac_signature;
  if (trailing === null || sig !== trailing[1]) {
    refuse('malformed');
    return;
  }
  // latin1 maps one byte to one unit and the member is ASCII, so the match
  // index is a byte index.
  const canonical = Buffer.concat([msg.content.subarray(0, trailing.index), Buffer.from('}', 'ascii')]);
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(decodeUtf8Strict(canonical)) as Record<string, unknown>;
  } catch {
    refuse('malformed');
    return;
  }
  // Step 2c, typed (D-9): the configured type's layout ONLY, before the HMAC
  // and before anything is decoded.
  if (!matchesSignedLayout(Object.keys(body), spec.layout)) {
    refuse('malformed');
    return;
  }

  // (4) HMAC over the canonical bytes, compared in constant time.
  if (!verifyPayload(signingKey, canonical, trailing[1])) {
    refuse('signature');
    return;
  }

  // (5) the verified bytes decode into the configured type.
  if (!decodesAs(spec.kinds, body)) {
    refuse('malformed');
    return;
  }

  // (6)-(8) NEW-4 (CONTRACT.md §8 v2, hard cutover): key_version, freshness,
  // replay — three ADDITIONAL gates over bytes already verified; the nonce is
  // recorded only when all of them pass.
  const skewMs = options.skewMs ?? DEFAULT_REPLAY_SKEW_MS;
  const nonceStore = options.nonceStore ?? new InMemoryNonceStore();
  const gate = checkReplayProtection(body, skewMs, nonceStore);
  if (gate !== undefined) {
    refuse(gate);
    return;
  }

  try {
    await handler(body);
  } catch (err) {
    // Do not requeue a handler-crashing message into a hot loop.
    try {
      channel.nack(msg, false, false);
    } catch {
      // channel already closed
    }
    try {
      logger?.warn('axiam_sdk.security', 'AMQP handler threw; nacking without requeue', {
        exchange: msg.fields.exchange,
        routingKey: msg.fields.routingKey,
        error: err instanceof Error ? err.message : String(err),
      });
    } catch {
      // an integrator logger's failure is not the delivery's problem
    }
    return;
  }

  channel.ack(msg);
}

/**
 * Connect to the AMQP broker at `amqpUrl`, declare `queue` as durable, and
 * consume from it — verifying each delivery's HMAC-SHA256 signature
 * (CONTRACT.md §8) BEFORE invoking `handler`. The handler never sees an
 * unverified message; verification failures are nacked without requeue and
 * logged as a security event.
 *
 * `signingKey` is a required, caller-supplied `Sensitive<Buffer>` — the SDK
 * does not fetch it from the server (no such endpoint exists; CONTRACT.md
 * §8.1 assumes out-of-band provisioning).
 *
 * This function owns the full ack/nack loop; `handler` MUST NOT itself call
 * ack/nack (there is no delivery handle exposed to it).
 *
 * `amqpUrl` MUST be `amqps://` (CONTRACT.md §8b). It is checked before any
 * socket is opened, so a plaintext URL fails with a message naming the rule
 * rather than connecting and quietly putting signed-but-readable authorization
 * requests and audit events on the wire.
 */
export async function consume(
  amqpUrl: string,
  queue: string,
  signingKey: Sensitive<Buffer>,
  handler: (event: Record<string, unknown>) => Promise<void>,
  options: ConsumeOptions,
): Promise<void> {
  assertConsumeConfig(options, 'consume()');
  // §8b: validated BEFORE dialling. A bad URL or half a client identity is a
  // configuration fault, and finding out at connect time turns it into a
  // network error message that says nothing about what to fix.
  const socketOptions = buildAmqpConnectOptions(amqpUrl, options.tls, 'consume() amqpUrl');
  const connection = await amqp.connect(amqpUrl, socketOptions);
  const channel: Channel = await connection.createChannel();
  await channel.assertQueue(queue, { durable: true });

  // NEW-4: one nonce store shared across every delivery on this consumer —
  // a fresh store per message (the per-call default in `verifyAndDispatch`)
  // would defeat replay dedup entirely.
  const sharedOptions: ConsumeOptions = {
    ...options,
    nonceStore: options.nonceStore ?? new InMemoryNonceStore(),
  };

  await channel.consume(queue, (msg) => {
    if (!msg) return;
    verifyAndDispatch(channel, msg, signingKey.expose(), handler, sharedOptions).catch(() => {
      // Never an unhandled rejection (it would take the process down and the
      // unacked delivery would come back): nack without requeue first, then
      // log without body content; neither step may throw out of here.
      try {
        channel.nack(msg, false, false);
      } catch {
        // channel already closed
      }
      try {
        sharedOptions.logger?.warn('axiam_sdk.security', 'AMQP event discarded (malformed)', {
          timestamp: new Date().toISOString(),
          exchange: msg.fields.exchange,
          routingKey: msg.fields.routingKey,
          tenantId: sharedOptions.tenantId,
          reason: 'malformed' satisfies EventDiscardReason,
        });
      } catch {
        // an integrator logger's failure is not the delivery's problem
      }
    });
  });
}
