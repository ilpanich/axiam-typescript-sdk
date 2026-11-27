// Closure-handler AMQP consumer (D-12, CONTRACT.md §8.3g/§8.4).
//
// The SDK owns the full ack/nack loop. Every delivery is HMAC-verified
// (CONTRACT.md §8) BEFORE the caller-supplied handler is ever invoked. On
// any verification failure (signature mismatch, a missing signature — there is no
// lenient mode, CONTRACT.md §8 rule 3 — a body outside the signed layout, or a body that is not one well-formed JSON object without duplicate keys) the delivery
// is nacked WITHOUT requeue and a security event is emitted — the event
// never contains the received/expected HMAC value or the signing key. Only
// a verified delivery reaches the handler, and only then is it acked.
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
import { verifyPayload } from './hmac.js';
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

type ReplayRejectReason = 'key_version' | 'issued_at' | 'nonce';

/**
 * NEW-4 validation gates, checked only AFTER the HMAC has already verified.
 * Returns the failing gate's name, or `undefined` when all three pass.
 * `ttlMs` for the nonce store is 2x `skewMs` — the freshness window plus a
 * margin so a nonce cannot be replayed the instant its dedup entry expires
 * while `issued_at` might still (barely) be judged fresh by a differently-
 * skewed verifier.
 */
function checkReplayProtection(
  body: Record<string, unknown>,
  skewMs: number,
  nonceStore: NonceStore,
): ReplayRejectReason | undefined {
  const keyVersion = body.key_version;
  if (typeof keyVersion !== 'number' || keyVersion < 2) {
    return 'key_version';
  }

  const issuedAtRaw = body.issued_at;
  if (typeof issuedAtRaw !== 'string') {
    return 'issued_at';
  }
  const issuedAtMs = Date.parse(issuedAtRaw);
  if (Number.isNaN(issuedAtMs) || Math.abs(Date.now() - issuedAtMs) > skewMs) {
    return 'issued_at';
  }

  const nonce = body.nonce;
  if (typeof nonce !== 'string' || nonce.length === 0) {
    return 'nonce';
  }
  if (nonceStore.checkAndRecord(nonce, skewMs * 2)) {
    return 'nonce';
  }

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

/**
 * The signed members of the two event types this consumer accepts, in
 * declaration order (CONTRACT.md §8 "Exact signed field order"); a name ending
 * in `?` is optional. Step 2c: the canonical bytes' top-level names MUST be
 * exactly one of these lists, each optional member present in its place or
 * absent, nothing else — every tenant-subkey-signed shape shares the key, so
 * without this a signed `AuthzResponse` or a cache-invalidation message would
 * pass as an event.
 */
const SIGNED_LAYOUTS: readonly (readonly string[])[] = [
  // AuthzRequest
  ['correlation_id', 'tenant_id', 'subject_id', 'action', 'resource_id', 'scope?', 'key_version', 'nonce', 'issued_at'],
  // AuditEventMessage
  [
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
];

/** Whether `names` (top-level member names, in wire order) fit one declared layout exactly. */
function matchesSignedLayout(names: readonly string[]): boolean {
  return SIGNED_LAYOUTS.some((layout) => {
    let i = 0;
    for (const declared of layout) {
      const optional = declared.endsWith('?');
      const name = optional ? declared.slice(0, -1) : declared;
      if (i < names.length && names[i] === name) i += 1;
      else if (!optional) return false;
    }
    return i === names.length;
  });
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
  options: ConsumeOptions = {},
): Promise<void> {
  const { logger } = options;

  // CONTRACT.md §8 step 2 / axiam#882: verify over the RECEIVED bytes — the body
  // with its trailing `,"hmac_signature":"<hex>"}` member removed — never over a
  // re-serialization, which disagrees with serde_json on floats (`1.0`),
  // integer-like keys (reordered) and large integers. The handler is given the
  // value decoded from those same verified bytes, so what is verified and what
  // is delivered cannot differ.
  const refuse = (message: string): void => {
    logger?.warn('axiam_sdk.security', message, {
      timestamp: new Date().toISOString(),
      exchange: msg.fields.exchange,
      routingKey: msg.fields.routingKey,
    });
    // channel.nack(msg, /* allUpTo */ false, /* requeue */ false)
    channel.nack(msg, false, false);
  };

  // 2a: one JSON object, nothing after the closing `}` (not even whitespace),
  // no repeated member at any depth. Invalid UTF-8 is refused rather than
  // decoded to U+FFFD, which would make the handler's value differ from the bytes.
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(msg.content);
  } catch {
    refuse('AMQP message body is not one well-formed JSON object; nacking without requeue');
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
    !text.endsWith('}') ||
    hasDuplicateKey(text)
  ) {
    refuse('AMQP message body is not one well-formed JSON object; nacking without requeue');
    return;
  }

  // 2b: the body must END in the signature member; missing, null, non-string,
  // not-last and trailing content are refused, never repaired (and an unsigned
  // message is always refused: §8 rule 3, there is no lenient mode).
  const trailing = TRAILING_SIGNATURE.exec(msg.content.toString('latin1'));
  const sig = (whole as Record<string, unknown>).hmac_signature;
  if (trailing === null || sig !== trailing[1]) {
    refuse('AMQP message has no trailing hmac_signature member; nacking without requeue');
    return;
  }
  // latin1 maps one byte to one unit and the member is ASCII, so the match
  // index is a byte index.
  const canonical = Buffer.concat([msg.content.subarray(0, trailing.index), Buffer.from('}', 'ascii')]);
  const body = JSON.parse(canonical.toString('utf8')) as Record<string, unknown>;

  // 2c: layout check over the canonical bytes' top-level names, exactly.
  if (!matchesSignedLayout(Object.keys(body))) {
    refuse('AMQP message is not an AuthzRequest or AuditEventMessage layout; nacking without requeue');
    return;
  }

  // 2d-2e: HMAC over the canonical bytes, compared in constant time.
  const verified = verifyPayload(signingKey, canonical, trailing[1]);

  if (!verified) {
    // Security event (§8.4): timestamp, exchange, routing key, and tenant
    // context (if present in the body) — NEVER the signature value or the
    // signing key.
    const tenantContext: Record<string, unknown> = {};
    if (typeof body.tenant_id === 'string') tenantContext.tenantId = body.tenant_id;
    logger?.warn('axiam_sdk.security', 'AMQP HMAC verification failed; nacking without requeue', {
      timestamp: new Date().toISOString(),
      exchange: msg.fields.exchange,
      routingKey: msg.fields.routingKey,
      ...tenantContext,
    });
    // channel.nack(msg, /* allUpTo */ false, /* requeue */ false)
    channel.nack(msg, false, false);
    return;
  }

  // NEW-4 (CONTRACT.md §8 v2, hard cutover): only reached once the HMAC has
  // verified. `canonical` above is the received bytes, so `nonce`/`issued_at`
  // are already inside the bytes that were just verified — these are the three ADDITIONAL validation
  // gates (key_version, freshness, replay), not re-verification.
  const skewMs = options.skewMs ?? DEFAULT_REPLAY_SKEW_MS;
  const nonceStore = options.nonceStore ?? new InMemoryNonceStore();
  const replayRejectReason = checkReplayProtection(body, skewMs, nonceStore);
  if (replayRejectReason) {
    const tenantContext: Record<string, unknown> = {};
    if (typeof body.tenant_id === 'string') tenantContext.tenantId = body.tenant_id;
    logger?.warn(
      'axiam_sdk.security',
      `AMQP v2 replay-protection check failed (${replayRejectReason}); nacking without requeue`,
      {
        timestamp: new Date().toISOString(),
        exchange: msg.fields.exchange,
        routingKey: msg.fields.routingKey,
        ...tenantContext,
      },
    );
    // channel.nack(msg, /* allUpTo */ false, /* requeue */ false)
    channel.nack(msg, false, false);
    return;
  }

  try {
    await handler(body);
  } catch (err) {
    // Do not requeue a handler-crashing message into a hot loop.
    logger?.warn('axiam_sdk.security', 'AMQP handler threw; nacking without requeue', {
      exchange: msg.fields.exchange,
      routingKey: msg.fields.routingKey,
      error: err instanceof Error ? err.message : String(err),
    });
    // channel.nack(msg, /* allUpTo */ false, /* requeue */ false)
    channel.nack(msg, false, false);
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
  options: ConsumeOptions = {},
): Promise<void> {
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
    void verifyAndDispatch(channel, msg, signingKey.expose(), handler, sharedOptions);
  });
}
