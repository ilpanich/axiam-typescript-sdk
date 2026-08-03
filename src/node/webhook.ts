// Webhook signature verification (CONTRACT.md §13, T-145).
//
// Verifies the server's Stripe-style signed-timestamp webhook scheme:
//   X-Axiam-Signature: t=<unix_seconds>,v1=<hex_lowercase_hmac>
//   v1 = HMAC-SHA256(secret_utf8_bytes, "<t>.<raw_body>")
// Mirrors — never imports — the server's algorithm in
// crates/axiam-api-rest/src/webhook.rs (`compute_signature_v2`), the same
// "reproduce, don't import" discipline `amqp/hmac.ts` follows for the AMQP
// HMAC contract (CONTRACT.md §8).
//
// The raw body is load-bearing: re-serializing parsed JSON before calling
// this changes key order/whitespace and breaks the MAC. Common frameworks
// discard the raw bytes by default — Express's `express.json()` does not
// keep them — so callers MUST capture the untouched bytes off the wire
// (Express `verify` callback, or `express.raw({ type: 'application/json' })`
// on the webhook route) and pass those, not a re-stringified object. See the
// README for the worked receiver example.

import { createHmac, timingSafeEqual } from 'node:crypto';
import { Sensitive } from '../core/sensitive.js';

/** Default freshness window, in seconds, for the `t=` timestamp (CONTRACT.md §13.2). */
export const DEFAULT_WEBHOOK_TOLERANCE_SEC = 300;

/**
 * Stable, machine-readable reason codes for a failed {@link verifyWebhook}
 * call. Never derived from — and never leaks — the expected/computed
 * signature or the secret (CONTRACT.md §13.3 rule 6).
 */
export type WebhookVerifyFailureReason =
  | 'malformed_header'
  | 'invalid_timestamp'
  | 'signature_mismatch'
  | 'stale_timestamp'
  | 'future_timestamp';

/**
 * Thrown by {@link verifyWebhook} on any verification failure.
 *
 * @remarks
 * Carries a stable {@link reason} code for programmatic branching. `message`
 * is short and generic — it MUST NOT, and never does, include the expected
 * or computed signature, the secret, or the raw signature header value
 * (CONTRACT.md §13.3 rule 6). Callers should treat any `WebhookVerifyError`
 * uniformly (reject the delivery); the `reason` is for logging/metrics, not
 * for varying the trust decision.
 */
export class WebhookVerifyError extends Error {
  /** Stable reason code — see {@link WebhookVerifyFailureReason}. */
  readonly reason: WebhookVerifyFailureReason;

  constructor(reason: WebhookVerifyFailureReason, message: string) {
    super(message);
    this.name = 'WebhookVerifyError';
    this.reason = reason;
    Object.setPrototypeOf(this, WebhookVerifyError.prototype);
  }
}

/** The verified event returned by {@link verifyWebhook} on success. */
export interface VerifiedWebhookEvent {
  /** The delivery body's `event` field (event type), when the body is a JSON object carrying one. */
  event?: string;
  /**
   * The delivery body's `id` field. Use this — or the separate
   * `X-Axiam-Delivery` request header — as the at-least-once dedup key
   * (CONTRACT.md §13.3 rule 7): a retried delivery replays a validly-signed
   * request inside the freshness window, so receivers should keep a
   * short-lived seen-set keyed on it.
   */
  id?: string;
  /** The verified `t=` timestamp, epoch seconds. */
  timestamp: number;
  /** The JSON-parsed body, when it parses as JSON; `undefined` for a non-JSON payload (the signature is still verified either way). */
  body?: unknown;
  /** The exact raw body bytes that were verified. */
  rawBody: Buffer;
}

/** Options for {@link verifyWebhook}. */
export interface VerifyWebhookOptions {
  /**
   * Freshness window in seconds. Defaults to
   * {@link DEFAULT_WEBHOOK_TOLERANCE_SEC} (300s). Two-sided: a `t=` more
   * than `tolerance` seconds in the past OR more than `tolerance` seconds in
   * the future is rejected (CONTRACT.md §13.3 rule 5 — rejecting
   * future-dated timestamps too is required, not optional, as a guard
   * against clock-skew abuse).
   */
  tolerance?: number;
  /**
   * Injectable "current time" in epoch seconds, for deterministic tests.
   * Defaults to `Math.floor(Date.now() / 1000)`.
   */
  now?: number;
}

function fail(reason: WebhookVerifyFailureReason, message: string): never {
  throw new WebhookVerifyError(reason, message);
}

const STRICT_HEX_PATTERN = /^[0-9a-fA-F]+$/;
const STRICT_INTEGER_PATTERN = /^-?\d+$/;

/**
 * Parse `t=<seconds>,v1=<hex>[,v1=<hex>,...]` into the timestamp string and
 * the set of candidate `v1` hex signatures. Unknown keys/schemes are ignored
 * for forward compatibility (CONTRACT.md §13.3 rule 3); a header carrying no
 * `t` or no `v1` at all is a hard failure — "nothing to verify" is never
 * treated as success.
 */
function parseSignatureHeader(header: string): { t: string; v1: string[] } {
  let t: string | undefined;
  let tCount = 0;
  const v1: string[] = [];

  for (const rawPair of header.split(',')) {
    const pair = rawPair.trim();
    if (pair.length === 0) continue;
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    const key = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (key === 't') {
      t = value;
      tCount += 1;
    } else if (key === 'v1') {
      v1.push(value);
    }
    // Any other key is an unrecognized/future scheme — ignored.
  }

  if (tCount !== 1 || t === undefined) {
    fail('malformed_header', 'signature header must carry exactly one "t" field');
  }
  if (v1.length === 0) {
    fail('malformed_header', 'signature header carries no "v1" field');
  }
  return { t, v1 };
}

/**
 * Verify an AXIAM webhook delivery's `X-Axiam-Signature` header against the
 * raw request body (CONTRACT.md §13).
 *
 * Verification order (§13.3, normative): parse the header → parse `t` →
 * recompute `HMAC-SHA256(secret, "<t>.<raw_body>")` → constant-time compare
 * against every supplied `v1` candidate → two-sided freshness check → on
 * success, return the parsed event.
 *
 * @param secret The webhook's plaintext signing secret, wrapped per
 *   CONTRACT.md §7.
 * @param signatureHeader The raw `X-Axiam-Signature` header value. (Do NOT
 *   pass `X-Axiam-Timestamp` here — `t=` in this header is the value
 *   actually covered by the MAC; if you also read the separate
 *   `X-Axiam-Timestamp` header, require it to equal the parsed `t` yourself
 *   before calling this function.)
 * @param body The **exact raw bytes** received off the wire (`Buffer`,
 *   `Uint8Array`, or the identical raw string) — never a re-serialized
 *   `JSON.stringify` of the parsed body, which changes key order/whitespace
 *   and breaks the MAC.
 * @param options Freshness tolerance (default 300s) and a `now` injection
 *   seam for tests.
 * @returns The verified event on success.
 * @throws {WebhookVerifyError} On any verification failure. Never throws a
 *   generic `Error` whose message could leak the expected signature.
 */
export function verifyWebhook(
  secret: Sensitive<string>,
  signatureHeader: string,
  body: Buffer | Uint8Array | string,
  options: VerifyWebhookOptions = {},
): VerifiedWebhookEvent {
  const { t, v1 } = parseSignatureHeader(signatureHeader);

  if (!STRICT_INTEGER_PATTERN.test(t)) {
    fail('invalid_timestamp', 'signature header "t" is not an integer');
  }
  const timestamp = Number(t);
  if (!Number.isFinite(timestamp)) {
    fail('invalid_timestamp', 'signature header "t" is out of range');
  }

  const rawBody: Buffer = typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
  const secretBytes = Buffer.from(secret.expose(), 'utf8');
  const signedPayload = Buffer.concat([Buffer.from(`${t}.`, 'utf8'), rawBody]);
  const expected = createHmac('sha256', secretBytes).update(signedPayload).digest();

  // Constant-time compare over DECODED bytes, never the hex strings
  // themselves, and never an early-return byte-by-byte loop. A length
  // mismatch is not itself secret information (it depends only on the
  // attacker-supplied candidate's own length), so short-circuiting past it
  // is safe and required — `timingSafeEqual` throws on unequal-length
  // buffers, so this guard is load-bearing, not just an optimization.
  let matched = false;
  for (const candidate of v1) {
    if (!STRICT_HEX_PATTERN.test(candidate) || candidate.length % 2 !== 0) {
      // Malformed hex fails closed: never decoded, never compared, never
      // treated as a match.
      continue;
    }
    const candidateBytes = Buffer.from(candidate, 'hex');
    if (candidateBytes.length !== expected.length) continue;
    if (timingSafeEqual(candidateBytes, expected)) {
      matched = true;
      break;
    }
  }
  if (!matched) {
    fail('signature_mismatch', 'no v1 signature in the header matched the computed HMAC');
  }

  // Freshness — two-sided (§13.3 rule 5): a future-dated timestamp is
  // rejected exactly like a stale one.
  const nowSec = options.now ?? Math.floor(Date.now() / 1000);
  const tolerance = options.tolerance ?? DEFAULT_WEBHOOK_TOLERANCE_SEC;
  const age = nowSec - timestamp;
  if (age > tolerance) {
    fail('stale_timestamp', `timestamp is ${age}s old, outside the ${tolerance}s tolerance`);
  }
  if (-age > tolerance) {
    fail('future_timestamp', `timestamp is ${-age}s in the future, outside the ${tolerance}s tolerance`);
  }

  let parsedBody: unknown;
  let event: string | undefined;
  let id: string | undefined;
  try {
    parsedBody = JSON.parse(rawBody.toString('utf8'));
    if (parsedBody !== null && typeof parsedBody === 'object') {
      const obj = parsedBody as Record<string, unknown>;
      if (typeof obj.event === 'string') event = obj.event;
      if (typeof obj.id === 'string') id = obj.id;
    }
  } catch {
    // Signature verification does not depend on the body being JSON; a
    // non-JSON (but correctly signed) payload still verifies, it just
    // carries no `event`/`id` convenience fields.
    parsedBody = undefined;
  }

  return { event, id, timestamp, body: parsedBody, rawBody };
}
