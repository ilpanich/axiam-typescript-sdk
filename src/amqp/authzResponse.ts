// Signed AMQP authorization responses (CONTRACT.md §8, "Signed authorization
// responses", contract 1.68; SA-15, N2, D-9).
//
// From 1.68 the server signs every `AuthzResponse` with the requester's own
// tenant subkey and binds it to the request it answers (`tenant_id`, `nonce`,
// `correlation_id`). This module is the requester half: it verifies a received
// response and matches it to a request the caller still has outstanding.
//
// The one rule that differs from every other §8 message: the canonical bytes
// are the RECEIVED bytes with the trailing `,"hmac_signature":"<64 hex>"`
// member removed — never a re-serialization of the parsed members. `reason`
// echoes the requested action, which the requester chooses, and JSON encoders
// disagree on escaping, so a re-serialization fails to verify the genuine
// answer (contract vector 4). And the response handed back is parsed from
// those same verified bytes, so what is verified and what is delivered cannot
// differ (the Go SDK's C2).
//
// `AuthzRequester` (authzRequester.ts) is built on this class. An application
// that publishes its own requests registers each with `expect()` and hands
// every delivery from its private reply queue to `verify()` (or `settle()`,
// which also acks/nacks).

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { ConsumeMessage } from 'amqplib';
import type { Sensitive } from '../core/index.js';
import type { ConsumeLogger } from './consumer.js';

/** The members of a request that its response must echo (§8 rule 3). */
export interface OutstandingAuthzRequest {
  /** The request's `correlation_id`. */
  correlation_id: string;
  /** The request's `nonce`, which a 1.68 response echoes. */
  nonce: string;
  /** The request's `tenant_id`; MUST be the verifier's own tenant. */
  tenant_id: string;
}

/** A response that passed §8 rules 1–3, parsed from the bytes that were verified. */
export interface VerifiedAuthzResponse {
  /** Echo of the request's `correlation_id`. */
  correlation_id: string;
  /** The decision. */
  allowed: boolean;
  /** Human-readable reason, when the server gave one. */
  reason?: string;
  /** Machine-readable reason (`allowed`, `no_grant`, `denied_by_rule`, `tenant_suspended`, or a code this SDK does not know, verbatim). */
  reason_code?: string;
  /** The tenant the response answers for; equals the verifier's tenant. Absent only on an unsigned response admitted by the opt-out. */
  tenant_id?: string;
  /** Echo of the request's `nonce`. Absent only on an unsigned response admitted by the opt-out. */
  nonce?: string;
}

/** Why a response was discarded. Never carries a signature value. */
export type AuthzResponseRejection =
  /** Not JSON, or missing / ill-typed `correlation_id`, `allowed`, `tenant_id`, `nonce` (rule 1). */
  | 'malformed'
  /** No trailing `hmac_signature` member, and the unsigned opt-out is off or does not apply. */
  | 'unsigned'
  /** The HMAC does not verify under this tenant's subkey (rule 2). */
  | 'signature'
  /** `tenant_id` is not this verifier's tenant (rule 3). */
  | 'tenant'
  /** No outstanding request has this `correlation_id` and `nonce` (rule 3). */
  | 'unknown_request';

/** The outcome of {@link AuthzResponseVerifier.verify}. */
export type AuthzResponseVerdict =
  | {
      /** The response passed every rule; its request has been retired. */
      accepted: true;
      /** The verified response. */
      response: VerifiedAuthzResponse;
      /** `true` only when admitted unsigned by {@link AuthzResponseVerifierOptions.acceptUnsignedResponses}. */
      unsigned: boolean;
    }
  | {
      /** The response was discarded: never an allow, and its request stays outstanding. */
      accepted: false;
      /** Which rule failed. */
      reason: AuthzResponseRejection;
    };

/** Configuration for an {@link AuthzResponseVerifier}. */
export interface AuthzResponseVerifierOptions {
  /**
   * The requester's own tenant subkey — the HKDF-derived per-tenant AMQP key
   * for `tenantId` and the `key_version` the requests were signed with
   * (currently `2`), never the master key (§8.1: provisioned out of band).
   */
  subkey: Sensitive<Buffer>;
  /** The requester's own tenant; every accepted response names it. */
  tenantId: string;
  /**
   * Accept responses unsigned (§8, "Against a server older than 1.68").
   *
   * **Off by default.** Set it only for one rolling upgrade against a server
   * older than 1.68: a response that carries **no** `hmac_signature` member is
   * then accepted on its `correlation_id` alone, with a warning logged. A
   * response that carries a signature is verified whatever this says, and one
   * that fails is still discarded.
   */
  acceptUnsignedResponses?: boolean;
  /** Receives security events. Never receives a signature value or the key. */
  logger?: ConsumeLogger;
}

/**
 * Where a response was read from, for the security event a discarded (or an
 * unsigned-admitted) response logs (CONTRACT.md §8 rule 4: timestamp,
 * exchange, routing key, tenant). {@link AuthzResponseVerifier.settle} takes
 * it from the delivery's `msg.fields`.
 */
export interface AuthzResponseDelivery {
  /** The exchange the response was published to (`''` for the default exchange). */
  exchange: string;
  /** The routing key it was published with (the reply queue's name on the default exchange). */
  routingKey: string;
}

/** The ack/nack subset of an amqplib `Channel` that {@link AuthzResponseVerifier.settle} needs. */
export interface SettleChannel {
  /** `channel.ack(msg)`. */
  ack(msg: ConsumeMessage): void;
  /** `channel.nack(msg, allUpTo, requeue)`. */
  nack(msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void;
}

/** `,"hmac_signature":"<64 hex>"}` at the very end of the body, nothing after it. */
const TRAILING_SIGNATURE = /,"hmac_signature":"([0-9a-fA-F]{64})"\}$/;

const isString = (value: unknown): value is string => typeof value === 'string';

/**
 * Verifies signed `AuthzResponse` messages for one tenant and matches them to
 * the caller's outstanding requests (CONTRACT.md §8 rules 1–4, contract 1.68).
 *
 * @example
 * ```ts
 * const verifier = new AuthzResponseVerifier({ subkey, tenantId });
 * // when publishing a request (with an exclusive reply_to queue):
 * verifier.expect({ correlation_id, nonce, tenant_id: tenantId });
 * // for every delivery on that queue:
 * const verdict = verifier.settle(channel, msg);
 * if (verdict.accepted) resolvePending(verdict.response);
 * ```
 */
export class AuthzResponseVerifier {
  readonly #subkey: Sensitive<Buffer>;
  readonly #tenantId: string;
  readonly #acceptUnsigned: boolean;
  readonly #logger: ConsumeLogger | undefined;
  /** correlation_id → nonce of each outstanding request. */
  readonly #outstanding = new Map<string, string>();

  /** @param options the tenant, its subkey, and the (off by default) unsigned opt-out. */
  constructor(options: AuthzResponseVerifierOptions) {
    this.#subkey = options.subkey;
    this.#tenantId = options.tenantId.toLowerCase();
    this.#acceptUnsigned = options.acceptUnsignedResponses === true;
    this.#logger = options.logger;
  }

  /**
   * Register a published request whose answer is awaited. Its `tenant_id`
   * must be this verifier's tenant.
   *
   * @throws RangeError when the request names another tenant.
   */
  expect(request: OutstandingAuthzRequest): void {
    if (request.tenant_id.toLowerCase() !== this.#tenantId) {
      throw new RangeError('AuthzResponseVerifier.expect: the request names another tenant');
    }
    this.#outstanding.set(request.correlation_id, request.nonce);
  }

  /** Stop waiting for `correlationId` (for example on the caller's own timeout). */
  forget(correlationId: string): void {
    this.#outstanding.delete(correlationId);
  }

  /** Number of requests still awaiting an answer. */
  get pending(): number {
    return this.#outstanding.size;
  }

  /**
   * Verify one received response body (CONTRACT.md §8 rules 1–4). On
   * acceptance the matching request is retired, so a second response for it
   * is dropped. On any failure nothing is retired — the genuine answer may
   * still arrive — and a security event is logged without either signature.
   *
   * @param delivery where the body was read from; when given, the security
   *   event names its exchange and routing key (§8 rule 4).
   *   {@link settle} passes it.
   */
  verify(body: Buffer, delivery?: AuthzResponseDelivery): AuthzResponseVerdict {
    // Byte offsets: latin1 maps each byte to one UTF-16 unit, and the
    // signature member is pure ASCII, so the match index is a byte index.
    const match = TRAILING_SIGNATURE.exec(body.toString('latin1'));
    if (!match) {
      return this.#unsignedOrRefuse(body, delivery);
    }

    // Rule 2 — the canonical bytes are the received bytes with the trailing
    // member removed: everything before it, then the closing brace.
    const canonical = Buffer.concat([body.subarray(0, match.index), Buffer.from('}', 'ascii')]);
    const expected = createHmac('sha256', this.#subkey.expose()).update(canonical).digest();
    const received = Buffer.from(match[1], 'hex');
    if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
      return this.#refuse('signature', delivery);
    }

    // Rule 1 on the VERIFIED bytes, which are also what is delivered.
    let parsed: unknown;
    try {
      parsed = JSON.parse(canonical.toString('utf8'));
    } catch {
      return this.#refuse('malformed', delivery);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return this.#refuse('malformed', delivery);
    }
    const r = parsed as Record<string, unknown>;
    if (
      !isString(r.correlation_id) ||
      typeof r.allowed !== 'boolean' ||
      !isString(r.tenant_id) ||
      !isString(r.nonce) ||
      (r.reason !== undefined && !isString(r.reason)) ||
      (r.reason_code !== undefined && !isString(r.reason_code)) ||
      Object.prototype.hasOwnProperty.call(r, 'hmac_signature')
    ) {
      return this.#refuse('malformed', delivery);
    }

    // Rule 3 — the binding.
    if (r.tenant_id.toLowerCase() !== this.#tenantId) {
      return this.#refuse('tenant', delivery);
    }
    const nonce = this.#outstanding.get(r.correlation_id);
    if (nonce === undefined || nonce !== r.nonce) {
      return this.#refuse('unknown_request', delivery);
    }

    this.#outstanding.delete(r.correlation_id);
    return {
      accepted: true,
      unsigned: false,
      response: {
        correlation_id: r.correlation_id,
        allowed: r.allowed,
        ...(r.reason !== undefined ? { reason: r.reason as string } : {}),
        ...(r.reason_code !== undefined ? { reason_code: r.reason_code as string } : {}),
        tenant_id: r.tenant_id,
        nonce: r.nonce,
      },
    };
  }

  /**
   * {@link verify} a delivery read from a queue, then ack it when accepted
   * and nack it **without requeue** when discarded (§8 rule 4).
   */
  settle(channel: SettleChannel, msg: ConsumeMessage): AuthzResponseVerdict {
    const verdict = this.verify(msg.content, {
      exchange: msg.fields.exchange,
      routingKey: msg.fields.routingKey,
    });
    if (verdict.accepted) {
      channel.ack(msg);
    } else {
      channel.nack(msg, false, false);
    }
    return verdict;
  }

  /** No trailing signature: refused, unless the opt-out admits a body with no signature member at all. */
  #unsignedOrRefuse(body: Buffer, delivery: AuthzResponseDelivery | undefined): AuthzResponseVerdict {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString('utf8'));
    } catch {
      return this.#refuse('malformed', delivery);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return this.#refuse('malformed', delivery);
    }
    const r = parsed as Record<string, unknown>;
    // A body that carries a signature anywhere but at the end is not
    // "unsigned": it fails, whatever the opt-out says.
    if (!this.#acceptUnsigned || Object.prototype.hasOwnProperty.call(r, 'hmac_signature')) {
      return this.#refuse('unsigned', delivery);
    }
    if (!isString(r.correlation_id) || typeof r.allowed !== 'boolean') {
      return this.#refuse('malformed', delivery);
    }
    if (!this.#outstanding.has(r.correlation_id)) {
      return this.#refuse('unknown_request', delivery);
    }
    this.#outstanding.delete(r.correlation_id);
    this.#logger?.warn(
      'axiam_sdk.security',
      'accepted an UNSIGNED AMQP authorization response (acceptUnsignedResponses is set; pre-1.68 server)',
      this.#eventContext(delivery),
    );
    return {
      accepted: true,
      unsigned: true,
      response: {
        correlation_id: r.correlation_id,
        allowed: r.allowed,
        ...(isString(r.reason) ? { reason: r.reason } : {}),
        ...(isString(r.reason_code) ? { reason_code: r.reason_code } : {}),
      },
    };
  }

  #refuse(reason: AuthzResponseRejection, delivery: AuthzResponseDelivery | undefined): AuthzResponseVerdict {
    this.#logger?.warn(
      'axiam_sdk.security',
      `AMQP authorization response discarded (${reason})`,
      this.#eventContext(delivery),
    );
    return { accepted: false, reason };
  }

  /** §8 rule 4: timestamp, exchange, routing key, tenant — never a signature value. */
  #eventContext(delivery: AuthzResponseDelivery | undefined): Record<string, unknown> {
    return {
      timestamp: new Date().toISOString(),
      ...(delivery !== undefined ? { exchange: delivery.exchange, routingKey: delivery.routingKey } : {}),
      tenantId: this.#tenantId,
    };
  }
}
