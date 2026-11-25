// CONTRACT.md §8 "Signed authorization responses" (contract 1.68; SA-15, N2,
// D-9): the requester verifies the server-signed `AuthzResponse` over the
// RECEIVED bytes with the trailing signature member removed, with its own
// tenant subkey, and checks `tenant_id`, `correlation_id` and `nonce` against
// a request it still has outstanding. The four normative vectors and every
// required negative case are pinned here.

import { createHmac, hkdfSync } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { Sensitive } from '../../src/core/index.js';
import { AuthzResponseVerifier } from '../../src/amqp/authzResponse.js';
import vectors from '../../testdata/v2_reference_vectors.json' with { type: 'json' };

const MASTER = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const TENANT = '11111111-1111-1111-1111-111111111111';
const OTHER_TENANT = '99999999-9999-9999-9999-999999999999';
const CORRELATION = '22222222-2222-2222-2222-222222222222';
const NONCE = '55555555-5555-5555-5555-555555555555';
const SUBKEY_HEX = '919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89';

function deriveSubkey(tenantId: string, keyVersion: number): Buffer {
  const info = Buffer.concat([
    Buffer.from('axiam-amqp-v1', 'utf8'),
    Buffer.from([keyVersion]),
    Buffer.from(tenantId.replace(/-/g, ''), 'hex'),
  ]);
  return Buffer.from(hkdfSync('sha256', MASTER, Buffer.from('axiam-amqp-hkdf-salt-v1', 'utf8'), info, 32));
}

// The four vectors, byte for byte from CONTRACT.md §8.
const V1 =
  '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true,"reason_code":"allowed","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}';
const V1_SIG = '8d81f0437df6c6fffafd13f4265bd41d3cfd6fcbf7c251b3bb79e0846578574a';
const V2 =
  '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action \'documents:read\'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}';
const V2_SIG = 'f3105ee678acd79da6ffd28c02b86311e16bb8d8dfd3fd0addbacdf73bd5a400';
const V3 =
  '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"an explicit deny rule refuses action \'documents:read\'","reason_code":"denied_by_rule","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}';
const V3_SIG = '4bfc2ce9a035bd4a028ee2a5cb75a08832915c60cd2b176c8d4bf28910a61adc';
const V4 =
  '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action \'docs:a&b</\\"c\\">/é€\'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}';
const V4_SIG = '5194142df4bf66b07e9e8d516caf6be099af025219ab12deb26fea39e93490ff';

/** Wire JSON: the canonical bytes with the signature member appended last. */
function wire(canonical: string, signature: string): Buffer {
  return Buffer.from(`${canonical.slice(0, -1)},"hmac_signature":"${signature}"}`, 'utf8');
}

function sign(canonical: string, key: Buffer): string {
  return createHmac('sha256', key).update(Buffer.from(canonical, 'utf8')).digest('hex');
}

function verifier(options: { acceptUnsignedResponses?: boolean } = {}) {
  const logger = { warn: vi.fn() };
  const v = new AuthzResponseVerifier({
    subkey: new Sensitive(Buffer.from(SUBKEY_HEX, 'hex')),
    tenantId: TENANT,
    logger,
    ...options,
  });
  v.expect({ correlation_id: CORRELATION, nonce: NONCE, tenant_id: TENANT });
  return { v, logger };
}

describe('§8 signed AuthzResponse — vectors', () => {
  it('the fixture subkey is the HKDF derivation the vectors use', () => {
    expect(deriveSubkey(TENANT, 2).toString('hex')).toBe(SUBKEY_HEX);
    expect((vectors as { hkdf: { derived_subkey_hex: string } }).hkdf.derived_subkey_hex).toBe(SUBKEY_HEX);
  });

  it.each([
    ['1 allow', V1, V1_SIG, true, 'allowed'],
    ['2 no_grant', V2, V2_SIG, false, 'no_grant'],
    ['3 denied_by_rule', V3, V3_SIG, false, 'denied_by_rule'],
    ['4 escaped reason', V4, V4_SIG, false, 'no_grant'],
  ])('vector %s verifies over its wire JSON', (_n, canonical, sig, allowed, reasonCode) => {
    expect(sign(canonical, deriveSubkey(TENANT, 2))).toBe(sig);
    const { v } = verifier();
    const verdict = v.verify(wire(canonical, sig));
    expect(verdict.accepted).toBe(true);
    if (!verdict.accepted) return;
    expect(verdict.response.allowed).toBe(allowed);
    expect(verdict.response.reason_code).toBe(reasonCode);
    expect(verdict.response.correlation_id).toBe(CORRELATION);
    expect(verdict.unsigned).toBe(false);
  });

  it('vector 4 delivers the reason exactly as the verified bytes carry it', () => {
    const { v } = verifier();
    const verdict = v.verify(wire(V4, V4_SIG));
    expect(verdict.accepted && verdict.response.reason).toBe('no permission grants action \'docs:a&b</"c">/é€\'');
  });

  it('a second response for an already-answered request is dropped (retired on acceptance)', () => {
    const { v } = verifier();
    expect(v.verify(wire(V1, V1_SIG)).accepted).toBe(true);
    expect(v.verify(wire(V1, V1_SIG)).accepted).toBe(false);
  });
});

describe('§8 signed AuthzResponse — each discarded, never an allow', () => {
  it('vector 1 signed with the subkey of another tenant', () => {
    const { v } = verifier();
    expect(v.verify(wire(V1, sign(V1, deriveSubkey(OTHER_TENANT, 2)))).accepted).toBe(false);
  });

  it('vector 1 signed under key_version 3', () => {
    const { v } = verifier();
    expect(v.verify(wire(V1, sign(V1, deriveSubkey(TENANT, 3)))).accepted).toBe(false);
  });

  it('a tampered decision: vector 1 with allowed flipped to false, signature kept', () => {
    const { v } = verifier();
    expect(v.verify(wire(V1.replace('"allowed":true', '"allowed":false'), V1_SIG)).accepted).toBe(false);
  });

  it('a tampered decision: vector 2 with allowed flipped to true, signature kept', () => {
    const { v } = verifier();
    expect(v.verify(wire(V2.replace('"allowed":false', '"allowed":true'), V2_SIG)).accepted).toBe(false);
  });

  it('a valid signed response for another nonce', () => {
    const canonical = V1.replace(NONCE, '66666666-6666-6666-6666-666666666666');
    const { v } = verifier();
    expect(v.verify(wire(canonical, sign(canonical, deriveSubkey(TENANT, 2)))).accepted).toBe(false);
    // The genuine answer is still accepted afterwards: a failure never completes the request.
    expect(v.verify(wire(V1, V1_SIG)).accepted).toBe(true);
  });

  it('a valid signed response for another correlation_id', () => {
    const canonical = V1.replace(CORRELATION, '77777777-7777-7777-7777-777777777777');
    const { v } = verifier();
    expect(v.verify(wire(canonical, sign(canonical, deriveSubkey(TENANT, 2)))).accepted).toBe(false);
  });

  it('a valid signed response for another tenant', () => {
    const canonical = V1.replace(`"tenant_id":"${TENANT}"`, `"tenant_id":"${OTHER_TENANT}"`);
    const { v } = verifier();
    // Signed with OUR subkey (a same-subkey holder), naming another tenant.
    expect(v.verify(wire(canonical, sign(canonical, deriveSubkey(TENANT, 2)))).accepted).toBe(false);
    // And signed with the other tenant's own subkey.
    expect(v.verify(wire(canonical, sign(canonical, deriveSubkey(OTHER_TENANT, 2)))).accepted).toBe(false);
  });

  it('a body with no allowed (a signed AuthzRequest delivered on the response queue)', () => {
    const req = (vectors as { authz_request: { canonical_signed_json: string; hmac_signature_hex: string } })
      .authz_request;
    // The genuine, server-vector-signed request under the SAME subkey.
    expect(sign(req.canonical_signed_json, deriveSubkey(TENANT, 2))).toBe(req.hmac_signature_hex);
    const { v } = verifier();
    expect(v.verify(wire(req.canonical_signed_json, req.hmac_signature_hex)).accepted).toBe(false);
  });

  it('a body whose signature member is not the trailing one', () => {
    const moved = `{"hmac_signature":"${V1_SIG}",${V1.slice(1)}`;
    const { v } = verifier();
    expect(v.verify(Buffer.from(moved, 'utf8')).accepted).toBe(false);
  });

  it('a re-serialized (re-escaped) vector 4 does not verify — the received bytes are what is signed', () => {
    const reencoded = V4.replace('é€', '\\u00e9\\u20ac');
    const { v } = verifier();
    expect(v.verify(wire(reencoded, V4_SIG)).accepted).toBe(false);
  });

  it('malformed JSON', () => {
    const { v } = verifier();
    expect(v.verify(Buffer.from('not json', 'utf8')).accepted).toBe(false);
  });

  it('logs a security event without either signature value', () => {
    const { v, logger } = verifier();
    v.verify(wire(V1.replace('"allowed":true', '"allowed":false'), V1_SIG));
    expect(logger.warn).toHaveBeenCalled();
    expect(JSON.stringify(logger.warn.mock.calls)).not.toContain(V1_SIG);
  });
});

describe('§8 signed AuthzResponse — against a server older than 1.68', () => {
  const UNSIGNED = Buffer.from(`{"correlation_id":"${CORRELATION}","allowed":true,"reason":"ok"}`, 'utf8');

  it('an unsigned 1.67-shaped response is refused by default', () => {
    const { v } = verifier();
    expect(v.verify(UNSIGNED).accepted).toBe(false);
  });

  it('with the opt-out set, a response carrying no hmac_signature at all is accepted on its correlation_id, with a warning', () => {
    const { v, logger } = verifier({ acceptUnsignedResponses: true });
    const verdict = v.verify(UNSIGNED);
    expect(verdict.accepted).toBe(true);
    expect(verdict.accepted && verdict.unsigned).toBe(true);
    expect(logger.warn).toHaveBeenCalled();
  });

  it('with the opt-out set, an unsigned response for no outstanding request is still dropped', () => {
    const { v } = verifier({ acceptUnsignedResponses: true });
    const stray = Buffer.from('{"correlation_id":"88888888-8888-8888-8888-888888888888","allowed":true}', 'utf8');
    expect(v.verify(stray).accepted).toBe(false);
  });

  it('with the opt-out set, a response that carries a signature is still verified, and a bad one fails', () => {
    const { v } = verifier({ acceptUnsignedResponses: true });
    expect(v.verify(wire(V1.replace('"allowed":true', '"allowed":false'), V1_SIG)).accepted).toBe(false);
    expect(v.verify(wire(V1, V1_SIG)).accepted).toBe(true);
  });
});

describe('§8 signed AuthzResponse — settling a delivery read from a queue', () => {
  function message(content: Buffer): ConsumeMessage {
    return {
      content,
      fields: { exchange: '', routingKey: 'amq.gen-abc' },
      properties: {},
    } as unknown as ConsumeMessage;
  }

  it('acks an accepted response and nacks a discarded one without requeue', () => {
    const { v } = verifier();
    const channel = { ack: vi.fn(), nack: vi.fn() };
    const bad = message(wire(V1.replace('"allowed":true', '"allowed":false'), V1_SIG));
    expect(v.settle(channel, bad).accepted).toBe(false);
    expect(channel.nack).toHaveBeenCalledWith(bad, false, false);
    const good = message(wire(V1, V1_SIG));
    expect(v.settle(channel, good).accepted).toBe(true);
    expect(channel.ack).toHaveBeenCalledWith(good);
  });

  it('the security event of a discarded delivery names its exchange and routing key (§8 rule 4)', () => {
    const { v, logger } = verifier();
    const channel = { ack: vi.fn(), nack: vi.fn() };
    v.settle(channel, message(wire(V1.replace('"allowed":true', '"allowed":false'), V1_SIG)));
    expect(logger.warn).toHaveBeenCalledTimes(1);
    const [event, , context] = logger.warn.mock.calls[0] as [string, string, Record<string, unknown>];
    expect(event).toBe('axiam_sdk.security');
    expect(context).toMatchObject({ exchange: '', routingKey: 'amq.gen-abc', tenantId: TENANT });
    expect(typeof context.timestamp).toBe('string');
    expect(JSON.stringify(logger.warn.mock.calls)).not.toContain(V1_SIG);
  });

  it('the warning for an unsigned response admitted by the opt-out names its exchange and routing key', () => {
    const { v, logger } = verifier({ acceptUnsignedResponses: true });
    const channel = { ack: vi.fn(), nack: vi.fn() };
    const unsigned = Buffer.from(`{"correlation_id":"${CORRELATION}","allowed":true}`, 'utf8');
    expect(v.settle(channel, message(unsigned)).accepted).toBe(true);
    const [, , context] = logger.warn.mock.calls[0] as [string, string, Record<string, unknown>];
    expect(context).toMatchObject({ exchange: '', routingKey: 'amq.gen-abc', tenantId: TENANT });
  });
});
