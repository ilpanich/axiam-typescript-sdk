// CONTRACT.md 1.69 §8 protocol step 2 against the server-produced reference vectors
// (testdata/v2_reference_vectors.json, `wire_json`): the event consumer cuts the delivered body to
// exactly `canonical_signed_json`, verifies it, checks the layout (2c) and dispatches; every refusal
// in the "Required tests" list is nacked without requeue and the handler never runs.

import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { signPayload } from '../../src/amqp/hmac.js';
import { InMemoryNonceStore, verifyAndDispatch, type ConsumeChannel } from '../../src/amqp/consumer.js';

interface Vector {
  canonical_signed_json: string;
  hmac_signature_hex: string;
  wire_json: string;
}
const vectors = JSON.parse(readFileSync(new URL('../../testdata/v2_reference_vectors.json', import.meta.url), 'utf8')) as {
  master_signing_key_hex: string;
  hkdf: { derived_subkey_hex: string };
  authz_request: Vector;
  audit_event: Vector;
};
const SUBKEY = Buffer.from(vectors.hkdf.derived_subkey_hex, 'hex');

class Channel implements ConsumeChannel {
  acked = 0;
  nacked: Array<{ allUpTo: boolean; requeue: boolean }> = [];
  async consume(): Promise<unknown> {
    throw new Error('unused');
  }
  ack(): void {
    this.acked += 1;
  }
  nack(_msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void {
    this.nacked.push({ allUpTo, requeue });
  }
}

function message(content: Buffer | string): ConsumeMessage {
  return {
    content: Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8'),
    fields: { deliveryTag: 1, redelivered: false, exchange: 'axiam.events', routingKey: 'k', consumerTag: 't' },
    properties: {},
  } as unknown as ConsumeMessage;
}

async function run(content: Buffer | string, key: Buffer = SUBKEY, eventType: 'AuthzRequest' | 'AuditEventMessage' = 'AuditEventMessage') {
  const channel = new Channel();
  const handler = vi.fn(async (_event: Record<string, unknown>) => {});
  // The vectors are dated 2026-07-10; a wide skew keeps this test about the wire, not the clock.
  await verifyAndDispatch(channel, message(content), key, handler, {
    tenantId: '99999999-9999-9999-9999-999999999999',
    eventType,
    skewMs: Number.MAX_SAFE_INTEGER,
    nonceStore: new InMemoryNonceStore(),
  });
  return { channel, handler };
}

function signed(canonical: string): string {
  return `${canonical.slice(0, -1)},"hmac_signature":"${signPayload(SUBKEY, Buffer.from(canonical, 'utf8'))}"}`;
}

const NACK = [{ allUpTo: false, requeue: false }];

describe('§8 step 2 — reference vectors', () => {
  it.each(['authz_request', 'audit_event'] as const)('%s: wire_json cuts to canonical_signed_json, verifies, passes the layout and dispatches', async (name) => {
    const v = vectors[name];
    expect(v.wire_json).toBe(`${v.canonical_signed_json.slice(0, -1)},"hmac_signature":"${v.hmac_signature_hex}"}`);
    const { channel, handler } = await run(v.wire_json, SUBKEY, name === 'authz_request' ? 'AuthzRequest' : 'AuditEventMessage');
    expect(channel.nacked).toEqual([]);
    expect(channel.acked).toBe(1);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0][0]).toEqual(JSON.parse(v.canonical_signed_json));
  });

  it('the vector `message` member (key-sorted, signature in the middle) is not wire bytes and is refused', async () => {
    const reading = JSON.stringify((vectors.audit_event as unknown as { message: unknown }).message);
    const { channel, handler } = await run(reading);
    expect(handler).not.toHaveBeenCalled();
    expect(channel.nacked).toEqual(NACK);
  });
});

describe('§8 step 2 — refusals (handler never runs, nack without requeue)', () => {
  const audit = vectors.audit_event.canonical_signed_json;

  it.each([
    ['members reordered, signature over the reordered canonical bytes', () => signed(audit.replace('"actor_id":"66666666-6666-6666-6666-666666666666","actor_type":"User"', '"actor_type":"User","actor_id":"66666666-6666-6666-6666-666666666666"'))],
    ['an extra member, signed', () => signed(audit.replace('"outcome"', '"extra":1,"outcome"'))],
    ['a required member missing, signed', () => signed(audit.replace('"outcome":"Success",', ''))],
    ['a member name differing only in case, signed', () => signed(audit.replace('"actor_type"', '"Actor_Type"'))],
    ['a validly signed AuthzResponse', () => authzResponse()],
    ['a validly signed cache-invalidation-shaped message', () => signed('{"event":"cache_invalidation","tenant_id":"11111111-1111-1111-1111-111111111111","key_version":2,"nonce":"n","issued_at":"2026-07-10T12:00:00Z"}')],
    ['hmac_signature: null', () => `${audit.slice(0, -1)},"hmac_signature":null}`],
    ['a non-string signature', () => `${audit.slice(0, -1)},"hmac_signature":1}`],
    ['no signature member', () => audit],
    ['a signature that is not 64 hex digits', () => `${audit.slice(0, -1)},"hmac_signature":"abcd"}`],
    ['trailing whitespace after the closing brace', () => `${vectors.audit_event.wire_json}\n`],
    ['trailing content after the closing brace', () => `${vectors.audit_event.wire_json}{}`],
    ['a signature that is not the last member', () => `{"hmac_signature":"${vectors.audit_event.hmac_signature_hex}",${audit.slice(1)}`],
    ['a top-level duplicate member', () => signed(audit.replace('"outcome"', '"action":"x","outcome"'))],
    ['a nested duplicate member', () => signed(audit.replace('{"method":"password"}', '{"method":"password","method":"x"}'))],
    ['a wrong signature', () => `${audit.slice(0, -1)},"hmac_signature":"${'0'.repeat(64)}"}`],
    ['invalid UTF-8', () => Buffer.concat([Buffer.from(vectors.audit_event.wire_json.replace('password', 'pass'), 'utf8'), Buffer.from([0xff])])],
  ])('%s', async (_label, build) => {
    const { channel, handler } = await run(build() as string | Buffer);
    expect(handler).not.toHaveBeenCalled();
    expect(channel.acked).toBe(0);
    expect(channel.nacked).toEqual(NACK);
  });

  function authzResponse(): string {
    return signed(
      '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}',
    );
  }

  it('the AuthzResponse used above verifies under the same key (so only the layout check refuses it)', () => {
    const body = authzResponse();
    const cut = body.replace(/,"hmac_signature":"[0-9a-f]{64}"\}$/, '}');
    expect(body).toBe(`${cut.slice(0, -1)},"hmac_signature":"${signPayload(SUBKEY, Buffer.from(cut, 'utf8'))}"}`);
  });
});

describe('§8 step 2 — genuine message with markup, non-ASCII and a \\u escape', () => {
  it('verifies and the handler receives exactly those values', async () => {
    const canonical = vectors.audit_event.canonical_signed_json
      .replace('"user.login"', '"a<b>&c é\\u0041"')
      .replace('{"method":"password"}', '{"m":"<x>&é\\u0042"}');
    const { channel, handler } = await run(signed(canonical));
    expect(channel.nacked).toEqual([]);
    const event = handler.mock.calls[0][0] as { action: string; metadata: { m: string } };
    expect(event.action).toBe('a<b>&c éA');
    expect(event.metadata.m).toBe('<x>&éB');
  });
});
