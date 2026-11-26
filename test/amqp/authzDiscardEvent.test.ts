// CONTRACT.md §8 consumer obligation 4 (contract 1.69, #883; fix plan
// Appendix A.2): every discard path of the requester emits ONE warning on the
// security channel carrying exactly timestamp, exchange, routing key, the
// requester's OWN tenant and a reason code — and never a signature value, a
// nonce, or anything read from the discarded body.

import { createHmac, hkdfSync } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { Sensitive } from '../../src/core/index.js';
import {
  createAuthzRequester,
  type AuthzRequesterChannel,
} from '../../src/amqp/authzRequester.js';
import { AuthzResponseVerifier } from '../../src/amqp/authzResponse.js';

const MASTER = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const TENANT = '11111111-1111-1111-1111-111111111111';
const OTHER_TENANT = '99999999-9999-9999-9999-999999999999';
const SUBJECT = '33333333-3333-3333-3333-333333333333';
const RESOURCE = '44444444-4444-4444-4444-444444444444';
const REPLY_QUEUE = 'amq.gen-Xk3p';

function subkey(tenantId: string): Buffer {
  const info = Buffer.concat([
    Buffer.from('axiam-amqp-v1', 'utf8'),
    Buffer.from([2]),
    Buffer.from(tenantId.replace(/-/g, ''), 'hex'),
  ]);
  return Buffer.from(hkdfSync('sha256', MASTER, Buffer.from('axiam-amqp-hkdf-salt-v1', 'utf8'), info, 32));
}

const hmacHex = (canonical: string, key: Buffer): string =>
  createHmac('sha256', key).update(Buffer.from(canonical, 'utf8')).digest('hex');

function signed(canonical: string, key: Buffer): { body: Buffer; sig: string } {
  const sig = hmacHex(canonical, key);
  return { body: Buffer.from(`${canonical.slice(0, -1)},"hmac_signature":"${sig}"}`, 'utf8'), sig };
}

class FakeChannel implements AuthzRequesterChannel {
  published: Array<{ content: Buffer; correlationId: string }> = [];
  onMessage: ((msg: ConsumeMessage | null) => void) | undefined;
  async assertQueue() {
    return { queue: REPLY_QUEUE };
  }
  async consume(_q: string, onMessage: (msg: ConsumeMessage | null) => void) {
    this.onMessage = onMessage;
    return { consumerTag: 'ctag' };
  }
  sendToQueue(_q: string, content: Buffer, options: { correlationId: string }): boolean {
    this.published.push({ content, correlationId: options.correlationId });
    return true;
  }
  ack(): void {}
  nack(): void {}
  deliver(content: Buffer): void {
    this.onMessage!({ content, fields: { exchange: '', routingKey: REPLY_QUEUE }, properties: {} } as unknown as ConsumeMessage);
  }
}

/** A requester with one check in flight; returns what a forger would know and the logger. */
async function inFlight() {
  const ch = new FakeChannel();
  const logger = { warn: vi.fn() };
  const r = await createAuthzRequester(ch, { tenantId: TENANT, subkey: new Sensitive(subkey(TENANT)), logger });
  const pending = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
  pending.catch(() => {});
  const pub = ch.published[0];
  const { nonce } = JSON.parse(pub.content.toString('utf8')) as { nonce: string };
  const own = (extra: string, over: { tenant?: string; nonce?: string } = {}) =>
    `{"correlation_id":"${pub.correlationId}","allowed":true${extra},"tenant_id":"${over.tenant ?? TENANT}","nonce":"${over.nonce ?? nonce}"}`;
  return { ch, r, logger, pub, nonce, own };
}

type Event = Record<string, unknown>;

function expectEvent(logger: { warn: ReturnType<typeof vi.fn> }, reason: string, secrets: string[]): void {
  expect(logger.warn).toHaveBeenCalledTimes(1);
  const [channel, , context] = logger.warn.mock.calls[0] as [string, string, Event];
  expect(channel).toBe('axiam_sdk.security');
  expect(context.reason).toBe(reason);
  expect(context.exchange).toBe('');
  expect(context.routingKey).toBe(REPLY_QUEUE);
  expect(context.tenantId).toBe(TENANT);
  expect(new Date(context.timestamp as string).toISOString()).toBe(context.timestamp);
  expect(Object.keys(context).sort()).toEqual(['exchange', 'reason', 'routingKey', 'tenantId', 'timestamp']);
  const serialized = JSON.stringify(logger.warn.mock.calls);
  for (const secret of secrets) {
    expect(serialized).not.toContain(secret);
  }
}

describe('§8 discard event (A.2) — every discard path of the requester', () => {
  it('signature: the HMAC does not verify under the tenant subkey', async () => {
    const { ch, r, logger, nonce, own } = await inFlight();
    const canonical = own('');
    const received = signed(canonical, subkey(OTHER_TENANT));
    ch.deliver(received.body);
    expectEvent(logger, 'signature', [received.sig, hmacHex(canonical, subkey(TENANT)), nonce]);
    await r.close();
  });

  it('tenant: a validly signed answer that names another tenant; the event carries the OWN tenant', async () => {
    const { ch, r, logger, nonce, own } = await inFlight();
    const received = signed(own('', { tenant: OTHER_TENANT }), subkey(TENANT));
    ch.deliver(received.body);
    expectEvent(logger, 'tenant', [received.sig, nonce, OTHER_TENANT]);
    await r.close();
  });

  it('unknown_request: right tenant and key, but the nonce matches no outstanding request', async () => {
    const { ch, r, logger, nonce, own } = await inFlight();
    const wrongNonce = '66666666-6666-6666-6666-666666666666';
    const received = signed(own('', { nonce: wrongNonce }), subkey(TENANT));
    ch.deliver(received.body);
    expectEvent(logger, 'unknown_request', [received.sig, nonce, wrongNonce]);
    await r.close();
  });

  it('unsigned: no hmac_signature member at all', async () => {
    const { ch, r, logger, nonce, own } = await inFlight();
    ch.deliver(Buffer.from(own(''), 'utf8'));
    expectEvent(logger, 'unsigned', [nonce]);
    await r.close();
  });

  it('malformed: not JSON', async () => {
    const { ch, r, logger } = await inFlight();
    ch.deliver(Buffer.from('not json', 'utf8'));
    expectEvent(logger, 'malformed', []);
    await r.close();
  });

  it('malformed: a validly signed body whose `allowed` is not a boolean', async () => {
    const { ch, r, logger, nonce, own } = await inFlight();
    const received = signed(own('').replace('"allowed":true', '"allowed":"yes"'), subkey(TENANT));
    ch.deliver(received.body);
    expectEvent(logger, 'malformed', [received.sig, nonce]);
    await r.close();
  });

  it('malformed: the signature member is present but does not end the body', async () => {
    const { ch, r, logger, nonce, own } = await inFlight();
    const sig = 'a'.repeat(64);
    ch.deliver(Buffer.from(`${own('').slice(0, -1)},"hmac_signature":"${sig}","extra":1}`, 'utf8'));
    expectEvent(logger, 'malformed', [sig, nonce]);
    await r.close();
  });

  it('malformed: the signature member is not 64 hex digits', async () => {
    const { ch, r, logger, nonce, own } = await inFlight();
    ch.deliver(Buffer.from(`${own('').slice(0, -1)},"hmac_signature":"abc123"}`, 'utf8'));
    expectEvent(logger, 'malformed', ['abc123', nonce]);
    await r.close();
  });

  it('a discarded answer does not complete the check', async () => {
    const { ch, r, logger, own } = await inFlight();
    ch.deliver(Buffer.from(own(''), 'utf8'));
    expect(r.pending).toBe(1);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    await r.close();
  });
});

describe('§8 discard event (A.2) — a verifier used without a delivery', () => {
  it('reports the default exchange and the configured reply queue', () => {
    const logger = { warn: vi.fn() };
    const v = new AuthzResponseVerifier({
      subkey: new Sensitive(subkey(TENANT)),
      tenantId: TENANT,
      replyQueue: REPLY_QUEUE,
      logger,
    });
    expect(v.verify(Buffer.from('not json', 'utf8')).accepted).toBe(false);
    const [, , context] = logger.warn.mock.calls[0] as [string, string, Event];
    expect(context).toMatchObject({ exchange: '', routingKey: REPLY_QUEUE, tenantId: TENANT, reason: 'malformed' });
  });
});
