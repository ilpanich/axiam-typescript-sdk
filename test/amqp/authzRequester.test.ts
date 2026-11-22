// AuthzRequester (CONTRACT.md §8 "Signed authorization responses", contract
// 1.68; N2, D-9) end to end over a fake channel: the published request (queue,
// reply_to, correlation_id, signed body), forged answers ignored while the
// genuine one completes, fresh ids per request, close and timeout.
// Mirrors the Go SDK's amqp/authz_requester_test.go.

import { createHmac, hkdfSync } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { NetworkError, Sensitive } from '../../src/core/index.js';
import {
  AUTHZ_REQUEST_QUEUE,
  AuthzRequesterClosedError,
  buildAuthzRequest,
  createAuthzRequester,
  type AuthzRequesterChannel,
} from '../../src/amqp/authzRequester.js';
import vectors from '../../testdata/v2_reference_vectors.json' with { type: 'json' };

const MASTER = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const TENANT = '11111111-1111-1111-1111-111111111111';
const OTHER_TENANT = '99999999-9999-9999-9999-999999999999';
const SUBJECT = '33333333-3333-3333-3333-333333333333';
const RESOURCE = '44444444-4444-4444-4444-444444444444';

function subkey(tenantId: string, keyVersion = 2): Buffer {
  const info = Buffer.concat([
    Buffer.from('axiam-amqp-v1', 'utf8'),
    Buffer.from([keyVersion]),
    Buffer.from(tenantId.replace(/-/g, ''), 'hex'),
  ]);
  return Buffer.from(hkdfSync('sha256', MASTER, Buffer.from('axiam-amqp-hkdf-salt-v1', 'utf8'), info, 32));
}

function signed(canonical: string, key: Buffer): Buffer {
  const sig = createHmac('sha256', key).update(Buffer.from(canonical, 'utf8')).digest('hex');
  return Buffer.from(`${canonical.slice(0, -1)},"hmac_signature":"${sig}"}`, 'utf8');
}

/** Split a wire body into its canonical bytes and trailing signature. */
function cut(body: Buffer): { canonical: Buffer; sig: string } {
  const m = /,"hmac_signature":"([0-9a-f]{64})"\}$/.exec(body.toString('latin1'));
  expect(m).not.toBeNull();
  return { canonical: Buffer.concat([body.subarray(0, m!.index), Buffer.from('}')]), sig: m![1] };
}

interface Published {
  queue: string;
  content: Buffer;
  options: { correlationId: string; replyTo: string; contentType: string };
}

class FakeChannel implements AuthzRequesterChannel {
  queueName = 'amq.gen-Xk3p';
  declared: Array<{ queue: string; options: unknown }> = [];
  consumed: Array<{ queue: string; options: unknown }> = [];
  published: Published[] = [];
  acked: ConsumeMessage[] = [];
  nacked: Array<{ msg: ConsumeMessage; allUpTo: boolean; requeue: boolean }> = [];
  cancelled: string[] = [];
  onMessage: ((msg: ConsumeMessage | null) => void) | undefined;
  failPublish = false;

  async assertQueue(queue: string, options: { exclusive: boolean; autoDelete: boolean; durable: boolean }) {
    this.declared.push({ queue, options });
    return { queue: this.queueName };
  }
  async consume(queue: string, onMessage: (msg: ConsumeMessage | null) => void, options: unknown) {
    this.consumed.push({ queue, options });
    this.onMessage = onMessage;
    return { consumerTag: 'ctag-1' };
  }
  sendToQueue(queue: string, content: Buffer, options: Published['options']): boolean {
    if (this.failPublish) throw new Error('channel closed');
    this.published.push({ queue, content, options });
    return true;
  }
  ack(msg: ConsumeMessage): void {
    this.acked.push(msg);
  }
  nack(msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void {
    this.nacked.push({ msg, allUpTo, requeue });
  }
  async cancel(tag: string) {
    this.cancelled.push(tag);
  }
  deliver(content: Buffer): ConsumeMessage {
    const msg = { content, fields: { exchange: '', routingKey: this.queueName }, properties: {} } as unknown as ConsumeMessage;
    this.onMessage!(msg);
    return msg;
  }
}

function options(extra: Record<string, unknown> = {}) {
  return { tenantId: TENANT, subkey: new Sensitive(subkey(TENANT)), ...extra };
}

function answerFor(pub: Published, allowed = true): string {
  const req = JSON.parse(cut(pub.content).canonical.toString('utf8')) as { nonce: string };
  return `{"correlation_id":"${pub.options.correlationId}","allowed":${allowed},"reason_code":"${allowed ? 'allowed' : 'no_grant'}","tenant_id":"${TENANT}","nonce":"${req.nonce}"}`;
}

/** Whether `promise` has settled after a turn of the event loop. */
async function settled(promise: Promise<unknown>): Promise<boolean> {
  let done = false;
  promise.then(
    () => (done = true),
    () => (done = true),
  );
  await new Promise((r) => setTimeout(r, 10));
  return done;
}

afterEach(() => vi.useRealTimers());

describe('buildAuthzRequest', () => {
  it('reproduces the contract AuthzRequest vector byte for byte', () => {
    const v = (vectors as { authz_request: { canonical_signed_json: string; hmac_signature_hex: string } })
      .authz_request;
    const body = buildAuthzRequest(subkey(TENANT), {
      correlationId: '22222222-2222-2222-2222-222222222222',
      tenantId: TENANT,
      subjectId: SUBJECT,
      action: 'documents:read',
      resourceId: RESOURCE,
      scope: 'confidential',
      nonce: '55555555-5555-5555-5555-555555555555',
      issuedAt: new Date('2026-07-10T12:00:00.000Z'),
    });
    const { canonical, sig } = cut(body);
    expect(canonical.toString('utf8')).toBe(v.canonical_signed_json);
    expect(sig).toBe(v.hmac_signature_hex);
  });

  it('writes characters raw as serde_json does (no HTML escaping)', () => {
    const body = buildAuthzRequest(subkey(TENANT), {
      correlationId: '22222222-2222-2222-2222-222222222222',
      tenantId: TENANT,
      subjectId: SUBJECT,
      action: 'docs:a&b</"c">/é€ ',
      resourceId: RESOURCE,
      nonce: '55555555-5555-5555-5555-555555555555',
      issuedAt: new Date(),
    }).toString('utf8');
    expect(body).toContain('"action":"docs:a&b</\\"c\\">/é€ "');
    expect(body).not.toContain('"scope"');
  });

  it.each([
    ['a non-UUID subject', { subjectId: 'not-a-uuid' }],
    ['a non-UUID resource', { resourceId: 'r' }],
    ['a lone surrogate in the action', { action: 'a\uD800b' }],
  ])('refuses %s', (_n, override) => {
    expect(() =>
      buildAuthzRequest(subkey(TENANT), {
        correlationId: '22222222-2222-2222-2222-222222222222',
        tenantId: TENANT,
        subjectId: SUBJECT,
        action: 'a',
        resourceId: RESOURCE,
        nonce: '55555555-5555-5555-5555-555555555555',
        issuedAt: new Date(),
        ...override,
      }),
    ).toThrow(TypeError);
  });
});

describe('createAuthzRequester', () => {
  it('declares a private, exclusive, auto-delete, broker-named reply queue and consumes it exclusively with manual ack', async () => {
    const ch = new FakeChannel();
    const r = await createAuthzRequester(ch, options());
    expect(ch.declared).toEqual([{ queue: '', options: { exclusive: true, autoDelete: true, durable: false } }]);
    expect(ch.consumed).toEqual([{ queue: 'amq.gen-Xk3p', options: { noAck: false, exclusive: true } }]);
    expect(r.replyTo).toBe('amq.gen-Xk3p');
    await r.close();
  });

  it.each(['', 'axiam.authz.response', 'axiam.mail.outbound'])('refuses the reply queue %j', async (name) => {
    const ch = new FakeChannel();
    ch.queueName = name;
    await expect(createAuthzRequester(ch, options())).rejects.toThrow(/not a private queue/);
    expect(ch.consumed).toHaveLength(0);
  });

  it.each([Number.NaN, Infinity, 0, -1, 2 ** 31])('refuses timeoutMs %s with a RangeError', async (timeoutMs) => {
    const ch = new FakeChannel();
    await expect(createAuthzRequester(ch, options({ timeoutMs }))).rejects.toThrow(RangeError);
    expect(ch.declared).toHaveLength(0);
  });

  it('accepts a timeoutMs of 2^31-1', async () => {
    const r = await createAuthzRequester(new FakeChannel(), options({ timeoutMs: 2 ** 31 - 1 }));
    await r.close();
  });

  it('refuses a non-UUID tenant and an empty subkey', async () => {
    await expect(createAuthzRequester(new FakeChannel(), options({ tenantId: 'acme' }))).rejects.toThrow(TypeError);
    await expect(
      createAuthzRequester(new FakeChannel(), options({ subkey: new Sensitive(Buffer.alloc(0)) })),
    ).rejects.toThrow(TypeError);
  });
});

describe('AuthzRequester.check end to end', () => {
  it('publishes the signed request, ignores a forged answer, completes on the genuine one', async () => {
    const ch = new FakeChannel();
    const r = await createAuthzRequester(ch, options());
    const pending = r.check({ subjectId: SUBJECT, action: 'documents:read', resourceId: RESOURCE, scope: 'confidential' });

    expect(ch.published).toHaveLength(1);
    const pub = ch.published[0];
    // Default exchange, routed to the request queue; the private reply_to.
    expect(pub.queue).toBe(AUTHZ_REQUEST_QUEUE);
    expect(pub.options.replyTo).toBe('amq.gen-Xk3p');
    expect(pub.options.contentType).toBe('application/json');
    // The body: same correlation_id as the property, own tenant, key_version 2,
    // and it verifies under the tenant subkey over its canonical bytes.
    const { canonical, sig } = cut(pub.content);
    const req = JSON.parse(canonical.toString('utf8')) as Record<string, unknown>;
    expect(Object.keys(req)).toEqual([
      'correlation_id',
      'tenant_id',
      'subject_id',
      'action',
      'resource_id',
      'scope',
      'key_version',
      'nonce',
      'issued_at',
    ]);
    expect(req.correlation_id).toBe(pub.options.correlationId);
    expect(req.tenant_id).toBe(TENANT);
    expect(req.subject_id).toBe(SUBJECT);
    expect(req.resource_id).toBe(RESOURCE);
    expect(req.key_version).toBe(2);
    expect(req.nonce).not.toBe(req.correlation_id);
    expect(createHmac('sha256', subkey(TENANT)).update(canonical).digest('hex')).toBe(sig);

    // Forgeries with the right ids: another tenant's key, a wrong nonce, an
    // unsigned body — each nacked without requeue, none completes the check.
    const genuine = answerFor(pub);
    const forged = [
      ch.deliver(signed(genuine, subkey(OTHER_TENANT))),
      ch.deliver(signed(genuine.replace(String(req.nonce), '66666666-6666-6666-6666-666666666666'), subkey(TENANT))),
      ch.deliver(Buffer.from(`{"correlation_id":"${pub.options.correlationId}","allowed":true}`, 'utf8')),
    ];
    expect(await settled(pending)).toBe(false);
    expect(ch.nacked.map((n) => [n.msg, n.allUpTo, n.requeue])).toEqual(forged.map((m) => [m, false, false]));
    expect(r.pending).toBe(1);

    const good = ch.deliver(signed(genuine, subkey(TENANT)));
    await expect(pending).resolves.toEqual({ allowed: true, reasonCode: 'allowed', unsigned: false });
    expect(ch.acked).toEqual([good]);
    expect(r.pending).toBe(0);

    // A replay of the genuine answer after completion is dropped.
    ch.deliver(signed(genuine, subkey(TENANT)));
    expect(ch.nacked).toHaveLength(4);
    await r.close();
  });

  it('delivers a deny as a decision, not an error', async () => {
    const ch = new FakeChannel();
    const r = await createAuthzRequester(ch, options());
    const pending = r.check({ subjectId: SUBJECT, action: 'documents:read', resourceId: RESOURCE });
    ch.deliver(signed(answerFor(ch.published[0], false), subkey(TENANT)));
    await expect(pending).resolves.toEqual({ allowed: false, reasonCode: 'no_grant', unsigned: false });
    await r.close();
  });

  it('uses fresh, distinct correlation_id and nonce per request', async () => {
    const ch = new FakeChannel();
    const r = await createAuthzRequester(ch, options());
    const a = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
    const b = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
    const [p1, p2] = ch.published;
    const n1 = JSON.parse(cut(p1.content).canonical.toString()).nonce;
    const n2 = JSON.parse(cut(p2.content).canonical.toString()).nonce;
    expect(p1.options.correlationId).not.toBe(p2.options.correlationId);
    expect(n1).not.toBe(n2);
    expect(new Set([p1.options.correlationId, p2.options.correlationId, n1, n2]).size).toBe(4);
    // Each answer completes only its own request.
    ch.deliver(signed(answerFor(p2, false), subkey(TENANT)));
    await expect(b).resolves.toMatchObject({ allowed: false });
    expect(await settled(a)).toBe(false);
    await r.close();
    await expect(a).rejects.toBeInstanceOf(AuthzRequesterClosedError);
  });

  it('close() releases every waiter, cancels the consumer, and refuses later checks', async () => {
    const ch = new FakeChannel();
    const r = await createAuthzRequester(ch, options());
    const pending = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
    await r.close();
    await expect(pending).rejects.toBeInstanceOf(AuthzRequesterClosedError);
    expect(ch.cancelled).toEqual(['ctag-1']);
    expect(r.pending).toBe(0);
    await expect(r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE })).rejects.toBeInstanceOf(
      AuthzRequesterClosedError,
    );
  });

  it('a broker-cancelled consumer (null delivery) closes the requester', async () => {
    const ch = new FakeChannel();
    const r = await createAuthzRequester(ch, options());
    const pending = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
    ch.onMessage!(null);
    await expect(pending).rejects.toBeInstanceOf(AuthzRequesterClosedError);
  });

  it('times out with a NetworkError and leaves no outstanding entry; a late answer is then dropped', async () => {
    vi.useFakeTimers();
    const ch = new FakeChannel();
    const r = await createAuthzRequester(ch, options({ timeoutMs: 50 }));
    const pending = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
    const assertion = expect(pending).rejects.toBeInstanceOf(NetworkError);
    await vi.advanceTimersByTimeAsync(60);
    await assertion;
    expect(r.pending).toBe(0);
    ch.deliver(signed(answerFor(ch.published[0]), subkey(TENANT)));
    expect(ch.acked).toHaveLength(0);
    expect(ch.nacked).toHaveLength(1);
    await r.close();
  });

  it('an aborted signal ends the wait and leaves no outstanding entry', async () => {
    const ch = new FakeChannel();
    const r = await createAuthzRequester(ch, options());
    const controller = new AbortController();
    const pending = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE, signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toBeInstanceOf(NetworkError);
    expect(r.pending).toBe(0);
    await r.close();
  });

  it('a publish failure rejects and leaves no outstanding entry', async () => {
    const ch = new FakeChannel();
    const r = await createAuthzRequester(ch, options());
    ch.failPublish = true;
    await expect(r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE })).rejects.toBeInstanceOf(
      NetworkError,
    );
    expect(r.pending).toBe(0);
    await r.close();
  });

  describe('unsigned responses (server older than 1.68)', () => {
    const unsigned = (pub: Published) =>
      Buffer.from(`{"correlation_id":"${pub.options.correlationId}","allowed":true,"reason":"ok"}`, 'utf8');

    it('are refused by default: the check keeps waiting', async () => {
      const ch = new FakeChannel();
      const r = await createAuthzRequester(ch, options());
      const pending = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
      ch.deliver(unsigned(ch.published[0]));
      expect(await settled(pending)).toBe(false);
      expect(ch.nacked).toHaveLength(1);
      await r.close();
      await expect(pending).rejects.toBeInstanceOf(AuthzRequesterClosedError);
    });

    it('are accepted with the opt-out, flagged unsigned and logged', async () => {
      const ch = new FakeChannel();
      const logger = { warn: vi.fn() };
      const r = await createAuthzRequester(ch, options({ acceptUnsignedResponses: true, logger }));
      const pending = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
      ch.deliver(unsigned(ch.published[0]));
      await expect(pending).resolves.toEqual({ allowed: true, reason: 'ok', unsigned: true });
      expect(logger.warn).toHaveBeenCalled();
      await r.close();
    });

    it('with the opt-out, a signed but forged answer is still refused', async () => {
      const ch = new FakeChannel();
      const r = await createAuthzRequester(ch, options({ acceptUnsignedResponses: true }));
      const pending = r.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
      ch.deliver(signed(answerFor(ch.published[0]), subkey(OTHER_TENANT)));
      expect(await settled(pending)).toBe(false);
      await r.close();
      await expect(pending).rejects.toBeInstanceOf(AuthzRequesterClosedError);
    });
  });
});
