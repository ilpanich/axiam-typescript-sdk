// CONTRACT.md 1.69 §8 (D-10): the requester refuses a body whose first byte is not `{` (a byte-order mark,
// whitespace) as malformed, never strips it, and nothing escapes its delivery loop.

import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { Sensitive } from '../../src/core/index.js';
import { createAuthzRequester, type AuthzRequesterChannel } from '../../src/amqp/authzRequester.js';

const vectors = JSON.parse(readFileSync(new URL('../../testdata/v2_reference_vectors.json', import.meta.url), 'utf8')) as {
  hkdf: { derived_subkey_hex: string };
};
const SUBKEY = Buffer.from(vectors.hkdf.derived_subkey_hex, 'hex');
const TENANT = '11111111-1111-1111-1111-111111111111';
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);

class Channel implements AuthzRequesterChannel {
  published: Array<{ content: Buffer }> = [];
  nacks: Array<[boolean, boolean]> = [];
  acks = 0;
  nackThrows = false;
  onMessage!: (msg: ConsumeMessage | null) => void;
  async assertQueue() {
    return { queue: 'amq.gen-q' };
  }
  async consume(_q: string, onMessage: (msg: ConsumeMessage | null) => void) {
    this.onMessage = onMessage;
    return { consumerTag: 't' };
  }
  sendToQueue(_q: string, content: Buffer): boolean {
    this.published.push({ content });
    return true;
  }
  ack(): void {
    this.acks += 1;
  }
  nack(_m: ConsumeMessage, a: boolean, r: boolean): void {
    if (this.nackThrows) throw new Error('channel closed');
    this.nacks.push([a, r]);
  }
  async cancel(): Promise<void> {}
}
const deliver = (ch: Channel, content: Buffer): void =>
  ch.onMessage({ content, fields: { exchange: '', routingKey: 'amq.gen-q' }, properties: {} } as unknown as ConsumeMessage);
const canonicalFor = (cid: string, nonce: string): string => `{"correlation_id":"${cid}","allowed":true,"tenant_id":"${TENANT}","nonce":"${nonce}"}`;
const wireOf = (canonical: string): Buffer => {
  const sig = createHmac('sha256', SUBKEY).update(Buffer.from(canonical, 'utf8')).digest('hex');
  return Buffer.from(`${canonical.slice(0, -1)},"hmac_signature":"${sig}"}`, 'utf8');
};

async function start(logger: { warn: (...a: unknown[]) => void }) {
  const ch = new Channel();
  const r = await createAuthzRequester(ch, { tenantId: TENANT, subkey: new Sensitive(SUBKEY), logger: logger as never });
  const pending = r.check({ subjectId: '33333333-3333-3333-3333-333333333333', action: 'a', resourceId: '44444444-4444-4444-4444-444444444444' });
  const pub = JSON.parse(ch.published[0].content.toString('utf8')) as { correlation_id: string; nonce: string };
  return { ch, r, pending, pub };
}

describe('requester: first byte must be `{` (D-10)', () => {
  it.each([
    ['a byte-order mark', (b: Buffer) => Buffer.concat([BOM, b])],
    ['leading whitespace (signed over the whitespace too)', null],
  ])('%s is malformed, nacked, one event, and the genuine answer still resolves the check', async (_label, prefix) => {
    const events: Array<Record<string, unknown>> = [];
    const { ch, pending, pub } = await start({ warn: (_e, _m, ctx) => void events.push(ctx as Record<string, unknown>) });
    const genuine = wireOf(canonicalFor(pub.correlation_id, pub.nonce));
    const bad = prefix === null ? wireOf(` ${canonicalFor(pub.correlation_id, pub.nonce)}`) : prefix(genuine);
    expect(() => deliver(ch, bad)).not.toThrow();
    expect(ch.nacks).toEqual([[false, false]]);
    expect(events.map((e) => e.reason)).toEqual(['malformed']);
    expect(ch.acks).toBe(0);
    deliver(ch, genuine);
    await expect(pending).resolves.toMatchObject({ allowed: true });
    expect(ch.acks).toBe(1);
  });

  it('a throwing logger and a throwing nack never escape the delivery loop', async () => {
    const { ch, pending } = await start({
      warn: () => {
        throw new Error('logger down');
      },
    });
    pending.catch(() => {});
    ch.nackThrows = true;
    expect(() => deliver(ch, Buffer.concat([BOM, Buffer.from('{}')]))).not.toThrow();
    expect(() => deliver(ch, Buffer.alloc(0))).not.toThrow();
  });
});
