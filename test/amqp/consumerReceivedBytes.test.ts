// Pins for axiam#882 (cross-SDK; TypeScript is a "pin" SDK): the event consumer
// must verify a genuine server-signed message whatever its string content, and
// must never hand the handler a parse that differs from what was verified.
//
// The bodies below are written as literal text, the way the server's serde_json
// emits them (the signature is computed over that text with the trailing
// `hmac_signature` member removed) — NOT built with JSON.stringify, which is
// the encoder under test.

import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { signPayload } from '../../src/amqp/hmac.js';
import { InMemoryNonceStore, verifyAndDispatch, type ConsumeChannel } from '../../src/amqp/consumer.js';

const KEY = Buffer.from('received-bytes-pin-key', 'utf8');

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

function message(content: Buffer): ConsumeMessage {
  return {
    content,
    fields: { deliveryTag: 1, redelivered: false, exchange: 'axiam.events', routingKey: 'k', consumerTag: 't' },
    properties: {},
  } as unknown as ConsumeMessage;
}

/** Fixed fields every v2 body needs, as literal JSON member text. */
function head(nonce: string): string {
  return `"key_version":2,"nonce":"${nonce}","issued_at":"${new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')}"`;
}

/** Sign the literal text `canonical` (a JSON object) and append the member last, as the server does. */
function wire(canonical: string, tail = ''): Buffer {
  const sig = signPayload(KEY, Buffer.from(canonical, 'utf8'));
  return Buffer.from(`${canonical.slice(0, -1)}${tail},"hmac_signature":"${sig}"}`, 'utf8');
}

async function run(content: Buffer) {
  const channel = new Channel();
  const handler = vi.fn(async (_event: Record<string, unknown>) => {});
  await verifyAndDispatch(channel, message(content), KEY, handler, { nonceStore: new InMemoryNonceStore() });
  return { channel, handler };
}

describe('axiam#882 pin — verification is over the received bytes', () => {
  it.each([
    ['<, > and &', 'docs:a&b</\\"c\\">'],
    ['non-ASCII (raw UTF-8)', 'é€日本'],
    ['a control character the server writes as \\u001f', 'a\\u001fb'],
    ['the short escapes', 'a\\n\\t\\"\\\\b'],
  ])('a genuine message whose action holds %s verifies and is delivered', async (_label, action) => {
    const canonical = `{"action":"${action}",${head('n-1')}}`;
    const { channel, handler } = await run(wire(canonical));
    expect(channel.nacked).toEqual([]);
    expect(channel.acked).toBe(1);
    expect(handler).toHaveBeenCalledTimes(1);
    const delivered = handler.mock.calls[0][0];
    expect(delivered).toEqual(JSON.parse(canonical));
    expect(delivered.hmac_signature).toBeUndefined();
  });

  it('every control character, written the way serde_json writes it (\\u00xx lower-case, short escapes), verifies', async () => {
    const short: Record<number, string> = { 8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r' };
    let escaped = '';
    for (let c = 0; c < 0x20; c += 1) {
      escaped += short[c] ?? `\\u${c.toString(16).padStart(4, '0')}`;
    }
    // DEL (0x7f) is written raw by serde_json and by JSON.stringify alike.
    const canonical = `{"action":"${escaped}\x7f",${head('n-2')}}`;
    const { channel, handler } = await run(wire(canonical));
    expect(channel.nacked).toEqual([]);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0][0].action).toBe(
      Array.from({ length: 0x20 }, (_, c) => String.fromCharCode(c)).join('') + '\x7f',
    );
  });

  it('a body with a duplicate key is nacked without requeue and the handler never runs', async () => {
    const canonical = `{"action":"read","action":"admin",${head('n-3')}}`;
    const { channel, handler } = await run(wire(canonical));
    expect(handler).not.toHaveBeenCalled();
    expect(channel.acked).toBe(0);
    expect(channel.nacked).toEqual([{ allUpTo: false, requeue: false }]);
  });

  it('a body with trailing content after the object is nacked without requeue and the handler never runs', async () => {
    const good = wire(`{"action":"read",${head('n-4')}}`);
    for (const trailer of [' {}', '\n{"action":"admin"}', 'x']) {
      const { channel, handler } = await run(Buffer.concat([good, Buffer.from(trailer, 'utf8')]));
      expect(handler).not.toHaveBeenCalled();
      expect(channel.nacked).toEqual([{ allUpTo: false, requeue: false }]);
    }
  });
});
