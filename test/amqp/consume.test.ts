// consume() (amqp/consumer.ts): the connect -> createChannel -> assertQueue
// (durable) -> channel.consume wiring, and that each delivery is routed
// through verifyAndDispatch (a valid signed body is acked; a null delivery
// is ignored). amqplib is mocked — no live RabbitMQ broker.

import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';

const connectMock = vi.fn();

vi.mock('amqplib', () => ({
  default: { connect: connectMock },
}));

// Imported after the mock is registered.
const { consume, InMemoryNonceStore } = await import('../../src/amqp/consumer.js');
const { signPayload } = await import('../../src/amqp/hmac.js');
const { Sensitive } = await import('../../src/core/index.js');

const SIGNING_KEY = Buffer.from('consume-test-key', 'utf8');

interface FakeChannel {
  assertQueue: ReturnType<typeof vi.fn>;
  consume: ReturnType<typeof vi.fn>;
  ack: ReturnType<typeof vi.fn>;
  nack: ReturnType<typeof vi.fn>;
  deliver: (msg: ConsumeMessage | null) => Promise<void>;
}

function makeFakeChannel(): FakeChannel {
  let onMessage: (msg: ConsumeMessage | null) => void | Promise<void> = () => {};
  const channel: FakeChannel = {
    assertQueue: vi.fn().mockResolvedValue({}),
    consume: vi.fn().mockImplementation(async (_queue: string, cb: typeof onMessage) => {
      onMessage = cb;
      return { consumerTag: 'ct-1' };
    }),
    ack: vi.fn(),
    nack: vi.fn(),
    deliver: async (msg) => {
      await onMessage(msg);
      // Let the fire-and-forget verifyAndDispatch microtasks settle.
      await new Promise((r) => setTimeout(r, 0));
    },
  };
  return channel;
}

function signedDelivery(): ConsumeMessage {
  const body: Record<string, unknown> = {
    correlation_id: '00000000-0000-0000-0000-000000000000',
    action: 'read',
    key_version: 2,
    nonce: randomUUID(),
    issued_at: new Date().toISOString(),
  };
  const canonical = Buffer.from(JSON.stringify(body), 'utf8');
  const signed = { ...body, hmac_signature: signPayload(SIGNING_KEY, canonical) };
  return {
    content: Buffer.from(JSON.stringify(signed), 'utf8'),
    fields: {
      deliveryTag: 1,
      redelivered: false,
      exchange: 'axiam.authz.request',
      routingKey: 'authz',
      consumerTag: 'ct-1',
    },
    properties: {} as ConsumeMessage['properties'],
  };
}

let channel: FakeChannel;
let connection: { createChannel: ReturnType<typeof vi.fn> };

beforeEach(() => {
  channel = makeFakeChannel();
  connection = { createChannel: vi.fn().mockResolvedValue(channel) };
  connectMock.mockResolvedValue(connection);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('consume() wiring', () => {
  it('connects, declares the queue durable, and registers a consumer', async () => {
    const handler = vi.fn().mockResolvedValue(undefined);
    await consume('amqp://broker.test', 'axiam.authz.request', new Sensitive(SIGNING_KEY), handler);

    expect(connectMock).toHaveBeenCalledWith('amqp://broker.test');
    expect(connection.createChannel).toHaveBeenCalledOnce();
    expect(channel.assertQueue).toHaveBeenCalledWith('axiam.authz.request', { durable: true });
    expect(channel.consume).toHaveBeenCalledOnce();
  });

  it('routes a valid signed delivery through verifyAndDispatch and acks it', async () => {
    const handled: Array<Record<string, unknown>> = [];
    const handler = vi.fn().mockImplementation(async (event: Record<string, unknown>) => {
      handled.push(event);
    });

    await consume('amqp://broker.test', 'q', new Sensitive(SIGNING_KEY), handler);
    await channel.deliver(signedDelivery());

    expect(handler).toHaveBeenCalledOnce();
    expect(handled[0].action).toBe('read');
    // hmac_signature was stripped before the handler saw the body.
    expect(handled[0]).not.toHaveProperty('hmac_signature');
    expect(channel.ack).toHaveBeenCalledOnce();
    expect(channel.nack).not.toHaveBeenCalled();
  });

  it('ignores a null delivery (consumer cancellation) without ack/nack', async () => {
    const handler = vi.fn();
    await consume('amqp://broker.test', 'q', new Sensitive(SIGNING_KEY), handler);
    await channel.deliver(null);

    expect(handler).not.toHaveBeenCalled();
    expect(channel.ack).not.toHaveBeenCalled();
    expect(channel.nack).not.toHaveBeenCalled();
  });

  it('shares one nonce store across deliveries so a replayed nonce is nacked', async () => {
    const handler = vi.fn().mockResolvedValue(undefined);
    await consume('amqp://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, {
      nonceStore: new InMemoryNonceStore(),
    });

    const delivery = signedDelivery();
    await channel.deliver(delivery);
    await channel.deliver(delivery); // same nonce -> replay

    expect(channel.ack).toHaveBeenCalledOnce();
    expect(channel.nack).toHaveBeenCalledOnce();
  });
});
