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
const OPTS = { tenantId: '99999999-9999-9999-9999-999999999999', eventType: 'AuthzRequest' } as const;

// Shape-only PEM fixtures for the §8b tests below. Nothing here is parsed by a
// TLS stack — amqplib is mocked — so these only need to satisfy the SDK's own
// PEM-marker validation, which is exactly what is under test.
const CA_PEM = '-----BEGIN CERTIFICATE-----\nZmFrZS1jYQ==\n-----END CERTIFICATE-----\n';
const CLIENT_CERT_PEM =
  '-----BEGIN CERTIFICATE-----\nZmFrZS1jbGllbnQ=\n-----END CERTIFICATE-----\n';
const CLIENT_KEY_PEM = '-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n';

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
    tenant_id: '11111111-1111-1111-1111-111111111111',
    subject_id: '33333333-3333-3333-3333-333333333333',
    action: 'read',
    resource_id: '44444444-4444-4444-4444-444444444444',
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
    await consume('amqps://broker.test', 'axiam.authz.request', new Sensitive(SIGNING_KEY), handler, OPTS);

    expect(connectMock).toHaveBeenCalledWith('amqps://broker.test', undefined);
    expect(connection.createChannel).toHaveBeenCalledOnce();
    expect(channel.assertQueue).toHaveBeenCalledWith('axiam.authz.request', { durable: true });
    expect(channel.consume).toHaveBeenCalledOnce();
  });

  it('routes a valid signed delivery through verifyAndDispatch and acks it', async () => {
    const handled: Array<Record<string, unknown>> = [];
    const handler = vi.fn().mockImplementation(async (event: Record<string, unknown>) => {
      handled.push(event);
    });

    await consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, OPTS);
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
    await consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, OPTS);
    await channel.deliver(null);

    expect(handler).not.toHaveBeenCalled();
    expect(channel.ack).not.toHaveBeenCalled();
    expect(channel.nack).not.toHaveBeenCalled();
  });

  it('a rejection inside verification is nacked once without requeue and logs exactly timestamp, exchange, routingKey, tenantId, reason', async () => {
    const handler = vi.fn().mockResolvedValue(undefined);
    const logger = { warn: vi.fn() };
    const nonceStore = {
      checkAndRecord: () => {
        throw new Error('store down');
      },
    };
    await consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, { ...OPTS, nonceStore, logger });
    await channel.deliver(signedDelivery());
    await new Promise((r) => setTimeout(r, 0));

    expect(handler).not.toHaveBeenCalled();
    expect(channel.ack).not.toHaveBeenCalled();
    expect(channel.nack).toHaveBeenCalledTimes(1);
    expect(channel.nack.mock.calls[0].slice(1)).toEqual([false, false]);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    const [, , context] = logger.warn.mock.calls[0] as [string, string, Record<string, unknown>];
    expect(Object.keys(context).sort()).toEqual(['exchange', 'reason', 'routingKey', 'tenantId', 'timestamp']);
    expect(context.tenantId).toBe(OPTS.tenantId);
  });

  it('a BOM-prefixed delivery is nacked as malformed, nothing escapes, and the next delivery is still processed (D-10)', async () => {
    const handler = vi.fn().mockResolvedValue(undefined);
    const logger = { warn: vi.fn() };
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    await consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, { ...OPTS, logger });
    const good = signedDelivery();
    const bom = signedDelivery();
    bom.content = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), good.content]);
    await channel.deliver(bom);
    await channel.deliver(good);
    await new Promise((r) => setTimeout(r, 10));
    process.off('unhandledRejection', unhandled);

    expect(unhandled).not.toHaveBeenCalled();
    expect(channel.nack).toHaveBeenCalledTimes(1);
    expect((logger.warn.mock.calls[0] as [string, string, Record<string, unknown>])[2].reason).toBe('malformed');
    expect(handler).toHaveBeenCalledOnce();
    expect(channel.ack).toHaveBeenCalledOnce();
  });

  it('a logger whose warn throws neither leaves the delivery unacked nor raises an unhandled rejection', async () => {
    const logger = {
      warn: () => {
        throw new Error('logger down');
      },
    };
    const nonceStore = {
      checkAndRecord: () => {
        throw new Error('store down');
      },
    };
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    await consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), vi.fn(), { ...OPTS, nonceStore, logger });
    await channel.deliver(signedDelivery());
    await new Promise((r) => setTimeout(r, 10));
    process.off('unhandledRejection', unhandled);

    expect(unhandled).not.toHaveBeenCalled();
    expect(channel.nack).toHaveBeenCalledTimes(1);
    expect(channel.ack).not.toHaveBeenCalled();
  });

  it('a throwing logger on a refused body still nacks it and does not reject', async () => {
    const logger = {
      warn: () => {
        throw new Error('logger down');
      },
    };
    await consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), vi.fn(), { ...OPTS, logger });
    const bad = signedDelivery();
    bad.content = Buffer.from('not json', 'utf8');
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    await channel.deliver(bad);
    await new Promise((r) => setTimeout(r, 10));
    process.off('unhandledRejection', unhandled);
    expect(unhandled).not.toHaveBeenCalled();
    expect(channel.nack).toHaveBeenCalledTimes(1);
  });

  it('shares one nonce store across deliveries so a replayed nonce is nacked', async () => {
    const handler = vi.fn().mockResolvedValue(undefined);
    await consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, {
      ...OPTS,
      nonceStore: new InMemoryNonceStore(),
    });

    const delivery = signedDelivery();
    await channel.deliver(delivery);
    await channel.deliver(delivery); // same nonce -> replay

    expect(channel.ack).toHaveBeenCalledOnce();
    expect(channel.nack).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// §8b — transport security
// ---------------------------------------------------------------------------
//
// These assert on `connectMock` NOT having been called, which is the whole
// point: §8b rule 5 forbids falling back to plaintext, and the way to be sure
// there is no fallback is to prove no socket was opened at all. A test that
// only checked the thrown message would still pass if the implementation
// dialled first and threw afterwards.

describe('consume() transport security (§8b)', () => {
  it('refuses a plaintext amqp:// URL before opening a socket', async () => {
    const handler = vi.fn();
    await expect(
      consume('amqp://broker.test:5672', 'q', new Sensitive(SIGNING_KEY), handler, OPTS),
    ).rejects.toThrow(/amqps:\/\//);
    expect(connectMock).not.toHaveBeenCalled();
  });

  it('refuses every other scheme too, and is not fooled by an amqps prefix', async () => {
    const handler = vi.fn();
    for (const url of ['http://broker.test', 'amqpsomething://broker.test', 'broker.test']) {
      await expect(
        consume(url, 'q', new Sensitive(SIGNING_KEY), handler, OPTS),
      ).rejects.toThrow(/amqps:\/\//);
    }
    expect(connectMock).not.toHaveBeenCalled();
  });

  it('accepts AMQPS:// case-insensitively — an operator who wrote it meant TLS', async () => {
    const handler = vi.fn();
    await consume('AMQPS://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, OPTS);
    expect(connectMock).toHaveBeenCalledOnce();
  });

  it('passes a supplied CA bundle through as tls socket options (rule 2)', async () => {
    const handler = vi.fn();
    await consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, { ...OPTS, tls: { caCert: CA_PEM },
    });
    expect(connectMock).toHaveBeenCalledWith('amqps://broker.test', { ca: CA_PEM });
  });

  it('never sends rejectUnauthorized — there is no verification-skip path (rule 4)', async () => {
    const handler = vi.fn();
    await consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, { ...OPTS, tls: { caCert: CA_PEM, clientCert: CLIENT_CERT_PEM, clientKey: CLIENT_KEY_PEM },
    });
    const [, socketOptions] = connectMock.mock.calls[0];
    expect(socketOptions).not.toHaveProperty('rejectUnauthorized');
    expect(Object.keys(socketOptions).sort()).toEqual(['ca', 'cert', 'key']);
  });

  it('rejects half a client identity before dialling (rule 3)', async () => {
    const handler = vi.fn();
    await expect(
      consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, { ...OPTS, tls: { clientCert: CLIENT_CERT_PEM },
      }),
    ).rejects.toThrow(/together/);
    await expect(
      consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, { ...OPTS, tls: { clientKey: CLIENT_KEY_PEM },
      }),
    ).rejects.toThrow(/together/);
    expect(connectMock).not.toHaveBeenCalled();
  });

  it('rejects a caCert that is not PEM', async () => {
    const handler = vi.fn();
    await expect(
      consume('amqps://broker.test', 'q', new Sensitive(SIGNING_KEY), handler, { ...OPTS, tls: { caCert: '/etc/ssl/certs/broker-ca.pem' },
      }),
    ).rejects.toThrow(/PEM/);
    expect(connectMock).not.toHaveBeenCalled();
  });
});
