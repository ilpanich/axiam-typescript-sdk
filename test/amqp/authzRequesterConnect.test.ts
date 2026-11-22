// connectAuthzRequester (amqp/authzRequester.ts; review gate TYP-R1-1): the
// requester owns its amqplib connection and channel, so it must handle their
// 'error' and 'close' events itself. An EventEmitter 'error' with no listener
// throws — inside amqplib's socket handler that is an uncaught exception that
// ends the process — and a closed connection must release every waiter at
// once rather than leave it hanging until its timeout.
//
// amqplib is mocked with EventEmitter-based fakes; no broker is involved.

import { EventEmitter } from 'node:events';
import { hkdfSync } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';

const connectMock = vi.fn();

vi.mock('amqplib', () => ({
  default: { connect: (...args: unknown[]) => connectMock(...args) },
  connect: (...args: unknown[]) => connectMock(...args),
}));

const { connectAuthzRequester, AuthzRequesterClosedError } = await import('../../src/amqp/authzRequester.js');
const { Sensitive } = await import('../../src/core/index.js');

const TENANT = '11111111-1111-1111-1111-111111111111';
const SUBJECT = '33333333-3333-3333-3333-333333333333';
const RESOURCE = '44444444-4444-4444-4444-444444444444';
const MASTER = Buffer.alloc(32, 7);

function subkey(): Buffer {
  const info = Buffer.concat([
    Buffer.from('axiam-amqp-v1', 'utf8'),
    Buffer.from([2]),
    Buffer.from(TENANT.replace(/-/g, ''), 'hex'),
  ]);
  return Buffer.from(hkdfSync('sha256', MASTER, Buffer.from('axiam-amqp-hkdf-salt-v1', 'utf8'), info, 32));
}

class FakeAmqpChannel extends EventEmitter {
  onMessage: ((msg: ConsumeMessage | null) => void) | undefined;
  published = 0;
  async assertQueue() {
    return { queue: 'amq.gen-connect' };
  }
  async consume(_queue: string, onMessage: (msg: ConsumeMessage | null) => void) {
    this.onMessage = onMessage;
    return { consumerTag: 'ctag-c' };
  }
  sendToQueue(): boolean {
    this.published += 1;
    return true;
  }
  ack(): void {}
  nack(): void {}
  async cancel() {
    throw new Error('channel closed');
  }
}

class FakeConnection extends EventEmitter {
  readonly channel = new FakeAmqpChannel();
  closeCalls = 0;
  async createChannel() {
    return this.channel;
  }
  async close() {
    this.closeCalls += 1;
    throw new Error('connection already closed');
  }
}

async function connect(logger = { warn: vi.fn() }) {
  const connection = new FakeConnection();
  connectMock.mockResolvedValueOnce(connection);
  const requester = await connectAuthzRequester('amqps://broker.example:5671', {
    tenantId: TENANT,
    subkey: new Sensitive(subkey()),
    timeoutMs: 60_000,
    logger,
  });
  return { connection, requester, logger };
}

describe('connectAuthzRequester — connection and channel events', () => {
  it("a connection 'error' is logged, not thrown, and carries no URL or key", async () => {
    const { connection, requester, logger } = await connect();
    expect(() => connection.emit('error', new Error('Heartbeat timeout'))).not.toThrow();
    expect(logger.warn).toHaveBeenCalledTimes(1);
    const logged = JSON.stringify(logger.warn.mock.calls);
    expect(logged).toContain('Heartbeat timeout');
    expect(logged).not.toContain('broker.example');
    expect(logged).not.toContain(subkey().toString('hex'));
    await requester.close();
  });

  it("a channel 'error' is logged, not thrown", async () => {
    const { connection, requester, logger } = await connect();
    expect(() => connection.channel.emit('error', new Error('PRECONDITION_FAILED'))).not.toThrow();
    expect(logger.warn).toHaveBeenCalledTimes(1);
    await requester.close();
  });

  it("'error' then 'close' on the connection: the process survives and every pending check rejects at once", async () => {
    const { connection, requester } = await connect();
    const a = requester.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
    const b = requester.check({ subjectId: SUBJECT, action: 'b', resourceId: RESOURCE });
    expect(requester.pending).toBe(2);

    expect(() => connection.emit('error', new Error('read ECONNRESET'))).not.toThrow();
    connection.emit('close', new Error('read ECONNRESET'));

    await expect(a).rejects.toBeInstanceOf(AuthzRequesterClosedError);
    await expect(b).rejects.toBeInstanceOf(AuthzRequesterClosedError);
    expect(requester.pending).toBe(0);
    // Later checks are refused, not published to a dead channel.
    await expect(requester.check({ subjectId: SUBJECT, action: 'c', resourceId: RESOURCE })).rejects.toBeInstanceOf(
      AuthzRequesterClosedError,
    );
    expect(connection.channel.published).toBe(2);
  });

  it("a 'close' of the channel alone also closes the requester", async () => {
    const { connection, requester } = await connect();
    const pending = requester.check({ subjectId: SUBJECT, action: 'a', resourceId: RESOURCE });
    connection.channel.emit('close');
    await expect(pending).rejects.toBeInstanceOf(AuthzRequesterClosedError);
  });
});
