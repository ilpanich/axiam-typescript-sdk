// CONTRACT.md §22.13 "Runtime", the two claims that need the whole of
// `reactorServe` rather than one dispatch: **the runtime declares no exchange,
// queue or binding** (asserted against the AMQP client's declare calls, as
// §22.13 words it) and **shutdown drains in-flight events per §18**.
//
// `amqplib` is mocked, so nothing here touches a broker.

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';

const connectMock = vi.fn();

vi.mock('amqplib', () => ({
  default: { connect: (...args: unknown[]) => connectMock(...args) },
  connect: (...args: unknown[]) => connectMock(...args),
}));

const { Sensitive } = await import('../../../src/core/index.js');
const { signPayload } = await import('../../../src/amqp/hmac.js');
const { REACTOR_EVENTS, allow, reactorServe, reactorQueueName, toChronoRfc3339 } = await import(
  '../../../src/amqp/reactor/index.js'
);

const fixture = JSON.parse(
  readFileSync(
    new URL('../../../testdata/reactor_v2_reference_vectors.json', import.meta.url),
    'utf8',
  ),
) as Record<string, any>;

const SUBKEY = Buffer.from(fixture.hkdf.derived_subkey_hex as string, 'hex');
const TENANT = fixture.tenant_id as string;
const REACTOR_ID = fixture.reactor_id as string;

/**
 * A fake channel that offers **more** than the runtime is allowed to use.
 *
 * `assertQueue`, `assertExchange` and `bindQueue` exist here precisely so the
 * test can prove the runtime never reaches for them — an assertion against the
 * AMQP client's declare calls, not against a comment. If a future edit adds a
 * declare, this fails.
 */
class FakeChannel {
  declareCalls: string[] = [];
  published: Array<{ queue: string; content: Buffer }> = [];
  acked = 0;
  nacked: Array<{ requeue: boolean }> = [];
  cancelled: string[] = [];
  closed = false;
  private onMessage?: (msg: ConsumeMessage | null) => void | Promise<void>;

  async assertQueue(): Promise<unknown> {
    this.declareCalls.push('assertQueue');
    return {};
  }

  async assertExchange(): Promise<unknown> {
    this.declareCalls.push('assertExchange');
    return {};
  }

  async bindQueue(): Promise<unknown> {
    this.declareCalls.push('bindQueue');
    return {};
  }

  async consume(
    queue: string,
    onMessage: (msg: ConsumeMessage | null) => void | Promise<void>,
  ): Promise<{ consumerTag: string }> {
    this.consumedQueue = queue;
    this.onMessage = onMessage;
    return { consumerTag: 'fake-consumer-tag' };
  }

  consumedQueue?: string;

  ack(): void {
    this.acked += 1;
  }

  nack(_msg: ConsumeMessage, _allUpTo: boolean, requeue: boolean): void {
    this.nacked.push({ requeue });
  }

  sendToQueue(queue: string, content: Buffer): boolean {
    this.published.push({ queue, content });
    return true;
  }

  async cancel(tag: string): Promise<void> {
    this.cancelled.push(tag);
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  /** Push a delivery the way a broker would. */
  deliver(msg: ConsumeMessage): void {
    void this.onMessage?.(msg);
  }
}

class FakeConnection {
  readonly channel = new FakeChannel();
  closed = false;
  private closeHandlers: Array<() => void> = [];

  async createChannel(): Promise<FakeChannel> {
    return this.channel;
  }

  on(event: string, handler: () => void): this {
    if (event === 'close') this.closeHandlers.push(handler);
    return this;
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const handler of this.closeHandlers) handler();
  }
}

function signedEventMessage(event: string = REACTOR_EVENTS.LOGIN_POST_AUTH): ConsumeMessage {
  const body: Record<string, unknown> = {
    tenant_id: TENANT,
    event,
    correlation_id: randomUUID(),
    payload: { sub: 'alice' },
    timeout_ms: 5_000,
    key_version: 2,
    nonce: randomUUID(),
    issued_at: toChronoRfc3339(new Date()),
    hmac_signature: null,
  };
  const signature = signPayload(SUBKEY, Buffer.from(JSON.stringify(body), 'utf8'));
  return {
    content: Buffer.from(JSON.stringify({ ...body, hmac_signature: signature }), 'utf8'),
    fields: {
      deliveryTag: 1,
      redelivered: false,
      exchange: 'axiam.reactor.events',
      routingKey: `${TENANT}.${event}`,
      consumerTag: 'fake-consumer-tag',
    },
    properties: {
      replyTo: 'amq.reply-to.abc',
      correlationId: 'property-correlation',
    } as ConsumeMessage['properties'],
  };
}

describe('reactorServe', () => {
  let connection: FakeConnection;

  beforeEach(() => {
    connection = new FakeConnection();
    connectMock.mockReset();
    connectMock.mockResolvedValue(connection);
  });

  it('consumes the server-declared queue and declares nothing itself (§22.1)', async () => {
    const controller = new AbortController();
    const served = reactorServe(
      {
        amqpUrl: 'amqps://broker.example.com:5671',
        tenantId: TENANT,
        reactorId: REACTOR_ID,
        signingKey: new Sensitive(SUBKEY),
        signal: controller.signal,
      },
      () => allow(),
    );

    // Let the connect/consume setup settle before asserting.
    await new Promise((resolve) => setImmediate(resolve));

    expect(connection.channel.consumedQueue).toBe(reactorQueueName(TENANT, REACTOR_ID));
    expect(
      connection.channel.declareCalls,
      'actors consume; they never declare topology (§22.1)',
    ).toEqual([]);

    controller.abort();
    await served;
    expect(connection.channel.declareCalls).toEqual([]);
  });

  it('drains the in-flight event on shutdown rather than truncating it (§18)', async () => {
    const controller = new AbortController();
    let releaseHandler: (() => void) | undefined;
    const handlerStarted = new Promise<void>((resolve) => {
      releaseHandler = resolve;
    });

    const served = reactorServe(
      {
        amqpUrl: 'amqps://broker.example.com:5671',
        tenantId: TENANT,
        reactorId: REACTOR_ID,
        signingKey: new Sensitive(SUBKEY),
        signal: controller.signal,
      },
      async () => {
        releaseHandler?.();
        // Still working when the signal fires.
        await new Promise((resolve) => setTimeout(resolve, 40));
        return allow();
      },
    );

    await new Promise((resolve) => setImmediate(resolve));
    connection.channel.deliver(signedEventMessage());
    await handlerStarted;

    // Shutdown arrives mid-dispatch.
    controller.abort();
    await served;

    expect(
      connection.channel.published,
      'the in-flight event must be answered before the runtime returns',
    ).toHaveLength(1);
    expect(connection.channel.acked).toBe(1);
    expect(connection.channel.cancelled).toEqual(['fake-consumer-tag']);
    expect(connection.channel.closed).toBe(true);
    expect(connection.closed).toBe(true);
  });

  it('requeues a delivery that arrives after the signal rather than half-processing it', async () => {
    const controller = new AbortController();
    const served = reactorServe(
      {
        amqpUrl: 'amqps://broker.example.com:5671',
        tenantId: TENANT,
        reactorId: REACTOR_ID,
        signingKey: new Sensitive(SUBKEY),
        signal: controller.signal,
      },
      () => allow(),
    );

    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();
    await served;

    connection.channel.deliver(signedEventMessage());
    expect(connection.channel.published).toHaveLength(0);
    expect(connection.channel.nacked).toEqual([{ requeue: true }]);
  });

  it('returns when the broker closes the connection', async () => {
    const served = reactorServe(
      {
        amqpUrl: 'amqps://broker.example.com:5671',
        tenantId: TENANT,
        reactorId: REACTOR_ID,
        signingKey: new Sensitive(SUBKEY),
      },
      () => allow(),
    );

    await new Promise((resolve) => setImmediate(resolve));
    await connection.close();
    await served;
    expect(connection.channel.cancelled).toEqual(['fake-consumer-tag']);
  });

  it('returns immediately on a signal that was already aborted', async () => {
    // §18: shutdown is deterministic, and a runtime handed an already-aborted
    // signal must not attach a listener that will never fire and hang the
    // caller's process for the lifetime of the connection.
    const controller = new AbortController();
    controller.abort();

    await reactorServe(
      {
        amqpUrl: 'amqps://broker.example.com:5671',
        tenantId: TENANT,
        reactorId: REACTOR_ID,
        signingKey: new Sensitive(SUBKEY),
        signal: controller.signal,
      },
      () => allow(),
    );

    expect(connection.channel.cancelled).toEqual(['fake-consumer-tag']);
    expect(connection.channel.closed).toBe(true);
    expect(connection.closed).toBe(true);
    expect(connection.channel.declareCalls).toEqual([]);
  });

  it('ignores a null delivery — the broker cancelling the consumer, not an event', async () => {
    const controller = new AbortController();
    const served = reactorServe(
      {
        amqpUrl: 'amqps://broker.example.com:5671',
        tenantId: TENANT,
        reactorId: REACTOR_ID,
        signingKey: new Sensitive(SUBKEY),
        signal: controller.signal,
      },
      () => allow(),
    );

    await new Promise((resolve) => setImmediate(resolve));
    connection.channel.deliver(null as unknown as ConsumeMessage);

    controller.abort();
    await served;

    expect(connection.channel.published).toHaveLength(0);
    expect(connection.channel.nacked).toEqual([]);
    expect(connection.channel.acked).toBe(0);
  });

  it('wires the §19 telemetry hook through to each dispatch', async () => {
    const seen: Array<Record<string, unknown>> = [];
    const controller = new AbortController();
    const served = reactorServe(
      {
        amqpUrl: 'amqps://broker.example.com:5671',
        tenantId: TENANT,
        reactorId: REACTOR_ID,
        signingKey: new Sensitive(SUBKEY),
        signal: controller.signal,
        telemetryHook: (event) => seen.push(event as unknown as Record<string, unknown>),
      },
      () => allow(),
    );

    await new Promise((resolve) => setImmediate(resolve));
    connection.channel.deliver(signedEventMessage(REACTOR_EVENTS.TOKEN_PRE_ISSUE));

    controller.abort();
    await served;

    expect(seen.map((e) => e.type)).toEqual(['requestStart', 'requestEnd']);
    // A bounded label from the registry, never the wire string.
    expect(seen[0]!.pathTemplate).toBe('token.pre_issue');
    expect(seen[0]!.method).toBe('AMQP');
    expect(connection.channel.published).toHaveLength(1);
  });

  it('survives a channel whose cancel and close both reject', async () => {
    // The connection may already be gone when the signal fires; tearing down a
    // corpse is the state the caller asked for, not an error to surface at
    // them (§18.1 rule 2 — teardown is idempotent).
    connection.channel.cancel = async () => {
      throw new Error('channel already closed');
    };
    connection.channel.close = async () => {
      throw new Error('channel already closed');
    };

    const controller = new AbortController();
    const served = reactorServe(
      {
        amqpUrl: 'amqps://broker.example.com:5671',
        tenantId: TENANT,
        reactorId: REACTOR_ID,
        signingKey: new Sensitive(SUBKEY),
        signal: controller.signal,
      },
      () => allow(),
    );

    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();
    await expect(served).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// §8b — transport security, as required by §22.2's closing paragraph
// ---------------------------------------------------------------------------
//
// "Reactors connect across a trust boundary: `amqps://`, a supplied CA bundle,
// no verification-skip switch, no plaintext fallback."
//
// Each refusal asserts that `connectMock` was never called. That is the
// substance of rule 5: proving no socket was opened is proving there is no
// fallback, where checking only the error message would still pass an
// implementation that dialled first and complained second.

describe('reactorServe transport security (§8b)', () => {
  const CA_PEM = '-----BEGIN CERTIFICATE-----\nZmFrZS1jYQ==\n-----END CERTIFICATE-----\n';
  const CLIENT_CERT_PEM =
    '-----BEGIN CERTIFICATE-----\nZmFrZS1jbGllbnQ=\n-----END CERTIFICATE-----\n';
  const CLIENT_KEY_PEM =
    '-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----\n';

  // This describe needs its own fixture: the one above lives inside its own
  // `describe`, so nothing here would reset `connectMock` between cases and the
  // "was never called" assertions would see the previous test's call.
  beforeEach(() => {
    connectMock.mockReset();
    connectMock.mockResolvedValue(new FakeConnection());
  });

  /**
   * Start a reactor and stop it again immediately.
   *
   * The abort is what makes the resolving cases terminate — `reactorServe`
   * otherwise runs until the connection closes or the signal fires, and a test
   * asserting on the connect arguments has no interest in either.
   */
  function serve(amqpUrl: string, tls?: Record<string, string>) {
    const controller = new AbortController();
    const served = reactorServe(
      {
        amqpUrl,
        tenantId: TENANT,
        reactorId: REACTOR_ID,
        signingKey: new Sensitive(SUBKEY),
        signal: controller.signal,
        ...(tls ? { tls } : {}),
      },
      () => allow(),
    );
    // Abort on the next tick so a connection that DID open still gets torn
    // down; a rejected promise is unaffected by it.
    void Promise.resolve().then(() => controller.abort());
    return served;
  }

  it('refuses a plaintext amqp:// broker URL before opening a socket', async () => {
    await expect(serve('amqp://broker.example.com:5672')).rejects.toThrow(/amqps:\/\//);
    expect(connectMock).not.toHaveBeenCalled();
  });

  it('refuses every other scheme, and an amqps-prefixed impostor', async () => {
    for (const url of [
      'http://broker.example.com',
      'amqpsomething://broker.example.com:5671',
      'broker.example.com:5671',
      '',
    ]) {
      await expect(serve(url)).rejects.toThrow(/amqps:\/\//);
    }
    expect(connectMock).not.toHaveBeenCalled();
  });

  it('passes a private-CA bundle to the TLS socket (rule 2)', async () => {
    await serve('amqps://broker.example.com:5671', { caCert: CA_PEM });
    expect(connectMock).toHaveBeenCalledWith('amqps://broker.example.com:5671', { ca: CA_PEM });
  });

  it('carries a client identity for mutual TLS, and nothing else (rules 3 and 4)', async () => {
    await serve('amqps://broker.example.com:5671', {
      caCert: CA_PEM,
      clientCert: CLIENT_CERT_PEM,
      clientKey: CLIENT_KEY_PEM,
    });
    const [, socketOptions] = connectMock.mock.calls[0];
    // Rule 4 is an assertion about what is ABSENT: no key here may weaken
    // verification, under this or any other name.
    expect(Object.keys(socketOptions).sort()).toEqual(['ca', 'cert', 'key']);
  });

  it('rejects half a client identity before dialling (rule 3)', async () => {
    await expect(
      serve('amqps://broker.example.com:5671', { clientCert: CLIENT_CERT_PEM }),
    ).rejects.toThrow(/together/);
    await expect(
      serve('amqps://broker.example.com:5671', { clientKey: CLIENT_KEY_PEM }),
    ).rejects.toThrow(/together/);
    expect(connectMock).not.toHaveBeenCalled();
  });
});
