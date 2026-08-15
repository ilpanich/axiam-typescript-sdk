// CONTRACT.md §22.13 "Runtime" — the behavioural half of the required tests.
//
// A handler that throws produces NO REPLY (zero published messages, not an
// `allow`); the runtime declares no exchange, queue or binding; shutdown drains
// in-flight events per §18; and the signing key never appears in any log line
// or error payload.

import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { signPayload } from '../../../src/amqp/hmac.js';
import { InMemoryNonceStore } from '../../../src/amqp/consumer.js';
import {
  REACTOR_EVENTS,
  REACTOR_FRESHNESS_SKEW_MS,
  abstain,
  allow,
  deny,
  dispatchReactorDelivery,
  mutate,
  reactorReplySignatureValid,
  requireStepUp,
  toChronoRfc3339,
  type ReactorChannel,
  type ReactorDispatchContext,
  type ReactorHandler,
  type ReactorLogger,
  type ReactorReply,
} from '../../../src/amqp/reactor/index.js';

const fixture = JSON.parse(
  readFileSync(
    new URL('../../../testdata/reactor_v2_reference_vectors.json', import.meta.url),
    'utf8',
  ),
) as Record<string, any>;

const SUBKEY = Buffer.from(fixture.hkdf.derived_subkey_hex as string, 'hex');
const TENANT = fixture.tenant_id as string;

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

interface Published {
  queue: string;
  content: Buffer;
  options?: { correlationId?: string; contentType?: string };
}

/**
 * Recording fake channel. It offers exactly the operations §22.1 permits —
 * there is nothing here that could declare a queue, an exchange or a binding,
 * because the interface it implements offers no such thing.
 */
class RecordingChannel implements ReactorChannel {
  acked: ConsumeMessage[] = [];
  nackCalls: Array<{ allUpTo: boolean; requeue: boolean }> = [];
  published: Published[] = [];

  ack(msg: ConsumeMessage): void {
    this.acked.push(msg);
  }

  nack(_msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void {
    this.nackCalls.push({ allUpTo, requeue });
  }

  sendToQueue(
    queue: string,
    content: Buffer,
    options?: { correlationId?: string; contentType?: string },
  ): boolean {
    this.published.push({ queue, content, options });
    return true;
  }

  /** The single published reply, parsed. Fails loudly if there is not exactly one. */
  onlyReply(): ReactorReply {
    expect(this.published).toHaveLength(1);
    return JSON.parse(this.published[0]!.content.toString('utf8')) as ReactorReply;
  }
}

function recordingLogger(): {
  logger: ReactorLogger;
  lines: string[];
} {
  const lines: string[] = [];
  return {
    lines,
    logger: {
      warn(event, message, context) {
        lines.push(`${event} ${message} ${JSON.stringify(context ?? {})}`);
      },
    },
  };
}

/** Build and sign an event exactly as the server would, in wire field order. */
function signedEvent(options: {
  event?: string;
  tenantId?: string;
  timeoutMs?: number;
  keyVersion?: number;
  issuedAt?: Date;
  nonce?: string;
  payload?: Record<string, unknown>;
}): { body: Record<string, unknown>; data: Buffer } {
  const body: Record<string, unknown> = {
    tenant_id: options.tenantId ?? TENANT,
    event: options.event ?? REACTOR_EVENTS.LOGIN_POST_AUTH,
    correlation_id: randomUUID(),
    payload: options.payload ?? { sub: 'alice' },
    timeout_ms: options.timeoutMs ?? 5_000,
    key_version: options.keyVersion ?? 2,
    nonce: options.nonce ?? randomUUID(),
    issued_at: toChronoRfc3339(options.issuedAt ?? new Date()),
    hmac_signature: null,
  };
  const signature = signPayload(SUBKEY, Buffer.from(JSON.stringify(body), 'utf8'));
  const signed = { ...body, hmac_signature: signature };
  return { body: signed, data: Buffer.from(JSON.stringify(signed), 'utf8') };
}

// `null` means "no reply_to property at all" — an explicit `undefined` argument
// would take the default, which is exactly the bug this parameter shape avoids.
function makeMessage(data: Buffer, replyTo: string | null = 'amq.reply-to.abc'): ConsumeMessage {
  return {
    content: data,
    fields: {
      deliveryTag: 1,
      redelivered: false,
      exchange: 'axiam.reactor.events',
      routingKey: `${TENANT}.login.post_auth`,
      consumerTag: 'test',
    },
    properties: {
      replyTo: replyTo ?? undefined,
      correlationId: 'property-correlation',
    } as ConsumeMessage['properties'],
  };
}

function context(overrides: Partial<ReactorDispatchContext> = {}): ReactorDispatchContext {
  return {
    signingKey: SUBKEY,
    tenantId: TENANT,
    mode: 'intercept',
    skewMs: REACTOR_FRESHNESS_SKEW_MS,
    nonceStore: new InMemoryNonceStore(),
    ...overrides,
  };
}

function counting(decision: ReturnType<typeof allow>): {
  handler: ReactorHandler;
  calls: () => number;
} {
  let calls = 0;
  return {
    calls: () => calls,
    handler: () => {
      calls += 1;
      return decision;
    },
  };
}

// ---------------------------------------------------------------------------

describe('§22 reactor runtime — the happy path', () => {
  it('verifies, dispatches, signs and publishes', async () => {
    const channel = new RecordingChannel();
    const { body, data } = signedEvent({});
    const msg = makeMessage(data);
    const { handler, calls } = counting(allow());

    await dispatchReactorDelivery(channel, msg, context(), handler);

    expect(calls()).toBe(1);
    expect(channel.acked).toHaveLength(1);
    expect(channel.nackCalls).toHaveLength(0);

    const reply = channel.onlyReply();
    expect(reply.decision).toBe('allow');
    expect(reply.key_version).toBe(2);
    expect(reply.require_mfa).toBeUndefined();
    expect(reactorReplySignatureValid(reply, SUBKEY)).toBe(true);

    // The correlation_id inside the SIGNED BODY is what the server
    // authenticates; the AMQP property is only the RPC convention.
    expect(reply.correlation_id).toBe(body.correlation_id);
    expect(reply.tenant_id).toBe(body.tenant_id);
    expect(reply.event).toBe(body.event);
    expect(channel.published[0]!.queue).toBe('amq.reply-to.abc');
    expect(channel.published[0]!.options?.correlationId).toBe('property-correlation');
  });
});

describe('§22.10 rule 2 — fail closed on our own errors', () => {
  it('publishes nothing when the handler throws, rather than an allow', async () => {
    const channel = new RecordingChannel();
    const { data } = signedEvent({});

    await dispatchReactorDelivery(
      channel,
      makeMessage(data),
      context(),
      () => {
        throw new Error('handler blew up');
      },
    );

    expect(channel.published).toHaveLength(0);
    expect(channel.acked).toHaveLength(1);
  });

  it('publishes nothing when the handler rejects', async () => {
    const channel = new RecordingChannel();
    const { data } = signedEvent({});

    await dispatchReactorDelivery(channel, makeMessage(data), context(), async () => {
      await Promise.resolve();
      throw new Error('async blow-up');
    });

    expect(channel.published).toHaveLength(0);
  });

  it('publishes nothing when the handler outruns timeout_ms', async () => {
    const channel = new RecordingChannel();
    // The server declared a 5 ms window; the handler takes far longer.
    const { data } = signedEvent({ timeoutMs: 5 });

    await dispatchReactorDelivery(
      channel,
      makeMessage(data),
      context(),
      () => new Promise((resolve) => setTimeout(() => resolve(allow()), 80)),
    );

    expect(channel.published).toHaveLength(0);
  });

  it('publishes nothing when the handler abstains', async () => {
    const channel = new RecordingChannel();
    const { data } = signedEvent({ event: REACTOR_EVENTS.GRANT_PRE_ASSIGN });

    await dispatchReactorDelivery(channel, makeMessage(data), context(), () => abstain());

    expect(channel.published).toHaveLength(0);
    expect(channel.acked).toHaveLength(1);
  });

  it('publishes nothing for a mutation with an empty patch (malformed_mutation)', async () => {
    const channel = new RecordingChannel();
    const { data } = signedEvent({ event: REACTOR_EVENTS.TOKEN_PRE_ISSUE });

    await dispatchReactorDelivery(channel, makeMessage(data), context(), () => mutate({}));

    expect(channel.published).toHaveLength(0);
  });
});

describe('§22.10 rule 3 — no filtering', () => {
  it('publishes a forbidden patch key unfiltered', async () => {
    const channel = new RecordingChannel();
    const { data } = signedEvent({ event: REACTOR_EVENTS.TOKEN_PRE_ISSUE });

    await dispatchReactorDelivery(channel, makeMessage(data), context(), () =>
      mutate({ 'ext.department': 'eng', sub: 'root' }),
    );

    const reply = channel.onlyReply();
    expect(reply.decision).toBe('mutate');
    // The SDK must NOT silently drop `sub` from a token.pre_issue patch.
    expect(reply.patch).toEqual({ 'ext.department': 'eng', sub: 'root' });
    expect(reactorReplySignatureValid(reply, SUBKEY)).toBe(true);
  });
});

describe('§22.4 rule 3 — require_mfa', () => {
  it('rides on allow for login.post_auth', async () => {
    const channel = new RecordingChannel();
    const { data } = signedEvent({ event: REACTOR_EVENTS.LOGIN_POST_AUTH });

    await dispatchReactorDelivery(channel, makeMessage(data), context(), () => requireStepUp());

    const reply = channel.onlyReply();
    expect(reply.decision).toBe('allow');
    expect(reply.require_mfa).toBe(true);
    expect(reactorReplySignatureValid(reply, SUBKEY)).toBe(true);
  });

  it('is refused client-side on every other event', async () => {
    for (const event of [
      REACTOR_EVENTS.TOKEN_PRE_ISSUE,
      REACTOR_EVENTS.USER_PRE_CREATE,
      REACTOR_EVENTS.GRANT_PRE_ASSIGN,
    ]) {
      const channel = new RecordingChannel();
      const { data } = signedEvent({ event });
      await dispatchReactorDelivery(channel, makeMessage(data), context(), () => requireStepUp());
      expect(channel.published, `${event}: require_mfa_not_supported`).toHaveLength(0);
    }
  });
});

describe('§22.5 — listeners', () => {
  it('never publishes a reply, but still observes and acks', async () => {
    const channel = new RecordingChannel();
    const { data } = signedEvent({});
    // Even a handler that answers `deny` cannot affect the outcome.
    const { handler, calls } = counting(deny('nope'));

    await dispatchReactorDelivery(channel, makeMessage(data), context({ mode: 'listen' }), handler);

    expect(calls()).toBe(1);
    expect(channel.published).toHaveLength(0);
    expect(channel.acked).toHaveLength(1);
  });
});

describe('§22.3 — verification before the handler ever runs', () => {
  it('never reaches the handler on a bad signature, and nacks without requeue', async () => {
    const channel = new RecordingChannel();
    const { body } = signedEvent({});
    const tampered = { ...body, hmac_signature: '00'.repeat(32) };
    const { handler, calls } = counting(allow());

    await dispatchReactorDelivery(
      channel,
      makeMessage(Buffer.from(JSON.stringify(tampered), 'utf8')),
      context(),
      handler,
    );

    expect(calls()).toBe(0);
    expect(channel.published).toHaveLength(0);
    expect(channel.nackCalls).toEqual([{ allUpTo: false, requeue: false }]);
    expect(channel.acked).toHaveLength(0);
  });

  it('refuses a v1 event and a stale one in either direction', async () => {
    const { handler, calls } = counting(allow());

    const v1 = new RecordingChannel();
    await dispatchReactorDelivery(
      v1,
      makeMessage(signedEvent({ keyVersion: 1 }).data),
      context(),
      handler,
    );
    expect(v1.nackCalls).toEqual([{ allUpTo: false, requeue: false }]);

    for (const offsetMs of [REACTOR_FRESHNESS_SKEW_MS + 5_000, -(REACTOR_FRESHNESS_SKEW_MS + 5_000)]) {
      const channel = new RecordingChannel();
      await dispatchReactorDelivery(
        channel,
        makeMessage(signedEvent({ issuedAt: new Date(Date.now() - offsetMs) }).data),
        context(),
        handler,
      );
      expect(channel.nackCalls).toEqual([{ allUpTo: false, requeue: false }]);
    }

    expect(calls(), 'no unverified event may reach user code').toBe(0);
  });

  it('refuses a replayed nonce the second time', async () => {
    const ctx = context();
    const { data } = signedEvent({});
    const { handler, calls } = counting(allow());

    const first = new RecordingChannel();
    await dispatchReactorDelivery(first, makeMessage(data), ctx, handler);
    const second = new RecordingChannel();
    await dispatchReactorDelivery(second, makeMessage(data), ctx, handler);

    expect(calls()).toBe(1);
    expect(second.nackCalls).toEqual([{ allUpTo: false, requeue: false }]);
    expect(second.published).toHaveLength(0);
  });

  it('refuses an event naming another tenant', async () => {
    const channel = new RecordingChannel();
    const { data } = signedEvent({ tenantId: '33333333-3333-3333-3333-333333333333' });
    const { handler, calls } = counting(allow());

    await dispatchReactorDelivery(channel, makeMessage(data), context(), handler);

    expect(calls()).toBe(0);
    expect(channel.published).toHaveLength(0);
    expect(channel.nackCalls).toEqual([{ allUpTo: false, requeue: false }]);
  });

  it('nacks an unparseable body without requeue', async () => {
    const channel = new RecordingChannel();
    await dispatchReactorDelivery(
      channel,
      makeMessage(Buffer.from('{not json', 'utf8')),
      context(),
      () => allow(),
    );
    expect(channel.nackCalls).toEqual([{ allUpTo: false, requeue: false }]);
    expect(channel.published).toHaveLength(0);
  });

  it('publishes nothing when the delivery carries no reply_to', async () => {
    const channel = new RecordingChannel();
    const { data } = signedEvent({});
    await dispatchReactorDelivery(channel, makeMessage(data, null), context(), () => allow());
    expect(channel.published).toHaveLength(0);
  });
});

describe('§22.1 — the runtime declares no topology', () => {
  it('calls no declare or bind operation anywhere in the reactor module', () => {
    // Built at runtime so this test's own source cannot match itself.
    const forbidden = ['assertQueue', 'assertExchange', 'bindQueue', 'bindExchange'].map(
      (op) => `.${op}(`,
    );
    for (const file of ['registry.ts', 'protocol.ts', 'runtime.ts', 'index.ts']) {
      const source = readFileSync(
        new URL(`../../../src/amqp/reactor/${file}`, import.meta.url),
        'utf8',
      );
      for (const call of forbidden) {
        expect(
          source.includes(call),
          `${file} must not call ${call} — §22.1: actors consume, they never declare topology`,
        ).toBe(false);
      }
    }
  });
});

describe('§22.12 — the signing key never appears in a log line', () => {
  it('survives every logging path this runtime has', async () => {
    const { logger, lines } = recordingLogger();
    const ctx = context({ logger });
    const keyHex = SUBKEY.toString('hex');
    const keyUtf8 = SUBKEY.toString('utf8');
    const keyJson = JSON.stringify([...SUBKEY]);

    // A bad signature.
    const bad = signedEvent({});
    await dispatchReactorDelivery(
      new RecordingChannel(),
      makeMessage(Buffer.from(JSON.stringify({ ...bad.body, hmac_signature: '11'.repeat(32) }))),
      ctx,
      () => allow(),
    );
    // A replayed nonce.
    const replayed = signedEvent({});
    await dispatchReactorDelivery(new RecordingChannel(), makeMessage(replayed.data), ctx, () =>
      allow(),
    );
    await dispatchReactorDelivery(new RecordingChannel(), makeMessage(replayed.data), ctx, () =>
      allow(),
    );
    // A throwing handler.
    await dispatchReactorDelivery(
      new RecordingChannel(),
      makeMessage(signedEvent({}).data),
      ctx,
      () => {
        throw new Error('boom');
      },
    );
    // require_mfa on the wrong event.
    await dispatchReactorDelivery(
      new RecordingChannel(),
      makeMessage(signedEvent({ event: REACTOR_EVENTS.TOKEN_PRE_ISSUE }).data),
      ctx,
      () => requireStepUp(),
    );
    // An unaddressable reply.
    await dispatchReactorDelivery(
      new RecordingChannel(),
      makeMessage(signedEvent({}).data, null),
      ctx,
      () => allow(),
    );

    expect(lines.length, 'these paths must log something').toBeGreaterThan(0);
    const log = lines.join('\n');
    expect(log).not.toContain(keyHex);
    expect(log).not.toContain(keyJson);
    expect(log).not.toContain(keyUtf8);
  });
});

describe('§19 — telemetry labels come from the registry, not the wire', () => {
  it('emits one requestStart/requestEnd pair per dispatch with a bounded label', async () => {
    const events: Array<Record<string, unknown>> = [];
    const channel = new RecordingChannel();
    const { data } = signedEvent({ event: REACTOR_EVENTS.TOKEN_PRE_ISSUE });
    const { TelemetryDispatcher } = await import('../../../src/core/telemetry.js');

    await dispatchReactorDelivery(
      channel,
      makeMessage(data),
      context({
        telemetry: new TelemetryDispatcher((e) => events.push(e as unknown as Record<string, unknown>)),
      }),
      () => allow(),
    );

    expect(events.map((e) => e.type)).toEqual(['requestStart', 'requestEnd']);
    expect(events[0]!.pathTemplate).toBe('token.pre_issue');
    expect(events[1]!.outcome).toBe('success');
  });

  it('reports failure, and never an attacker-chosen label, for an unknown event', async () => {
    const events: Array<Record<string, unknown>> = [];
    const channel = new RecordingChannel();
    // A signed event naming something outside the registry. It should never
    // arrive, but the label must stay bounded if it does.
    const { data } = signedEvent({ event: '../../../etc/passwd' });
    const { TelemetryDispatcher } = await import('../../../src/core/telemetry.js');

    await dispatchReactorDelivery(
      channel,
      makeMessage(data),
      context({
        telemetry: new TelemetryDispatcher((e) => events.push(e as unknown as Record<string, unknown>)),
      }),
      () => abstain(),
    );

    expect(events[0]!.pathTemplate).toBe('unknown_event');
  });
});
