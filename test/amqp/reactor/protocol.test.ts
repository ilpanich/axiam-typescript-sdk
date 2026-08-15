// CONTRACT.md §22.2–§22.4 — the protocol helpers and the dispatch paths the
// fixture vectors do not reach on their own.
//
// The §22.13 vectors pin the bytes of a well-formed message in both
// directions; what is left is everything a *malformed* one does, plus the
// handler-facing accessors. Both are load-bearing: §22.10 rule 2 says a body
// the runtime cannot decode produces NO REPLY, and a rule whose failure path is
// untested is a rule that has never been observed to hold.

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { signPayload } from '../../../src/amqp/hmac.js';
import { InMemoryNonceStore } from '../../../src/amqp/consumer.js';
import { TelemetryDispatcher } from '../../../src/core/telemetry.js';
import {
  REACTOR_EVENTS,
  REACTOR_FRESHNESS_SKEW_MS,
  allow,
  buildReactorReply,
  chainedPatch,
  deny,
  dispatchReactorDelivery,
  mutate,
  reactorReplySignatureValid,
  signingKeyFingerprint,
  specForEvent,
  toChronoRfc3339,
  verifyEvent,
  type ReactorChannel,
  type ReactorDispatchContext,
  type ReactorEvent,
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

class RecordingChannel implements ReactorChannel {
  acked = 0;
  nacked: Array<{ allUpTo: boolean; requeue: boolean }> = [];
  published: Array<{ queue: string; content: Buffer; correlationId?: string }> = [];

  ack(): void {
    this.acked += 1;
  }

  nack(_msg: ConsumeMessage, allUpTo: boolean, requeue: boolean): void {
    this.nacked.push({ allUpTo, requeue });
  }

  sendToQueue(
    queue: string,
    content: Buffer,
    options?: { correlationId?: string; contentType?: string },
  ): boolean {
    this.published.push({ queue, content, correlationId: options?.correlationId });
    return true;
  }

  onlyReply(): ReactorReply {
    expect(this.published).toHaveLength(1);
    return JSON.parse(this.published[0]!.content.toString('utf8')) as ReactorReply;
  }
}

/** Sign an arbitrary body the way the server does — `hmac_signature` as null. */
function sign(body: Record<string, unknown>): Record<string, unknown> {
  const unsigned = { ...body, hmac_signature: null };
  return {
    ...unsigned,
    hmac_signature: signPayload(SUBKEY, Buffer.from(JSON.stringify(unsigned), 'utf8')),
  };
}

function eventBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    tenant_id: TENANT,
    event: REACTOR_EVENTS.LOGIN_POST_AUTH,
    correlation_id: randomUUID(),
    payload: { sub: 'alice' },
    timeout_ms: 5_000,
    key_version: 2,
    nonce: randomUUID(),
    issued_at: toChronoRfc3339(new Date()),
    ...overrides,
  };
}

function message(
  body: Record<string, unknown> | string,
  properties: Record<string, unknown> = { replyTo: 'amq.reply-to.abc', correlationId: 'prop-cid' },
): ConsumeMessage {
  const content =
    typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(JSON.stringify(body), 'utf8');
  return {
    content,
    fields: {
      deliveryTag: 1,
      redelivered: false,
      exchange: 'axiam.reactor.events',
      routingKey: `${TENANT}.login.post_auth`,
      consumerTag: 'test',
    },
    properties: properties as unknown as ConsumeMessage['properties'],
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

afterEach(() => {
  vi.restoreAllMocks();
});

describe('§22.3 — verifyEvent refuses a body it cannot trust', () => {
  it('refuses a non-numeric key_version as malformed, before any MAC work', () => {
    // Not `key_version_too_old`: the floor comparison is only meaningful once
    // the field is an integer at all, and "2" is not 2.
    for (const keyVersion of ['2', 2.5, null, undefined]) {
      const body = sign(eventBody({ key_version: keyVersion }));
      expect(verifyEvent(body, SUBKEY), String(keyVersion)).toEqual({
        ok: false,
        rejection: 'malformed',
      });
    }
  });

  it('refuses a correctly signed body whose fields are the wrong shape', () => {
    // The MAC verifies — these bodies really were signed with the tenant subkey
    // — and the runtime still refuses them, because a signature attests to who
    // wrote the bytes, not to what they mean. Only after the MAC passes is the
    // shape read at all (§22.3's ordering), so this is the one class of
    // rejection that a signature cannot rescue.
    const shapes: Array<[string, Record<string, unknown>]> = [
      ['timeout_ms as a string', { timeout_ms: '500' }],
      ['payload as an array', { payload: [1, 2, 3] }],
      ['payload as null', { payload: null }],
      ['tenant_id absent', { tenant_id: undefined }],
      ['event absent', { event: undefined }],
      ['correlation_id as a number', { correlation_id: 7 }],
      ['nonce absent', { nonce: undefined }],
      ['issued_at absent', { issued_at: undefined }],
    ];
    for (const [label, override] of shapes) {
      const body = sign(eventBody(override));
      expect(verifyEvent(body, SUBKEY), label).toEqual({ ok: false, rejection: 'malformed' });
    }
  });

  it('refuses an unparseable issued_at as stale rather than accepting it', () => {
    const body = sign(eventBody({ issued_at: 'not a timestamp' }));
    expect(verifyEvent(body, SUBKEY)).toEqual({ ok: false, rejection: 'stale' });
  });
});

describe('§22.3 — the handler-facing accessors', () => {
  const event: ReactorEvent = {
    tenant_id: TENANT,
    event: REACTOR_EVENTS.TOKEN_PRE_ISSUE,
    correlation_id: 'c',
    payload: { sub: 'alice', _reactor_patch: { 'ext.department': 'eng' } },
    timeout_ms: 500,
    key_version: 2,
    nonce: 'n',
    issued_at: '2026-07-10T12:00:00Z',
    hmac_signature: 'deadbeef',
  };

  it('surfaces the chained patch an earlier reactor returned (§22.3)', () => {
    expect(chainedPatch(event)).toEqual({ 'ext.department': 'eng' });
  });

  it('reports no chained patch on a first-in-chain dispatch', () => {
    expect(chainedPatch({ ...event, payload: { sub: 'alice' } })).toBeUndefined();
  });

  it('resolves the registry spec for an event, and nothing for an unknown name', () => {
    expect(specForEvent(event)?.name).toBe(REACTOR_EVENTS.TOKEN_PRE_ISSUE);
    expect(specForEvent({ ...event, event: 'nope.not.real' })).toBeUndefined();
  });
});

describe('§22.12 — the signing key is fingerprinted, never printed', () => {
  it('returns eight stable hex characters that are not the key', () => {
    const print = signingKeyFingerprint(SUBKEY);
    expect(print).toMatch(/^[0-9a-f]{8}$/);
    expect(print).toBe(signingKeyFingerprint(SUBKEY));
    expect(SUBKEY.toString('hex')).not.toContain(print);
    expect(signingKeyFingerprint(Buffer.from('another key'))).not.toBe(print);
  });
});

describe('§22.4 — reply signature validation', () => {
  it('refuses an unsigned reply outright', () => {
    // A reply is an instruction to change a token or refuse a login, so an
    // unsigned reply is not a weak reply — it is not a reply at all.
    const unsigned = buildReactorReply(
      { correlation_id: 'c', tenant_id: TENANT, event: REACTOR_EVENTS.LOGIN_POST_AUTH },
      { decision: 'allow' },
    );
    expect(unsigned.hmac_signature).toBeNull();
    expect(reactorReplySignatureValid(unsigned, SUBKEY)).toBe(false);
  });
});

describe('§22.10 rule 2 — bodies the runtime cannot decode publish nothing', () => {
  it('nacks a JSON body that is not an object', async () => {
    for (const raw of ['[1,2,3]', '"a string"', '42', 'null']) {
      const channel = new RecordingChannel();
      await dispatchReactorDelivery(channel, message(raw), context(), () => allow());
      expect(channel.published, raw).toHaveLength(0);
      expect(channel.nacked, raw).toEqual([{ allUpTo: false, requeue: false }]);
    }
  });
});

describe('§22.4 — the deny answer on the wire', () => {
  it('publishes decision "deny" with the reason, signed', async () => {
    const channel = new RecordingChannel();
    await dispatchReactorDelivery(channel, message(sign(eventBody())), context(), () =>
      deny('embargoed region'),
    );

    const reply = channel.onlyReply();
    expect(reply.decision).toBe('deny');
    expect(reply.reason).toBe('embargoed region');
    expect(reactorReplySignatureValid(reply, SUBKEY)).toBe(true);
  });

  it('omits reason entirely when the handler gives none', async () => {
    // A deny with no reason still denies; the server substitutes "denied by
    // reactor". Omitting the key rather than sending `""` matters because the
    // omission is inside the signed bytes.
    const channel = new RecordingChannel();
    await dispatchReactorDelivery(channel, message(sign(eventBody())), context(), () => deny());

    const wire = channel.published[0]!.content.toString('utf8');
    expect(wire).toContain('"decision":"deny"');
    expect(wire).not.toContain('reason');
    expect(reactorReplySignatureValid(channel.onlyReply(), SUBKEY)).toBe(true);
  });
});

describe('§22.1 — reply addressing', () => {
  it('falls back to the body correlation when the delivery carries no property', async () => {
    // The AMQP property is the RPC convention; what the server AUTHENTICATES is
    // the correlation_id inside the signed body, so a delivery missing the
    // property is answerable — it just cannot echo what it was not given.
    const body = sign(eventBody());
    const channel = new RecordingChannel();
    await dispatchReactorDelivery(
      channel,
      message(body, { replyTo: 'amq.reply-to.abc' }),
      context(),
      () => allow(),
    );

    expect(channel.published[0]!.correlationId).toBe(body.correlation_id);
    expect(channel.onlyReply().correlation_id).toBe(body.correlation_id);
  });
});

describe('§22.3 / §22.10 rule 4 — a reply whose window closed is not published', () => {
  it('abandons the reply rather than answering late', async () => {
    // The handler returns in time, but the clock crosses the deadline while the
    // answer is being built. §22.3: a late reply is discarded, and the CPU spent
    // producing it was spent for nothing — do not spend the network on it too.
    const realNow = Date.now.bind(Date);
    let jumped = false;
    vi.spyOn(Date, 'now').mockImplementation(() => (jumped ? realNow() + 60_000 : realNow()));

    const channel = new RecordingChannel();
    await dispatchReactorDelivery(
      channel,
      message(sign(eventBody({ timeout_ms: 5_000 }))),
      context(),
      () => {
        jumped = true;
        return allow();
      },
    );

    expect(channel.published).toHaveLength(0);
    expect(channel.acked).toBe(1);
  });
});

describe('§19 — telemetry reports the no-reply outcome as a failure', () => {
  it('emits requestEnd outcome "failure" when the handler throws a non-Error', async () => {
    const events: Array<Record<string, unknown>> = [];
    const channel = new RecordingChannel();

    await dispatchReactorDelivery(
      channel,
      message(sign(eventBody({ event: REACTOR_EVENTS.USER_PRE_CREATE }))),
      context({
        telemetry: new TelemetryDispatcher((e) =>
          events.push(e as unknown as Record<string, unknown>),
        ),
      }),
      () => {
        // Not an Error. The runtime must still fail closed, and the thrown
        // value must not become part of a synthesized answer.
        throw 'a bare string';
      },
    );

    expect(channel.published).toHaveLength(0);
    expect(events.map((e) => e.type)).toEqual(['requestStart', 'requestEnd']);
    expect(events[1]!.outcome).toBe('failure');
    expect(events[1]!.pathTemplate).toBe('user.pre_create');
  });
});

describe('§22.10 rule 2 — a handler that throws a non-Error still fails closed', () => {
  it('renders the thrown value into the log without letting it become an answer', async () => {
    const lines: string[] = [];
    const logger = {
      warn(event: string, msg: string, ctxObj?: Record<string, unknown>) {
        lines.push(`${event} ${msg} ${JSON.stringify(ctxObj ?? {})}`);
      },
    };

    // Thrown synchronously: the value never passes through the deadline
    // wrapper, so the dispatch path is the one that has to stringify it.
    const sync = new RecordingChannel();
    await dispatchReactorDelivery(sync, message(sign(eventBody())), context({ logger }), () => {
      throw 'a bare string';
    });

    // Rejected asynchronously: the deadline wrapper normalizes it to an Error
    // first, so the two paths are genuinely different code.
    const async = new RecordingChannel();
    await dispatchReactorDelivery(async, message(sign(eventBody())), context({ logger }), () =>
      Promise.reject('a bare rejection'),
    );

    expect(sync.published).toHaveLength(0);
    expect(async.published).toHaveLength(0);
    expect(sync.acked).toBe(1);
    expect(async.acked).toBe(1);

    const log = lines.join('\n');
    expect(log).toContain('a bare string');
    expect(log).toContain('a bare rejection');
    // Whatever was thrown, no `allow` was synthesized on the handler's behalf.
    expect(log).not.toContain('"decision"');
  });
});

describe('§22.5 — a listener publishes nothing even when it mutates', () => {
  it('drops a mutation answer on the floor and acks', async () => {
    const channel = new RecordingChannel();
    await dispatchReactorDelivery(
      channel,
      message(sign(eventBody({ event: REACTOR_EVENTS.TOKEN_PRE_ISSUE }))),
      context({ mode: 'listen' }),
      () => mutate({ 'ext.department': 'eng' }),
    );
    expect(channel.published).toHaveLength(0);
    expect(channel.acked).toBe(1);
  });
});
