// CONTRACT.md 1.69 §8 (D-8, D-9, D-10): the event consumer is typed, logs one fixed event for every
// discard, in the normative reason order, and no body (a byte-order mark included) escapes it.

import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { signPayload } from '../../src/amqp/hmac.js';
import {
  InMemoryNonceStore,
  verifyAndDispatch,
  type ConsumeChannel,
  type ConsumeOptions,
  type EventType,
} from '../../src/amqp/consumer.js';

interface Vector {
  canonical_signed_json: string;
  hmac_signature_hex: string;
  wire_json: string;
}
const vectors = JSON.parse(readFileSync(new URL('../../testdata/v2_reference_vectors.json', import.meta.url), 'utf8')) as {
  tenant_id: string;
  hkdf: { derived_subkey_hex: string };
  authz_request: Vector;
  audit_event: Vector;
};
const SUBKEY = Buffer.from(vectors.hkdf.derived_subkey_hex, 'hex');
const CONFIGURED_TENANT = 'cccccccc-cccc-cccc-cccc-cccccccccccc';

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-07-10T12:00:30Z'));
});
afterEach(() => {
  vi.useRealTimers();
});

class Channel implements ConsumeChannel {
  acked = 0;
  nacked: Array<[boolean, boolean]> = [];
  async consume(): Promise<unknown> {
    throw new Error('unused');
  }
  ack(): void {
    this.acked += 1;
  }
  nack(_m: ConsumeMessage, allUpTo: boolean, requeue: boolean): void {
    this.nacked.push([allUpTo, requeue]);
  }
}
const message = (content: Buffer | string): ConsumeMessage =>
  ({
    content: Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8'),
    fields: { deliveryTag: 1, redelivered: false, exchange: 'axiam.events', routingKey: 'axiam.audit.events', consumerTag: 't' },
    properties: {},
  }) as unknown as ConsumeMessage;

type Event = { event: string; message: string; context: Record<string, unknown> };
function setup(eventType: EventType, extra: Partial<ConsumeOptions> = {}) {
  const channel = new Channel();
  const events: Event[] = [];
  const handler = vi.fn(async (_e: Record<string, unknown>) => {});
  const options = {
    tenantId: CONFIGURED_TENANT,
    eventType,
    nonceStore: new InMemoryNonceStore(),
    logger: { warn: (event: string, m: string, context?: Record<string, unknown>) => void events.push({ event, message: m, context: context ?? {} }) },
    ...extra,
  } as ConsumeOptions;
  const run = (content: Buffer | string) => verifyAndDispatch(channel, message(content), SUBKEY, handler, options);
  return { channel, events, handler, run };
}
const sign = (canonical: string): string =>
  `${canonical.slice(0, -1)},"hmac_signature":"${signPayload(SUBKEY, Buffer.from(canonical, 'utf8'))}"}`;
const flipLastHexDigit = (wire: string): string => {
  const i = wire.lastIndexOf('"}') - 1;
  return `${wire.slice(0, i)}${wire[i] === '0' ? '1' : '0'}${wire.slice(i + 1)}`;
};
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const NACK: Array<[boolean, boolean]> = [[false, false]];

describe('D-9 typed consume', () => {
  it.each([
    ['AuthzRequest', 'audit_event'],
    ['AuditEventMessage', 'authz_request'],
  ] as const)('a %s consumer refuses the %s vector as malformed, before the HMAC', async (type, other) => {
    const { channel, events, handler, run } = setup(type);
    await run(vectors[other].wire_json);
    expect(handler).not.toHaveBeenCalled();
    expect(channel.nacked).toEqual(NACK);
    expect(events).toHaveLength(1);
    expect(events[0].context.reason).toBe('malformed');
  });

  it.each([
    ['AuthzRequest', 'audit_event'],
    ['AuditEventMessage', 'authz_request'],
  ] as const)('a %s consumer still says malformed (not signature) with one signature digit changed', async (type, other) => {
    const { channel, events, handler, run } = setup(type);
    await run(flipLastHexDigit(vectors[other].wire_json));
    expect(handler).not.toHaveBeenCalled();
    expect(channel.nacked).toEqual(NACK);
    expect(events.map((e) => e.context.reason)).toEqual(['malformed']);
  });

  it.each([
    ['AuthzRequest', 'authz_request'],
    ['AuditEventMessage', 'audit_event'],
  ] as const)('a %s consumer accepts its own vector', async (type, own) => {
    const { channel, events, handler, run } = setup(type);
    await run(vectors[own].wire_json);
    expect(events).toEqual([]);
    expect(channel.acked).toBe(1);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('the handler is never given a body chosen by its layout: the typed check precedes the HMAC', async () => {
    // an AuthzResponse-shaped body, correctly signed, is another type
    const { handler, events, run } = setup('AuthzRequest');
    await run(sign('{"correlation_id":"a","allowed":true,"tenant_id":"t","nonce":"n"}'));
    expect(handler).not.toHaveBeenCalled();
    expect(events.map((e) => e.context.reason)).toEqual(['malformed']);
  });
});

describe('D-8 the discard event', () => {
  it('malformed, unsigned and signature carry exactly the five members, the configured tenant, and no secret', async () => {
    const cases: Array<[string, Buffer | string, string]> = [
      ['malformed', 'not json', 'malformed'],
      ['unsigned', vectors.authz_request.canonical_signed_json, 'unsigned'],
      ['signature', flipLastHexDigit(vectors.authz_request.wire_json), 'signature'],
    ];
    for (const [, body, reason] of cases) {
      const { events, run } = setup('AuthzRequest');
      await run(body);
      expect(events).toHaveLength(1);
      expect(events[0].event).toBe('axiam_sdk.security');
      const ctx = events[0].context;
      expect(Object.keys(ctx).sort()).toEqual(['exchange', 'reason', 'routingKey', 'tenantId', 'timestamp']);
      expect(ctx).toMatchObject({ exchange: 'axiam.events', routingKey: 'axiam.audit.events', tenantId: CONFIGURED_TENANT, reason });
      expect(ctx.timestamp).toBe('2026-07-10T12:00:30.000Z');
      const dump = JSON.stringify(events);
      expect(dump).not.toContain(vectors.authz_request.hmac_signature_hex);
      expect(dump).not.toContain('55555555-5555-5555-5555-555555555555');
      expect(dump).not.toContain(vectors.tenant_id); // never the body's tenant
    }
  });

  it('reason order: (1) not an object, (2) unsigned whatever else is wrong, (3) layout, (4) HMAC, (5) decode, (6) key_version, (7) stale, (8) replay', async () => {
    const good = JSON.parse(vectors.authz_request.canonical_signed_json) as Record<string, unknown>;
    const wireOf = (over: Record<string, unknown>) => sign(JSON.stringify({ ...good, ...over }));
    const reasonOf = async (body: Buffer | string, extra: Partial<ConsumeOptions> = {}) => {
      const { events, run } = setup('AuthzRequest', extra);
      await run(body);
      return events.map((e) => e.context.reason);
    };
    expect(await reasonOf(' ' + vectors.authz_request.wire_json)).toEqual(['malformed']); // whitespace prefix
    expect(await reasonOf(vectors.authz_request.wire_json + ' ')).toEqual(['malformed']); // trailing content
    expect(await reasonOf('{"a":1,"a":2}')).toEqual(['unsigned']); // (2) before the duplicate member of (3)
    expect(await reasonOf('{"subject_id":"x"}')).toEqual(['unsigned']);
    expect(await reasonOf(vectors.authz_request.wire_json.replace('"hmac_signature":"', '"hmac_signature":"0'))).toEqual(['malformed']); // 65 hex
    expect(await reasonOf(flipLastHexDigit(vectors.audit_event.wire_json))).toEqual(['malformed']); // (3) before (4)
    expect(await reasonOf(flipLastHexDigit(vectors.authz_request.wire_json))).toEqual(['signature']);
    expect(await reasonOf(wireOf({ key_version: '2' }))).toEqual(['malformed']); // (5) correctly signed, ill-typed
    expect(await reasonOf(wireOf({ nonce: 'not-a-uuid' }))).toEqual(['malformed']);
    expect(await reasonOf(wireOf({ issued_at: 'yesterday' }))).toEqual(['malformed']);
    expect(await reasonOf(wireOf({ key_version: 1, issued_at: '2020-01-01T00:00:00Z' }))).toEqual(['key_version']); // (6) before (7)
    expect(await reasonOf(wireOf({ issued_at: '2020-01-01T00:00:00Z' }))).toEqual(['stale']);
  });

  it('(8) replay is the last gate, and the nonce is recorded only when every gate passed', async () => {
    const nonceStore = new InMemoryNonceStore();
    const good = JSON.parse(vectors.authz_request.canonical_signed_json) as Record<string, unknown>;
    const { events, handler, run } = setup('AuthzRequest', { nonceStore });
    // refused as stale: leaves no nonce behind
    await run(sign(JSON.stringify({ ...good, issued_at: '2020-01-01T00:00:00Z' })));
    expect(nonceStore.checkAndRecord('55555555-5555-5555-5555-555555555555', 1000)).toBe(false);
    const fresh = new InMemoryNonceStore();
    const second = setup('AuthzRequest', { nonceStore: fresh });
    await second.run(vectors.authz_request.wire_json);
    await second.run(vectors.authz_request.wire_json);
    expect(second.handler).toHaveBeenCalledTimes(1);
    expect(second.events.map((e) => e.context.reason)).toEqual(['replay']);
    expect(events.map((e) => e.context.reason)).toEqual(['stale']);
    expect(handler).not.toHaveBeenCalled();
  });
});

describe('D-10 no body escapes the consumer', () => {
  it('BOM + a valid vector is malformed, never stripped, no exception, and the next delivery is processed', async () => {
    for (const type of ['AuthzRequest', 'AuditEventMessage'] as const) {
      const own = type === 'AuthzRequest' ? vectors.authz_request : vectors.audit_event;
      const { channel, events, handler, run } = setup(type);
      await expect(run(Buffer.concat([BOM, Buffer.from(own.wire_json, 'utf8')]))).resolves.toBeUndefined();
      expect(handler).not.toHaveBeenCalled();
      expect(channel.nacked).toEqual(NACK);
      expect(events.map((e) => e.context.reason)).toEqual(['malformed']);
      await run(own.wire_json);
      expect(handler).toHaveBeenCalledTimes(1);
      expect(channel.acked).toBe(1);
    }
  });

  it.each([
    ['empty', Buffer.alloc(0)],
    ['not UTF-8', Buffer.from([0xff, 0xfe, 0x7b])],
    ['deeply nested', Buffer.from('['.repeat(200000))],
    ['truncated', Buffer.from(vectors.authz_request.wire_json.slice(0, 50))],
  ])('%s is malformed with one event', async (_n, body) => {
    const { channel, events, run } = setup('AuthzRequest');
    await expect(run(body)).resolves.toBeUndefined();
    expect(channel.nacked).toEqual(NACK);
    expect(events.map((e) => e.context.reason)).toEqual(['malformed']);
  });

  it('a logger that throws cannot strand the delivery or reject', async () => {
    const { channel, run } = setup('AuthzRequest', {
      logger: {
        warn: () => {
          throw new Error('boom');
        },
      },
    });
    await expect(run('nope')).resolves.toBeUndefined();
    expect(channel.nacked).toEqual(NACK);
  });

  it('exchange and routing key are exactly as the broker reported them: "" and "0" are kept (unsigned and signature paths)', async () => {
    for (const [exchange, routingKey] of [['', ''], ['', '0']]) {
      for (const [body, reason] of [
        [vectors.authz_request.canonical_signed_json, 'unsigned'],
        [flipLastHexDigit(vectors.authz_request.wire_json), 'signature'],
      ]) {
        const { events, run: _r } = setup('AuthzRequest');
        const msg = message(body);
        msg.fields.exchange = exchange;
        msg.fields.routingKey = routingKey;
        await verifyAndDispatch(new Channel(), msg, SUBKEY, async () => {}, {
          tenantId: CONFIGURED_TENANT,
          eventType: 'AuthzRequest',
          nonceStore: new InMemoryNonceStore(),
          logger: { warn: (_e, _m, c) => void events.push({ event: _e, message: _m, context: c ?? {} }) },
        });
        expect(events).toHaveLength(1);
        expect(Object.keys(events[0].context).sort()).toEqual(['exchange', 'reason', 'routingKey', 'tenantId', 'timestamp']);
        expect(events[0].context).toMatchObject({ exchange, routingKey, tenantId: CONFIGURED_TENANT, reason });
      }
    }
  });
});
