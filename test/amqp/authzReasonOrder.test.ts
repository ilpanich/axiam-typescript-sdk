// CONTRACT.md 1.69 §8 consumer obligation 4: the normative reason order of the AuthzResponse
// requester, the after-Close rule, and the producer's wire form (`authz_request.wire_json`).

import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { Sensitive } from '../../src/core/index.js';
import { buildAuthzRequest, createAuthzRequester, type AuthzRequesterChannel } from '../../src/amqp/authzRequester.js';
import { AuthzResponseVerifier } from '../../src/amqp/authzResponse.js';

const vectors = JSON.parse(readFileSync(new URL('../../testdata/v2_reference_vectors.json', import.meta.url), 'utf8')) as {
  hkdf: { derived_subkey_hex: string };
  authz_request: { message: Record<string, string>; wire_json: string };
};
const SUBKEY = Buffer.from(vectors.hkdf.derived_subkey_hex, 'hex');
const OPTS = { tenantId: '99999999-9999-9999-9999-999999999999', eventType: 'AuthzRequest' } as const;
const TENANT = '11111111-1111-1111-1111-111111111111';
const OTHER = '99999999-9999-9999-9999-999999999999';
const CID = '22222222-2222-2222-2222-222222222222';
const NONCE = '55555555-5555-5555-5555-555555555555';

const sign = (canonical: string): string => createHmac('sha256', SUBKEY).update(Buffer.from(canonical, 'utf8')).digest('hex');
const wire = (canonical: string): Buffer => Buffer.from(`${canonical.slice(0, -1)},"hmac_signature":"${sign(canonical)}"}`, 'utf8');
const full = (over: Partial<Record<string, string>> = {}): string =>
  `{"correlation_id":"${over.cid ?? CID}","allowed":true,"tenant_id":"${over.tenant ?? TENANT}","nonce":"${over.nonce ?? NONCE}"}`;

function verifier() {
  const logger = { warn: vi.fn() };
  const v = new AuthzResponseVerifier({ subkey: new Sensitive(SUBKEY), tenantId: TENANT, logger });
  v.expect({ correlation_id: CID, nonce: NONCE, tenant_id: TENANT });
  return { v, logger };
}
const reasonOf = (body: Buffer | string): string => {
  const { v } = verifier();
  const verdict = v.verify(Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8'));
  return verdict.accepted ? 'accepted' : verdict.reason;
};
const BADSIG = `,"hmac_signature":"${'0'.repeat(64)}"}`;

describe('§8 obligation 4 — normative reason order', () => {
  it('(1) not one JSON object is malformed', () => {
    expect(reasonOf('nope')).toBe('malformed');
    expect(reasonOf('[]')).toBe('malformed');
  });
  it('(2) no hmac_signature member is unsigned, whatever else is missing', () => {
    expect(reasonOf('{"correlation_id":"x"}')).toBe('unsigned');
    expect(reasonOf('{}')).toBe('unsigned');
    expect(reasonOf(full())).toBe('unsigned');
  });
  it('(3) a bad signature member is malformed', () => {
    expect(reasonOf(`${full().slice(0, -1)},"hmac_signature":null}`)).toBe('malformed');
    expect(reasonOf(`${full().slice(0, -1)},"hmac_signature":"abcd"}`)).toBe('malformed');
    expect(reasonOf(`{"hmac_signature":"${'0'.repeat(64)}",${full().slice(1)}`)).toBe('malformed');
  });
  it.each([
    ['allowed missing', '{"correlation_id":"%C","tenant_id":"%T","nonce":"%N"'],
    ['tenant_id missing', '{"correlation_id":"%C","allowed":true,"nonce":"%N"'],
    ['nonce missing', '{"correlation_id":"%C","allowed":true,"tenant_id":"%T"'],
    ['correlation_id missing', '{"allowed":true,"tenant_id":"%T","nonce":"%N"'],
    ['allowed ill-typed', '{"correlation_id":"%C","allowed":"yes","tenant_id":"%T","nonce":"%N"'],
  ])('(3) %s with a WRONG signature is malformed, not signature', (_l, tpl) => {
    const canonical = tpl.replace('%C', CID).replace('%T', TENANT).replace('%N', NONCE) + '}';
    expect(reasonOf(`${canonical.slice(0, -1)}${BADSIG}`)).toBe('malformed');
    expect(reasonOf(wire(canonical))).toBe('malformed');
  });
  it('(4) a well-formed body with a wrong HMAC is signature', () => {
    expect(reasonOf(`${full().slice(0, -1)}${BADSIG}`)).toBe('signature');
  });
  it('(5) wrong tenant is tenant, (6) no outstanding request is unknown_request', () => {
    expect(reasonOf(wire(full({ tenant: OTHER })))).toBe('tenant');
    expect(reasonOf(wire(full({ nonce: '66666666-6666-6666-6666-666666666666' })))).toBe('unknown_request');
    expect(reasonOf(wire(full()))).toBe('accepted');
  });
});

class Channel implements AuthzRequesterChannel {
  published: Array<{ content: Buffer }> = [];
  nacks: Array<[boolean, boolean]> = [];
  onMessage: ((msg: ConsumeMessage | null) => void) | undefined;
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
  ack(): void {}
  nack(_m: ConsumeMessage, allUpTo: boolean, requeue: boolean): void {
    this.nacks.push([allUpTo, requeue]);
  }
  async cancel(): Promise<void> {}
}

describe('§8 obligation 4 — after Close', () => {
  it('an answer delivered after close() is not decoded or dispatched, is nacked without requeue, and logs no event', async () => {
    const ch = new Channel();
    const logger = { warn: vi.fn() };
    const r = await createAuthzRequester(ch, { tenantId: TENANT, subkey: new Sensitive(SUBKEY), logger });
    const pending = r.check({ subjectId: '33333333-3333-3333-3333-333333333333', action: 'a', resourceId: '44444444-4444-4444-4444-444444444444' });
    pending.catch(() => {});
    const pub = JSON.parse(ch.published[0].content.toString('utf8')) as { correlation_id: string; nonce: string };
    await r.close();
    const answer = wire(full({ cid: pub.correlation_id, nonce: pub.nonce }));
    const parse = vi.spyOn(JSON, 'parse');
    ch.onMessage!({ content: answer, fields: { exchange: '', routingKey: 'amq.gen-q' }, properties: {} } as unknown as ConsumeMessage);
    expect(parse).not.toHaveBeenCalled();
    parse.mockRestore();
    expect(ch.nacks).toEqual([[false, false]]);
    expect(logger.warn).not.toHaveBeenCalled();
  });
});

describe('§8 rule 2 — producer wire form', () => {
  it('buildAuthzRequest emits authz_request.wire_json byte for byte for the vector inputs', () => {
    const m = vectors.authz_request.message;
    const out = buildAuthzRequest(SUBKEY, {
      correlationId: m.correlation_id,
      tenantId: m.tenant_id,
      subjectId: m.subject_id,
      action: m.action,
      resourceId: m.resource_id,
      scope: m.scope,
      nonce: m.nonce,
      issuedAt: new Date(m.issued_at),
    });
    expect(out.toString('utf8')).toBe(vectors.authz_request.wire_json);
  });
});

describe('review round 1', () => {
  it('a BOM-prefixed body is nacked without requeue, the handler never runs and the call does not reject', async () => {
    const { verifyAndDispatch } = await import('../../src/amqp/consumer.js');
    const body = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(`{"a":1,"hmac_signature":"${'0'.repeat(64)}"}`, 'utf8')]);
    const nacks: Array<[boolean, boolean]> = [];
    const channel = { consume: vi.fn(), ack: vi.fn(), nack: (_m: unknown, a: boolean, r: boolean) => nacks.push([a, r]) };
    const handler = vi.fn(async () => {});
    const msg = { content: body, fields: { exchange: '', routingKey: 'k' }, properties: {} } as unknown as ConsumeMessage;
    await expect(verifyAndDispatch(channel, msg, SUBKEY, handler, OPTS)).resolves.toBeUndefined();
    expect(handler).not.toHaveBeenCalled();
    expect(nacks).toEqual([[false, false]]);
  });

  it('a BOM-prefixed response body is malformed', () => {
    const w = wire(full());
    expect(reasonOf(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), w]))).toBe('malformed');
  });

  it('an ill-typed reason with a wrong HMAC is signature (normative order), with a right HMAC malformed', () => {
    const canonical = `{"correlation_id":"${CID}","allowed":true,"reason":5,"tenant_id":"${TENANT}","nonce":"${NONCE}"}`;
    expect(reasonOf(`${canonical.slice(0, -1)}${BADSIG}`)).toBe('signature');
    expect(reasonOf(wire(canonical))).toBe('malformed');
  });
});
