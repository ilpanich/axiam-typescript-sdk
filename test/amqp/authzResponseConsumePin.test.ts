// N2 validation pin (SA-20). Before contract 1.68 this SDK shipped no
// AuthzRequest publisher and no AuthzResponse reader; the only AMQP read path
// is the generic `consume()`/`verifyAndDispatch()`. These cases show that path
// never hands an application an authorization response — signed, forged or
// unsigned — because a response carries none of the §8 v2 replay fields its
// gates require. They pass on the code before SA-20 and must keep passing:
// `AuthzRequester` / `AuthzResponseVerifier` are the only way to read a response.

import { describe, expect, it, vi } from 'vitest';
import type { ConsumeMessage } from 'amqplib';
import { verifyAndDispatch } from '../../src/amqp/consumer.js';

const SUBKEY = Buffer.from('919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89', 'hex');

function message(body: string): ConsumeMessage {
  return {
    content: Buffer.from(body, 'utf8'),
    fields: { exchange: '', routingKey: 'axiam.authz.response' },
    properties: {},
  } as unknown as ConsumeMessage;
}

async function delivered(body: string): Promise<boolean> {
  const channel = { consume: vi.fn(), ack: vi.fn(), nack: vi.fn() };
  const handler = vi.fn(async () => {});
  await verifyAndDispatch(channel, message(body), SUBKEY, handler);
  return handler.mock.calls.length > 0;
}

describe('N2 pin — consume() never delivers an AuthzResponse', () => {
  it('a forged unsigned allow (1.67 shape) is not delivered', async () => {
    const forged = '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true}';
    expect(await delivered(forged)).toBe(false);
  });

  it('the genuine signed vector 1 is not delivered either (no replay fields)', async () => {
    const v1 =
      '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true,"reason_code":"allowed","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555","hmac_signature":"8d81f0437df6c6fffafd13f4265bd41d3cfd6fcbf7c251b3bb79e0846578574a"}';
    expect(await delivered(v1)).toBe(false);
  });
});
