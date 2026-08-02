// verifyWebhook — CONTRACT.md §13, T-145. Required test list (spec §"Required tests"):
//   1. valid signature + fresh timestamp -> accepted
//   2. tampered body (one byte flipped) -> rejected
//   3. wrong secret -> rejected
//   4. stale timestamp -> rejected
//   5. future timestamp beyond tolerance -> rejected
//   6. malformed header (no v1, t non-numeric, empty) -> rejected
//   7. cross-SDK pin: compute v1 for the shared fixture vector in test setup
//      (never copy a hardcoded hex value) and assert verify() accepts it.
import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { Sensitive } from '../../src/core/sensitive.js';
import {
  DEFAULT_WEBHOOK_TOLERANCE_SEC,
  verifyWebhook,
  WebhookVerifyError,
} from '../../src/node/webhook.js';

function sign(secret: string, timestamp: number, body: string): string {
  const hex = createHmac('sha256', Buffer.from(secret, 'utf8'))
    .update(`${timestamp}.${body}`, 'utf8')
    .digest('hex');
  return `t=${timestamp},v1=${hex}`;
}

const SECRET = 'whsec_test_secret_abc123';
const TIMESTAMP = 1785700000;
const BODY = '{"event":"user.created","id":"evt_1"}';

describe('verifyWebhook', () => {
  it('1. accepts a valid signature with a fresh timestamp', () => {
    const header = sign(SECRET, TIMESTAMP, BODY);
    const result = verifyWebhook(new Sensitive(SECRET), header, BODY, { now: TIMESTAMP + 5 });
    expect(result.event).toBe('user.created');
    expect(result.id).toBe('evt_1');
    expect(result.timestamp).toBe(TIMESTAMP);
    expect(result.body).toEqual({ event: 'user.created', id: 'evt_1' });
    expect(result.rawBody.toString('utf8')).toBe(BODY);
  });

  it('accepts raw body bytes (Buffer) identically to the raw string', () => {
    const header = sign(SECRET, TIMESTAMP, BODY);
    const result = verifyWebhook(new Sensitive(SECRET), header, Buffer.from(BODY, 'utf8'), {
      now: TIMESTAMP,
    });
    expect(result.event).toBe('user.created');
  });

  it('2. rejects a tampered body (one byte flipped)', () => {
    const header = sign(SECRET, TIMESTAMP, BODY);
    const tampered = BODY.replace('user.created', 'user.deleted');
    expect(() => verifyWebhook(new Sensitive(SECRET), header, tampered, { now: TIMESTAMP })).toThrow(
      WebhookVerifyError,
    );
    try {
      verifyWebhook(new Sensitive(SECRET), header, tampered, { now: TIMESTAMP });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(WebhookVerifyError);
      expect((err as WebhookVerifyError).reason).toBe('signature_mismatch');
    }
  });

  it('3. rejects a signature computed with the wrong secret', () => {
    const header = sign('a-different-secret', TIMESTAMP, BODY);
    expect(() => verifyWebhook(new Sensitive(SECRET), header, BODY, { now: TIMESTAMP })).toThrow(
      WebhookVerifyError,
    );
  });

  it('4. rejects a stale timestamp (now - t > tolerance)', () => {
    const header = sign(SECRET, TIMESTAMP, BODY);
    const now = TIMESTAMP + DEFAULT_WEBHOOK_TOLERANCE_SEC + 1;
    expect(() => verifyWebhook(new Sensitive(SECRET), header, BODY, { now })).toThrowError(
      expect.objectContaining({ reason: 'stale_timestamp' }),
    );
  });

  it('accepts a timestamp exactly at the tolerance boundary (two-sided, inclusive)', () => {
    const header = sign(SECRET, TIMESTAMP, BODY);
    const now = TIMESTAMP + DEFAULT_WEBHOOK_TOLERANCE_SEC;
    expect(() => verifyWebhook(new Sensitive(SECRET), header, BODY, { now })).not.toThrow();
  });

  it('5. rejects a future timestamp beyond tolerance', () => {
    const header = sign(SECRET, TIMESTAMP, BODY);
    const now = TIMESTAMP - DEFAULT_WEBHOOK_TOLERANCE_SEC - 1;
    expect(() => verifyWebhook(new Sensitive(SECRET), header, BODY, { now })).toThrowError(
      expect.objectContaining({ reason: 'future_timestamp' }),
    );
  });

  it('honors a caller-supplied tolerance override', () => {
    const header = sign(SECRET, TIMESTAMP, BODY);
    // 10s stale, default tolerance (300s) would accept it — a tight 5s
    // tolerance must not.
    const now = TIMESTAMP + 10;
    expect(() =>
      verifyWebhook(new Sensitive(SECRET), header, BODY, { now, tolerance: 5 }),
    ).toThrowError(expect.objectContaining({ reason: 'stale_timestamp' }));
  });

  describe('6. malformed header', () => {
    it('rejects a header with no v1 field', () => {
      expect(() =>
        verifyWebhook(new Sensitive(SECRET), `t=${TIMESTAMP}`, BODY, { now: TIMESTAMP }),
      ).toThrowError(expect.objectContaining({ reason: 'malformed_header' }));
    });

    it('rejects a header whose t is non-numeric', () => {
      const validHex = createHmac('sha256', Buffer.from(SECRET, 'utf8'))
        .update(`${TIMESTAMP}.${BODY}`, 'utf8')
        .digest('hex');
      expect(() =>
        verifyWebhook(new Sensitive(SECRET), `t=not-a-number,v1=${validHex}`, BODY, {
          now: TIMESTAMP,
        }),
      ).toThrowError(expect.objectContaining({ reason: 'invalid_timestamp' }));
    });

    it('rejects an empty header', () => {
      expect(() => verifyWebhook(new Sensitive(SECRET), '', BODY, { now: TIMESTAMP })).toThrowError(
        expect.objectContaining({ reason: 'malformed_header' }),
      );
    });

    it('rejects a header with no t field', () => {
      const validHex = createHmac('sha256', Buffer.from(SECRET, 'utf8'))
        .update(`${TIMESTAMP}.${BODY}`, 'utf8')
        .digest('hex');
      expect(() =>
        verifyWebhook(new Sensitive(SECRET), `v1=${validHex}`, BODY, { now: TIMESTAMP }),
      ).toThrowError(expect.objectContaining({ reason: 'malformed_header' }));
    });

    it('rejects a header with two t fields', () => {
      const validHex = createHmac('sha256', Buffer.from(SECRET, 'utf8'))
        .update(`${TIMESTAMP}.${BODY}`, 'utf8')
        .digest('hex');
      expect(() =>
        verifyWebhook(new Sensitive(SECRET), `t=${TIMESTAMP},t=${TIMESTAMP + 1},v1=${validHex}`, BODY, {
          now: TIMESTAMP,
        }),
      ).toThrowError(expect.objectContaining({ reason: 'malformed_header' }));
    });

    it('fails closed on non-hex v1 garbage rather than throwing from timingSafeEqual', () => {
      expect(() =>
        verifyWebhook(new Sensitive(SECRET), `t=${TIMESTAMP},v1=not-hex-at-all`, BODY, {
          now: TIMESTAMP,
        }),
      ).toThrowError(expect.objectContaining({ reason: 'signature_mismatch' }));
    });

    it('fails closed on an odd-length (truncated) v1 hex value', () => {
      expect(() =>
        verifyWebhook(new Sensitive(SECRET), `t=${TIMESTAMP},v1=abc`, BODY, { now: TIMESTAMP }),
      ).toThrowError(expect.objectContaining({ reason: 'signature_mismatch' }));
    });

    it('ignores unknown scheme keys (forward compatibility) alongside a valid v1', () => {
      const header = `${sign(SECRET, TIMESTAMP, BODY)},v2=some-future-scheme-value`;
      expect(() => verifyWebhook(new Sensitive(SECRET), header, BODY, { now: TIMESTAMP })).not.toThrow();
    });

    it('accepts when at least one of several v1 candidates matches', () => {
      const validHex = createHmac('sha256', Buffer.from(SECRET, 'utf8'))
        .update(`${TIMESTAMP}.${BODY}`, 'utf8')
        .digest('hex');
      const header = `t=${TIMESTAMP},v1=deadbeef,v1=${validHex}`;
      expect(() => verifyWebhook(new Sensitive(SECRET), header, BODY, { now: TIMESTAMP })).not.toThrow();
    });
  });

  it('never surfaces the expected/computed signature or the secret in the error', () => {
    const header = sign(SECRET, TIMESTAMP, BODY);
    const tampered = BODY.replace('user.created', 'user.deleted');
    try {
      verifyWebhook(new Sensitive(SECRET), header, tampered, { now: TIMESTAMP });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(WebhookVerifyError);
      const message = (err as Error).message;
      expect(message).not.toContain(SECRET);
      // Neither the header's v1 hex nor the freshly recomputed one may leak.
      const headerHex = header.split('v1=')[1];
      expect(message).not.toContain(headerHex);
    }
  });

  it("doesn't fail signature verification just because the body isn't JSON — event/id are simply absent", () => {
    const nonJsonBody = 'not-json-at-all';
    const header = sign(SECRET, TIMESTAMP, nonJsonBody);
    const result = verifyWebhook(new Sensitive(SECRET), header, nonJsonBody, { now: TIMESTAMP });
    expect(result.event).toBeUndefined();
    expect(result.id).toBeUndefined();
    expect(result.rawBody.toString('utf8')).toBe(nonJsonBody);
  });

  it('7. cross-SDK pin — computes v1 for the shared spec vector locally and accepts it (never hardcode the hex)', () => {
    // Shared fixture vector (webhook-verifier-spec.md / CONTRACT.md §13.4),
    // identical across all 11 SDKs' test suites — each SDK computes v1 with
    // its own HMAC-SHA256 in test setup, never copies a hex value from a
    // fixture file, so this is a real cross-implementation pin rather than a
    // shared constant.
    const vectorSecret = 'whsec_test_0123456789abcdef';
    const vectorTimestamp = 1785700000;
    const vectorBody = '{"event":"user.created","id":"01JQ0000000000000000000000"}';

    const vectorHex = createHmac('sha256', Buffer.from(vectorSecret, 'utf8'))
      .update(`${vectorTimestamp}.${vectorBody}`, 'utf8')
      .digest('hex');
    const header = `t=${vectorTimestamp},v1=${vectorHex}`;

    const result = verifyWebhook(new Sensitive(vectorSecret), header, vectorBody, {
      now: vectorTimestamp,
    });
    expect(result.event).toBe('user.created');
    expect(result.id).toBe('01JQ0000000000000000000000');

    // Separately assert a byte-flipped body against the same header is
    // rejected, per the spec's explicit instruction alongside the pin.
    const flippedBody = vectorBody.replace('user.created', 'user.dreated');
    expect(() =>
      verifyWebhook(new Sensitive(vectorSecret), header, flippedBody, { now: vectorTimestamp }),
    ).toThrow(WebhookVerifyError);
  });
});
