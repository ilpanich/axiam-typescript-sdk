// CONTRACT.md §22.13 — the required reactor tests, run against the
// server-generated vectors in `testdata/reactor_v2_reference_vectors.json`.
//
// Those vectors were produced by the AXIAM server's own reactor sign path and
// ship beside the §8 vectors, under the SAME master key, tenant and derived
// subkey — so the one loader below serves both files, exactly as §22.13
// intends. Nothing here hand-rolls an expectation: every byte string and every
// MAC is read from the fixture.

import { readFileSync } from 'node:fs';
import { createHmac, hkdfSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  REACTOR_EXCHANGE,
  buildReactorReply,
  canonicalEventBytes,
  canonicalReplyBytes,
  isFresh,
  reactorQueueName,
  reactorReplySignatureValid,
  reactorRoutingKey,
  signReactorReply,
  toChronoRfc3339,
  verifyEvent,
  type ReplyDecision,
} from '../../../src/amqp/reactor/index.js';
import {
  REACTOR_EVENTS,
  eventSpec,
  patchFieldAllowed,
} from '../../../src/amqp/reactor/registry.js';

// ---------------------------------------------------------------------------
// Fixture loading — one loader, two files (§22.13 preamble)
// ---------------------------------------------------------------------------

function load(name: string): Record<string, any> {
  return JSON.parse(
    readFileSync(new URL(`../../../testdata/${name}`, import.meta.url), 'utf8'),
  ) as Record<string, any>;
}

const reactorVectors = load('reactor_v2_reference_vectors.json');
const hmacVectors = load('v2_reference_vectors.json');

/** The tenant's HKDF-derived AMQP subkey, as both fixtures committed it. */
const SUBKEY = Buffer.from(reactorVectors.hkdf.derived_subkey_hex as string, 'hex');
const SKEW_MS = (reactorVectors.freshness_skew_secs as number) * 1000;
const VERIFIED_AT_MS = Date.parse(reactorVectors.verified_at as string);

/** HMAC-SHA256 computed here, so the assertions check the SDK's canonical BYTES. */
function hmacHex(key: Buffer, message: Buffer): string {
  return createHmac('sha256', key).update(message).digest('hex');
}

/**
 * The bytes the server actually put on the wire for an event vector.
 *
 * **Read this before reaching for `vector.message`.** The fixture stores each
 * `message` object with its keys in ALPHABETICAL order, because that is how the
 * generator's JSON writer emitted them; the authoritative wire order lives in
 * `canonical_signed_json`. Since the signed bytes are order-sensitive, a
 * verifier must be fed the wire body — which is exactly what a broker delivers
 * — and not the fixture's convenience copy.
 */
function eventWireBody(vector: Record<string, any>): Record<string, unknown> {
  const wire = (vector.canonical_signed_json as string).replace(
    '"hmac_signature":null',
    `"hmac_signature":"${vector.hmac_signature_hex as string}"`,
  );
  return JSON.parse(wire) as Record<string, unknown>;
}

/**
 * Rebuild a reply from a vector's `message` object through the SDK's own
 * builder, so the assertion exercises the field order and every omission rule.
 */
function replyFromVector(message: Record<string, any>) {
  return buildReactorReply(
    {
      correlation_id: message.correlation_id as string,
      tenant_id: message.tenant_id as string,
      event: message.event as string,
    },
    {
      decision: message.decision as ReplyDecision,
      reason: message.reason as string | undefined,
      patch: message.patch as Record<string, string> | undefined,
      requireMfa: message.require_mfa === true,
      nonce: message.nonce as string,
      issuedAt: new Date(message.issued_at as string),
    },
  );
}

describe('§22.13 — one loader serves both fixtures', () => {
  it('shares the master key, tenant and derived subkey with the §8 vectors', () => {
    expect(reactorVectors.master_signing_key_hex).toBe(hmacVectors.master_signing_key_hex);
    expect(reactorVectors.tenant_id).toBe(hmacVectors.tenant_id);
    expect(reactorVectors.hkdf.derived_subkey_hex).toBe(hmacVectors.hkdf.derived_subkey_hex);
    expect(reactorVectors.hkdf.app_salt_utf8).toBe(hmacVectors.hkdf.app_salt_utf8);
    expect(reactorVectors.hkdf.domain_tag_utf8).toBe(hmacVectors.hkdf.domain_tag_utf8);
    expect(reactorVectors.key_version).toBe(2);
  });

  it('derives that subkey with the §8 HKDF parameters, unchanged', () => {
    const master = Buffer.from(reactorVectors.master_signing_key_hex as string, 'hex');
    const salt = Buffer.from(reactorVectors.hkdf.app_salt_utf8 as string, 'utf8');
    const info = Buffer.concat([
      Buffer.from(reactorVectors.hkdf.domain_tag_utf8 as string, 'utf8'),
      Buffer.from([reactorVectors.key_version as number]),
      Buffer.from((reactorVectors.tenant_id as string).replace(/-/g, ''), 'hex'),
    ]);
    const derived = Buffer.from(hkdfSync('sha256', master, salt, info, 32));
    expect(derived.toString('hex')).toBe(reactorVectors.hkdf.derived_subkey_hex);
  });
});

describe('§22.1 — topology', () => {
  it('renders the exchange, queue and routing keys the fixture committed', () => {
    const tenant = reactorVectors.tenant_id as string;
    const reactor = reactorVectors.reactor_id as string;
    expect(REACTOR_EXCHANGE).toBe(reactorVectors.topology.exchange);
    expect(reactorVectors.topology.exchange_type).toBe('topic');
    expect(reactorQueueName(tenant, reactor)).toBe(reactorVectors.topology.queue);
    expect(reactorRoutingKey(tenant, REACTOR_EVENTS.TOKEN_PRE_ISSUE)).toBe(
      reactorVectors.topology.routing_key_token_pre_issue,
    );
    expect(reactorRoutingKey(tenant, REACTOR_EVENTS.LOGIN_POST_AUTH)).toBe(
      reactorVectors.topology.routing_key_login_post_auth,
    );
  });
});

describe('§22.13 — sign direction', () => {
  it('reproduces every committed reply vector byte-for-byte and recomputes its MAC', () => {
    let checked = 0;
    for (const group of ['reactor_to_server', 'rejected_replies']) {
      for (const [name, vector] of Object.entries(
        reactorVectors[group] as Record<string, any>,
      )) {
        if (!vector || typeof vector !== 'object' || !('message' in vector)) continue;
        // The `key_version_too_old` vector was downgraded to 1 AFTER signing, to
        // pin the server's rejection ORDER. This SDK's builder cannot reproduce
        // it and must not be able to: it always stamps the current version, so
        // there is no code path here that emits a body the server would refuse
        // on `key_version` alone. Asserted below rather than skipped silently.
        if ((vector.message as Record<string, any>).key_version < 2) {
          const stamped = replyFromVector(vector.message as Record<string, any>);
          expect(stamped.key_version, `${group}.${name}`).toBe(2);
          continue;
        }
        const reply = replyFromVector(vector.message as Record<string, any>);
        const bytes = canonicalReplyBytes(reply);
        expect(bytes.toString('utf8'), `${group}.${name}: canonical bytes`).toBe(
          vector.canonical_signed_json as string,
        );

        expect(hmacHex(SUBKEY, bytes), `${group}.${name}: MAC`).toBe(
          vector.hmac_signature_hex as string,
        );
        const signed = signReactorReply(reply, SUBKEY);
        expect(signed.hmac_signature).toBe(vector.hmac_signature_hex);
        expect(reactorReplySignatureValid(signed, SUBKEY)).toBe(true);
        checked += 1;
      }
    }
    expect(checked).toBeGreaterThanOrEqual(9);
  });

  it('omits require_mfa when false, and reason/patch when absent', () => {
    const reply = replyFromVector(reactorVectors.reactor_to_server.allow.message);
    expect(reply.require_mfa).toBeUndefined();

    const json = canonicalReplyBytes(reply).toString('utf8');
    expect(json).not.toContain('require_mfa');
    expect(json).not.toContain('reason');
    expect(json).not.toContain('patch');
    expect(json.endsWith('"hmac_signature":null}')).toBe(true);

    // And the other half: true IS serialized, right after `decision`.
    const mfa = replyFromVector(reactorVectors.reactor_to_server.require_mfa.message);
    expect(canonicalReplyBytes(mfa).toString('utf8')).toContain(
      '"decision":"allow","require_mfa":true',
    );
  });

  it('signs hmac_signature as null, not omitted — the §8 rule produces a different MAC', () => {
    const canonical = reactorVectors.reactor_to_server.allow.canonical_signed_json as string;
    const omitted = canonical.replace(',"hmac_signature":null', '');
    expect(omitted).not.toBe(canonical);
    expect(hmacHex(SUBKEY, Buffer.from(omitted, 'utf8'))).not.toBe(
      reactorVectors.reactor_to_server.allow.hmac_signature_hex,
    );
  });

  it('sorts patch keys, because the server signs a BTreeMap rendering', () => {
    const reply = buildReactorReply(
      { correlation_id: 'c', tenant_id: 't', event: REACTOR_EVENTS.TOKEN_PRE_ISSUE },
      { decision: 'mutate', patch: { 'ext.zebra': '1', 'ext.alpha': '2' } },
    );
    expect(canonicalReplyBytes(reply).toString('utf8')).toContain(
      '"patch":{"ext.alpha":"2","ext.zebra":"1"}',
    );
  });

  /**
   * `Date.prototype.toISOString()` always emits three fractional digits; the
   * server's `chrono` emits none when the nanoseconds are zero. Signing over
   * `…T12:00:00.000Z` and having the server re-serialize `…T12:00:00Z` is a
   * `bad_signature` with no other symptom, so the formatter is load-bearing.
   */
  it('formats issued_at the way chrono does, with no fraction on a whole second', () => {
    expect(toChronoRfc3339(new Date('2026-07-10T12:00:00.000Z'))).toBe('2026-07-10T12:00:00Z');
    expect(toChronoRfc3339(new Date('2026-07-10T12:00:00.123Z'))).toBe(
      '2026-07-10T12:00:00.123Z',
    );
    // The committed vectors are all whole seconds, which is exactly the case a
    // naive toISOString() gets wrong.
    const reply = replyFromVector(reactorVectors.reactor_to_server.allow.message);
    expect(reply.issued_at).toBe('2026-07-10T12:00:00Z');
    expect(new Date(reply.issued_at).toISOString()).toBe('2026-07-10T12:00:00.000Z');
  });
});

describe('§22.13 — verify direction', () => {
  it('verifies every event vector under the derived subkey and no other', () => {
    for (const [name, vector] of Object.entries(
      reactorVectors.server_to_reactor as Record<string, any>,
    )) {
      const body = eventWireBody(vector);
      const canonical = canonicalEventBytes(body);
      expect(canonical, `${name}: canonical bytes exist`).toBeDefined();
      expect(canonical!.toString('utf8'), `${name}: canonical bytes`).toBe(
        vector.canonical_signed_json as string,
      );
      expect(hmacHex(SUBKEY, canonical!), `${name}: MAC`).toBe(
        vector.hmac_signature_hex as string,
      );

      const ok = verifyEvent(body, SUBKEY, VERIFIED_AT_MS, SKEW_MS);
      expect(ok.ok, `${name} must verify`).toBe(true);

      const wrongKey = verifyEvent(body, Buffer.from('a different key'), VERIFIED_AT_MS, SKEW_MS);
      expect(wrongKey).toEqual({ ok: false, rejection: 'bad_signature' });
    }
  });

  it('refuses a tampered payload, timeout_ms, tenant_id or nonce', () => {
    const original = eventWireBody(reactorVectors.server_to_reactor.token_pre_issue);
    const tampers: Array<[string, (b: Record<string, any>) => void]> = [
      ['payload', (b) => ((b.payload as Record<string, unknown>).sub = 'root')],
      ['timeout_ms', (b) => (b.timeout_ms = 60_000)],
      ['tenant_id', (b) => (b.tenant_id = '33333333-3333-3333-3333-333333333333')],
      ['nonce', (b) => (b.nonce = 'dddddddd-dddd-dddd-dddd-dddddddddddd')],
    ];
    for (const [field, tamper] of tampers) {
      const body = JSON.parse(JSON.stringify(original)) as Record<string, any>;
      tamper(body);
      expect(
        verifyEvent(body, SUBKEY, VERIFIED_AT_MS, SKEW_MS),
        `tampering with ${field} must invalidate`,
      ).toEqual({ ok: false, rejection: 'bad_signature' });
    }
  });

  /**
   * §22.2: `key_version` below the floor is refused BEFORE anything else about
   * the body is considered — including before the signature is computed. The
   * downgrade breaks the MAC, so a verifier that checked the signature first
   * would report `bad_signature` instead.
   */
  it('refuses key_version < 2 before the signature is computed', () => {
    const body = eventWireBody(reactorVectors.server_to_reactor.token_pre_issue);
    body.key_version = 1;
    expect(verifyEvent(body, SUBKEY, VERIFIED_AT_MS, SKEW_MS)).toEqual({
      ok: false,
      rejection: 'key_version_too_old',
    });
    expect(reactorVectors.rejected_replies.key_version_too_old.expected_rejection).toBe(
      'key_version_too_old',
    );
  });

  it('refuses an issued_at outside ±300 s in BOTH directions', () => {
    const body = eventWireBody(reactorVectors.server_to_reactor.token_pre_issue);
    expect(verifyEvent(body, SUBKEY, VERIFIED_AT_MS + SKEW_MS + 1000, SKEW_MS)).toEqual({
      ok: false,
      rejection: 'stale',
    });
    // A future timestamp is not "extra fresh" — it is the shape of a captured
    // message held for later.
    expect(verifyEvent(body, SUBKEY, VERIFIED_AT_MS - SKEW_MS - 1000, SKEW_MS)).toEqual({
      ok: false,
      rejection: 'stale',
    });
    expect(verifyEvent(body, SUBKEY, VERIFIED_AT_MS + SKEW_MS, SKEW_MS).ok).toBe(true);

    // The reply-side vectors carry both halves too, with VALID signatures — only
    // the freshness gate refuses them.
    for (const name of ['stale', 'stale_future']) {
      const vector = reactorVectors.rejected_replies[name] as Record<string, any>;
      expect(vector.expected_rejection).toBe('stale');
      const signed = signReactorReply(replyFromVector(vector.message), SUBKEY);
      expect(reactorReplySignatureValid(signed, SUBKEY)).toBe(true);
      expect(isFresh(Date.parse(signed.issued_at), VERIFIED_AT_MS, SKEW_MS)).toBe(false);
    }
  });

  it('refuses an event with no signature at all', () => {
    const body = eventWireBody(reactorVectors.server_to_reactor.token_pre_issue);
    delete body.hmac_signature;
    expect(canonicalEventBytes(body)).toBeUndefined();
    expect(verifyEvent(body, SUBKEY, VERIFIED_AT_MS, SKEW_MS)).toEqual({
      ok: false,
      rejection: 'bad_signature',
    });
  });
});

describe('§22.13 — replay', () => {
  it('refuses the correlation_replay vector against a different correlation_id', () => {
    const vector = reactorVectors.rejected_replies.correlation_replay as Record<string, any>;
    const signed = signReactorReply(replyFromVector(vector.message), SUBKEY);
    expect(reactorReplySignatureValid(signed, SUBKEY)).toBe(true);
    expect(vector.expected_rejection).toBe('wrong_correlation');
    expect(signed.correlation_id).not.toBe(vector.verify_against_correlation_id);
    // The reply body is byte-identical to the accepted `allow` vector — a
    // perfectly valid signature does not make it the answer to another question.
    expect(vector.hmac_signature_hex).toBe(
      reactorVectors.reactor_to_server.allow.hmac_signature_hex,
    );
  });

  it('gives two replies differing only in nonce different MACs', () => {
    const binding = reactorVectors.nonce_binding as Record<string, any>;
    const base = reactorVectors.reactor_to_server.allow.message as Record<string, any>;

    const a = signReactorReply(
      replyFromVector({ ...base, nonce: binding.nonce_a as string }),
      SUBKEY,
    );
    const b = signReactorReply(
      replyFromVector({ ...base, nonce: binding.nonce_b as string }),
      SUBKEY,
    );
    expect(a.hmac_signature).toBe(binding.hmac_a_hex);
    expect(b.hmac_signature).toBe(binding.hmac_b_hex);
    expect(a.hmac_signature).not.toBe(b.hmac_signature);
  });

  it('mints a fresh nonce for every reply', () => {
    const event = { correlation_id: 'c', tenant_id: 't', event: REACTOR_EVENTS.LOGIN_POST_AUTH };
    const a = buildReactorReply(event, { decision: 'allow' });
    const b = buildReactorReply(event, { decision: 'allow' });
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.key_version).toBe(2);
  });
});

describe('§22.13 — reply construction', () => {
  it('sends a forbidden patch key unfiltered rather than dropping it', () => {
    const vector = reactorVectors.rejected_replies.forbidden_patch_field as Record<string, any>;
    expect(vector.expected_rejection).toBe('forbidden_patch_field:sub');

    const signed = signReactorReply(replyFromVector(vector.message), SUBKEY);
    const wire = JSON.stringify(signed);
    expect(wire).toContain('"decision":"mutate"');
    expect(wire, 'the SDK must NOT silently drop `sub`').toContain('"sub":"root"');
    expect(wire).toContain('"ext.department":"eng"');

    const spec = eventSpec(REACTOR_EVENTS.TOKEN_PRE_ISSUE)!;
    expect(patchFieldAllowed(spec, 'sub')).toBe(false);
    expect(patchFieldAllowed(spec, 'ext.department')).toBe(true);
  });

  it('builds a mutation as decision "mutate", never allow + patch', () => {
    const mutateReply = replyFromVector(reactorVectors.reactor_to_server.mutate.message);
    expect(mutateReply.decision).toBe('mutate');
    expect(Object.keys(mutateReply.patch ?? {})).toHaveLength(2);

    const allowReply = replyFromVector(reactorVectors.reactor_to_server.allow.message);
    expect(allowReply.decision).toBe('allow');
    expect(allowReply.patch).toBeUndefined();
  });

  it('recognises a mutation on a veto-only event locally', () => {
    const vector = reactorVectors.rejected_replies.mutation_on_veto_only_event as Record<
      string,
      any
    >;
    expect(vector.expected_rejection).toBe('not_mutable');
    const spec = eventSpec(vector.message.event as string)!;
    expect(spec.mutable).toBe(false);
    expect(patchFieldAllowed(spec, 'role')).toBe(false);
  });

  it('carries a deny reason through, and omits it when absent', () => {
    const vector = reactorVectors.reactor_to_server.deny as Record<string, any>;
    expect(vector.expected_outcome.reason).toBe('embargoed region');

    const withReason = signReactorReply(replyFromVector(vector.message), SUBKEY);
    expect(withReason.reason).toBe('embargoed region');
    expect(withReason.hmac_signature).toBe(vector.hmac_signature_hex);

    const unexplained = buildReactorReply(
      { correlation_id: 'c', tenant_id: 't', event: REACTOR_EVENTS.LOGIN_POST_AUTH },
      { decision: 'deny' },
    );
    expect(JSON.stringify(unexplained)).not.toContain('reason');
    expect(unexplained.decision).toBe('deny');
  });
});
