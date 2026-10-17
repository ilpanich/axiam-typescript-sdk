// Contract 1.62 — the change-taking SSF form (§32.8 test 7), the three meanings
// at the `update_stream` call site (item (h)) and the rule that an assigned
// `null` is "none" (§27.11 rule 5, §32.2; item (f)). The `network` namespace is
// in contract162.test.ts.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { ssfStreamInputFrom, ssfStreamInputWith } from '../../src/management/checks.js';
import type { SsfStream } from '../../src/management/models.js';
import { EXAMPLE_ID, TENANT_ID, capture, managementClient, mockServer } from '../managementSupport.js';
import { freshId } from '../redaction.js';

const NOW = '2026-10-16T00:00:00Z';

// ── §32.8 (7) the change-taking form ────────────────────────────────────────

const A = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';
const B = 'https://schemas.openid.net/secevent/caep/event-type/credential-change';
const C = 'https://schemas.openid.net/secevent/risc/event-type/account-disabled';

const stream = (extra: Partial<SsfStream> = {}): SsfStream =>
  ({
    id: freshId(),
    tenant_id: TENANT_ID,
    receiver_client_id: 'rp-1',
    audience: 'https://rp.example',
    description: null,
    delivery_method: 'push',
    endpoint_url: 'https://rp.example/ssf',
    authorization_header_set: true,
    events_allowed: [A, B, C],
    events_requested: [A, B],
    events_delivered: [A, B],
    subject_format: 'iss_sub',
    status: 'enabled',
    status_reason: null,
    status_actor: 'admin',
    last_verification_at: null,
    created_at: NOW,
    updated_at: '2026-10-04T08:15:30.123456789+00:00',
    transmitter_active: true,
    ...extra,
  }) as SsfStream;

describe('§32.8 (7), contract 1.62 — the change-taking form', () => {
  it('lowering events_allowed cuts events_requested to the new ceiling, in order', () => {
    const body = ssfStreamInputWith(stream(), { events_allowed: [B] });
    expect(body.events_allowed).toEqual([B]);
    expect(body.events_requested).toEqual([B]);

    const widened = ssfStreamInputWith(stream(), { events_allowed: [B, A, C] });
    expect(widened.events_requested).toEqual([A, B]);
  });

  it('a lowered ceiling that excludes every requested event sends [] (the receiver\'s "none"), not an absent key', () => {
    const body = ssfStreamInputWith(stream(), { events_allowed: [C] });
    expect(body.events_requested).toEqual([]);
    expect('events_requested' in body).toBe(true);
  });

  it('a change that is not about events sends events_requested as read, [] as [], and the server\'s own updated_at string', () => {
    const read = stream();
    const body = ssfStreamInputWith(read, { status: 'paused' });
    expect(body.status).toBe('paused');
    expect(body.events_requested).toEqual([A, B]);
    // Nine fraction digits and a +00:00 offset: byte for byte.
    expect(body.expected_updated_at).toBe('2026-10-04T08:15:30.123456789+00:00');
    expect(body.expected_updated_at).toBe(read.updated_at);

    const none = ssfStreamInputWith(stream({ events_requested: [] }), { description: 'x' });
    expect(none.events_requested).toEqual([]);
    expect(none.description).toBe('x');
  });

  it('an events_requested named in changes is sent as given, even beside a lowered ceiling', () => {
    const body = ssfStreamInputWith(stream(), { events_allowed: [B], events_requested: [A] });
    expect(body.events_requested).toEqual([A]);
  });

  it('an assigned null for expected_updated_at leaves the key out; so does null for events_requested (the reset)', () => {
    const noStamp = ssfStreamInputWith(stream(), { expected_updated_at: null });
    expect('expected_updated_at' in noStamp).toBe(false);
    const reset = ssfStreamInputWith(stream(), { events_requested: null });
    expect('events_requested' in reset).toBe(false);
    // `undefined` in changes is not a change.
    const unchanged = ssfStreamInputWith(stream(), { status: undefined, expected_updated_at: undefined });
    expect(unchanged.status).toBe('enabled');
    expect(unchanged.expected_updated_at).toBe('2026-10-04T08:15:30.123456789+00:00');
  });

  it('does not mutate the stream it was given', () => {
    const read = stream();
    ssfStreamInputWith(read, { events_allowed: [B] });
    expect(read.events_allowed).toEqual([A, B, C]);
    expect(read.events_requested).toEqual([A, B]);
  });

  it('sent through updateStream, the body carries the cut list and the verbatim stamp', async () => {
    const server = mockServer();
    const read = stream();
    const seen = capture(
      server,
      'PUT',
      `/api/v1/tenants/${TENANT_ID}/ssf/streams/${read.id}`,
      200,
      read as unknown as Record<string, unknown>,
    );
    await managementClient().ssf.updateStream(read.id, ssfStreamInputWith(read, { events_allowed: [A] }));
    const sent = seen[0]!.json as Record<string, unknown>;
    expect(sent.events_requested).toEqual([A]);
    expect(sent.expected_updated_at).toBe('2026-10-04T08:15:30.123456789+00:00');
  });

  it('the plain converter remains, and its documentation names the caller\'s duty and the three meanings', () => {
    const body = ssfStreamInputFrom(stream());
    expect(body.events_requested).toEqual([A, B]);
    const source = readFileSync(
      fileURLToPath(new URL('../../src/management/checks.ts', import.meta.url)),
      'utf8',
    );
    const doc = source.slice(0, source.indexOf('export function ssfStreamInputFrom'));
    expect(doc).toContain('The caller\'s duty');
    expect(doc).toContain('cut');
    expect(doc).toContain('three meanings');
    expect(doc).toContain('409');
  });

  it('the update_stream documentation states the three meanings (a documentation check, not a mock)', () => {
    const source = readFileSync(
      fileURLToPath(new URL('../../src/management/ops/ssf.ts', import.meta.url)),
      'utf8',
    );
    const at = source.indexOf('async updateStream');
    const doc = source.slice(source.lastIndexOf('/**', at), at);
    expect(doc).toContain('three meanings');
    expect(doc).toMatch(/absent resets/);
    expect(doc).toContain('`[]` is stored');
    expect(doc).toMatch(/a list is stored as given/);
    expect(doc).toContain('`400`');
  });
});

// ── §27.11 rule 5, §32.2 (f) — an assigned null is "none" ───────────────────

describe('contract 1.62 (f) — an explicitly assigned null on user_id and expected_updated_at is "none"', () => {
  it('certificates.generate and signCsr leave a null user_id out, never send null', async () => {
    const server = mockServer();
    const cert = {
      id: freshId(), tenant_id: TENANT_ID, cert_type: 'User', issuer_ca_id: EXAMPLE_ID, subject: 'ada',
      fingerprint: 'ab', not_before: NOW, not_after: NOW, created_at: NOW, key_algorithm: 'Ed25519',
      status: 'Active', metadata: {}, public_cert_pem: 'pem',
    };
    const generated = capture(server, 'POST', '/api/v1/certificates', 201, { ...cert, private_key_pem: 'k' });
    const signed = capture(server, 'POST', '/api/v1/certificates/sign-csr', 201, cert);
    const { certificates } = managementClient();

    await certificates.generate({
      cert_type: 'User', issuer_ca_id: EXAMPLE_ID, key_algorithm: 'Ed25519', subject: 'ada', validity_days: 90,
      user_id: null,
    });
    await certificates.signCsr({
      cert_type: 'User', csr_pem: 'csr', issuer_ca_id: EXAMPLE_ID, validity_days: 90,
      user_id: null,
    });

    for (const seen of [generated, signed]) {
      expect(seen[0]!.text).not.toContain('null');
      expect('user_id' in (seen[0]!.json as object)).toBe(false);
    }
  });

  it('a user_id that is set still goes as given — a malformed one included (item (i): an untyped string)', async () => {
    const server = mockServer();
    const cert = {
      id: freshId(), tenant_id: TENANT_ID, cert_type: 'User', issuer_ca_id: EXAMPLE_ID, subject: 'ada',
      fingerprint: 'ab', not_before: NOW, not_after: NOW, created_at: NOW, key_algorithm: 'Ed25519',
      status: 'Active', metadata: {}, public_cert_pem: 'pem',
    };
    const seen = capture(server, 'POST', '/api/v1/certificates', 201, { ...cert, private_key_pem: 'k' });
    await managementClient().certificates.generate({
      cert_type: 'User', issuer_ca_id: EXAMPLE_ID, key_algorithm: 'Ed25519', subject: 'ada', validity_days: 90,
      user_id: 'not-a-uuid',
    });
    expect((seen[0]!.json as { user_id: string }).user_id).toBe('not-a-uuid');
  });

  it('ssf.updateStream and scimTargets.update leave a null expected_updated_at out, and still send the members that ARE null on purpose', async () => {
    const server = mockServer();
    const id = freshId();
    const ssf = capture(server, 'PUT', `/api/v1/tenants/${TENANT_ID}/ssf/streams/${id}`, 200, stream() as unknown as Record<string, unknown>);
    const scim = capture(server, 'PUT', `/api/v1/scim-targets/${id}`, 200, { id });
    const client = managementClient();

    await client.ssf.updateStream(id, {
      receiver_client_id: 'rp-1', audience: 'a', delivery_method: 'poll', events_allowed: [A],
      expected_updated_at: null, description: null,
    });
    await client.scimTargets.update(id, {
      auth: { type: 'bearer' },
      base_url: 'https://idp.example/scim/v2',
      name: 'Downstream',
      scope: { type: 'all_users' },
      expected_updated_at: null,
    });

    const ssfBody = ssf[0]!.json as Record<string, unknown>;
    expect('expected_updated_at' in ssfBody).toBe(false);
    // `description: null` is a clear on a replacement: meaningful, and sent.
    expect(ssfBody.description).toBeNull();
    expect('expected_updated_at' in (scim[0]!.json as object)).toBe(false);
  });

  it('create_stream shares the type: a null expected_updated_at is dropped there too', async () => {
    const server = mockServer();
    const seen = capture(server, 'POST', `/api/v1/tenants/${TENANT_ID}/ssf/streams`, 201, stream() as unknown as Record<string, unknown>);
    await managementClient().ssf.createStream({
      receiver_client_id: 'rp-1', audience: 'a', delivery_method: 'poll', events_allowed: [A],
      expected_updated_at: null,
    });
    expect('expected_updated_at' in (seen[0]!.json as object)).toBe(false);
  });
});
