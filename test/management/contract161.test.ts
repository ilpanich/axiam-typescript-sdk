// Contract 1.61 — the rows §34.5 assigns every SDK that ships `certificates`:
// §27.11 rule 5, `Certificate.user_id` and the optional request member on
// `certificates.generate` and `certificates.sign_csr` (the one required test).
//
// `SsfStreamInput.expected_updated_at` and the three meanings of
// `events_requested` are §32.8 test 1's and live in ssf.test.ts. `CibaPendingList`
// is a console surface no operation returns (§33.3 rule 16); this SDK models
// neither it nor `CibaApprovalPage`.

import { describe, expect, it } from 'vitest';

import type { Certificate } from '../../src/management/models.js';
import { EXAMPLE_ID, TENANT_ID, capture, managementClient, mockServer } from '../managementSupport.js';
import { freshId } from '../redaction.js';

const NOW = '2026-10-13T00:00:00Z';

const certificateJson = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: freshId(),
  tenant_id: TENANT_ID,
  cert_type: 'User',
  issuer_ca_id: EXAMPLE_ID,
  subject: 'ada',
  fingerprint: 'ab:cd',
  not_before: NOW,
  not_after: NOW,
  created_at: NOW,
  key_algorithm: 'Ed25519',
  status: 'Active',
  metadata: {},
  public_cert_pem: 'pem',
  ...extra,
});

const generate = (user_id?: string) => ({
  cert_type: 'User' as const,
  issuer_ca_id: EXAMPLE_ID,
  key_algorithm: 'Ed25519' as const,
  subject: 'ada',
  validity_days: 90,
  ...(user_id !== undefined ? { user_id } : {}),
});

const sign = (user_id?: string) => ({
  cert_type: 'User' as const,
  csr_pem: 'csr',
  issuer_ca_id: EXAMPLE_ID,
  subject: 'ada',
  validity_days: 90,
  ...(user_id !== undefined ? { user_id } : {}),
});

describe('§27.11 rule 5 — Certificate.user_id', () => {
  it('generate and signCsr send the user_id the caller set as given, and no key when unset', async () => {
    const server = mockServer();
    const generated = capture(server, 'POST', '/api/v1/certificates', 201, certificateJson({ private_key_pem: 'k' }));
    const signed = capture(server, 'POST', '/api/v1/certificates/sign-csr', 201, certificateJson());
    const account = freshId();
    const { certificates } = managementClient();

    await certificates.generate(generate(account));
    await certificates.generate(generate());
    await certificates.signCsr(sign(account));
    await certificates.signCsr(sign());

    const bodies = [generated, signed].map((seen) => seen.map((r) => r.json as Record<string, unknown>));
    expect(bodies[0]![0]!.user_id).toBe(account);
    expect('user_id' in bodies[0]![1]!, 'unset is absent, never null').toBe(false);
    expect(bodies[1]![0]!.user_id).toBe(account);
    expect('user_id' in bodies[1]![1]!, 'unset is absent, never null').toBe(false);
    expect(generated[1]!.text).not.toContain('user_id');
    expect(signed[1]!.text).not.toContain('user_id');
  });

  it('a Certificate carrying a UUID, a null and no member each decode; the last two name no account', async () => {
    const server = mockServer();
    const account = freshId();
    const id = freshId();
    const { certificates } = managementClient();

    const read = async (extra: Record<string, unknown>): Promise<Certificate> => {
      server.resetHandlers();
      capture(server, 'GET', `/api/v1/certificates/${id}`, 200, certificateJson(extra));
      return certificates.get(id);
    };

    expect((await read({ user_id: account })).user_id).toBe(account);
    // `null` and absence both mean "no account named", and neither is coalesced
    // to a nil UUID or synthesised from metadata.
    expect((await read({ user_id: null })).user_id ?? null).toBeNull();
    const absent = await read({ metadata: { user_id: account } });
    expect(absent.user_id ?? null).toBeNull();
    expect('user_id' in absent).toBe(false);
  });

  it('reaches a GeneratedCertificate as well, with no second request', async () => {
    const server = mockServer();
    const account = freshId();
    const seen = capture(server, 'POST', '/api/v1/certificates', 201, certificateJson({ private_key_pem: 'k', user_id: account }));
    const generated = await managementClient().certificates.generate(generate(account));
    expect(generated.user_id).toBe(account);
    expect(seen).toHaveLength(1);
  });
});
