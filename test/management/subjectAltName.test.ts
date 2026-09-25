// CONTRACT.md §27.13, externally tagged unions — CONTRACT 1.52 N3 (C-12).
//
// `SubjectAltName` is sent as exactly one of `{"dns": …}` / `{"ip": …}`. The
// TypeScript union type does not itself stop a dynamically-built value from
// holding neither key or both — excess-property checks only fire on an
// object literal assigned directly, never on a value built up field-by-field
// (e.g. from user input) or passed through a variable. Before this fix,
// `certificates.generate`/`.signCsr` sent such a malformed element straight
// to the wire.

import { describe, expect, it } from 'vitest';

import { NetworkError } from '../../src/core/errors.js';
import type { CreateCertificateRequest, SubjectAltName } from '../../src/management/models.js';
import { BASE_URL, mockServer, managementClient } from '../managementSupport.js';
import { http, HttpResponse } from 'msw';

const NOW = '2026-08-26T00:00:00Z';

function baseRequest(subjectAltNames: SubjectAltName[]): CreateCertificateRequest {
  return {
    cert_type: 'Server',
    issuer_ca_id: '44444444-4444-4444-8444-444444444444',
    key_algorithm: 'Ed25519',
    subject: 'api.lakeside.internal',
    subject_alt_names: subjectAltNames,
    validity_days: 30,
  };
}

/** A value built field-by-field, the way a caller assembling names from a
 * loop or user input would — not an object literal, so TypeScript's
 * excess-property check (which only fires on a literal) does not catch a
 * malformed shape here even at compile time. */
function buildBoth(): SubjectAltName {
  const v = {} as Record<string, string>;
  v.dns = 'api.lakeside.internal';
  v.ip = '10.0.0.5';
  return v as unknown as SubjectAltName;
}

function buildNeither(): SubjectAltName {
  const v = {} as Record<string, string>;
  return v as unknown as SubjectAltName;
}

describe('CONTRACT 1.52 N3 (C-12) — SubjectAltName refuses neither/both client-side', () => {
  it('a SubjectAltName naming BOTH dns and ip is refused before any request', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/certificates`, () => {
        reached += 1;
        return HttpResponse.json({ id: 'x' }, { status: 201 });
      }),
    );

    const client = managementClient();
    await expect(client.certificates.generate(baseRequest([buildBoth()]))).rejects.toBeInstanceOf(NetworkError);
    expect(reached).toBe(0);
  });

  it('a SubjectAltName naming NEITHER dns nor ip is refused before any request', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/certificates`, () => {
        reached += 1;
        return HttpResponse.json({ id: 'x' }, { status: 201 });
      }),
    );

    const client = managementClient();
    await expect(client.certificates.generate(baseRequest([buildNeither()]))).rejects.toBeInstanceOf(NetworkError);
    expect(reached).toBe(0);
  });

  it('signCsr applies the same refusal', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/certificates/sign-csr`, () => {
        reached += 1;
        return HttpResponse.json({ id: 'x' }, { status: 201 });
      }),
    );

    const client = managementClient();
    await expect(
      client.certificates.signCsr({
        cert_type: 'Server',
        csr_pem: '-----BEGIN CERTIFICATE REQUEST-----\nplaceholder\n-----END CERTIFICATE REQUEST-----',
        issuer_ca_id: '44444444-4444-4444-8444-444444444444',
        subject_alt_names: [buildBoth()],
        validity_days: 30,
      }),
    ).rejects.toBeInstanceOf(NetworkError);
    expect(reached).toBe(0);
  });

  // I4 twin: a well-formed list (exactly one key each) is unaffected and
  // still reaches the wire.
  it('twin (I4): a well-formed SubjectAltName list is unaffected and reaches the wire', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/certificates`, () => {
        reached += 1;
        return HttpResponse.json(
          {
            id: '11111111-1111-4111-8111-111111111111',
            tenant_id: '22222222-2222-4222-8222-222222222222',
            cert_type: 'Server',
            subject: 'api.lakeside.internal',
            status: 'Active',
            serial_number: '01',
            not_before: NOW,
            not_after: NOW,
            created_at: NOW,
          },
          { status: 201 },
        );
      }),
    );

    const client = managementClient();
    await client.certificates.generate(baseRequest([{ dns: 'api.lakeside.internal' }, { ip: '10.0.0.5' }]));
    expect(reached).toBe(1);
  });

  it('twin (I4): an absent subject_alt_names list is unaffected', async () => {
    const server = mockServer();
    let reached = 0;
    server.use(
      http.post(`${BASE_URL}/api/v1/certificates`, () => {
        reached += 1;
        return HttpResponse.json(
          {
            id: '11111111-1111-4111-8111-111111111111',
            tenant_id: '22222222-2222-4222-8222-222222222222',
            cert_type: 'User',
            subject: 'user@example.com',
            status: 'Active',
            serial_number: '01',
            not_before: NOW,
            not_after: NOW,
            created_at: NOW,
          },
          { status: 201 },
        );
      }),
    );

    const client = managementClient();
    await client.certificates.generate({
      cert_type: 'User',
      issuer_ca_id: '44444444-4444-4444-8444-444444444444',
      key_algorithm: 'Ed25519',
      subject: 'user@example.com',
      validity_days: 30,
    });
    expect(reached).toBe(1);
  });
});
