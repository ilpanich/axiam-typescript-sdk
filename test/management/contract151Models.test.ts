// CONTRACT.md §27.13 — the model and status changes the dogfooding
// remediation (contract 1.51) added to the §27 surface: the `Server`
// certificate type, `SubjectAltName`'s externally-tagged wire shape, and
// `inherit` on the role-assignment listings.
//
// This pins the two generator defects the re-vendor exposed (see C-1
// EXECUTED item 2 in axiam's dogfooding-findings-fix-plan.md, mirrored here):
// `SubjectAltName` fell through the generator's internally-tagged-union
// detector and would have generated as an empty interface serializing as
// `{}`; a required `inherit` on the three role-side listings would have
// typed every response as carrying it, when a pre-1.51 server simply omits
// it. Both are fixed in scripts/gen-management.mjs; these tests are what
// would go red if either regressed.

import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { roleAssignmentInherits, type SubjectAltName } from '../../src/management/models.js';
import { BASE_URL, EXAMPLE_ID, TENANT_ID, managementClient, mockServer } from '../managementSupport.js';

const NOW = '2026-09-24T00:00:00Z';
const EMPTY_PAGE = { items: [], total: 0, offset: 0, limit: 200 };

const certificateJson = (certType: string) => ({
  id: EXAMPLE_ID,
  tenant_id: TENANT_ID,
  cert_type: certType,
  issuer_ca_id: EXAMPLE_ID,
  subject: 'CN=example',
  fingerprint: 'aa:bb',
  not_before: NOW,
  not_after: NOW,
  created_at: NOW,
  key_algorithm: 'Ed25519',
  status: 'Active',
});

describe('§27.13 S-7 — CertificateType and the Server type', () => {
  it('an unrecognised cert_type still decodes and does not fail the whole listing', async () => {
    await mockServer().use(
      http.get(`${BASE_URL}/api/v1/certificates`, () =>
        HttpResponse.json({ ...EMPTY_PAGE, items: [certificateJson('QuantumBeacon')] }),
      ),
    );
    const client = managementClient();
    const page = await client.certificates.list();
    // CertificateType is an open enum (§27.11 rule 1's discipline, already in
    // place before 1.51 — the generator needed a test here, not a fix): a
    // value this SDK's copy of the spec does not list still reaches the
    // caller as itself, rather than throwing or being coerced to undefined.
    expect(page.items[0]!.cert_type).toBe('QuantumBeacon');
  });

  it('a certificate carrying the new Server type round-trips', async () => {
    await mockServer().use(
      http.get(`${BASE_URL}/api/v1/certificates`, () =>
        HttpResponse.json({ ...EMPTY_PAGE, items: [certificateJson('Server')] }),
      ),
    );
    const client = managementClient();
    const page = await client.certificates.list();
    expect(page.items[0]!.cert_type).toBe('Server');
  });
});

describe('§27.13 S-7 — SubjectAltName is externally tagged', () => {
  it('the type itself admits only { dns } or { ip } — a type-level pin', () => {
    // `SubjectAltName` degrading to an empty interface (the generator's
    // original defect) has NO effect on the wire — TypeScript erases types at
    // runtime, so a plain `{ dns: "x" }` object literal serializes correctly
    // regardless of what the *type* says. An empty interface's actual failure
    // mode is structural: TypeScript's `{}` accepts (almost) any value, so a
    // caller who mistypes a key gets no error at all. That is what this pins,
    // via `npm run typecheck` (`tsc --noEmit`) — not the runtime `it` blocks
    // below, which would stay green even against the broken generator output.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    // @ts-expect-error — neither key is `dns` nor `ip`; a properly-generated
    // SubjectAltName (a real `{dns}|{ip}` union) must reject this literal.
    // With the generator's defect (an empty `{}` interface) TypeScript
    // accepts anything, this directive goes unused, and `tsc --noEmit` fails.
    const notAName: SubjectAltName = { hostname: 'wrong-key.example' };
    expect(typeof notAName).toBe('object');
  });

  it('a DNS name serializes as {"dns": …}, never {}', async () => {
    let sentBody: unknown;
    await mockServer().use(
      http.post(`${BASE_URL}/api/v1/certificates`, async ({ request }) => {
        sentBody = await request.json();
        return HttpResponse.json({ ...certificateJson('Server'), private_key_pem: 'PEM' });
      }),
    );
    const client = managementClient();
    const names: SubjectAltName[] = [{ dns: 'api.lakeside.internal' }, { ip: '10.0.0.5' }];
    await client.certificates.generate({
      cert_type: 'Server',
      issuer_ca_id: EXAMPLE_ID,
      key_algorithm: 'Ed25519',
      subject: 'CN=api.lakeside.internal',
      subject_alt_names: names,
      validity_days: 90,
    });
    const sent = sentBody as { subject_alt_names?: unknown[] };
    // The failure mode the generator's defect produced: each entry
    // serializing as `{}` because the generated type had no fields at all.
    expect(sent.subject_alt_names).toEqual([{ dns: 'api.lakeside.internal' }, { ip: '10.0.0.5' }]);
    expect(sent.subject_alt_names).not.toEqual([{}, {}]);
  });

  it('a leaf request with no names omits the key rather than sending null or []', async () => {
    let sentBody: unknown;
    await mockServer().use(
      http.post(`${BASE_URL}/api/v1/certificates`, async ({ request }) => {
        sentBody = await request.json();
        return HttpResponse.json({ ...certificateJson('User'), private_key_pem: 'PEM' });
      }),
    );
    const client = managementClient();
    await client.certificates.generate({
      cert_type: 'User',
      issuer_ca_id: EXAMPLE_ID,
      key_algorithm: 'Ed25519',
      subject: 'CN=alice',
      validity_days: 90,
    });
    expect(sentBody).not.toHaveProperty('subject_alt_names');
  });
});

describe('§27.13 S-10 — inherit on the role-assignment listings', () => {
  it('a role-side listing without inherit reads as true via roleAssignmentInherits', async () => {
    // A pre-1.51 server's response — the field is simply absent, exactly as
    // it would be from a server that predates the field.
    await mockServer().use(
      http.get(`${BASE_URL}/api/v1/roles/${EXAMPLE_ID}/users`, () =>
        HttpResponse.json([
          {
            user: {
              id: EXAMPLE_ID,
              tenant_id: TENANT_ID,
              username: 'alice',
              email: 'alice@example.com',
              status: 'Active',
              created_at: NOW,
              updated_at: NOW,
            },
            // inherit omitted, as a server built before contract 1.51 sends it
          },
        ]),
      ),
    );
    const client = managementClient();
    const assignments = await client.roles.listUsers(EXAMPLE_ID);
    expect(assignments[0]!.inherit).toBeUndefined();
    // The property under test: absence reads as `true`, never `false` and
    // never a decode failure. `!assignments[0].inherit` would read `undefined`
    // as falsy and get this backwards — which is exactly why the helper
    // exists rather than reading the field directly.
    expect(roleAssignmentInherits(assignments[0]!)).toBe(true);
  });

  it('a role-side listing with inherit: false reads as false', () => {
    expect(roleAssignmentInherits({ inherit: false })).toBe(false);
  });

  it('the subject-side RoleAssignment reads absent inherit as true too', async () => {
    await mockServer().use(
      http.get(`${BASE_URL}/api/v1/users/${EXAMPLE_ID}/roles`, () =>
        HttpResponse.json([
          {
            role: {
              id: EXAMPLE_ID,
              tenant_id: TENANT_ID,
              name: 'editor',
              description: 'Edits things',
              is_global: false,
              created_at: NOW,
              updated_at: NOW,
            },
            // inherit omitted
          },
        ]),
      ),
    );
    const client = managementClient();
    const assignments = await client.users.listRoles(EXAMPLE_ID);
    expect(roleAssignmentInherits(assignments[0]!)).toBe(true);
  });

  it('an assign request carries inherit only when stated as false', async () => {
    let sentBody: unknown;
    await mockServer().use(
      http.post(`${BASE_URL}/api/v1/roles/${EXAMPLE_ID}/users`, async ({ request }) => {
        sentBody = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const client = managementClient();
    await client.roles.assignToUser(EXAMPLE_ID, { user_id: EXAMPLE_ID, inherit: false });
    expect(sentBody).toMatchObject({ inherit: false });
  });

  it('an inheritable assign request omits inherit — the body stays byte-for-byte pre-1.51', async () => {
    let sentBody: unknown;
    await mockServer().use(
      http.post(`${BASE_URL}/api/v1/roles/${EXAMPLE_ID}/users`, async ({ request }) => {
        sentBody = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const client = managementClient();
    await client.roles.assignToUser(EXAMPLE_ID, { user_id: EXAMPLE_ID });
    expect(sentBody).not.toHaveProperty('inherit');
  });
});
