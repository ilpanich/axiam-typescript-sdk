// R-18 (contract 1.59 §34.3, review finding F-1): a management write that
// fails with a `5xx` or a transport error MUST NOT carry its write-only secret
// in the thrown error (§30.5, §31.5, §32.5 "an error raised by set/update/
// create MUST NOT include it"; §27.5 for the older request secrets; §7 rule 1).
//
// The §30.8/§31.8/§32.8 redaction tests drive a `400`, which takes the
// `ValidationError` path and carries no transport error at all; the leak sat
// on the other path, where `NetworkError.cause` was the axios error and its
// `config.data` the serialized request body. So this file drives every
// secret-bearing write in the registry through a `500` with a JSON body, a
// bodiless `503` and a dropped connection, and inspects the error every way
// it can be printed or serialized — including a reflective walk of every
// value reachable from it.
//
// Every secret is generated at run time; a failing assertion names only the
// offset of the fragment it found (test/redaction.ts).

import { http, HttpResponse } from 'msw';
import { afterEach, describe, expect, it } from 'vitest';

import { NetworkError } from '../../src/core/errors.js';
import { Sensitive } from '../../src/core/sensitive.js';
import type { AxiamClient } from '../../src/rest/client.js';
import { BASE_URL, ORG_ID, TENANT_ID, managementClient, mockServer } from '../managementSupport.js';
import { assertNoFragment, exhaustiveErrorRenderings, freshId, freshSecret } from '../redaction.js';

afterEach(() => mockServer().resetHandlers());

const REVOKED = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';

/** One secret-bearing write: the registry's operation, its route, and how to call it with `secret`. */
interface SecretWrite {
  operation: string;
  method: 'post' | 'put' | 'patch';
  path: (id: string) => string;
  call: (client: AxiamClient, id: string, secret: string) => Promise<unknown>;
  /** Where the secret sits in the wire body. */
  member: string;
}

const scimInput = (secret: string) => ({
  name: 'downstream',
  base_url: 'https://idp.example/scim/v2',
  auth: { type: 'bearer' as const },
  credential: new Sensitive(secret),
  scope: { type: 'all_users' as const },
});

const ssfInput = (secret: string) => ({
  receiver_client_id: 'rp-1',
  audience: 'https://rp.example',
  delivery_method: 'push',
  endpoint_url: 'https://rp.example/ssf/push',
  events_allowed: [REVOKED],
  authorization_header: new Sensitive(`Bearer ${secret}`),
});

/** Every operation `management-registry.json` lists with a `sensitive_request_fields` entry. */
const WRITES: SecretWrite[] = [
  {
    operation: 'users.create',
    method: 'post',
    path: () => '/api/v1/users',
    call: (c, _id, s) => c.users.create({ username: 'u', email: 'u@example.test', password: new Sensitive(s) }),
    member: 'password',
  },
  {
    operation: 'ca_certificates.import_ca',
    method: 'post',
    path: () => `/api/v1/organizations/${ORG_ID}/ca-certificates/import`,
    call: (c, _id, s) => c.caCertificates.importCa({ public_cert_pem: 'cert', private_key_pem: new Sensitive(s) }),
    member: 'private_key_pem',
  },
  {
    operation: 'webhooks.create',
    method: 'post',
    path: () => '/api/v1/webhooks',
    call: (c, _id, s) => c.webhooks.create({ url: 'https://hook.example', events: ['user.created'], secret: new Sensitive(s) }),
    member: 'secret',
  },
  {
    operation: 'webhooks.update',
    method: 'put',
    path: (id) => `/api/v1/webhooks/${id}`,
    call: (c, id, s) => c.webhooks.update(id, { secret: new Sensitive(s) }),
    member: 'secret',
  },
  {
    operation: 'federation.create_config',
    method: 'post',
    path: () => '/api/v1/federation-configs',
    call: (c, _id, s) =>
      c.federation.createConfig({ provider: 'p', protocol: 'oidc', client_id: 'rp', client_secret: new Sensitive(s) }),
    member: 'client_secret',
  },
  {
    operation: 'federation.update_config',
    method: 'put',
    path: (id) => `/api/v1/federation-configs/${id}`,
    call: (c, id, s) => c.federation.updateConfig(id, { client_secret: new Sensitive(s) }),
    member: 'client_secret',
  },
  {
    operation: 'directory.set',
    method: 'put',
    path: () => `/api/v1/tenants/${TENANT_ID}/directory`,
    call: (c, _id, s) =>
      c.directory.set({
        enabled: true,
        kind: 'active_directory',
        url: 'ldaps://dc.corp.example',
        start_tls: false,
        bind_dn: 'cn=svc,dc=corp',
        base_dn: 'dc=corp',
        user_filter: '(sAMAccountName={username})',
        bind_secret: new Sensitive(s),
      }),
    member: 'bind_secret',
  },
  {
    operation: 'directory.update',
    method: 'patch',
    path: () => `/api/v1/tenants/${TENANT_ID}/directory`,
    call: (c, _id, s) => c.directory.update({ url: 'ldaps://dc2.corp.example', bind_secret: new Sensitive(s) }),
    member: 'bind_secret',
  },
  {
    operation: 'scim_targets.create',
    method: 'post',
    path: () => '/api/v1/scim-targets',
    call: (c, _id, s) => c.scimTargets.create(scimInput(s)),
    member: 'credential',
  },
  {
    operation: 'scim_targets.update',
    method: 'put',
    path: (id) => `/api/v1/scim-targets/${id}`,
    call: (c, id, s) => c.scimTargets.update(id, scimInput(s)),
    member: 'credential',
  },
  {
    operation: 'ssf.create_stream',
    method: 'post',
    path: () => `/api/v1/tenants/${TENANT_ID}/ssf/streams`,
    call: (c, _id, s) => c.ssf.createStream(ssfInput(s)),
    member: 'authorization_header',
  },
  {
    operation: 'ssf.update_stream',
    method: 'put',
    path: (id) => `/api/v1/tenants/${TENANT_ID}/ssf/streams/${id}`,
    call: (c, id, s) => c.ssf.updateStream(id, ssfInput(s)),
    member: 'authorization_header',
  },
];

/** The failures that reach `NetworkError`: a 5xx with the server's JSON body, a bodiless 5xx, no response at all. */
const FAILURES: { label: string; respond: () => Response }[] = [
  { label: '500 {"error":"internal_error"}', respond: () => HttpResponse.json({ error: 'internal_error', message: 'boom' }, { status: 500 }) },
  { label: 'bodiless 503', respond: () => new HttpResponse(null, { status: 503 }) },
  { label: 'transport failure', respond: () => HttpResponse.error() },
];

describe('R-18 — a failed secret-bearing write never carries the secret in its error', () => {
  it('the table covers every registry operation with a sensitive request field', async () => {
    const registry = (await import('../../management-registry.json', { with: { type: 'json' } })).default as {
      namespaces: Record<string, { operations: Record<string, { sensitive_request_fields: string[] }> }>;
    };
    const expected: string[] = [];
    for (const [ns, def] of Object.entries(registry.namespaces)) {
      for (const [op, o] of Object.entries(def.operations)) {
        if (o.sensitive_request_fields.length > 0) expected.push(`${ns}.${op}`);
      }
    }
    expect(WRITES.map((w) => w.operation).sort()).toEqual(expected.sort());
  });

  for (const write of WRITES) {
    for (const failure of FAILURES) {
      it(`${write.operation} — ${failure.label}`, async () => {
        const server = mockServer();
        const id = freshId();
        const secret = freshSecret();
        const bodies: string[] = [];
        server.use(
          http[write.method](`${BASE_URL}${write.path(id)}`, async ({ request }) => {
            bodies.push(await request.text());
            return failure.respond();
          }),
        );

        const err = await write.call(managementClient(), id, secret).catch((e: unknown) => e);

        expect(err).toBeInstanceOf(NetworkError);
        // The secret did go out: the redaction is of the error, not of the request.
        expect(bodies).toHaveLength(1);
        const sent = JSON.parse(bodies[0] ?? '{}') as Record<string, unknown>;
        expect(typeof sent[write.member] === 'string' && (sent[write.member] as string).includes(secret), 'the secret was not sent').toBe(true);

        assertNoFragment(exhaustiveErrorRenderings(err), secret, `${write.operation} error`);
      });
    }
  }
});
