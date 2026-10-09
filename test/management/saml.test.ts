// The `saml` management namespace — CONTRACT.md §29.8's eight required tests.

import { http, HttpResponse } from 'msw';
import { afterEach, describe, expect, it } from 'vitest';

import { NetworkError } from '../../src/core/errors.js';
import {
  parseSpMetadataFromUrl,
  parseSpMetadataFromXml,
  samlServiceProviderInputFrom,
} from '../../src/management/checks.js';
import { ConflictError, NotFoundError, ValidationError } from '../../src/management/errors.js';
import type {
  ParseSamlSpMetadata,
  SamlIdpCredential,
  SamlServiceProvider,
  SamlServiceProviderInput,
} from '../../src/management/models.js';
import {
  BASE_URL,
  TENANT_ID,
  capture,
  managementClient,
  mockServer,
  retryingManagementClient,
} from '../managementSupport.js';
import { assertNoFragment, freshId, freshSecret, renderings } from '../redaction.js';

const SAML = `/api/v1/tenants/${TENANT_ID}/saml`;

afterEach(() => mockServer().resetHandlers());

function spBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    enabled: true,
    display_name: 'Payroll',
    entity_id: 'https://payroll.example/sp',
    acs_urls: [{ url: 'https://payroll.example/acs', binding: 'http_post', index: 0, is_default: true }],
    slo_url: null,
    slo_binding: null,
    name_id_format: 'persistent',
    sign_responses: true,
    encrypt_assertions: false,
    sp_signing_cert_pem: null,
    sp_encryption_cert_pem: null,
    want_authn_requests_signed: false,
    allow_idp_initiated: false,
    attribute_mappings: [],
    allowed_groups: [],
    created_at: '2026-10-04T00:00:00Z',
    updated_at: '2026-10-04T00:00:00Z',
    ...extra,
  };
}

function credentialBody(status: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    issuer_ca_id: freshId(),
    certificate_pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
    serial: '0a1b',
    fingerprint: 'ab'.repeat(32),
    not_before: '2026-10-04T00:00:00Z',
    not_after: '2027-10-04T00:00:00Z',
    status,
    created_at: '2026-10-04T00:00:00Z',
    retired_at: null,
    ...extra,
  };
}

function input(): SamlServiceProviderInput {
  return {
    acs_urls: [{ binding: 'http_post', index: 0, is_default: true, url: 'https://payroll.example/acs' }],
    display_name: 'Payroll',
    entity_id: 'https://payroll.example/sp',
  };
}

// ── 1. Replacement ──────────────────────────────────────────────────────────

describe('§29.8 (1) — updateServiceProvider puts the whole registration', () => {
  it('sends every member of the read-modify-write body and decodes the 200', async () => {
    const server = mockServer();
    const id = freshId();
    const seen = capture(server, 'PUT', `${SAML}/service-providers/${id}`, 200, spBody());

    const current = spBody() as unknown as SamlServiceProvider;
    const body = samlServiceProviderInputFrom(current);
    body.display_name = 'Payroll (EU)';
    const sp = await managementClient().saml.updateServiceProvider(id, body);
    expect(sp.entity_id).toBe('https://payroll.example/sp');

    const sent = seen[0]?.json as Record<string, unknown>;
    for (const member of [
      'acs_urls',
      'allow_idp_initiated',
      'allowed_groups',
      'attribute_mappings',
      'display_name',
      'enabled',
      'encrypt_assertions',
      'entity_id',
      'name_id_format',
      'sign_responses',
      'slo_binding',
      'slo_url',
      'sp_encryption_cert_pem',
      'sp_signing_cert_pem',
      'want_authn_requests_signed',
    ]) {
      expect(member in sent, `${member} not sent`).toBe(true);
    }
    expect(sent.display_name).toBe('Payroll (EU)');
    // The input cannot be built without display_name, entity_id and acs_urls.
    // @ts-expect-error — `entity_id` and `acs_urls` are required.
    const incomplete: SamlServiceProviderInput = { display_name: 'x' };
    void incomplete;
  });
});

// ── 2. No signing switch, open decoding ─────────────────────────────────────

describe('§29.8 (2) — sign_assertions does not exist and unknown values decode', () => {
  it('decodes an unknown member and binding, and re-encoding sends neither unknown member', async () => {
    const server = mockServer();
    const id = freshId();
    const odd = spBody({ sign_assertions: false, some_future_member: 1 });
    (odd.acs_urls as Array<Record<string, unknown>>)[0]!.binding = 'http_artifact';
    capture(server, 'GET', `${SAML}/service-providers/${id}`, 200, odd);
    const seen = capture(server, 'PUT', `${SAML}/service-providers/${id}`, 200, spBody());

    const client = managementClient();
    const sp = await client.saml.getServiceProvider(id);
    expect(sp.acs_urls[0]?.binding).toBe('http_artifact');
    // An unknown enum value decodes; the caller replaces it before writing back.
    const body = samlServiceProviderInputFrom(sp);
    body.acs_urls[0]!.binding = 'http_post';
    await client.saml.updateServiceProvider(id, body);
    const sent = seen[0]?.json as Record<string, unknown>;
    expect('sign_assertions' in sent).toBe(false);
    expect('some_future_member' in sent).toBe(false);
    // @ts-expect-error — no signing switch on the input type.
    const withSwitch: SamlServiceProviderInput = { ...input(), sign_assertions: false };
    void withSwitch;
  });
});

// ── 3. Draft round trip ─────────────────────────────────────────────────────

describe('§29.8 (3) — parseSpMetadata sends exactly one member, and the draft creates', () => {
  it('url form, xml form, both/neither refused locally, draft passed unchanged', async () => {
    const server = mockServer();
    const draft = {
      service_provider: {
        display_name: 'Imported',
        entity_id: 'https://imported.example/sp',
        acs_urls: [{ url: 'https://imported.example/acs', binding: 'http_post', index: 1, is_default: false }],
        want_authn_requests_signed: true,
        sp_signing_cert_pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
      },
      signing_certificate_fingerprint: 'cd'.repeat(32),
      encryption_certificate_fingerprint: null,
      warnings: ["the metadata's signature was not evaluated"],
    };
    const parsed = capture(server, 'POST', `${SAML}/parse-sp-metadata`, 200, draft);
    const created = capture(server, 'POST', `${SAML}/service-providers`, 201, spBody());
    const client = managementClient();

    const fromUrl = await client.saml.parseSpMetadata(parseSpMetadataFromUrl('https://imported.example/metadata'));
    await client.saml.parseSpMetadata(parseSpMetadataFromXml('<EntityDescriptor/>'));

    const bothOrNeither: ParseSamlSpMetadata[] = [
      { metadata_url: 'https://a', metadata_xml: '<x/>' },
      {},
      { metadata_url: null, metadata_xml: null },
    ];
    for (const body of bothOrNeither) {
      await expect(client.saml.parseSpMetadata(body)).rejects.toBeInstanceOf(ValidationError);
    }
    expect(parsed).toHaveLength(2);
    expect(parsed[0]?.text).toBe('{"metadata_url":"https://imported.example/metadata"}');
    expect(parsed[1]?.text).toBe('{"metadata_xml":"<EntityDescriptor/>"}');

    await client.saml.createServiceProvider(fromUrl.service_provider);
    expect(created[0]?.json).toEqual(draft.service_provider);
  });
});

// ── 4. Credentials carry no key ─────────────────────────────────────────────

describe('§29.8 (4) — a credential has no key member', () => {
  it('drops private_key_pem everywhere, and a promotion may retire nothing', async () => {
    const server = mockServer();
    const leaked = `-----BEGIN PRIVATE KEY-----${freshSecret()}`;
    const id = freshId();
    capture(server, 'POST', `${SAML}/idp-credentials/${id}/retire`, 200,
      credentialBody('retired', { private_key_pem: leaked }));
    capture(server, 'POST', `${SAML}/idp-credentials/${id}/promote`, 200, {
      active: credentialBody('active', { private_key_pem: leaked }),
      retired: null,
    });
    capture(server, 'GET', `${SAML}/idp-credentials`, 200, [credentialBody('next', { private_key_pem: leaked })]);
    const client = managementClient();

    const credential: SamlIdpCredential = await client.saml.retireIdpCredential(id);
    const promotion = await client.saml.promoteIdpCredential(id);
    const list = await client.saml.listIdpCredentials();
    for (const value of [credential, promotion, list]) {
      const rendered = renderings(value);
      assertNoFragment(rendered, leaked.slice(27), 'credential');
      expect(rendered.includes('private_key_pem'), 'a key member survived').toBe(false);
    }
    expect(promotion.retired).toBeNull();
    expect(promotion.active.status).toBe('active');
    // @ts-expect-error — SamlIdpCredential declares no key member.
    void credential.private_key_pem;
  });
});

// ── 5. Pagination ───────────────────────────────────────────────────────────

describe('§29.8 (5) — service providers page with search; credentials are a plain list', () => {
  it('Page with total, the walk carries search, and listIdpCredentials is an array', async () => {
    const server = mockServer();
    const queries: string[] = [];
    server.use(
      http.get(`${BASE_URL}${SAML}/service-providers`, ({ request }) => {
        const url = new URL(request.url);
        queries.push(url.search);
        const offset = Number(url.searchParams.get('offset') ?? '0');
        return HttpResponse.json({ items: offset < 2 ? [spBody()] : [], total: 2, offset, limit: 1 });
      }),
    );
    capture(server, 'GET', `${SAML}/idp-credentials`, 200, [credentialBody('next'), credentialBody('active')]);
    const client = managementClient();

    const page = await client.saml.listServiceProviders({ limit: 1, search: 'payroll' });
    expect(page.total).toBe(2);
    const all = await client.saml.listServiceProvidersAll({ limit: 1, search: 'payroll' });
    expect(all).toHaveLength(2);
    expect(queries.length).toBeGreaterThan(1);
    for (const q of queries) expect(q).toContain('search=payroll');

    const credentials = await client.saml.listIdpCredentials();
    expect(Array.isArray(credentials)).toBe(true);
    expect(credentials).toHaveLength(2);
  });
});

// ── 6. No retry ─────────────────────────────────────────────────────────────

describe('§29.8 (6) — none of the seven writes is retried on 503', () => {
  it('exactly one request each, and NetworkError', async () => {
    const server = mockServer();
    const id = freshId();
    const hits = [
      capture(server, 'POST', `${SAML}/service-providers`, 503),
      capture(server, 'PUT', `${SAML}/service-providers/${id}`, 503),
      capture(server, 'DELETE', `${SAML}/service-providers/${id}`, 503),
      capture(server, 'POST', `${SAML}/parse-sp-metadata`, 503),
      capture(server, 'POST', `${SAML}/idp-credentials`, 503),
      capture(server, 'POST', `${SAML}/idp-credentials/${id}/promote`, 503),
      capture(server, 'POST', `${SAML}/idp-credentials/${id}/retire`, 503),
    ];
    const s = retryingManagementClient().saml;
    const errors = [
      await s.createServiceProvider(input()).catch((e: unknown) => e),
      await s.updateServiceProvider(id, input()).catch((e: unknown) => e),
      await s.deleteServiceProvider(id).catch((e: unknown) => e),
      await s.parseSpMetadata(parseSpMetadataFromUrl('https://m')).catch((e: unknown) => e),
      await s.issueIdpCredential({ issuer_ca_id: freshId(), slot: 'next' }).catch((e: unknown) => e),
      await s.promoteIdpCredential(id).catch((e: unknown) => e),
      await s.retireIdpCredential(id).catch((e: unknown) => e),
    ];
    for (const e of errors) expect(e).toBeInstanceOf(NetworkError);
    for (const h of hits) expect(h).toHaveLength(1);
  });
});

// ── 7. Errors ───────────────────────────────────────────────────────────────

describe('§29.8 (7) — statuses map per §2', () => {
  it('409, 400 with its message, 404, 409 on promote, 503 on parse', async () => {
    const server = mockServer();
    const id = freshId();
    capture(server, 'POST', `${SAML}/service-providers`, 409, { error: 'conflict', message: 'entity_id' });
    capture(server, 'PUT', `${SAML}/service-providers/${id}`, 400, {
      error: 'validation_error',
      message: 'entity_id is immutable: register a new service provider',
    });
    capture(server, 'GET', `${SAML}/service-providers/${id}`, 404, { error: 'not_found', message: 'no' });
    capture(server, 'POST', `${SAML}/idp-credentials/${id}/promote`, 409, { error: 'conflict', message: 'not next' });
    capture(server, 'POST', `${SAML}/parse-sp-metadata`, 503, { error: 'service_unavailable', message: 'saml' });
    const s = managementClient().saml;

    await expect(s.createServiceProvider(input())).rejects.toBeInstanceOf(ConflictError);
    const invalid = await s.updateServiceProvider(id, input()).catch((e: unknown) => e);
    expect(invalid).toBeInstanceOf(ValidationError);
    expect((invalid as ValidationError).message).toContain('immutable');
    await expect(s.getServiceProvider(id)).rejects.toBeInstanceOf(NotFoundError);
    await expect(s.promoteIdpCredential(id)).rejects.toBeInstanceOf(ConflictError);
    const unavailable = await s.parseSpMetadata(parseSpMetadataFromUrl('https://m')).catch((e: unknown) => e);
    expect(unavailable).toBeInstanceOf(NetworkError);
    expect(unavailable).not.toBeInstanceOf(ValidationError);
  });
});

// ── 8. Readiness is read, not cached ────────────────────────────────────────

describe('§29.8 (8) — getIdp is never cached and keeps null apart from absent', () => {
  it('two calls, two requests; the configured tenant in the path; null vs absent', async () => {
    const server = mockServer();
    const active = freshId();
    const paths: string[] = [];
    server.use(
      http.get(`${BASE_URL}/api/v1/tenants/:tenant/saml/idp`, ({ request }) => {
        paths.push(new URL(request.url).pathname);
        return HttpResponse.json({
          tenant_id: TENANT_ID,
          saml_available: true,
          saml_idp_enabled: false,
          metadata_served: true,
          entity_id: 'https://iam.example/saml/v2/t',
          metadata_url: 'https://iam.example/saml/v2/t/metadata',
          sso_url: 'https://iam.example/saml/v2/t/sso',
          slo_url: 'https://iam.example/saml/v2/t/slo',
          active_credential_id: active,
          next_credential_id: null,
        });
      }),
    );
    const client = managementClient();
    const info = await client.saml.getIdp();
    await client.saml.getIdp();
    expect(paths).toEqual([`${SAML}/idp`, `${SAML}/idp`]);
    expect(info.active_credential_id).toBe(active);
    expect(info.next_credential_id).toBeNull();
    expect('next_credential_id' in info).toBe(true);
    expect(info.saml_available && info.metadata_served && !info.saml_idp_enabled).toBe(true);

    server.resetHandlers();
    server.use(
      http.get(`${BASE_URL}${SAML}/idp`, () =>
        HttpResponse.json({
          tenant_id: TENANT_ID,
          saml_available: true,
          saml_idp_enabled: false,
          metadata_served: false,
          entity_id: 'e',
          metadata_url: 'm',
          sso_url: 's',
          slo_url: 'l',
        }),
      ),
    );
    const without = await client.saml.getIdp();
    expect(without.next_credential_id).toBeUndefined();
    expect('next_credential_id' in without).toBe(false);
  });
});
