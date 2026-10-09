// The `ssf` management namespace — CONTRACT.md §32.8's six management tests
// (the receiver helper's eight are in test/node/ssfReceiver.test.ts), plus the
// read-modify-write helper.

import { http, HttpResponse } from 'msw';
import { afterEach, describe, expect, it } from 'vitest';

import { AuthError, NetworkError } from '../../src/core/errors.js';
import { Sensitive } from '../../src/core/sensitive.js';
import { ssfStreamInputFrom } from '../../src/management/checks.js';
import { ConflictError, NotFoundError, ValidationError } from '../../src/management/errors.js';
import type { SsfStream, SsfStreamInput } from '../../src/management/models.js';
import {
  BASE_URL,
  TENANT_ID,
  capture,
  managementClient,
  mockServer,
  retryingManagementClient,
} from '../managementSupport.js';
import { assertNoFragment, exhaustiveErrorRenderings, freshId, freshSecret, renderings } from '../redaction.js';

const STREAMS = `/api/v1/tenants/${TENANT_ID}/ssf/streams`;
const REVOKED = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';

afterEach(() => mockServer().resetHandlers());

function streamBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: freshId(),
    tenant_id: TENANT_ID,
    receiver_client_id: 'rp-1',
    audience: 'https://rp.example',
    description: null,
    delivery_method: 'push',
    endpoint_url: 'https://rp.example/ssf',
    authorization_header_set: true,
    events_allowed: [REVOKED],
    events_requested: [REVOKED],
    events_delivered: [REVOKED],
    subject_format: 'iss_sub',
    status: 'enabled',
    status_reason: null,
    status_actor: 'admin',
    last_verification_at: null,
    created_at: '2026-10-04T00:00:00Z',
    updated_at: '2026-10-04T00:00:00Z',
    transmitter_active: true,
    ...extra,
  };
}

function input(header?: string): SsfStreamInput {
  return {
    audience: 'https://rp.example',
    ...(header !== undefined ? { authorization_header: new Sensitive(header) } : {}),
    delivery_method: 'push',
    description: 'the RP',
    endpoint_url: 'https://rp.example/ssf',
    events_allowed: [REVOKED],
    receiver_client_id: 'rp-1',
  };
}

// ── 1. Replacement ──────────────────────────────────────────────────────────

describe('§32.8 (1) — updateStream puts every member it models', () => {
  it('sends the whole body, decodes the 200, and absent header is not sent', async () => {
    const server = mockServer();
    const id = freshId();
    const seen = capture(server, 'PUT', `${STREAMS}/${id}`, 200, streamBody());
    const body: SsfStreamInput = {
      ...input(),
      events_requested: [REVOKED],
      subject_format: 'iss_sub',
      status: 'enabled',
      status_reason: 'ok',
      clear_authorization_header: false,
    };
    const stream = await managementClient().ssf.updateStream(id, body);
    expect(stream.transmitter_active).toBe(true);
    const sent = seen[0]?.json as Record<string, unknown>;
    for (const member of [
      'receiver_client_id',
      'audience',
      'delivery_method',
      'events_allowed',
      'description',
      'endpoint_url',
      'events_requested',
      'subject_format',
      'status',
      'status_reason',
      'clear_authorization_header',
    ]) {
      expect(member in sent, `${member} not sent`).toBe(true);
    }
    expect(sent.events_allowed).toEqual([REVOKED]);
    expect('authorization_header' in sent, 'absent keeps the stored header').toBe(false);
    // @ts-expect-error — the four required members cannot be left out.
    const incomplete: SsfStreamInput = { audience: 'a' };
    void incomplete;
  });
});

// ── 2. The header is Sensitive ──────────────────────────────────────────────

describe('§32.8 (2) — the push header is sent and never rendered or decoded', () => {
  it('redacts the input, sends the header, drops it from the response', async () => {
    const server = mockServer();
    const header = `Bearer ${freshSecret()}`;
    const body = input(header);
    assertNoFragment(renderings(body), header.slice(7), 'SsfStreamInput');
    const seen = capture(server, 'POST', STREAMS, 201, streamBody({ authorization_header: header }));
    const created: SsfStream = await managementClient().ssf.createStream(body);
    expect((seen[0]?.json as Record<string, unknown>).authorization_header === header, 'not sent').toBe(true);
    assertNoFragment(renderings(created), header.slice(7), 'SsfStream');
    expect('authorization_header' in created).toBe(false);
    expect(created.authorization_header_set).toBe(true);
    // @ts-expect-error — SsfStream declares no authorization_header member.
    void created.authorization_header;
  });

  // R-18 (contract 1.59): an error raised by create_stream or update_stream on
  // a 5xx or a dropped connection is a NetworkError whose cause carried the
  // serialized body; it must not hold the header either.
  it('redacts the error raised by createStream and updateStream on a 5xx and on a transport failure', async () => {
    const server = mockServer();
    const client = managementClient();
    const id = freshId();
    const failures = [
      () => HttpResponse.json({ error: 'internal_error' }, { status: 500 }),
      () => new HttpResponse(null, { status: 503 }),
      () => HttpResponse.error(),
    ];
    for (const respond of failures) {
      const token = freshSecret();
      server.use(
        http.post(`${BASE_URL}${STREAMS}`, respond),
        http.put(`${BASE_URL}${STREAMS}/${id}`, respond),
      );
      for (const err of [
        await client.ssf.createStream(input(`Bearer ${token}`)).catch((e: unknown) => e),
        await client.ssf.updateStream(id, input(`Bearer ${token}`)).catch((e: unknown) => e),
      ]) {
        expect(err).toBeInstanceOf(NetworkError);
        assertNoFragment(exhaustiveErrorRenderings(err), token, 'error');
      }
      server.resetHandlers();
    }
  });
});

// ── 3. Open decoding ────────────────────────────────────────────────────────

describe('§32.8 (3) — unknown values and both transmitter states decode', () => {
  it('unknown status / delivery_method / subject_format / status_actor / event type', async () => {
    const server = mockServer();
    const id = freshId();
    const odd = streamBody({
      status: 'quarantined',
      delivery_method: 'websocket',
      subject_format: 'opaque',
      status_actor: 'policy',
      events_allowed: ['https://example.test/event-type/new'],
    });
    capture(server, 'GET', `${STREAMS}/${id}`, 200, odd);
    const stream = await managementClient().ssf.getStream(id);
    expect(stream.status).toBe('quarantined');
    expect(stream.delivery_method).toBe('websocket');
    expect(stream.subject_format).toBe('opaque');
    expect(stream.status_actor).toBe('policy');
    expect(stream.events_allowed[0]).toBe('https://example.test/event-type/new');

    server.resetHandlers();
    capture(server, 'GET', `${STREAMS}/${id}`, 200, streamBody({
      transmitter_active: false,
      transmitter_inactive_reason: 'per-tenant issuers are off in a multi-tenant deployment',
    }));
    const inactive = await managementClient().ssf.getStream(id);
    expect(inactive.transmitter_active).toBe(false);
    expect(typeof inactive.transmitter_inactive_reason).toBe('string');

    server.resetHandlers();
    capture(server, 'GET', `${STREAMS}/${id}`, 200, streamBody());
    const active = await managementClient().ssf.getStream(id);
    expect(active.transmitter_inactive_reason).toBeUndefined();
  });
});

// ── 4. Pagination ───────────────────────────────────────────────────────────

describe('§32.8 (4) — listStreams pages and the walk carries search', () => {
  it('Page with total; search on every request', async () => {
    const server = mockServer();
    const queries: string[] = [];
    server.use(
      http.get(`${BASE_URL}${STREAMS}`, ({ request }) => {
        const url = new URL(request.url);
        queries.push(url.search);
        const offset = Number(url.searchParams.get('offset') ?? '0');
        return HttpResponse.json({ items: offset < 2 ? [streamBody()] : [], total: 2, offset, limit: 1 });
      }),
    );
    const client = managementClient();
    const page = await client.ssf.listStreams({ limit: 1, search: 'rp.example' });
    expect(page.total).toBe(2);
    const all = await client.ssf.listStreamsAll({ limit: 1, search: 'rp.example' });
    expect(all).toHaveLength(2);
    for (const q of queries) expect(q).toContain('search=rp.example');
  });
});

// ── 5. No retry ─────────────────────────────────────────────────────────────

describe('§32.8 (5) — none of the three writes is retried on 503', () => {
  it('exactly one request each, NetworkError', async () => {
    const server = mockServer();
    const id = freshId();
    const hits = [
      capture(server, 'POST', STREAMS, 503),
      capture(server, 'PUT', `${STREAMS}/${id}`, 503),
      capture(server, 'DELETE', `${STREAMS}/${id}`, 503),
    ];
    const s = retryingManagementClient().ssf;
    const errors = [
      await s.createStream(input(`Bearer ${freshSecret()}`)).catch((e: unknown) => e),
      await s.updateStream(id, input()).catch((e: unknown) => e),
      await s.deleteStream(id).catch((e: unknown) => e),
    ];
    for (const e of errors) expect(e).toBeInstanceOf(NetworkError);
    for (const h of hits) expect(h).toHaveLength(1);
  });
});

// ── 6. Errors ───────────────────────────────────────────────────────────────

describe('§32.8 (6) — statuses map per §2', () => {
  it('400 with message, 409 on create, 404 on get, 401', async () => {
    const server = mockServer();
    const id = freshId();
    capture(server, 'PUT', `${STREAMS}/${id}`, 400, { error: 'validation_error', message: 'endpoint_url: must be https' });
    capture(server, 'POST', STREAMS, 409, { error: 'conflict', message: 'audience' });
    capture(server, 'GET', `${STREAMS}/${id}`, 404, { error: 'not_found', message: 'no' });
    capture(server, 'DELETE', `${STREAMS}/${id}`, 401, { error: 'unauthorized', message: 'human only' });
    capture(server, 'POST', '/api/v1/auth/refresh', 401, { error: 'unauthorized' });
    const s = managementClient().ssf;
    const invalid = await s.updateStream(id, input()).catch((e: unknown) => e);
    expect(invalid).toBeInstanceOf(ValidationError);
    expect((invalid as ValidationError).message).toContain('https');
    await expect(s.createStream(input())).rejects.toBeInstanceOf(ConflictError);
    await expect(s.getStream(id)).rejects.toBeInstanceOf(NotFoundError);
    await expect(s.deleteStream(id)).rejects.toBeInstanceOf(AuthError);
  });
});

describe('read-modify-write', () => {
  it('a read converts into the replacement body without the header', () => {
    const stream = streamBody() as unknown as SsfStream;
    const body = ssfStreamInputFrom(stream);
    expect('authorization_header' in body).toBe(false);
    expect('clear_authorization_header' in body).toBe(false);
    expect(body.events_requested).toEqual(stream.events_requested);
    expect(body.description).toBeNull();
  });
});
