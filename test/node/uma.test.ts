// UMA 2.0 — CONTRACT.md §20.7 required assertions.
//
// Most of §20, like §15, is a list of things an SDK must not helpfully do, so
// most of these tests assert an absence. The centrepiece is §20.2 rule 6: a
// permission ticket must never be retried.
//
// That rule is the one §16 exception in the contract, and the only way to
// assert it is to count requests. A ticket is consumed *before* the request is
// evaluated, so a failed exchange has already spent it — and under concurrency
// a retry is precisely the concurrent redemption a server whose storage engine
// this SDK cannot attest may admit twice (ilpanich/axiam#302). "Exactly one
// request" is a security assertion here, not a performance one.
//
// Every test is named after the thing it stops.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import { umaChallengeHeader, umaParseChallenge } from '../../src/node/index.js';
import {
  BASE_URL,
  CLIENT_SECRET,
  createClient,
  createMockState,
  createServer,
  discoveryHandler,
  TOKEN_ENDPOINT,
} from './oidcTestKit.js';

const PAT = 'pat-token-value';
const TICKET = 'ticket-value';
const CLAIM_TOKEN = 'claim-token-value';
const RESOURCE_ID = '99999999-8888-7777-6666-555555555555';

const server = createServer();
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' });
});
afterEach(() => {
  server.resetHandlers();
});
afterAll(() => {
  server.close();
});

describe('§20.2 rule 6 — the ticket grant is never retried', () => {
  it('does not retry a 5xx', async () => {
    let calls = 0;
    server.use(
      discoveryHandler(createMockState()),
      http.post(TOKEN_ENDPOINT, () => {
        calls += 1;
        return new HttpResponse(null, { status: 500 });
      }),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    await expect(
      client.umaExchangeTicket({ ticket: TICKET, claimToken: CLAIM_TOKEN }),
    ).rejects.toBeInstanceOf(Error);

    expect(
      calls,
      'the ticket grant must issue exactly one request — retrying a spent ticket ' +
        'is the concurrent redemption ilpanich/axiam#302 describes',
    ).toBe(1);
  });

  // §20.7 names the timeout case alongside 5xx and invalid_grant, and it is
  // the one most tempting to treat as "the request never happened" — a §16
  // retry runner normally re-sends a request that produced no response at all.
  //
  // That instinct is wrong here. No response says nothing about whether the
  // server saw the exchange; it may well have arrived and spent the ticket, and
  // silence is not evidence that it did not. Re-sending is then the second
  // redemption.
  //
  // A transport failure stands in for the clock: it is the same observable —
  // no response — and it is deterministic, where a real timeout would race a
  // sleeping test. The other SDKs in this contract do the same.
  it('does not retry when the exchange gets no response at all', async () => {
    let calls = 0;
    server.use(
      discoveryHandler(createMockState()),
      http.post(TOKEN_ENDPOINT, () => {
        calls += 1;
        return HttpResponse.error();
      }),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    await expect(
      client.umaExchangeTicket({ ticket: TICKET, claimToken: CLAIM_TOKEN }),
    ).rejects.toBeInstanceOf(Error);

    expect(
      calls,
      'the ticket grant must issue exactly one request even when it gets no ' +
        'response — the exchange may already have spent the ticket, so a retry ' +
        'is the concurrent redemption a server whose storage engine this SDK ' +
        'cannot attest may admit twice',
    ).toBe(1);
  });

  it('does not retry invalid_grant, the answer a replayed ticket gets', async () => {
    let calls = 0;
    server.use(
      discoveryHandler(createMockState()),
      http.post(TOKEN_ENDPOINT, () => {
        calls += 1;
        return HttpResponse.json(
          {
            error: 'invalid_grant',
            error_description: 'permission ticket is invalid, expired, or already used',
          },
          { status: 400 },
        );
      }),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    const err = await client
      .umaExchangeTicket({ ticket: TICKET, claimToken: CLAIM_TOKEN })
      .then(
        () => undefined,
        (e: unknown) => e,
      );

    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('invalid_grant');
    expect(calls).toBe(1);
  });

  // access_denied arrives as 403 on this grant (UMA 2.0 §3.3.6), unlike
  // RFC 8628's, which is a 400. The SDK dispatches on the `error` field, so the
  // code reaches the caller either way.
  it('surfaces a 403 access_denied as itself and does not auto-narrow', async () => {
    let calls = 0;
    server.use(
      discoveryHandler(createMockState()),
      http.post(TOKEN_ENDPOINT, () => {
        calls += 1;
        return HttpResponse.json(
          {
            error: 'access_denied',
            error_description: 'the requesting party is not authorized for every requested permission',
          },
          { status: 403 },
        );
      }),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    const err = await client
      .umaExchangeTicket({ ticket: TICKET, claimToken: CLAIM_TOKEN })
      .then(
        () => undefined,
        (e: unknown) => e,
      );

    expect((err as OAuthProtocolError).error).toBe('access_denied');
    expect(calls, 'a refused ticket must not be re-requested with fewer scopes').toBe(1);
  });
});

describe('the ticket grant', () => {
  it('sends the required claim_token and its format', async () => {
    let body: URLSearchParams | undefined;
    server.use(
      discoveryHandler(createMockState()),
      http.post(TOKEN_ENDPOINT, async ({ request }) => {
        body = new URLSearchParams(await request.text());
        return HttpResponse.json({
          access_token: 'rpt-value',
          token_type: 'Bearer',
          expires_in: 300,
        });
      }),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    const rpt = await client.umaExchangeTicket({
      ticket: new Sensitive(TICKET),
      claimToken: new Sensitive(CLAIM_TOKEN),
    });

    expect(body?.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:uma-ticket');
    expect(body?.get('ticket')).toBe(TICKET);
    expect(body?.get('claim_token')).toBe(CLAIM_TOKEN);
    expect(body?.get('claim_token_format')).toBe(
      'urn:ietf:params:oauth:token-type:access_token',
    );
    expect(rpt.accessToken.expose()).toBe('rpt-value');
    expect(rpt.expiresIn).toBe(300);
  });

  // §20.2 rule 5: the grant issues no refresh token, so the result type cannot
  // carry one — an application that wants a fresh RPT re-runs the grant.
  it('returns no refresh token', async () => {
    server.use(
      discoveryHandler(createMockState()),
      http.post(TOKEN_ENDPOINT, () =>
        HttpResponse.json({
          access_token: 'rpt-value',
          token_type: 'Bearer',
          expires_in: 300,
          // Even if a server sent one, the SDK must not surface it.
          refresh_token: 'should-not-appear',
        }),
      ),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    const rpt = await client.umaExchangeTicket({ ticket: TICKET, claimToken: CLAIM_TOKEN });

    expect(Object.keys(rpt)).not.toContain('refreshToken');
  });
});

describe('the Protection API', () => {
  it('registers a resource whose _id is directly usable as a ticket resourceId', async () => {
    let ticketBody: unknown;
    server.use(
      http.post(`${BASE_URL}/uma2/rreg/resource_set`, () =>
        HttpResponse.json(
          {
            _id: RESOURCE_ID,
            name: 'invoice-7',
            type: 'document',
            resource_scopes: ['view'],
          },
          { status: 201 },
        ),
      ),
      http.post(`${BASE_URL}/uma2/perm`, async ({ request }) => {
        ticketBody = await request.json();
        return HttpResponse.json({ ticket: TICKET }, { status: 201 });
      }),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    const registered = await client.umaRegisterResource(PAT, {
      name: 'invoice-7',
      type: 'document',
      resourceScopes: ['view'],
    });

    expect(registered.id).toBe(RESOURCE_ID);

    const ticket = await client.umaRequestTicket(PAT, [
      { resourceId: registered.id!, resourceScopes: ['view'] },
    ]);

    expect(ticket.expose()).toBe(TICKET);
    expect(ticketBody).toEqual([{ resource_id: RESOURCE_ID, resource_scopes: ['view'] }]);
  });

  it('sends the PAT as a bearer token', async () => {
    let auth: string | null = null;
    server.use(
      http.post(`${BASE_URL}/uma2/perm`, ({ request }) => {
        auth = request.headers.get('authorization');
        return HttpResponse.json({ ticket: TICKET }, { status: 201 });
      }),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    await client.umaRequestTicket(new Sensitive(PAT), [
      { resourceId: RESOURCE_ID, resourceScopes: ['view'] },
    ]);

    expect(auth).toBe(`Bearer ${PAT}`);
  });

  // §20.2 rule 8: an update replaces the scope list. If the SDK ever
  // read-modify-wrote, the missing GET handler would fail this test (the mock
  // server is configured with onUnhandledRequest: 'error') rather than let it
  // pass quietly.
  it('sends exactly the scopes given on an update, with no read first', async () => {
    let sent: { resource_scopes?: string[] } | undefined;
    server.use(
      http.put(`${BASE_URL}/uma2/rreg/resource_set/${RESOURCE_ID}`, async ({ request }) => {
        sent = (await request.json()) as { resource_scopes?: string[] };
        return HttpResponse.json({
          _id: RESOURCE_ID,
          name: 'invoice-7',
          type: 'document',
          resource_scopes: ['view'],
        });
      }),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    await client.umaUpdateResource(PAT, RESOURCE_ID, {
      name: 'invoice-7',
      type: 'document',
      resourceScopes: ['view'],
    });

    expect(sent?.resource_scopes).toEqual(['view']);
  });

  it('surfaces a 403 from a token that is not a PAT', async () => {
    let calls = 0;
    server.use(
      http.post(`${BASE_URL}/uma2/perm`, () => {
        calls += 1;
        return HttpResponse.json(
          {
            error: 'authorization_denied',
            message: "the protection API requires the 'uma_protection' scope",
          },
          { status: 403 },
        );
      }),
    );

    const { oidc: client } = createClient({ clientSecret: CLIENT_SECRET });
    await expect(
      client.umaRequestTicket('not-a-pat', [
        { resourceId: RESOURCE_ID, resourceScopes: ['view'] },
      ]),
    ).rejects.toBeInstanceOf(Error);
    expect(calls).toBe(1);
  });
});

describe('§20.3 the challenge helpers', () => {
  it('parses a well-formed challenge', () => {
    const parsed = umaParseChallenge(
      `UMA realm="example", as_uri="https://id.example", ticket="${TICKET}"`,
    );
    expect(parsed?.realm).toBe('example');
    expect(parsed?.asUri).toBe('https://id.example');
    expect(parsed?.ticket?.expose()).toBe(TICKET);
  });

  it('rejects a scheme that merely starts with UMA', () => {
    expect(umaParseChallenge('Bearer realm="example"')).toBeUndefined();
    expect(umaParseChallenge('UMAX realm="example"')).toBeUndefined();
  });

  // §20.3: parsing a challenge and acting on it are separate decisions. The
  // as_uri names an authorization server this client has not chosen to trust.
  // The mock server errors on any unhandled request, so an accidental exchange
  // would fail this test rather than pass silently.
  it('performs no exchange when parsing', () => {
    const parsed = umaParseChallenge(
      `UMA realm="example", as_uri="${BASE_URL}", ticket="${TICKET}"`,
    );
    expect(parsed?.ticket?.expose()).toBe(TICKET);
  });

  it('round-trips through the emit half', () => {
    const header = umaChallengeHeader('example', 'https://id.example', new Sensitive(TICKET));
    const parsed = umaParseChallenge(header);
    expect(parsed?.asUri).toBe('https://id.example');
    expect(parsed?.ticket?.expose()).toBe(TICKET);
  });

  // §20.6: the ticket's 60-second life is exactly what invites logging it.
  it('redacts the ticket when a challenge is serialized', () => {
    const parsed = umaParseChallenge(`UMA ticket="super-secret-ticket"`);
    expect(JSON.stringify(parsed)).not.toContain('super-secret-ticket');
  });
});
