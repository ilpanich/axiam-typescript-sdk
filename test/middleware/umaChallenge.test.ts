// The §20.3 emit half, wired into the §11 guards (Express and Fastify).
//
// `RequireAccessOptions.umaChallenge` turns a denial from a bare 403 into a 403
// that tells the caller where to obtain authority. Everything asserted here is
// about the *deny* path, because that is the only path that mints anything:
//
// 1. A denial with a challenger mints exactly one ticket and emits it.
// 2. An allow mints nothing — a guard that minted on the happy path would put a
//    Protection API call in front of every authorized request.
// 3. A minting failure still denies, without a challenge. An outage must not
//    turn a deny into a 500, and must never turn it into an allow.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import type { Response } from 'express';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createVerifier } from '../../src/node/jwks.js';
import { AxiamClient } from '../../src/rest/client.js';
import { Sensitive } from '../../src/core/index.js';
import { requireAccess, type AxiamRequest } from '../../src/middleware/express.js';
import { requireAccessHook } from '../../src/middleware/fastify.js';
import {
  type AuthzVerifiableSession,
  type UmaChallenger,
} from '../../src/middleware/index.js';
// The consuming half lives in the Node entry point; the emitting half is in the
// middleware core. Parsing what the guard emitted is the round-trip assertion.
import { umaParseChallenge } from '../../src/node/index.js';

const BASE_URL = 'https://axiam-mw-uma.test';
const CHECK_PATH = `${BASE_URL}/api/v1/authz/check`;
const PAT = 'pat-token-value';
const TICKET = 'ticket-value';
const RESOURCE_ID = '99999999-8888-7777-6666-555555555555';

const AXIAM_USER = { userId: 'user-1', tenantId: 'tenant-1', roles: [] };

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function session(): AuthzVerifiableSession {
  return {
    jwksVerifier: createVerifier(BASE_URL),
    tenantHeaderValue: 'tenant-1',
    authzClient: new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'tenant-1' }),
  };
}

function mockCheck(allowed: boolean): void {
  server.use(http.post(CHECK_PATH, () => HttpResponse.json({ allowed, reason: 'no matching grant' })));
}

/** A challenger whose minter is a spy, so the assertions can count calls. */
function challengerWith(
  mint: UmaChallenger['mint'],
): UmaChallenger & { mint: ReturnType<typeof vi.fn> } {
  return {
    realm: 'invoices',
    asUri: 'https://id.example',
    pat: PAT,
    mint: vi.fn(mint) as ReturnType<typeof vi.fn>,
  } as UmaChallenger & { mint: ReturnType<typeof vi.fn> };
}

const mintsTicket: UmaChallenger['mint'] = async () => new Sensitive(TICKET);
const mintFails: UmaChallenger['mint'] = async () => {
  throw new Error('protection api unavailable');
};

function fakeRes(): Response & { headers: Record<string, string>; statusCode?: number } {
  const headers: Record<string, string> = {};
  const res: Record<string, unknown> = { headers };
  res.status = vi.fn((code: number) => {
    res.statusCode = code;
    return res;
  });
  res.json = vi.fn(() => res);
  res.setHeader = vi.fn((name: string, value: string) => {
    headers[name] = value;
    return res;
  });
  return res as unknown as Response & { headers: Record<string, string>; statusCode?: number };
}

function fakeReq(): AxiamRequest {
  return { headers: {}, params: { id: RESOURCE_ID }, axiamUser: AXIAM_USER } as unknown as AxiamRequest;
}

describe('express: §20.3 challenge emission on denial', () => {
  it('mints one ticket and emits a parseable challenge', async () => {
    mockCheck(false);
    const challenger = challengerWith(mintsTicket);
    const res = fakeRes();

    await requireAccess(session(), 'invoices:read', RESOURCE_ID, { umaChallenge: challenger })(
      fakeReq(),
      res,
      vi.fn(),
    );

    expect(res.statusCode, 'the challenge is additive, not a redirect').toBe(403);
    expect(challenger.mint, 'one ticket, not two').toHaveBeenCalledTimes(1);

    // The emitted header is the one the consuming half parses — the round trip
    // is the point of shipping both halves.
    const parsed = umaParseChallenge(res.headers['WWW-Authenticate']);
    expect(parsed?.realm).toBe('invoices');
    expect(parsed?.asUri).toBe('https://id.example');
    expect(parsed?.ticket?.expose()).toBe(TICKET);
  });

  it('asks for the action that was refused, on the resource that was refused', async () => {
    mockCheck(false);
    const challenger = challengerWith(mintsTicket);

    await requireAccess(session(), 'invoices:approve', RESOURCE_ID, { umaChallenge: challenger })(
      fakeReq(),
      fakeRes(),
      vi.fn(),
    );

    // §20.2: the UMA scope is the AXIAM *action*. Asking for anything else would
    // mint a ticket for authority other than the one just refused — and would
    // break the deny-override property the server relies on.
    expect(challenger.mint).toHaveBeenCalledWith(PAT, [
      { resourceId: RESOURCE_ID, resourceScopes: ['invoices:approve'] },
    ]);
  });

  it('mints nothing on an allow', async () => {
    mockCheck(true);
    const challenger = challengerWith(mintsTicket);
    const next = vi.fn();

    await requireAccess(session(), 'invoices:read', RESOURCE_ID, { umaChallenge: challenger })(
      fakeReq(),
      fakeRes(),
      next,
    );

    expect(next).toHaveBeenCalled();
    // A guard that minted on the happy path would put a Protection API call —
    // and a live credential — in front of every authorized request.
    expect(challenger.mint).not.toHaveBeenCalled();
  });

  it('still denies, without a challenge, when minting fails', async () => {
    mockCheck(false);
    const challenger = challengerWith(mintFails);
    const res = fakeRes();

    await requireAccess(session(), 'invoices:read', RESOURCE_ID, { umaChallenge: challenger })(
      fakeReq(),
      res,
      vi.fn(),
    );

    // Failure is not escalation: the caller was going to be refused, and a
    // Protection API outage must not turn that into a 500 — nor into an allow.
    expect(res.statusCode).toBe(403);
    expect(res.headers['WWW-Authenticate']).toBeUndefined();
    expect(challenger.mint, 'one attempt, not a retry loop').toHaveBeenCalledTimes(1);
  });

  it('leaves an unconfigured guard exactly as it was', async () => {
    mockCheck(false);
    const res = fakeRes();

    await requireAccess(session(), 'invoices:read', RESOURCE_ID)(fakeReq(), res, vi.fn());

    // Opt-in means opt-in: an application that never asked for UMA semantics
    // gets no Protection API traffic from its guards.
    expect(res.statusCode).toBe(403);
    expect(res.headers['WWW-Authenticate']).toBeUndefined();
  });
});

describe('fastify: §20.3 challenge emission on denial', () => {
  /** Minimal reply double recording the header and status the hook sets. */
  function fakeReply(): {
    headers: Record<string, string>;
    statusCode?: number;
    header: ReturnType<typeof vi.fn>;
    code: ReturnType<typeof vi.fn>;
    send: ReturnType<typeof vi.fn>;
  } {
    const headers: Record<string, string> = {};
    const reply = {
      headers,
      statusCode: undefined as number | undefined,
      header: vi.fn((name: string, value: string) => {
        headers[name] = value;
        return reply;
      }),
      code: vi.fn((status: number) => {
        reply.statusCode = status;
        return reply;
      }),
      send: vi.fn(async () => reply),
    };
    return reply;
  }

  it('emits the challenge through reply.header', async () => {
    mockCheck(false);
    const challenger = challengerWith(mintsTicket);
    const reply = fakeReply();
    const request = { params: { id: RESOURCE_ID }, axiamUser: AXIAM_USER, headers: {} };

    await requireAccessHook(session(), 'invoices:read', RESOURCE_ID, {
      umaChallenge: challenger,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    })(request as any, reply as any);

    expect(reply.statusCode).toBe(403);
    expect(umaParseChallenge(reply.headers['WWW-Authenticate'])?.ticket?.expose()).toBe(TICKET);
  });

  it('mints nothing on an allow', async () => {
    mockCheck(true);
    const challenger = challengerWith(mintsTicket);
    const reply = fakeReply();
    const request = { params: { id: RESOURCE_ID }, axiamUser: AXIAM_USER, headers: {} };

    await requireAccessHook(session(), 'invoices:read', RESOURCE_ID, {
      umaChallenge: challenger,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    })(request as any, reply as any);

    expect(reply.code).not.toHaveBeenCalled();
    expect(challenger.mint).not.toHaveBeenCalled();
  });
});
