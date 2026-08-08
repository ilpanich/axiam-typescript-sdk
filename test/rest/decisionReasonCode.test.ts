// Decision reason codes — CONTRACT.md §11 rule 9 (B1 deny-override).
//
// The rule exists because the two refusals mean **opposite things to the
// person on the other end**: `no_grant` says *ask an admin for access*,
// `denied_by_rule` says *an admin has already decided*. An application that
// cannot tell them apart sends users to raise tickets that will be refused.

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { ReasonCode } from '../../src/core/index.js';
import { AxiamClient } from '../../src/rest/client.js';

const BASE_URL = 'https://axiam-authz.test';
const CHECK_URL = `${BASE_URL}/api/v1/authz/check`;
const BATCH_URL = `${BASE_URL}/api/v1/authz/check/batch`;
const RESOURCE_ID = '11111111-2222-3333-4444-555555555555';

const server = setupServer();
beforeAll(() => {
  server.listen({ onUnhandledRequest: 'error' });
});
afterEach(() => {
  server.resetHandlers();
});
afterAll(() => {
  server.close();
});

function client() {
  return new AxiamClient({ baseUrl: BASE_URL, tenantSlug: 'acme', orgSlug: 'acme' });
}

function mountCheck(body: Record<string, unknown>): void {
  server.use(http.post(CHECK_URL, () => HttpResponse.json(body)));
}

describe('reasonCode on a single check (§11 rule 9)', () => {
  it('surfaces `allowed` on an allow', async () => {
    mountCheck({ allowed: true, reason_code: 'allowed' });
    const decision = await client().checkAccess({ action: 'read', resourceId: RESOURCE_ID });

    expect(decision.allowed).toBe(true);
    expect(decision.reasonCode).toBe(ReasonCode.ALLOWED);
  });

  it('does not collapse no_grant and denied_by_rule', async () => {
    mountCheck({ allowed: false, reason_code: 'no_grant' });
    const noGrant = await client().checkAccess({ action: 'read', resourceId: RESOURCE_ID });

    server.resetHandlers();
    mountCheck({ allowed: false, reason_code: 'denied_by_rule' });
    const byRule = await client().checkAccess({ action: 'read', resourceId: RESOURCE_ID });

    // Both are refusals…
    expect(noGrant.allowed).toBe(false);
    expect(byRule.allowed).toBe(false);
    // …and the SDK must not reduce them to that shared `false`.
    expect(noGrant.reasonCode).toBe(ReasonCode.NO_GRANT);
    expect(byRule.reasonCode).toBe(ReasonCode.DENIED_BY_RULE);
    expect(noGrant.reasonCode).not.toBe(byRule.reasonCode);
  });

  it('surfaces an unrecognised code verbatim and lets it change nothing', async () => {
    // This is what lets the server add a fourth code without breaking every
    // deployed SDK: the outcome is carried by `allowed` alone.
    mountCheck({ allowed: false, reason_code: 'denied_by_some_future_thing' });
    const decision = await client().checkAccess({ action: 'read', resourceId: RESOURCE_ID });

    expect(decision.allowed).toBe(false);
    expect(decision.reasonCode).toBe('denied_by_some_future_thing');
  });

  it('does not let an unrecognised code flip an allow', async () => {
    mountCheck({ allowed: true, reason_code: 'something-unrecognised' });
    const decision = await client().checkAccess({ action: 'read', resourceId: RESOURCE_ID });

    expect(decision.allowed).toBe(true);
  });

  it('treats an older server omitting the field as absent, not an error', async () => {
    mountCheck({ allowed: false });
    const denied = await client().checkAccess({ action: 'read', resourceId: RESOURCE_ID });
    expect(denied.allowed).toBe(false);
    expect(denied.reasonCode).toBeUndefined();

    server.resetHandlers();
    mountCheck({ allowed: true, reason: 'role grants it' });
    const allowed = await client().checkAccess({ action: 'read', resourceId: RESOURCE_ID });
    expect(allowed.allowed).toBe(true);
    expect(allowed.reasonCode).toBeUndefined();
    expect(allowed.reason).toBe('role grants it');
  });
});

describe('enforcement is unchanged (§11 rule 9)', () => {
  it.each([ReasonCode.NO_GRANT, ReasonCode.DENIED_BY_RULE])(
    'answers false from `can` for %s',
    async (code) => {
      // The clause is about *reporting*, not enforcement: both refusals answer
      // `false` identically, and an SDK must not start varying on the code.
      mountCheck({ allowed: false, reason_code: code });
      const allowed = await client().can('read', RESOURCE_ID);
      expect(allowed).toBe(false);
    },
  );
});

describe('batchCheck (§11 rule 9)', () => {
  it('surfaces a reason code per decision', async () => {
    server.use(
      http.post(BATCH_URL, () =>
        HttpResponse.json({
          results: [
            { allowed: true, reason_code: 'allowed' },
            { allowed: false, reason_code: 'no_grant' },
            { allowed: false, reason_code: 'denied_by_rule' },
          ],
        }),
      ),
    );

    const decisions = await client().batchCheck([
      { action: 'read', resourceId: RESOURCE_ID },
      { action: 'write', resourceId: RESOURCE_ID },
      { action: 'delete', resourceId: RESOURCE_ID },
    ]);

    expect(decisions).toHaveLength(3);
    expect(decisions[0]!.reasonCode).toBe(ReasonCode.ALLOWED);
    expect(decisions[1]!.reasonCode).toBe(ReasonCode.NO_GRANT);
    expect(decisions[2]!.reasonCode).toBe(ReasonCode.DENIED_BY_RULE);
  });
});
