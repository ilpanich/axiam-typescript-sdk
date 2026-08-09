// D5 conformance — CONTRACT.md §16, §17, §18, §19.
//
// These assert through the **public `checkAccess` surface**, not against the
// helpers in isolation. That distinction is the whole reason this file exists:
// before this change `withRetry` was exported, unit-tested and green, while
// `checkAccess` never called it — so the SDK performed no read-only retries at
// all and every test passed. §16's preamble now requires conformance be shown
// through the public API for exactly that reason.

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { AxiamClient } from '../../src/rest/client.js';
import { NetworkError } from '../../src/core/index.js';
import {
  backoffMs,
  delayMs,
  MAX_ATTEMPTS,
  BASE_DELAY_MS,
  MAX_DELAY_MS,
} from '../../src/rest/retry.js';
import { DecisionMemo, MAX_TTL_MS, memoKey } from '../../src/core/decisionMemo.js';
import { TelemetryDispatcher, type TelemetryEvent } from '../../src/core/telemetry.js';

const BASE_URL = 'https://axiam-d5.test';
const CHECK_URL = `${BASE_URL}/api/v1/authz/check`;
const RESOURCE = '11111111-2222-3333-4444-555555555555';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});
afterAll(() => server.close());

function client(opts: Partial<ConstructorParameters<typeof AxiamClient>[0]> = {}) {
  return new AxiamClient({
    baseUrl: BASE_URL,
    tenantSlug: 'acme',
    orgSlug: 'acme',
    ...opts,
  });
}

/** Mount the check endpoint, counting hits. */
function mountCheck(responder: () => Response): { calls: () => number } {
  let calls = 0;
  server.use(
    http.post(CHECK_URL, () => {
      calls += 1;
      return responder();
    }),
  );
  return { calls: () => calls };
}

const ok = () => HttpResponse.json({ allowed: true, reason_code: 'allowed' });

// ---------------------------------------------------------------------------
// §16 — the policy table
// ---------------------------------------------------------------------------

describe('§16 backoff and jitter', () => {
  it('doubles from the base and stops at the cap', () => {
    expect(backoffMs(1)).toBe(BASE_DELAY_MS);
    expect(backoffMs(2)).toBe(400);
    expect(backoffMs(20)).toBe(MAX_DELAY_MS);
  });

  it('uses FULL jitter — the range is [0, backoff], not backoff ± something', () => {
    // The assertion that distinguishes full jitter from the partial jitter this
    // SDK used to have (`base + 0–20%`). Partial jitter keeps every client's
    // retries clustered around the same instant, which is the thundering herd
    // retries are supposed to prevent rather than cause.
    expect(delayMs(1, undefined, 0)).toBe(0);
    expect(delayMs(1, undefined, 1)).toBe(BASE_DELAY_MS);
    expect(delayMs(2, undefined, 0.5)).toBe(200);
  });

  it('treats Retry-After as a floor, never a ceiling', () => {
    // This SDK previously did `retryAfterMs ?? backoff(n)` — the hint REPLACED
    // the backoff, so a `Retry-After: 0` retried immediately and defeated the
    // policy entirely. That is the regression this test locks out.
    expect(delayMs(1, 2000, 1)).toBe(2000); // longer hint wins
    expect(delayMs(1, 0, 1)).toBe(BASE_DELAY_MS); // zero hint cannot shorten
    expect(delayMs(1, 50, 0)).toBe(50); // hint still floors a zero-jitter wait
  });
});

describe('§16 through the public checkAccess surface', () => {
  it('makes exactly 3 attempts on a persistent 503', async () => {
    vi.useFakeTimers();
    const { calls } = mountCheck(() => new HttpResponse(null, { status: 503 }));
    const c = client();

    const promise = c.checkAccess({ action: 'read', resourceId: RESOURCE }).catch((e) => e);
    await vi.runAllTimersAsync();
    const err = await promise;

    expect(err).toBeInstanceOf(NetworkError);
    // Exactly 3 — not 1 (the pre-D5 behaviour, where withRetry was never
    // called), and not 4.
    expect(calls()).toBe(MAX_ATTEMPTS);
  });

  it('retries a transient failure and returns the eventual success', async () => {
    vi.useFakeTimers();
    let n = 0;
    const { calls } = mountCheck(() => {
      n += 1;
      return n === 1 ? new HttpResponse(null, { status: 503 }) : (ok() as Response);
    });
    const c = client();

    const promise = c.checkAccess({ action: 'read', resourceId: RESOURCE });
    await vi.runAllTimersAsync();

    await expect(promise).resolves.toMatchObject({ allowed: true });
    expect(calls()).toBe(2);
  });

  it('does not retry a decisive 403', async () => {
    const { calls } = mountCheck(() => new HttpResponse(null, { status: 403 }));
    const c = client();

    await expect(c.checkAccess({ action: 'read', resourceId: RESOURCE })).rejects.toThrow();

    // A 403 is an answer, not a transport failure. Retrying reproduces the
    // identical rejection and wastes the caller's latency budget.
    expect(calls()).toBe(1);
  });

  it('makes exactly one attempt when retrying is disabled', async () => {
    const { calls } = mountCheck(() => new HttpResponse(null, { status: 503 }));
    const c = client({ retryEnabled: false });

    await expect(c.checkAccess({ action: 'read', resourceId: RESOURCE })).rejects.toThrow();

    expect(calls()).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// §17 — decision memo
// ---------------------------------------------------------------------------

describe('§17 decision memo', () => {
  it('is OFF by default — every repeat check reaches the wire', async () => {
    // The most important assertion here. §11.2 rule 6's ban on decision caching
    // is still the default; a build that quietly enabled this would change
    // authorization staleness for every existing caller without them asking.
    const { calls } = mountCheck(() => ok() as Response);
    const c = client();

    await c.checkAccess({ action: 'read', resourceId: RESOURCE });
    await c.checkAccess({ action: 'read', resourceId: RESOURCE });

    expect(calls()).toBe(2);
  });

  it('serves a repeat inside the TTL without a second call', async () => {
    const { calls } = mountCheck(() => ok() as Response);
    const c = client({ decisionMemoTtlMs: 5000 });

    const first = await c.checkAccess({ action: 'read', resourceId: RESOURCE });
    const second = await c.checkAccess({ action: 'read', resourceId: RESOURCE });

    expect(calls()).toBe(1);
    // §17.1 rule 5: the reason code survives the memo. Returning `allowed`
    // while dropping the code would make the field intermittently absent.
    expect(second.reasonCode).toBe('allowed');
    expect(second.allowed).toBe(first.allowed);
  });

  it('memoizes a deny exactly as it memoizes an allow', async () => {
    // §17.1 rule 4. Asymmetric caching makes the two outcomes take measurably
    // different times, leaking which one occurred — so assert the call count,
    // not the outcome.
    const { calls } = mountCheck(
      () => HttpResponse.json({ allowed: false, reason_code: 'denied_by_rule' }) as Response,
    );
    const c = client({ decisionMemoTtlMs: 5000 });

    await c.checkAccess({ action: 'read', resourceId: RESOURCE });
    const second = await c.checkAccess({ action: 'read', resourceId: RESOURCE });

    expect(calls()).toBe(1);
    expect(second.allowed).toBe(false);
    expect(second.reasonCode).toBe('denied_by_rule');
  });

  it('never memoizes a failure', async () => {
    // §17.1 rule 7 — caching a transport error as a deny turns a blip into a
    // TTL-long outage.
    const { calls } = mountCheck(() => new HttpResponse(null, { status: 503 }));
    const c = client({ decisionMemoTtlMs: 5000, retryEnabled: false });

    await expect(c.checkAccess({ action: 'read', resourceId: RESOURCE })).rejects.toThrow();
    await expect(c.checkAccess({ action: 'read', resourceId: RESOURCE })).rejects.toThrow();

    expect(calls()).toBe(2);
  });

  it('clears on logout', async () => {
    // §17.1 rule 9 — entries are keyed by subject, not session.
    const { calls } = mountCheck(() => ok() as Response);
    server.use(http.post(`${BASE_URL}/api/v1/auth/logout`, () => HttpResponse.json({})));
    const c = client({ decisionMemoTtlMs: 5000 });

    await c.checkAccess({ action: 'read', resourceId: RESOURCE });
    await c.checkAccess({ action: 'read', resourceId: RESOURCE });
    expect(calls()).toBe(1);

    await c.logout().catch(() => {});
    await c.checkAccess({ action: 'read', resourceId: RESOURCE });

    expect(calls()).toBe(2);
  });
});

describe('§17 memo unit behaviour', () => {
  it('clamps a TTL above the ceiling rather than rejecting it', () => {
    expect(new DecisionMemo(3_600_000).effectiveTtlMs).toBe(MAX_TTL_MS);
    expect(new DecisionMemo(2000).effectiveTtlMs).toBe(2000);
    expect(new DecisionMemo(0).enabled).toBe(false);
  });

  it('expires exactly at the TTL', () => {
    let now = 1000;
    const memo = new DecisionMemo(5000, () => now);
    memo.set('k', { allowed: true });

    now = 1000 + 4999;
    expect(memo.get('k')).toBeDefined();
    now = 1000 + 5000;
    expect(memo.get('k')).toBeUndefined();
  });

  it('distinguishes every key component, including absent vs present scope', () => {
    const base = { action: 'read', resourceId: 'r1' };
    const keys = new Set([
      memoKey(base),
      memoKey({ ...base, action: 'write' }),
      memoKey({ ...base, resourceId: 'r2' }),
      memoKey({ ...base, scope: 'col-a' }),
      memoKey({ ...base, subjectId: 'u1' }),
    ]);
    expect(keys.size).toBe(5);

    // And an absent scope cannot be forged into a collision with a present one
    // by embedding the separator in a value.
    expect(memoKey({ action: 'read', resourceId: 'r1' })).not.toBe(
      memoKey({ action: 'read', resourceId: 'r1', scope: '' }),
    );
  });
});

// ---------------------------------------------------------------------------
// §18 — deterministic shutdown
// ---------------------------------------------------------------------------

describe('§18 close()', () => {
  it('is idempotent', () => {
    const c = client();
    expect(() => {
      c.close();
      c.close();
    }).not.toThrow();
  });

  it('issues no network request', async () => {
    // §18.1 rule 5. No handler is mounted, so any outbound call would fail the
    // suite's onUnhandledRequest: 'error'. A close() that logged out would end
    // every user's session on each deploy — and would do it silently.
    const c = client();
    c.close();
    // Nothing to await: the assertion is that the line above touched no wire.
    expect(true).toBe(true);
  });

  it('rejects a call after close rather than reconnecting', async () => {
    mountCheck(() => ok() as Response);
    const c = client();
    await expect(c.checkAccess({ action: 'read', resourceId: RESOURCE })).resolves.toBeDefined();

    c.close();

    await expect(c.checkAccess({ action: 'read', resourceId: RESOURCE })).rejects.toThrow(/closed/);
    await expect(c.login('u@example.com', 'pw')).rejects.toThrow(/closed/);
    await expect(c.logout()).rejects.toThrow(/closed/);
  });
});

// ---------------------------------------------------------------------------
// §19 — telemetry
// ---------------------------------------------------------------------------

describe('§19 telemetry', () => {
  it('emits a request pair per ATTEMPT, with a retry between them', async () => {
    vi.useFakeTimers();
    const events: TelemetryEvent[] = [];
    let n = 0;
    mountCheck(() => {
      n += 1;
      return n === 1 ? new HttpResponse(null, { status: 503 }) : (ok() as Response);
    });
    const c = client({ telemetryHook: (e) => events.push(e) });

    const promise = c.checkAccess({ action: 'read', resourceId: RESOURCE });
    await vi.runAllTimersAsync();
    await promise;

    const kinds = events.map((e) => e.type);
    // One pair per attempt, not per logical call: §19.2 rule 5 exists so a
    // caller can count real wire calls from the events.
    expect(kinds).toEqual(['requestStart', 'requestEnd', 'retry', 'requestStart', 'requestEnd']);

    const starts = events.filter((e) => e.type === 'requestStart');
    expect(starts.map((e) => (e as { attempt: number }).attempt)).toEqual([1, 2]);
    // The path TEMPLATE, never a substituted URL — a metric label carrying a
    // UUID is a cardinality bomb.
    expect((starts[0] as { pathTemplate: string }).pathTemplate).toBe('/api/v1/authz/check');
  });

  it('does not let a throwing hook fail the operation', async () => {
    // §19.2 rule 2 — telemetry is not permitted to fail an authorization check.
    mountCheck(() => ok() as Response);
    const c = client({
      telemetryHook: () => {
        throw new Error('hook exploded');
      },
    });

    await expect(c.checkAccess({ action: 'read', resourceId: RESOURCE })).resolves.toMatchObject({
      allowed: true,
    });
  });

  it('carries no token in any event payload', async () => {
    // §19.2 rule 3. This surface exists to be shipped to a metrics backend,
    // which is the last place a bearer token should land.
    vi.useFakeTimers();
    const events: TelemetryEvent[] = [];
    mountCheck(() => new HttpResponse(null, { status: 503 }));
    const c = client({ telemetryHook: (e) => events.push(e) });

    const promise = c.checkAccess({ action: 'read', resourceId: RESOURCE }).catch(() => {});
    await vi.runAllTimersAsync();
    await promise;

    const rendered = JSON.stringify(events);
    expect(rendered).not.toMatch(/eyJ/); // no JWT-shaped string
    expect(rendered).not.toMatch(/authorization/i);
  });

  it('costs nothing when no hook is installed', () => {
    const dispatcher = new TelemetryDispatcher();
    expect(dispatcher.installed).toBe(false);
    expect(() => dispatcher.emit({ type: 'refresh', role: 'leader', durationMs: 1 })).not.toThrow();
  });
});
