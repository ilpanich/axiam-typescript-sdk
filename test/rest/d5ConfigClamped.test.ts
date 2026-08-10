// §19.2 rule 6 — a clamped setting is reported, not swallowed (contract 1.9).
//
// Clamping is right: rejecting would break a caller whose configuration was
// merely optimistic, and honoring would let one client become the herd §16
// exists to prevent. Doing it *silently* is the part that is wrong — an
// operator who set a 60-second memo TTL believes they have one, and their
// staleness reasoning is off by a factor of twelve with nothing to say so.

import { describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';
import { MAX_TTL_MS } from '../../src/core/decisionMemo.js';
import type { ConfigClampedEvent, TelemetryEvent } from '../../src/core/telemetry.js';

const BASE_URL = 'https://axiam-d5.test';

function clampsFor(decisionMemoTtlMs?: number): ConfigClampedEvent[] {
  const events: TelemetryEvent[] = [];
  // Construction alone is the subject here: the event fires at build time,
  // before any request, because that is the only moment an operator can act
  // on it.
  new AxiamClient({
    baseUrl: BASE_URL,
    tenantSlug: 'acme',
    orgSlug: 'acme',
    decisionMemoTtlMs,
    telemetryHook: (e) => events.push(e),
  });
  return events.filter((e): e is ConfigClampedEvent => e.type === 'configClamped');
}

describe('§19.2 rule 6: config_clamped', () => {
  it('reports a memo TTL that was clamped down', () => {
    const clamps = clampsFor(60_000);

    expect(clamps).toHaveLength(1);
    expect(clamps[0].setting).toBe('decisionMemoTtlMs');
    expect(clamps[0].requested).toBe('60000');
    expect(clamps[0].effective).toBe(String(MAX_TTL_MS));
    expect(clamps[0].contractReference).toBe('§17.1 rule 2');
  });

  it('reports nothing for a value already within its limit', () => {
    // An event that fires when nothing happened trains its reader to ignore it.
    expect(clampsFor(2_000)).toEqual([]);
  });

  it('reports nothing for the disabled default', () => {
    // Matters more than it looks: without this guard every client ever built
    // would fire a zero-to-zero "clamp", since the memo is off by default.
    expect(clampsFor()).toEqual([]);
    expect(clampsFor(0)).toEqual([]);
  });
});
