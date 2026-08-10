// Client-side decision memo — CONTRACT.md §17.
//
// **Disabled by default.** §11.2 rule 6's ban on caching allow/deny decisions
// is still the default behaviour; this is the single opt-in exception that
// section carves out, and a caller has to switch it on having read the cost.
//
// # What it costs
//
// The staleness bound is the TTL, **in both directions**. A grant revoked on
// the server can still read as allowed for up to the TTL, and a grant just
// added can still read as denied for up to the TTL. That second direction is
// the one that surprises people: **reads-your-own-writes is not guaranteed.**
// An admin UI that grants a role and immediately re-checks is the case that
// breaks, and it breaks silently.
//
// This mirrors the server's own bound rather than inventing a second staleness
// story — AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS (default 5 s) makes the same
// trade server-side. One deliberate difference: the server's setting is an
// unclamped integer, so an operator can configure a multi-hour staleness
// window. MAX_TTL_MS clamps this one at 5 s, because the client has no reason
// to repeat that.

import type { AccessDecision } from './authz.js';
import type { TelemetryDispatcher } from './telemetry.js';

/**
 * The §17.1 rule 2 ceiling. A configured TTL above this is clamped, not
 * rejected: a caller who asked for 60 s wants caching, and silently giving them
 * the maximum safe value beats failing construction.
 */
export const MAX_TTL_MS = 5_000;

/**
 * Entry cap before FIFO eviction (§17.1 rule 8). The memo is a latency
 * optimisation, so dropping an entry is always correct.
 */
const MAX_ENTRIES = 1024;

/**
 * The §17.1 rule 3 key: all four components, with absent distinguished from
 * present.
 *
 * `\u001f` (unit separator) joins the parts because it cannot appear in an
 * action, a UUID or a scope, so no combination of values can forge a
 * collision. `\u0000` marks an *absent* optional, which is why an absent scope
 * can never collide with a present one — a memo that let them collide would
 * answer a narrower question with a broader answer.
 */
export function memoKey(check: {
  action: string;
  resourceId: string;
  scope?: string;
  subjectId?: string;
}): string {
  const ABSENT = '\u0000';
  return [
    check.subjectId ?? ABSENT,
    check.resourceId,
    check.action,
    check.scope ?? ABSENT,
  ].join('\u001f');
}

interface Entry {
  decision: AccessDecision;
  storedAt: number;
}

/**
 * A bounded, TTL-clamped decision memo.
 *
 * `ttlMs === 0` means **disabled** — not "cache for zero milliseconds". That is
 * the default, and both `get` and `set` become no-ops.
 */
export class DecisionMemo {
  private readonly ttlMs: number;
  private readonly entries = new Map<string, Entry>();

  /**
   * @param ttlMs requested TTL in milliseconds; `0` disables the memo and any
   *   value above {@link MAX_TTL_MS} is clamped to it.
   * @param now injected clock, so the TTL can be tested without waiting.
   */
  constructor(
    ttlMs = 0,
    /** Injected so the TTL can be tested without waiting. */
    private readonly now: () => number = Date.now,
  ) {
    this.ttlMs = Math.min(Math.max(ttlMs, 0), MAX_TTL_MS);
  }

  /** Whether this memo does anything. `false` for the default configuration. */
  get enabled(): boolean {
    return this.ttlMs > 0;
  }

  /** The effective TTL after clamping. */
  get effectiveTtlMs(): number {
    return this.ttlMs;
  }

  /** A live decision for `key`, if one is memoized and unexpired. */
  get(key: string): AccessDecision | undefined {
    if (!this.enabled) return undefined;
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (this.now() - entry.storedAt >= this.ttlMs) {
      this.entries.delete(key);
      return undefined;
    }
    // Returned whole, including `reasonCode`: §17.1 rule 5 forbids returning
    // `allowed` while dropping the code, which would make the field
    // intermittently absent — worse than never having had it.
    return entry.decision;
  }

  /**
   * Memoize a decision the server actually returned.
   *
   * Callers must only reach here on success. §17.1 rule 7 forbids
   * negative-caching a failure: memoizing a transport error as a deny would
   * turn a blip into a TTL-long outage, and memoizing it as an allow is
   * unthinkable.
   */
  set(key: string, decision: AccessDecision): void {
    if (!this.enabled) return;
    // Re-inserting moves the key to the end of Map iteration order, which is
    // what makes the eviction below FIFO by insertion.
    this.entries.delete(key);
    this.entries.set(key, { decision, storedAt: this.now() });
    while (this.entries.size > MAX_ENTRIES) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }

  /**
   * Drop every entry (§17.1 rule 9).
   *
   * Called on login, verifyMfa, refresh and logout. Entries are keyed by
   * subject, not by session, so a re-authentication as a *different* principal
   * would otherwise read the previous principal's decisions.
   */
  clear(): void {
    this.entries.clear();
  }

  /**
   * Emit a {@link ConfigClampedEvent} if the requested TTL was clamped (§19.2
   * rule 6).
   *
   * This is the clamp that matters most to get right: an operator who set a
   * 60-second TTL believes their staleness bound is 60 seconds. It is five, and
   * without this event nothing anywhere says so.
   *
   * Nothing is emitted when the requested value was already inside the limit,
   * or when the memo is disabled — an event that fires when nothing happened
   * trains its reader to ignore it.
   */
  reportClamp(requestedMs: number, telemetry: TelemetryDispatcher): void {
    if (!telemetry.installed || requestedMs <= 0 || requestedMs === this.ttlMs) return;
    telemetry.emit({
      type: 'configClamped',
      setting: 'decisionMemoTtlMs',
      requested: String(requestedMs),
      effective: String(this.ttlMs),
      contractReference: '§17.1 rule 2',
    });
  }

  /** Entry count, for tests. */
  get size(): number {
    return this.entries.size;
  }
}
