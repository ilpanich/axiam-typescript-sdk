// Bounded read-only retry policy — CONTRACT.md §16.
//
// This file previously held a policy of its own invention: 1000 ms base, 8 s
// cap, partial jitter (`base + 0–20%`), and `Retry-After` *replacing* the
// computed backoff rather than flooring it. Two problems with that, both now
// fixed:
//
//   * `retryAfterMs ?? backoffDelayMs(attempt)` meant a `Retry-After: 0`
//     retried immediately, defeating the backoff entirely — exactly what
//     §16.1's "floor, never a ceiling" forbids.
//   * It was exported and unit-tested but **never called by any production
//     path**. `checkAccess` did not route through it, so this SDK performed no
//     read-only retries at all while appearing to. A tested helper nobody calls
//     is worse than an absent one: the green tests are what stop anyone from
//     looking.
//
// §16 is the normative table all eleven SDKs now share. `withRetry` is wired
// into the authz surface in `authz.ts`; the §16.7 tests assert the policy
// through the public `checkAccess` API, not just against this helper.

import { NetworkError } from '../core/index.js';
import type { TelemetryDispatcher } from '../core/telemetry.js';

/** Attempt cap: 1 initial + 2 retries (§16.1). */
export const MAX_ATTEMPTS = 3;
/** First backoff step, in milliseconds (§16.1). */
export const BASE_DELAY_MS = 200;
/** Ceiling on any single computed backoff, in milliseconds (§16.1). */
export const MAX_DELAY_MS = 5_000;

/** Options controlling {@link withRetry}. */
export interface RetryOptions {
  /**
   * Only operations that change **no server state** may be retried (§16.2).
   *
   * Note this means side-effect-free, **not** "is an HTTP GET": AXIAM's
   * authorization check is a `POST` with a request body and is the single most
   * important operation covered by this policy.
   */
  idempotent: boolean;
  /** Canonical operation name, for the §19 `retry` event. */
  operation?: string;
  /** Set `false` to disable retrying entirely (§16.1 disable switch). */
  enabled?: boolean;
  /** §19 sink, notified before each retry wait. */
  telemetry?: TelemetryDispatcher;
  /** Injected for tests — see §16.7 ("a test that really waits 200 ms is a test nobody runs"). */
  sleepFn?: (ms: number) => Promise<void>;
  /** Injected for tests: returns the jitter fraction in [0, 1]. */
  randomFn?: () => number;
}

interface RetryAfterCarrier {
  retryAfterMs?: number;
}

function isRetryAfterCarrier(err: unknown): err is RetryAfterCarrier {
  return typeof err === 'object' && err !== null && 'retryAfterMs' in err;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * The un-jittered backoff for a 1-based attempt: `min(cap, base * 2^(n-1))`.
 * Attempt 1 → 200 ms, attempt 2 → 400 ms.
 */
export function backoffMs(attempt: number): number {
  return Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** (attempt - 1));
}

/**
 * The actual wait: **full jitter** over `[0, backoff]`, then raised to any
 * server-supplied `Retry-After` (§16.1).
 *
 * Full jitter, not `backoff ± 10%`. Partial jitter keeps every client's retries
 * clustered around the same instant, which is the thundering herd retries are
 * supposed to prevent rather than cause.
 *
 * `Retry-After` is a **floor, never a ceiling**: the server is saying when it
 * will be ready, so retrying sooner is not permitted — and a `Retry-After: 0`
 * cannot shorten the wait below what jitter chose.
 */
export function delayMs(attempt: number, retryAfterMs: number | undefined, fraction: number): number {
  const jittered = backoffMs(attempt) * Math.min(Math.max(fraction, 0), 1);
  return retryAfterMs === undefined ? jittered : Math.max(jittered, retryAfterMs);
}

/**
 * Runs `fn` under the §16 policy.
 *
 * `fn` receives the 1-based attempt number so it can label its §19
 * `requestStart`/`requestEnd` pair. That is not cosmetic: §19.2 rule 5 requires
 * one pair **per attempt** with the attempt distinguishing them, so a caller
 * can count real wire calls. Emitting every pair as attempt 1 would make a
 * retried call indistinguishable from a single slow one — the exact blindness
 * §16.5 exists to remove.
 *
 * `fn` MUST be side-effect-free. This helper — like every retry helper — cannot
 * tell the difference, so routing a mutation through it would silently
 * duplicate a side effect, or replay a single-use credential (an authorization
 * code, a device code at redemption, a rotating refresh token) into a hard
 * `invalid_grant`.
 *
 * Only `NetworkError` is retried. The §2 taxonomy folds `408`/`429`/`5xx`/
 * transport into that one type, so this implements the whole §16.3 table:
 * `AuthError` and `AuthzError` are decisive answers, not transport failures.
 */
export async function withRetry<T>(
  fn: (attempt: number) => Promise<T>,
  options: RetryOptions,
): Promise<T> {
  const retryable = options.idempotent && options.enabled !== false;
  const maxAttempts = retryable ? MAX_ATTEMPTS : 1;
  const sleep = options.sleepFn ?? defaultSleep;
  const random = options.randomFn ?? Math.random;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await fn(attempt);
    } catch (err) {
      const isLastAttempt = attempt === maxAttempts;
      if (!retryable || !(err instanceof NetworkError) || isLastAttempt) {
        throw err;
      }
      const retryAfterMs = isRetryAfterCarrier(err) ? err.retryAfterMs : undefined;
      const delay = delayMs(attempt, retryAfterMs, random());
      // §16.5 — without this event a retried-then-succeeded call is invisible:
      // a slow success with no signal that the server is failing.
      options.telemetry?.emit({
        type: 'retry',
        operation: options.operation ?? 'unknown',
        attempt,
        delayMs: delay,
        reason: err instanceof Error ? err.message : String(err),
      });
      await sleep(delay);
    }
  }

  // Unreachable: the loop above always returns or throws.
  throw new NetworkError('retry loop exhausted without a result');
}
