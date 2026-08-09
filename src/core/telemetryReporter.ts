// Request-pair helper for CONTRACT.md §19.
//
// Kept apart from `telemetry.ts` (which is pure event types + the dispatcher)
// so the browser bundle can import the types without pulling timing code it
// does not use.

import { TelemetryDispatcher, type Outcome } from './telemetry.js';

/** Closes a §19 request pair. Call exactly once, on every exit path. */
export type FinishRequest = (status: number | undefined, outcome: Outcome) => void;

/**
 * Emits the §19 `requestStart`/`requestEnd` pair around one **attempt**.
 *
 * Per attempt, not per logical call: §19.2 rule 5 requires a caller to be able
 * to count real wire calls from the events, which one pair per operation would
 * hide — a retried call would look like a single slow one.
 */
export class TelemetryReporter {
  /** @param dispatcher the sink these events are emitted to. */
  constructor(
    /** The underlying §19 dispatcher. */
    readonly dispatcher: TelemetryDispatcher,
  ) {}

  /**
   * Emit `requestStart` and return the function that emits its `requestEnd`.
   *
   * `pathTemplate` must be the route constant — `/api/v1/authz/check`, never a
   * path with ids substituted in. A metric label carrying a UUID is a
   * cardinality bomb.
   */
  startRequest(operation: string, method: string, pathTemplate: string, attempt = 1): FinishRequest {
    if (!this.dispatcher.installed) {
      // Fast path: no hook, no timing work at all.
      return () => {};
    }
    this.dispatcher.emit({ type: 'requestStart', operation, method, pathTemplate, attempt });
    const started = Date.now();
    return (status, outcome) => {
      this.dispatcher.emit({
        type: 'requestEnd',
        operation,
        method,
        pathTemplate,
        attempt,
        status,
        durationMs: Date.now() - started,
        outcome,
      });
    };
  }
}
