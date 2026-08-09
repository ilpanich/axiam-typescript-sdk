// Telemetry hooks — CONTRACT.md §19.
//
// An optional callback surface so callers can wire OpenTelemetry, Prometheus,
// or a log line **without this package depending on any of them**. No hook
// installed costs one undefined check per request.
//
// Two rules from §19.2 are enforced here rather than left to documentation:
//
//   * A hook cannot break the SDK. `TelemetryDispatcher.emit` swallows anything
//     a sink throws, so a broken hook cannot fail an authorization check.
//   * No secrets, ever. `TelemetryEvent` is a closed discriminated union with a
//     fixed field set and no index signature, so there is no way to put a token
//     into a payload bound for a metrics backend. The type system, not a review
//     comment, is what keeps them out.

/** Why a request finished. */
export type Outcome = 'success' | 'failure';

/** Whether this caller performed a §9 refresh or waited on another's. */
export type RefreshRole = 'leader' | 'follower';

/** Emitted before an outbound call leaves the SDK. */
export interface RequestStartEvent {
  /** Discriminant. */
  type: 'requestStart';
  /** Canonical operation name, e.g. `checkAccess`. */
  operation: string;
  /** HTTP method. */
  method: string;
  /**
   * Path **template** — `/api/v1/authz/check`, never a URL with ids
   * substituted in. A metric label carrying a UUID is a cardinality bomb.
   */
  pathTemplate: string;
  /** 1 for the first attempt, incrementing per §16 retry. */
  attempt: number;
}

/** Emitted after a call completes, success or failure. */
export interface RequestEndEvent {
  /** Discriminant. */
  type: 'requestEnd';
  /** Canonical operation name. */
  operation: string;
  /** HTTP method. */
  method: string;
  /** Path template — see {@link RequestStartEvent.pathTemplate}. */
  pathTemplate: string;
  /** Attempt this event closes. */
  attempt: number;
  /** HTTP status, or `undefined` when the call never got a response. */
  status?: number;
  /** Wall-clock duration of this attempt, in milliseconds. */
  durationMs: number;
  /** Success or failure. */
  outcome: Outcome;
}

/**
 * Emitted before each §16 retry wait.
 *
 * §16.5 requires this: a retried-then-succeeded operation is otherwise
 * invisible — the caller sees a slow success and no signal that the server is
 * failing. That silence is the standing objection to automatic retry.
 */
export interface RetryEvent {
  /** Discriminant. */
  type: 'retry';
  /** Canonical operation name. */
  operation: string;
  /** The attempt that just failed. */
  attempt: number;
  /** The delay about to be taken, after jitter and any `Retry-After`. */
  delayMs: number;
  /** Redacted failure description. Never carries a token (§2 redaction rules). */
  reason: string;
}

/** Emitted around a §9 single-flight refresh. */
export interface RefreshEvent {
  /** Discriminant. */
  type: 'refresh';
  /** Whether this caller performed the refresh or waited on another's. */
  role: RefreshRole;
  /** How long the refresh (or the wait for one) took, in milliseconds. */
  durationMs: number;
}

/** A §19 telemetry event. Closed union — see the file header for why. */
export type TelemetryEvent = RequestStartEvent | RequestEndEvent | RetryEvent | RefreshEvent;

/**
 * A caller-supplied telemetry sink (§19).
 *
 * Invoked on the calling path, so it must not block: §19.2 rule 4 makes
 * buffering the caller's job so they can pick the policy. Every mature metrics
 * library already buffers.
 */
export type TelemetryHook = (event: TelemetryEvent) => void;

/**
 * Internal dispatcher. `undefined` is the overwhelmingly common case and costs
 * one check.
 */
export class TelemetryDispatcher {
  constructor(private readonly hook?: TelemetryHook) {}

  /**
   * Emit an event, swallowing anything the caller's hook throws.
   *
   * §19.2 rule 2: telemetry is not permitted to fail an authorization check.
   */
  emit(event: TelemetryEvent): void {
    if (!this.hook) return;
    try {
      this.hook(event);
    } catch {
      // Deliberately swallowed. A hook that throws is the caller's bug, and
      // surfacing it here would turn a metrics problem into an authorization
      // failure.
    }
  }

  /** Whether a hook is installed. */
  get installed(): boolean {
    return this.hook !== undefined;
  }
}
