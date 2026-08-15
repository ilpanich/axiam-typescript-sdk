// The reactor event registry and its mutable-field allow-lists
// (CONTRACT.md §22.5, §22.7, §22.8).
//
// Mirror, never import. This is the same data as the server's
// `EVENT_REGISTRY` in `crates/axiam-core/src/models/reactor.rs`, restated here
// so a reactor author can name an event, ask what it may mutate, and compute a
// registration's default failure policy without a network call. The live copy
// is served at `GET /api/v1/reactors/events` and is the one an admin UI SHOULD
// read; this table is the offline equivalent.
//
// What is deliberately absent (§22.7 — normative MUST NOT): `authz.check`,
// `authz.check_batch` and `token.introspect`. They are not hookable and this
// SDK does not present them as such — they appear in no constant, no array and
// no example here. A reactor round-trip is milliseconds; the check path's
// budget is microseconds. An application that needs external input on an
// authorization decision writes a deny grant, which the engine evaluates in the
// hot path at hot-path cost.

/**
 * What the server does when an interceptor produces no usable reply
 * (CONTRACT.md §22.8).
 *
 * "No usable reply" is one closed set and every member takes the same path:
 * timeout, transport failure, a budget exhausted before this reactor was
 * reached, the in-flight cap, and every §22.4 rejection — including a valid
 * signature carrying a forbidden patch field.
 */
export type FailurePolicy = 'fail_open' | 'fail_closed';

/**
 * How a reactor participates in an event (CONTRACT.md §22.5, §22.9).
 *
 * `listen` is fire-and-forget observation: the server never waits and never
 * reads a reply, so a listener cannot affect any outcome — and
 * {@link reactorServe} publishes nothing at all in that mode.
 */
export type ReactorMode = 'intercept' | 'listen';

/**
 * One hookable event: its name, what a reply may change, and what happens when
 * the reactor does not answer (CONTRACT.md §22.5).
 */
export interface ReactorEventSpec {
  /** Wire name, and the second half of the routing key (`<tenant_id>.<event>`). */
  readonly name: string;
  /** Whether an interceptor may register for this event at all. */
  readonly interceptable: boolean;
  /** Whether an interceptor's reply may carry a `patch`. */
  readonly mutable: boolean;
  /**
   * The **complete** allow-list. An entry ending in `.` is a namespace prefix
   * — see {@link patchFieldAllowed}.
   */
  readonly mutableFields: readonly string[];
  /** The `failure_policy` a registration gets when it names none. */
  readonly defaultFailurePolicy: FailurePolicy;
  /** One line, as the admin surface shows it. */
  readonly description: string;
}

/**
 * The five v1 event names.
 *
 * Handlers compare against these rather than string literals so a typo is a
 * type error rather than an event that silently never fires.
 */
export const REACTOR_EVENTS = {
  /** Before an access token is minted. Mutable: the `ext.` claim namespace. */
  TOKEN_PRE_ISSUE: 'token.pre_issue',
  /**
   * After credentials verify, before a session is issued. Veto or step-up.
   *
   * Fires on password authentication, on SAML ACS and on the OIDC callback
   * (§22.5, SEC-095). MFA completion and the WebAuthn `authenticate/finish`
   * ceremony are **not** separate firings — both continue a login that was
   * already gated at its first step.
   *
   * The federated paths have no step-up branch, so a `require_mfa` answer on
   * those is **refused** (the sign-in fails) rather than silently dropped: a
   * reactor that needs step-up there answers `deny` and drives enrolment out of
   * band.
   */
  LOGIN_POST_AUTH: 'login.post_auth',
  /** Before a user row is written. Mutable: `username`, `email`, `metadata.`. */
  USER_PRE_CREATE: 'user.pre_create',
  /** Before a user row is updated. Mutable: `username`, `email`, `metadata.`. */
  USER_PRE_UPDATE: 'user.pre_update',
  /** Before a role or permission is assigned. Veto only. */
  GRANT_PRE_ASSIGN: 'grant.pre_assign',
} as const;

/** The union of the five v1 registry event names. */
export type ReactorEventName = (typeof REACTOR_EVENTS)[keyof typeof REACTOR_EVENTS];

/**
 * Every hookable event in v1 — five of them (CONTRACT.md §22.5).
 *
 * The order matches the server's `EVENT_REGISTRY`. Nothing on the authorization
 * hot path appears here, and nothing may be added to it locally: an event
 * outside the registry dispatches to nothing and resolves to `allow`, which is
 * what makes §22.7's exclusion structural rather than advisory.
 */
export const EVENT_REGISTRY: readonly ReactorEventSpec[] = [
  {
    name: REACTOR_EVENTS.TOKEN_PRE_ISSUE,
    interceptable: true,
    mutable: true,
    // Custom claims only. `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`,
    // `scope`, `scp`, `azp`, `act` and `client_id` are all unreachable because
    // none of them begins with `ext.` — a hook that can rewrite `sub` is a hook
    // that can mint a token for anyone.
    mutableFields: ['ext.'],
    defaultFailurePolicy: 'fail_open',
    description: 'Enrich or veto token issuance. May add claims under `ext.` only.',
  },
  {
    name: REACTOR_EVENTS.LOGIN_POST_AUTH,
    interceptable: true,
    mutable: false,
    mutableFields: [],
    defaultFailurePolicy: 'fail_closed',
    description:
      'After credentials verify, before session issuance: veto or require step-up MFA.',
  },
  {
    name: REACTOR_EVENTS.USER_PRE_CREATE,
    interceptable: true,
    mutable: true,
    mutableFields: ['username', 'email', 'metadata.'],
    defaultFailurePolicy: 'fail_closed',
    description: "Validate or normalize a new user's profile fields.",
  },
  {
    name: REACTOR_EVENTS.USER_PRE_UPDATE,
    interceptable: true,
    mutable: true,
    mutableFields: ['username', 'email', 'metadata.'],
    defaultFailurePolicy: 'fail_closed',
    description: 'Validate or normalize a profile update.',
  },
  {
    name: REACTOR_EVENTS.GRANT_PRE_ASSIGN,
    interceptable: true,
    mutable: false,
    mutableFields: [],
    defaultFailurePolicy: 'fail_closed',
    description: 'Veto a role or permission assignment (four-eyes workflows). Veto-only.',
  },
];

/**
 * Look an event up by wire name. `undefined` for anything outside the registry
 * — including the three hot-path operations §22.7 excludes.
 */
export function eventSpec(name: string): ReactorEventSpec | undefined {
  return EVENT_REGISTRY.find((spec) => spec.name === name);
}

/**
 * Whether `field` may appear in a `patch` for `spec` (CONTRACT.md §22.5).
 *
 * An allow-list entry ending in `.` is a **namespace prefix**, and it matches a
 * field that starts with the entry and has **at least one character after the
 * dot**. So `ext.` admits `ext.department` and `ext.a.b.c`, and refuses `ext.`
 * itself (it names the namespace, not a claim), `ext` (not in the namespace),
 * `extra` / `external_id` (a prefix match on the *string* is not a match on the
 * namespace) and `evil.ext.department` (not a suffix match either).
 *
 * ## This is a lookup, not a filter
 *
 * It exists so a handler can check its own patch before returning it.
 * {@link reactorServe} does **not** call it to prune a patch: §22.4 rule 1 and
 * §22.10 rule 3 forbid filtering a handler's patch down to the allowed subset,
 * because one forbidden key rejects the *whole* patch server-side and dropping
 * it silently would leave the author believing a field was set when it was not.
 */
export function patchFieldAllowed(spec: ReactorEventSpec, field: string): boolean {
  if (!spec.mutable) return false;
  return spec.mutableFields.some((allowed) =>
    allowed.endsWith('.')
      ? field.length > allowed.length && field.startsWith(allowed)
      : field === allowed,
  );
}

/**
 * The `failure_policy` a registration gets when it names none: **the strictest
 * default among its events** (CONTRACT.md §22.8).
 *
 * A reactor registered for both `token.pre_issue` (open) and `login.post_auth`
 * (closed) can veto a login, so it inherits `fail_closed` — **in either array
 * order**. Reimplementing this as "take the first event's default" would let
 * the order of a JSON array decide whether an unreachable fraud check passes.
 *
 * An unknown event name contributes `fail_closed`: it will be refused at
 * registration anyway, and guessing `fail_open` for a name this SDK does not
 * recognise is the one guess that could weaken a decision. An empty list is
 * likewise `fail_closed` — a registration with no events is invalid, not
 * permissive.
 */
export function defaultFailurePolicyFor(eventNames: readonly string[]): FailurePolicy {
  if (eventNames.length === 0) return 'fail_closed';
  for (const name of eventNames) {
    const spec = eventSpec(name);
    if (!spec || spec.defaultFailurePolicy === 'fail_closed') return 'fail_closed';
  }
  return 'fail_open';
}

/** Default `timeout_ms` when a registration does not name one (§22.8). */
export const DEFAULT_REACTOR_TIMEOUT_MS = 500;

/** Lowest accepted `timeout_ms` at registration (§22.8). `0` is refused. */
export const MIN_REACTOR_TIMEOUT_MS = 1;

/**
 * Hard ceiling on a registration's `timeout_ms`, and on the whole chain's wall
 * clock (§22.8). A reactor that needs longer than five seconds to answer is not
 * an interceptor, it is an outage.
 */
export const MAX_REACTOR_TIMEOUT_MS = 5_000;

/**
 * Per-tenant in-flight interception cap, enforced server-side with a
 * non-blocking acquire (§22.8). Stated here so a reactor author sizing a worker
 * pool knows the ceiling they are working under.
 */
export const DEFAULT_REACTOR_MAX_IN_FLIGHT = 64;
