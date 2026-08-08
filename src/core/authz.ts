// Shared authz result shape (SDK-Q10, C2) — dependency-free, per D-04's
// core/*.ts rule (no @grpc/grpc-js, amqplib, axios, jose, or node:util
// imports here).
//
// Both the REST transport (`rest/types.ts`) and the gRPC transport
// (`grpc/client.ts`) resolve to the exact same public decision shape —
// `{ allowed, reason? }` — so it is defined once here and re-exported by
// both `rest/index.ts` and `grpc/index.ts` under the same `AccessDecision`
// name, rather than declaring two structurally-identical interfaces that
// could drift out of sync.

/**
 * The outcome of an access check, shared by the REST (`AxiamClient.checkAccess`
 * / `.batchCheck`) and gRPC (`AuthzGrpcClient.checkAccess` / `.batchCheck`)
 * transports (CONTRACT.md §1). `reason` is present (and non-empty) only when
 * `allowed` is `false`.
 */
export interface AccessDecision {
  /**
   * Whether the checked action on the checked resource is permitted.
   *
   * **This field alone carries the outcome.** {@link AccessDecision.reasonCode}
   * explains it and never contradicts it.
   */
  allowed: boolean;
  /** Present (and non-empty) only when `allowed` is `false`; a human-readable reason the check was denied. */
  reason?: string;
  /**
   * Machine-readable decision reason (CONTRACT.md §11 rule 9, B1
   * deny-override): `"allowed"`, `"no_grant"`, or `"denied_by_rule"`.
   *
   * **The two refusals mean opposite things to the person on the other end.**
   * `no_grant` says *ask an admin for access*; `denied_by_rule` says *an admin
   * has already decided*. An application that cannot tell them apart sends
   * users to raise tickets that will be refused — which is why the contract
   * forbids collapsing them into a bare `false`.
   *
   * Absent when the server does not send the field: a newer SDK against an
   * older server treats it as absent, never as an error. An unrecognised value
   * is surfaced verbatim and never changes {@link AccessDecision.allowed} —
   * which is why this is a `string` rather than a union, so a code the SDK has
   * never heard of still reaches the caller intact.
   */
  reasonCode?: string;
}

/**
 * The three `reasonCode` values CONTRACT.md §11 rule 9 defines.
 *
 * @remarks
 * Constants rather than a union type, so an unrecognised server value is still
 * assignable to {@link AccessDecision.reasonCode} and reaches the caller —
 * a closed union would force the SDK to drop it or lie about it.
 */
export const ReasonCode = {
  /** An allow grant matched and no deny did. */
  ALLOWED: 'allowed',
  /** Nothing matched — default deny. *Ask an admin for access.* */
  NO_GRANT: 'no_grant',
  /** An explicit deny rule matched and overrode any allow. *An admin has already decided.* */
  DENIED_BY_RULE: 'denied_by_rule',
} as const;
