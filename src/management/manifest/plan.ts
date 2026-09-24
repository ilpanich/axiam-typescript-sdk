/**
 * The plan a manifest reconciles to — CONTRACT.md §27.6.
 */

import { NetworkError } from '../../core/errors.js';
import type { Sensitive } from '../../core/sensitive.js';
import { inheritOf, resourceKeyOf, roleKeyOf, type ManagementManifest, type RoleBinding } from './spec.js';

/** What reconciling one spec would do. */
export type Change = 'create' | 'update' | 'no-change';

/** Which part of the manifest an action came from. */
export type Target =
  | 'resource'
  | 'scope'
  | 'permission'
  | 'role'
  | 'role-grant'
  | 'group'
  | 'group-role'
  | 'user'
  | 'user-role'
  | 'group-member'
  | 'service-account'
  | 'service-account-role';

/** One step of a plan. */
export interface PlannedAction {
  /** Whether this step creates, updates, or does nothing. */
  change: Change;
  /** What kind of thing it acts on. */
  target: Target;
  /** The manifest key it came from, for a human reading the plan. */
  key: string;
  /** A one-line description, stable across runs so plans can be diffed. */
  summary: string;
}

/**
 * The ordered set of actions that would reconcile a manifest.
 *
 * Ordering is derived, not incidental: resources (parents before children),
 * then scopes, permissions, roles, role grants, groups, group bindings, users,
 * and finally the user bindings that need all of the above to exist. Two plans
 * over unchanged state are equal, in the same order (§27.6 rule 8) — a plan
 * that reorders between runs cannot be diffed, and diffing it is most of the
 * reason it exists.
 */
export interface ManagementPlan {
  /** Every step, including the no-ops. */
  actions: PlannedAction[];
}

/** The steps of `plan` that would actually change something. */
export function changes(plan: ManagementPlan): PlannedAction[] {
  return plan.actions.filter((a) => a.change !== 'no-change');
}

/**
 * Whether applying `plan` would change nothing.
 *
 * This is the §27.6 rule 6 acceptance test: `apply` then `plan` must land
 * here, or the SDK has a drift-detection bug.
 */
export function isConverged(plan: ManagementPlan): boolean {
  return changes(plan).length === 0;
}

/**
 * What actually happened to one planned step.
 *
 * Named `StepOutcome` rather than `Outcome` because `core/telemetry` already
 * exports an `Outcome` — the success/failure of a single request — and two
 * exported types of that name in one package is one too many.
 */
export type StepOutcome =
  | {
      /** The step ran and the thing now exists. */
      status: 'created';
      /**
       * §27.5 rule 5 (contract 1.51): the one-time `client_secret` a
       * `service_accounts` `Create` action returned. `undefined` for every
       * other kind of `created` step. **This is the only place this secret
       * is ever surfaced** — `apply` never calls `rotate_secret` to
       * reconcile anything, so a caller who discards this value has
       * destroyed the credential just as surely as discarding
       * `service_accounts.create`'s own return value would.
       */
      serviceAccountSecret?: Sensitive<string>;
    }
  | {
      /** The step ran and the thing was updated. */
      status: 'updated';
    }
  | {
      /** A no-op step; nothing was sent. */
      status: 'unchanged';
    }
  | {
      /** The step failed. Everything before it has already happened. */
      status: 'failed';
      /** The error the server or transport gave. */
      message: string;
    }
  | {
      /** Never attempted, because an earlier step failed. */
      status: 'not-attempted';
    }
  | {
      /**
       * §27.6.1 item 2 (contract 1.51): a role-binding `Update` is
       * `unassign` then `assign`, and the `assign` half failed — the
       * subject now holds neither the old binding nor the new one, unless
       * `restoreSucceeded`. The SDK attempted to re-assign the previous
       * binding (same resource, same `inherit`) and reports both outcomes,
       * rather than leaving the caller to discover the gap on their own.
       */
      status: 'rebind-failed';
      /** The error the `assign` half gave. */
      message: string;
      /** Whether re-assigning the PREVIOUS binding succeeded. */
      restoreSucceeded: boolean;
      /** The error the restore attempt gave, if `restoreSucceeded` is `false`. */
      restoreMessage?: string;
    };

/** One planned step paired with what became of it. */
export interface AppliedStep {
  /** The step, exactly as `plan` reported it. */
  action: PlannedAction;
  /** What actually happened when it ran — or did not. */
  outcome: StepOutcome;
}

/** The step that stopped an apply, and why. */
export interface ManifestFailure {
  /** The step that failed. Everything before it has already happened. */
  action: PlannedAction;
  /** The error the server or transport gave. */
  message: string;
}

/**
 * The result of applying a manifest.
 *
 * **There is no transaction here and this type does not pretend there is**
 * (§27.6 rule 7). These are independent HTTP endpoints; nothing spans them. If
 * step 12 of 30 fails, steps 1–11 have happened and will not be undone — so
 * every step's outcome is reported, execution stops at the first failure
 * rather than continuing blindly, and there is no `rollback` because this SDK
 * could not honour one. Fix the cause and re-apply: rule 6's idempotence is
 * what makes that safe.
 */
export interface ApplyReport {
  /** Each planned step paired with what became of it, in plan order. */
  steps: AppliedStep[];
}

/**
 * The failing step, if the apply stopped early.
 *
 * A `rebind-failed` step counts too (contract 1.51): the subject's role
 * binding did not end up in either the old or the new shape unless the
 * restore succeeded, which is exactly the "stops at the first failure"
 * condition §27.6 rule 7 describes, even though the step's own outcome is
 * not literally `'failed'`.
 */
export function failure(report: ApplyReport): ManifestFailure | undefined {
  const found = report.steps.find(
    (s) => s.outcome.status === 'failed' || s.outcome.status === 'rebind-failed',
  );
  if (!found) return undefined;
  const message =
    found.outcome.status === 'rebind-failed'
      ? `${found.outcome.message}${found.outcome.restoreSucceeded ? ' (previous binding restored)' : ` (restore also failed: ${found.outcome.restoreMessage ?? 'unknown error'})`}`
      : (found.outcome as { message: string }).message;
  return { action: found.action, message };
}

/** Whether every step that was meant to run did. */
export function isComplete(report: ApplyReport): boolean {
  return failure(report) === undefined;
}

/** How many steps actually changed something. */
export function changedCount(report: ApplyReport): number {
  return report.steps.filter(
    (s) => s.outcome.status === 'created' || s.outcome.status === 'updated',
  ).length;
}

/**
 * Reject a manifest that cannot be reconciled, before any request is made.
 *
 * §27.6 rules 2 and 5 both land here. Every failure this catches would
 * otherwise surface halfway through an apply, with part of the tenant already
 * changed — which is the expensive moment to learn that a role refers to a
 * permission nobody declared.
 *
 * @internal
 */
export function validate(manifest: ManagementManifest): void {
  const problems: string[] = [];
  const resources = manifest.resources ?? [];
  const permissions = manifest.permissions ?? [];
  const roles = manifest.roles ?? [];
  const groups = manifest.groups ?? [];
  const users = manifest.users ?? [];
  const serviceAccounts = manifest.serviceAccounts ?? [];

  const resourceKeys = new Set(resources.map((r) => r.key));
  const scopeKeys = new Set(resources.flatMap((r) => (r.scopes ?? []).map((s) => s.key)));
  const permissionKeys = new Set(permissions.map((p) => p.key));
  const roleKeys = new Set(roles.map((r) => r.key));
  const roleIsGlobal = new Map(roles.map((r) => [r.key, r.isGlobal ?? false] as const));
  const groupKeys = new Set(groups.map((g) => g.key));

  duplicates('resource', resources.map((r) => r.key), problems);
  duplicates('scope', resources.flatMap((r) => (r.scopes ?? []).map((s) => s.key)), problems);
  duplicates('permission', permissions.map((p) => p.key), problems);
  duplicates('role', roles.map((r) => r.key), problems);
  duplicates('group', groups.map((g) => g.key), problems);
  duplicates('user', users.map((u) => u.key), problems);
  duplicates('service account', serviceAccounts.map((s) => s.key), problems);

  for (const resource of resources) {
    if (resource.parent && !resourceKeys.has(resource.parent)) {
      problems.push(
        `resource ${q(resource.key)} names parent ${q(resource.parent)}, which no resource declares`,
      );
    }
  }
  for (const role of roles) {
    for (const grant of role.grants ?? []) {
      if (!permissionKeys.has(grant.permission)) {
        problems.push(
          `role ${q(role.key)} grants permission ${q(grant.permission)}, which no permission declares`,
        );
      }
      for (const scope of grant.scopes ?? []) {
        if (!scopeKeys.has(scope)) {
          problems.push(`role ${q(role.key)} scopes a grant to ${q(scope)}, which no scope declares`);
        }
      }
    }
  }

  /**
   * §27.6.1 item 2: validate one subject's `roles[]` — every binding names a
   * declared role and (when scoped) a declared resource, the subject holds
   * each role at most once across BOTH shapes combined (the server keys
   * assignments on `(subject, role)` with no resource component — a
   * manifest that binds one role to one subject twice, plain-and-scoped
   * included, describes a state the server cannot hold), and a global role
   * is never bound here with `inherit: false` (the server refuses it with
   * `400`; §27.6.1's MAY to check it client-side).
   */
  function checkRoleBindings(kind: string, subjectKey: string, bindings: RoleBinding[]): void {
    const seenRoles = new Set<string>();
    for (const binding of bindings) {
      const role = roleKeyOf(binding);
      const resource = resourceKeyOf(binding);
      if (!roleKeys.has(role)) {
        problems.push(`${kind} ${q(subjectKey)} is assigned role ${q(role)}, which no role declares`);
        continue;
      }
      if (resource !== undefined && !resourceKeys.has(resource)) {
        problems.push(
          `${kind} ${q(subjectKey)}'s binding of role ${q(role)} names resource ${q(resource)}, which no resource declares`,
        );
      }
      if (seenRoles.has(role)) {
        problems.push(
          `${kind} ${q(subjectKey)} is assigned role ${q(role)} more than once (plain and/or resource-scoped) — ` +
            'the server holds at most one assignment per (subject, role)',
        );
      }
      seenRoles.add(role);
      if (!inheritOf(binding) && roleIsGlobal.get(role) === true) {
        problems.push(
          `${kind} ${q(subjectKey)} binds global role ${q(role)} with inherit: false, which the server refuses ` +
            '(a global role ignores resource scope)',
        );
      }
      // CONTRACT 1.52 N6.2 (C-12): "An object binding requires resource.
      // inherit without a resource is refused client-side." `inherit`
      // names which of a RESOURCE's descendants a binding reaches — with no
      // resource stated there is nothing for `inherit: false` to mean. A
      // stated `inherit: true` with no resource is NOT refused here: rule
      // 2's other clause treats it as accepted and planned exactly like an
      // omitted one (a plain, tenant-wide binding), so only the `false`
      // value — inheritOf(binding) === false, i.e. explicitly stated,
      // never the true/omitted default — triggers this.
      if (resource === undefined && !inheritOf(binding)) {
        problems.push(
          `${kind} ${q(subjectKey)} binds role ${q(role)} with inherit: false and no resource — ` +
            'inherit is meaningful only on a resource-scoped binding (CONTRACT.md §27.6.1 item 2)',
        );
      }
    }
  }

  for (const group of groups) {
    checkRoleBindings('group', group.key, group.roles ?? []);
  }
  for (const user of users) {
    checkRoleBindings('user', user.key, user.roles ?? []);
    for (const group of user.groups ?? []) {
      if (!groupKeys.has(group)) {
        problems.push(`user ${q(user.key)} is in group ${q(group)}, which no group declares`);
      }
    }
  }
  for (const serviceAccount of serviceAccounts) {
    checkRoleBindings('service account', serviceAccount.key, serviceAccount.roles ?? []);
  }

  try {
    topologicalOrder(manifest);
  } catch (err) {
    problems.push((err as Error).message);
  }

  if (problems.length) {
    throw new NetworkError(
      `manifest is not reconcilable (${problems.length} problem(s)): ${problems.join('; ')}`,
    );
  }
}

const q = (s: string) => JSON.stringify(s);

function duplicates(kind: string, keys: string[], problems: string[]): void {
  const seen = new Set<string>();
  for (const key of keys) {
    if (seen.has(key)) problems.push(`${kind} key ${q(key)} is declared more than once`);
    seen.add(key);
  }
}

/**
 * Resource keys ordered so a parent always precedes its children.
 *
 * Throws on a cycle rather than looping: a resource graph with a cycle has no
 * valid creation order, and discovering that by hanging is worse than
 * discovering it by message.
 *
 * @internal
 */
export function topologicalOrder(manifest: ManagementManifest): string[] {
  const resources = manifest.resources ?? [];
  const parents = new Map(resources.map((r) => [r.key, r.parent]));
  const order: string[] = [];
  const placed = new Set<string>();

  // Iterate the manifest's own order so the result is stable run to run
  // (§27.6 rule 8), rather than a map traversal order that is not.
  for (const resource of resources) {
    const chain: string[] = [];
    const guard = new Set<string>();
    let cursor: string | undefined = resource.key;
    while (cursor !== undefined && !placed.has(cursor)) {
      if (guard.has(cursor)) {
        throw new NetworkError(
          `resource parent graph has a cycle through ${q(cursor)}; there is no order in which ` +
            `these can be created`,
        );
      }
      guard.add(cursor);
      chain.push(cursor);
      cursor = parents.get(cursor);
    }
    for (const key of chain.reverse()) {
      if (!placed.has(key)) {
        placed.add(key);
        order.push(key);
      }
    }
  }
  return order;
}
