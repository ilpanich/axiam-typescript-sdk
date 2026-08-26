/**
 * The plan a manifest reconciles to — CONTRACT.md §27.6.
 */

import { NetworkError } from '../../core/errors.js';
import type { ManagementManifest } from './spec.js';

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
  | 'group-member';

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

/** The failing step, if the apply stopped early. */
export function failure(report: ApplyReport): ManifestFailure | undefined {
  const found = report.steps.find((s) => s.outcome.status === 'failed');
  return found ? { action: found.action, message: (found.outcome as { message: string }).message } : undefined;
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

  const resourceKeys = new Set(resources.map((r) => r.key));
  const scopeKeys = new Set(resources.flatMap((r) => (r.scopes ?? []).map((s) => s.key)));
  const permissionKeys = new Set(permissions.map((p) => p.key));
  const roleKeys = new Set(roles.map((r) => r.key));
  const groupKeys = new Set(groups.map((g) => g.key));

  duplicates('resource', resources.map((r) => r.key), problems);
  duplicates('scope', resources.flatMap((r) => (r.scopes ?? []).map((s) => s.key)), problems);
  duplicates('permission', permissions.map((p) => p.key), problems);
  duplicates('role', roles.map((r) => r.key), problems);
  duplicates('group', groups.map((g) => g.key), problems);
  duplicates('user', users.map((u) => u.key), problems);

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
  for (const group of groups) {
    for (const role of group.roles ?? []) {
      if (!roleKeys.has(role)) {
        problems.push(`group ${q(group.key)} is assigned role ${q(role)}, which no role declares`);
      }
    }
  }
  for (const user of users) {
    for (const role of user.roles ?? []) {
      if (!roleKeys.has(role)) {
        problems.push(`user ${q(user.key)} is assigned role ${q(role)}, which no role declares`);
      }
    }
    for (const group of user.groups ?? []) {
      if (!groupKeys.has(group)) {
        problems.push(`user ${q(user.key)} is in group ${q(group)}, which no group declares`);
      }
    }
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
