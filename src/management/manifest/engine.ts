/**
 * Reconciling a manifest against a live tenant — CONTRACT.md §27.6.
 */

import { NetworkError } from '../../core/errors.js';
import type { AxiamClient } from '../../rest/client.js';
import type * as models from '../models.js';
import type {
  ApplyReport,
  ManagementPlan,
  Outcome,
  PlannedAction,
  Target,
} from './plan.js';
import { topologicalOrder, validate } from './plan.js';
import type { ManagementManifest, ResourceSpec } from './spec.js';

/** How many items a planning read asks for per page. */
const PLAN_PAGE = 200;

/** Manifest keys resolved to server ids, built during planning. */
interface Resolved {
  resources: Map<string, string>;
  scopes: Map<string, string>;
  permissions: Map<string, string>;
  roles: Map<string, string>;
  groups: Map<string, string>;
  users: Map<string, string>;
}

const emptyResolved = (): Resolved => ({
  resources: new Map(),
  scopes: new Map(),
  permissions: new Map(),
  roles: new Map(),
  groups: new Map(),
  users: new Map(),
});

/** One executable step, carrying manifest keys rather than ids. */
type Step =
  | { kind: 'noop' }
  | { kind: 'create-resource'; key: string; name: string; resourceType: string; parent?: string }
  | { kind: 'update-resource'; key: string; resourceType: string }
  | { kind: 'create-scope'; resource: string; key: string; name: string; description: string }
  | { kind: 'create-permission'; key: string; action: string; description: string }
  | { kind: 'update-permission'; key: string; description: string }
  | { kind: 'create-role'; key: string; name: string; description: string; isGlobal: boolean }
  | { kind: 'update-role'; key: string; description: string; isGlobal: boolean }
  | {
      kind: 'grant-permission';
      role: string;
      permission: string;
      effect?: models.PermissionEffect;
      scopes: string[];
    }
  | { kind: 'create-group'; key: string; name: string; description: string }
  | { kind: 'update-group'; key: string; description: string }
  | { kind: 'assign-role-to-group'; role: string; group: string }
  | {
      kind: 'create-user';
      key: string;
      username: string;
      email: string;
      password: models.CreateUserRequest['password'];
    }
  | { kind: 'update-user'; key: string; email: string }
  | { kind: 'assign-role-to-user'; role: string; user: string }
  | { kind: 'add-group-member'; group: string; user: string };

/** The current state a plan is computed against. */
interface Snapshot {
  resources: models.Resource[];
  scopes: Map<string, models.Scope[]>;
  permissions: models.Permission[];
  roles: models.Role[];
  groups: models.Group[];
  users: models.UserResponse[];
  roleGrants: Map<string, string[]>;
  roleUsers: Map<string, string[]>;
  roleGroups: Map<string, string[]>;
  groupMembers: Map<string, string[]>;
}

/** The declarative-management handle, reached as `client.manifest`. */
export class ManifestApi {
  readonly #client: AxiamClient;

  /** @internal — reached through `client.manifest`, never constructed directly. */
  constructor(client: AxiamClient) {
    this.#client = client;
  }

  /** What reconciling `manifest` would do. **Issues no writes.** */
  async plan(manifest: ManagementManifest): Promise<ManagementPlan> {
    validate(manifest);
    const snapshot = await this.#read(manifest);
    return { actions: this.#compute(manifest, snapshot).map((s) => s.action) };
  }

  /**
   * Reconcile `manifest`, stopping at the first failure.
   *
   * Re-running after fixing the cause is the recovery path, and is safe:
   * applying twice converges (§27.6 rule 6).
   */
  async apply(manifest: ManagementManifest): Promise<ApplyReport> {
    validate(manifest);
    const snapshot = await this.#read(manifest);
    const steps = this.#compute(manifest, snapshot);
    const resolved = this.#resolvedFrom(manifest, snapshot);
    return this.#execute(steps, resolved);
  }

  // -------------------------------------------------------------------
  // Read
  // -------------------------------------------------------------------

  async #read(manifest: ManagementManifest): Promise<Snapshot> {
    const c = this.#client;
    const start = { limit: PLAN_PAGE };
    const resources = await c.resources.listAll(start);
    const permissions = await c.permissions.listAll(start);
    const roles = await c.roles.listAll(start);
    const groups = await c.groups.listAll(start);
    const users = await c.users.listAll(start);

    // Only the resources, roles and groups the manifest could match: a tenant
    // with a thousand resources should not cost a thousand scope reads to plan
    // five.
    const scopes = new Map<string, models.Scope[]>();
    for (const resource of resources) {
      if ((manifest.resources ?? []).some((s) => s.name === resource.name)) {
        scopes.set(resource.id, await c.scopes.list(resource.id));
      }
    }
    const roleGrants = new Map<string, string[]>();
    const roleUsers = new Map<string, string[]>();
    const roleGroups = new Map<string, string[]>();
    for (const role of roles) {
      if (!(manifest.roles ?? []).some((s) => s.name === role.name)) continue;
      roleGrants.set(role.id, (await c.roles.listPermissions(role.id)).map((g) => g.permission.id));
      roleUsers.set(role.id, (await c.roles.listUsers(role.id)).map((a) => a.user.id));
      roleGroups.set(role.id, (await c.roles.listGroups(role.id)).map((a) => a.group.id));
    }
    const groupMembers = new Map<string, string[]>();
    for (const group of groups) {
      if (!(manifest.groups ?? []).some((s) => s.name === group.name)) continue;
      groupMembers.set(group.id, (await c.groups.listMembersAll(group.id, start)).map((u) => u.id));
    }

    return {
      resources,
      scopes,
      permissions,
      roles,
      groups,
      users,
      roleGrants,
      roleUsers,
      roleGroups,
      groupMembers,
    };
  }

  // -------------------------------------------------------------------
  // Plan
  // -------------------------------------------------------------------

  #resolvedFrom(manifest: ManagementManifest, snapshot: Snapshot): Resolved {
    const resolved = emptyResolved();
    this.#compute(manifest, snapshot, resolved);
    return resolved;
  }

  #compute(
    manifest: ManagementManifest,
    snapshot: Snapshot,
    into: Resolved = emptyResolved(),
  ): Array<{ action: PlannedAction; step: Step }> {
    const resolved = into;
    const out: Array<{ action: PlannedAction; step: Step }> = [];
    const push = (change: PlannedAction['change'], target: Target, key: string, summary: string, step: Step) =>
      out.push({ action: { change, target, key, summary }, step });

    const specs = new Map((manifest.resources ?? []).map((r) => [r.key, r] as const));
    // `topologicalOrder` already rejected a cycle during validation.
    for (const key of topologicalOrder(manifest)) {
      const spec = specs.get(key) as ResourceSpec;
      const parentPending = spec.parent !== undefined && !resolved.resources.has(spec.parent);
      const parentId = spec.parent ? resolved.resources.get(spec.parent) : undefined;
      // A child whose parent is itself pending cannot already exist, so
      // matching it against a root of the same name would be wrong.
      const existing = parentPending
        ? undefined
        : snapshot.resources.find(
            (r) => r.name === spec.name && (r.parent_id ?? undefined) === parentId,
          );
      const summary = `resource ${JSON.stringify(spec.name)} (${spec.resourceType})`;
      if (existing) {
        resolved.resources.set(spec.key, existing.id);
        const drifted = existing.resource_type !== spec.resourceType;
        push(
          drifted ? 'update' : 'no-change',
          'resource',
          spec.key,
          summary,
          drifted
            ? { kind: 'update-resource', key: spec.key, resourceType: spec.resourceType }
            : { kind: 'noop' },
        );
      } else {
        push('create', 'resource', spec.key, summary, {
          kind: 'create-resource',
          key: spec.key,
          name: spec.name,
          resourceType: spec.resourceType,
          parent: spec.parent,
        });
      }
    }

    for (const key of topologicalOrder(manifest)) {
      const spec = specs.get(key) as ResourceSpec;
      const resourceId = resolved.resources.get(spec.key);
      const existingScopes = (resourceId && snapshot.scopes.get(resourceId)) || [];
      for (const scope of spec.scopes ?? []) {
        const found = existingScopes.find((s) => s.name === scope.name);
        const summary = `scope ${JSON.stringify(scope.name)} on ${JSON.stringify(spec.name)}`;
        if (found) {
          resolved.scopes.set(scope.key, found.id);
          push('no-change', 'scope', scope.key, summary, { kind: 'noop' });
        } else {
          push('create', 'scope', scope.key, summary, {
            kind: 'create-scope',
            resource: spec.key,
            key: scope.key,
            name: scope.name,
            description: scope.description,
          });
        }
      }
    }

    for (const spec of manifest.permissions ?? []) {
      const found = snapshot.permissions.find((p) => p.action === spec.action);
      const summary = `permission ${JSON.stringify(spec.action)}`;
      if (found) {
        resolved.permissions.set(spec.key, found.id);
        const drifted = found.description !== spec.description;
        push(
          drifted ? 'update' : 'no-change',
          'permission',
          spec.key,
          summary,
          drifted
            ? { kind: 'update-permission', key: spec.key, description: spec.description }
            : { kind: 'noop' },
        );
      } else {
        push('create', 'permission', spec.key, summary, {
          kind: 'create-permission',
          key: spec.key,
          action: spec.action,
          description: spec.description,
        });
      }
    }

    for (const spec of manifest.roles ?? []) {
      const found = snapshot.roles.find((r) => r.name === spec.name);
      const summary = `role ${JSON.stringify(spec.name)}`;
      const isGlobal = spec.isGlobal ?? false;
      if (found) {
        resolved.roles.set(spec.key, found.id);
        const drifted = found.description !== spec.description || found.is_global !== isGlobal;
        push(
          drifted ? 'update' : 'no-change',
          'role',
          spec.key,
          summary,
          drifted
            ? { kind: 'update-role', key: spec.key, description: spec.description, isGlobal }
            : { kind: 'noop' },
        );
      } else {
        push('create', 'role', spec.key, summary, {
          kind: 'create-role',
          key: spec.key,
          name: spec.name,
          description: spec.description,
          isGlobal,
        });
      }
    }

    // Role grants. Present-or-absent only: a grant this manifest does not
    // mention is left alone (§27.6 rule 3), which is why there is no revoke.
    for (const spec of manifest.roles ?? []) {
      const roleId = resolved.roles.get(spec.key);
      const held = roleId ? snapshot.roleGrants.get(roleId) : undefined;
      for (const grant of spec.grants ?? []) {
        const permissionId = resolved.permissions.get(grant.permission);
        const present = !!held && !!permissionId && held.includes(permissionId);
        push(
          present ? 'no-change' : 'create',
          'role-grant',
          spec.key,
          `role ${JSON.stringify(spec.name)} grants ${JSON.stringify(grant.permission)}`,
          present
            ? { kind: 'noop' }
            : {
                kind: 'grant-permission',
                role: spec.key,
                permission: grant.permission,
                effect: grant.effect,
                scopes: grant.scopes ?? [],
              },
        );
      }
    }

    for (const spec of manifest.groups ?? []) {
      const found = snapshot.groups.find((g) => g.name === spec.name);
      const summary = `group ${JSON.stringify(spec.name)}`;
      if (found) {
        resolved.groups.set(spec.key, found.id);
        const drifted = found.description !== spec.description;
        push(
          drifted ? 'update' : 'no-change',
          'group',
          spec.key,
          summary,
          drifted
            ? { kind: 'update-group', key: spec.key, description: spec.description }
            : { kind: 'noop' },
        );
      } else {
        push('create', 'group', spec.key, summary, {
          kind: 'create-group',
          key: spec.key,
          name: spec.name,
          description: spec.description,
        });
      }
    }

    for (const spec of manifest.groups ?? []) {
      const groupId = resolved.groups.get(spec.key);
      for (const roleKey of spec.roles ?? []) {
        const roleId = resolved.roles.get(roleKey);
        const present =
          !!roleId && !!groupId && (snapshot.roleGroups.get(roleId) ?? []).includes(groupId);
        push(
          present ? 'no-change' : 'create',
          'group-role',
          spec.key,
          `group ${JSON.stringify(spec.name)} holds role ${JSON.stringify(roleKey)}`,
          present ? { kind: 'noop' } : { kind: 'assign-role-to-group', role: roleKey, group: spec.key },
        );
      }
    }

    for (const spec of manifest.users ?? []) {
      const found = snapshot.users.find((u) => u.username === spec.username);
      const summary = `user ${JSON.stringify(spec.username)}`;
      if (found) {
        resolved.users.set(spec.key, found.id);
        const drifted = found.email !== spec.email;
        push(
          drifted ? 'update' : 'no-change',
          'user',
          spec.key,
          summary,
          drifted ? { kind: 'update-user', key: spec.key, email: spec.email } : { kind: 'noop' },
        );
      } else {
        // §27.6 rule 1: catch this here, before anything has been written,
        // rather than halfway through an apply.
        if (!spec.initialPassword) {
          throw new NetworkError(
            `user ${JSON.stringify(spec.username)} does not exist and would be created, but the ` +
              `spec carries no initialPassword`,
          );
        }
        push('create', 'user', spec.key, summary, {
          kind: 'create-user',
          key: spec.key,
          username: spec.username,
          email: spec.email,
          password: spec.initialPassword,
        });
      }
    }

    for (const spec of manifest.users ?? []) {
      const userId = resolved.users.get(spec.key);
      for (const roleKey of spec.roles ?? []) {
        const roleId = resolved.roles.get(roleKey);
        const present =
          !!roleId && !!userId && (snapshot.roleUsers.get(roleId) ?? []).includes(userId);
        push(
          present ? 'no-change' : 'create',
          'user-role',
          spec.key,
          `user ${JSON.stringify(spec.username)} holds role ${JSON.stringify(roleKey)}`,
          present ? { kind: 'noop' } : { kind: 'assign-role-to-user', role: roleKey, user: spec.key },
        );
      }
      for (const groupKey of spec.groups ?? []) {
        const groupId = resolved.groups.get(groupKey);
        const present =
          !!groupId && !!userId && (snapshot.groupMembers.get(groupId) ?? []).includes(userId);
        push(
          present ? 'no-change' : 'create',
          'group-member',
          spec.key,
          `user ${JSON.stringify(spec.username)} is in group ${JSON.stringify(groupKey)}`,
          present ? { kind: 'noop' } : { kind: 'add-group-member', group: groupKey, user: spec.key },
        );
      }
    }

    return out;
  }

  // -------------------------------------------------------------------
  // Apply
  // -------------------------------------------------------------------

  async #execute(
    steps: Array<{ action: PlannedAction; step: Step }>,
    resolved: Resolved,
  ): Promise<ApplyReport> {
    const out: ApplyReport['steps'] = [];
    let stopped = false;
    for (const { action, step } of steps) {
      if (stopped) {
        out.push({ action, outcome: { status: 'not-attempted' } });
        continue;
      }
      if (step.kind === 'noop') {
        out.push({ action, outcome: { status: 'unchanged' } });
        continue;
      }
      try {
        await this.#run(step, resolved);
        const outcome: Outcome =
          action.change === 'create' ? { status: 'created' } : { status: 'updated' };
        out.push({ action, outcome });
      } catch (err) {
        stopped = true;
        out.push({
          action,
          outcome: { status: 'failed', message: err instanceof Error ? err.message : String(err) },
        });
      }
    }
    return { steps: out };
  }

  async #run(step: Step, resolved: Resolved): Promise<void> {
    const c = this.#client;
    switch (step.kind) {
      case 'noop':
        return;
      case 'create-resource': {
        const created = await c.resources.create({
          name: step.name,
          resource_type: step.resourceType,
          parent_id: step.parent ? lookup(resolved.resources, step.parent, 'resource') : undefined,
        });
        resolved.resources.set(step.key, created.id);
        return;
      }
      case 'update-resource':
        await c.resources.update(lookup(resolved.resources, step.key, 'resource'), {
          resource_type: step.resourceType,
        });
        return;
      case 'create-scope': {
        const created = await c.scopes.create(
          lookup(resolved.resources, step.resource, 'resource'),
          { name: step.name, description: step.description },
        );
        resolved.scopes.set(step.key, created.id);
        return;
      }
      case 'create-permission': {
        const created = await c.permissions.create({
          action: step.action,
          description: step.description,
        });
        resolved.permissions.set(step.key, created.id);
        return;
      }
      case 'update-permission':
        await c.permissions.update(lookup(resolved.permissions, step.key, 'permission'), {
          description: step.description,
        });
        return;
      case 'create-role': {
        const created = await c.roles.create({
          name: step.name,
          description: step.description,
          is_global: step.isGlobal,
        });
        resolved.roles.set(step.key, created.id);
        return;
      }
      case 'update-role':
        await c.roles.update(lookup(resolved.roles, step.key, 'role'), {
          description: step.description,
          is_global: step.isGlobal,
        });
        return;
      case 'grant-permission':
        await c.roles.grantPermission(lookup(resolved.roles, step.role, 'role'), {
          permission_id: lookup(resolved.permissions, step.permission, 'permission'),
          effect: step.effect,
          scope_ids: step.scopes.length
            ? step.scopes.map((s) => lookup(resolved.scopes, s, 'scope'))
            : undefined,
        });
        return;
      case 'create-group': {
        const created = await c.groups.create({ name: step.name, description: step.description });
        resolved.groups.set(step.key, created.id);
        return;
      }
      case 'update-group':
        await c.groups.update(lookup(resolved.groups, step.key, 'group'), {
          description: step.description,
        });
        return;
      case 'assign-role-to-group':
        await c.roles.assignToGroup(lookup(resolved.roles, step.role, 'role'), {
          group_id: lookup(resolved.groups, step.group, 'group'),
        });
        return;
      case 'create-user': {
        const created = await c.users.create({
          username: step.username,
          email: step.email,
          password: step.password,
        });
        resolved.users.set(step.key, created.id);
        return;
      }
      case 'update-user':
        await c.users.update(lookup(resolved.users, step.key, 'user'), { email: step.email });
        return;
      case 'assign-role-to-user':
        await c.roles.assignToUser(lookup(resolved.roles, step.role, 'role'), {
          user_id: lookup(resolved.users, step.user, 'user'),
        });
        return;
      case 'add-group-member':
        await c.groups.addMember(lookup(resolved.groups, step.group, 'group'), {
          user_id: lookup(resolved.users, step.user, 'user'),
        });
        return;
    }
  }
}

/**
 * Resolve a manifest key to the id an earlier step recorded.
 *
 * A miss here is an SDK bug, not a user error — validation already rejected
 * dangling references and the plan orders producers before consumers — so it
 * says so rather than blaming the manifest.
 */
function lookup(map: Map<string, string>, key: string, kind: string): string {
  const id = map.get(key);
  if (id === undefined) {
    throw new NetworkError(
      `internal: ${kind} key ${JSON.stringify(key)} was consumed before the step that creates it ran`,
    );
  }
  return id;
}
