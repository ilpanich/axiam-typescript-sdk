/**
 * Reconciling a manifest against a live tenant — CONTRACT.md §27.6.
 */

import { NetworkError } from '../../core/errors.js';
import type { Sensitive } from '../../core/sensitive.js';
import type { AxiamClient } from '../../rest/client.js';
import * as models from '../models.js';
import type {
  ApplyReport,
  ManagementPlan,
  StepOutcome,
  PlannedAction,
  Target,
} from './plan.js';
import { topologicalOrder, validate } from './plan.js';
import {
  inheritOf,
  resourceKeyOf,
  roleKeyOf,
  type ManagementManifest,
  type ResourceSpec,
  type RoleBinding,
} from './spec.js';

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
  serviceAccounts: Map<string, string>;
}

const emptyResolved = (): Resolved => ({
  resources: new Map(),
  scopes: new Map(),
  permissions: new Map(),
  roles: new Map(),
  groups: new Map(),
  users: new Map(),
  serviceAccounts: new Map(),
});

/** Which kind of subject a role-binding step acts on — one set of step kinds serves all three (§27.6.1 item 2). */
type BindingSubjectKind = 'group' | 'user' | 'service-account';

/** The server's existing binding for one (role, subject) pair, or none. */
interface ExistingBinding {
  resourceId?: string;
  inherit: boolean;
  tenantScope?: string[];
}

/** One executable step, carrying manifest keys rather than ids. */
type Step =
  | { kind: 'noop' }
  | { kind: 'create-resource'; key: string; name: string; resourceType: string; parent?: string; metadata?: unknown }
  | { kind: 'update-resource'; key: string; resourceType?: string; metadata?: unknown; metadataStated: boolean }
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
  | {
      kind: 'create-user';
      key: string;
      username: string;
      email: string;
      password: models.CreateUserRequest['password'];
    }
  | { kind: 'update-user'; key: string; email: string }
  | { kind: 'add-group-member'; group: string; user: string }
  | { kind: 'create-service-account'; key: string; name: string; description?: string }
  | { kind: 'update-service-account'; key: string; description: string }
  | {
      /** A role bound to a subject the server does not yet hold — §27.6.1 item 2's `Create`. */
      kind: 'assign-role';
      subjectKind: BindingSubjectKind;
      role: string;
      subject: string;
      resource?: string;
      inherit: boolean;
    }
  | {
      /**
       * The binding's resource/inherit drifted from what the server holds
       * — §27.6.1 item 2's `Update`, always unassign then assign. `previous`
       * is re-assigned if the assign half fails.
       */
      kind: 'rebind-role';
      subjectKind: BindingSubjectKind;
      role: string;
      subject: string;
      resource?: string;
      inherit: boolean;
      previous: ExistingBinding;
    };

/** The current state a plan is computed against. */
interface Snapshot {
  resources: models.Resource[];
  scopes: Map<string, models.Scope[]>;
  permissions: models.Permission[];
  roles: models.Role[];
  groups: models.Group[];
  users: models.UserResponse[];
  serviceAccounts: models.ServiceAccountResponse[];
  roleGrants: Map<string, string[]>;
  /** Role id -> existing binding, per subject id (users). */
  roleUserBindings: Map<string, Map<string, ExistingBinding>>;
  /** Role id -> existing binding, per subject id (groups). */
  roleGroupBindings: Map<string, Map<string, ExistingBinding>>;
  /** Role id -> existing binding, per subject id (service accounts). */
  roleServiceAccountBindings: Map<string, Map<string, ExistingBinding>>;
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
    const serviceAccounts = (manifest.serviceAccounts ?? []).length
      ? await c.serviceAccounts.listAll(start)
      : [];

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
    const roleUserBindings = new Map<string, Map<string, ExistingBinding>>();
    const roleGroupBindings = new Map<string, Map<string, ExistingBinding>>();
    const roleServiceAccountBindings = new Map<string, Map<string, ExistingBinding>>();
    for (const role of roles) {
      if (!(manifest.roles ?? []).some((s) => s.name === role.name)) continue;
      roleGrants.set(role.id, (await c.roles.listPermissions(role.id)).map((g) => g.permission.id));
      roleUserBindings.set(
        role.id,
        new Map((await c.roles.listUsers(role.id)).map((a) => [a.user.id, bindingOf(a)] as const)),
      );
      roleGroupBindings.set(
        role.id,
        new Map((await c.roles.listGroups(role.id)).map((a) => [a.group.id, bindingOf(a)] as const)),
      );
      if (serviceAccounts.length) {
        roleServiceAccountBindings.set(
          role.id,
          new Map(
            (await c.roles.listServiceAccounts(role.id)).map(
              (a) => [a.service_account.id, bindingOf(a)] as const,
            ),
          ),
        );
      }
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
      serviceAccounts,
      roleGrants,
      roleUserBindings,
      roleGroupBindings,
      roleServiceAccountBindings,
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
        // §27.6.1 item 1: metadata drift is JSON value equality of the whole
        // object, and a stated metadata is silent-about-nothing (rule 3) —
        // an UNSTATED metadata (the field left off the spec entirely) never
        // drifts, whatever the server holds; only a STATED one is compared.
        const metadataStated = 'metadata' in spec;
        const metadataDrifted = metadataStated && !deepEqual(spec.metadata, existing.metadata);
        const typeDrifted = existing.resource_type !== spec.resourceType;
        const drifted = typeDrifted || metadataDrifted;
        push(
          drifted ? 'update' : 'no-change',
          'resource',
          spec.key,
          summary,
          drifted
            ? {
                kind: 'update-resource',
                key: spec.key,
                resourceType: typeDrifted ? spec.resourceType : undefined,
                metadata: metadataDrifted ? spec.metadata : undefined,
                metadataStated: metadataDrifted,
              }
            : { kind: 'noop' },
        );
      } else {
        push('create', 'resource', spec.key, summary, {
          kind: 'create-resource',
          key: spec.key,
          name: spec.name,
          resourceType: spec.resourceType,
          parent: spec.parent,
          metadata: spec.metadata,
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
      this.#roleBindingSteps(
        'group',
        'group-role',
        spec.key,
        `group ${JSON.stringify(spec.name)}`,
        spec.roles ?? [],
        groupId,
        resolved,
        snapshot.roleGroupBindings,
        push,
      );
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
      this.#roleBindingSteps(
        'user',
        'user-role',
        spec.key,
        `user ${JSON.stringify(spec.username)}`,
        spec.roles ?? [],
        userId,
        resolved,
        snapshot.roleUserBindings,
        push,
      );
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

    // §27.6 rule 5's order: service accounts, then service-account/role
    // bindings, after users/user-role bindings.
    for (const spec of manifest.serviceAccounts ?? []) {
      const matches = snapshot.serviceAccounts.filter((s) => s.name === spec.name);
      // §27.6.1 item 3: the server does not enforce name uniqueness. Picking
      // one of several matches would reconcile an arbitrary account, so this
      // fails plan() itself (§27.6.1: "plan MUST fail... before apply writes
      // anything") — thrown here, before any step for ANY spec is returned.
      if (matches.length > 1) {
        throw new NetworkError(
          `service account name ${JSON.stringify(spec.name)} matches ${matches.length} existing accounts ` +
            `(client_id ${matches.map((m) => m.client_id).join(', ')}) — the server does not enforce unique ` +
            'names, and reconciling an ambiguous one would pick an arbitrary account',
        );
      }
      const found = matches[0];
      const summary = `service account ${JSON.stringify(spec.name)}`;
      if (found) {
        resolved.serviceAccounts.set(spec.key, found.id);
        // §27.6.1 item 3: description is the only field Update reconciles
        // (sparse, §27.4 rule 5) — status is not a manifest field in 1.51.
        const drifted = spec.description !== undefined && found.description !== spec.description;
        push(
          drifted ? 'update' : 'no-change',
          'service-account',
          spec.key,
          summary,
          drifted
            ? { kind: 'update-service-account', key: spec.key, description: spec.description! }
            : { kind: 'noop' },
        );
      } else {
        push('create', 'service-account', spec.key, summary, {
          kind: 'create-service-account',
          key: spec.key,
          name: spec.name,
          description: spec.description,
        });
      }
    }

    for (const spec of manifest.serviceAccounts ?? []) {
      const serviceAccountId = resolved.serviceAccounts.get(spec.key);
      this.#roleBindingSteps(
        'service-account',
        'service-account-role',
        spec.key,
        `service account ${JSON.stringify(spec.name)}`,
        spec.roles ?? [],
        serviceAccountId,
        resolved,
        snapshot.roleServiceAccountBindings,
        push,
      );
    }

    return out;
  }

  /**
   * §27.6.1 item 2 — one subject's `roles[]` against the server's existing
   * bindings for it. Shared by groups, users and service accounts: the
   * comparison, the natural key `(subject, role)`, and the `Create`/`Update`/
   * `NoChange` shape are identical for all three, differing only in which
   * `Target` a step is labelled with and which `Snapshot` map holds the
   * existing bindings.
   */
  #roleBindingSteps(
    subjectKind: BindingSubjectKind,
    target: Target,
    specKey: string,
    subjectLabel: string,
    bindings: RoleBinding[],
    subjectId: string | undefined,
    resolved: Resolved,
    bindingsByRole: Map<string, Map<string, ExistingBinding>>,
    push: (change: PlannedAction['change'], target: Target, key: string, summary: string, step: Step) => void,
  ): void {
    for (const binding of bindings) {
      const roleKey = roleKeyOf(binding);
      const roleId = resolved.roles.get(roleKey);
      const resourceKey = resourceKeyOf(binding);
      const resourceId = resourceKey ? resolved.resources.get(resourceKey) : undefined;
      const desiredInherit = inheritOf(binding);
      const existing = roleId !== undefined && subjectId !== undefined
        ? bindingsByRole.get(roleId)?.get(subjectId)
        : undefined;
      const summary =
        `${subjectLabel} holds role ${JSON.stringify(roleKey)}` +
        (resourceKey ? ` on ${JSON.stringify(resourceKey)}` : '') +
        (desiredInherit ? '' : ' (inherit: false)');

      if (!existing) {
        push('create', target, specKey, summary, {
          kind: 'assign-role',
          subjectKind,
          role: roleKey,
          subject: specKey,
          resource: resourceKey,
          inherit: desiredInherit,
        });
        continue;
      }
      if (bindingDrifted({ resource: resourceId, inherit: desiredInherit }, existing)) {
        push('update', target, specKey, summary, {
          kind: 'rebind-role',
          subjectKind,
          role: roleKey,
          subject: specKey,
          resource: resourceKey,
          inherit: desiredInherit,
          previous: existing,
        });
        continue;
      }
      push('no-change', target, specKey, summary, { kind: 'noop' });
    }
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
        const explicit = await this.#run(step, resolved);
        // §27.6.1 item 2 (contract 1.51): a 'rebind-role' step reports its
        // OWN outcome shape ('updated' on a clean rebind, 'rebind-failed'
        // when the re-assign half failed) rather than the generic
        // create/update inference below — #run returns it explicitly for
        // exactly that reason. §27.5 rule 5: a 'create-service-account'
        // step's outcome carries the one-time client_secret the same way.
        const outcome: StepOutcome =
          explicit ?? (action.change === 'create' ? { status: 'created' } : { status: 'updated' });
        out.push({ action, outcome });
        // §27.6 rule 7: a 'rebind-failed' outcome is a failure for the
        // purposes of "stop at the first failure" even though it did not
        // throw — the assign half of the rebind failed, and continuing to
        // the next planned step would blindly build on a subject whose
        // binding is not in the state the plan assumed (restored to the
        // OLD shape, or — if the restore itself failed too — in neither).
        if (outcome.status === 'rebind-failed') {
          stopped = true;
        }
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

  async #run(step: Step, resolved: Resolved): Promise<StepOutcome | undefined> {
    const c = this.#client;
    switch (step.kind) {
      case 'noop':
        return undefined;
      case 'create-resource': {
        const created = await c.resources.create({
          name: step.name,
          resource_type: step.resourceType,
          parent_id: step.parent ? lookup(resolved.resources, step.parent, 'resource') : undefined,
          metadata: step.metadata,
        });
        resolved.resources.set(step.key, created.id);
        return undefined;
      }
      case 'update-resource':
        await c.resources.update(lookup(resolved.resources, step.key, 'resource'), {
          resource_type: step.resourceType,
          metadata: step.metadataStated ? step.metadata : undefined,
        });
        return undefined;
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
        return undefined;
      }
      case 'update-group':
        await c.groups.update(lookup(resolved.groups, step.key, 'group'), {
          description: step.description,
        });
        return undefined;
      case 'create-user': {
        const created = await c.users.create({
          username: step.username,
          email: step.email,
          password: step.password,
        });
        resolved.users.set(step.key, created.id);
        return undefined;
      }
      case 'update-user':
        await c.users.update(lookup(resolved.users, step.key, 'user'), { email: step.email });
        return undefined;
      case 'add-group-member':
        await c.groups.addMember(lookup(resolved.groups, step.group, 'group'), {
          user_id: lookup(resolved.users, step.user, 'user'),
        });
        return undefined;
      case 'create-service-account': {
        const created = await c.serviceAccounts.create({ name: step.name, description: step.description });
        resolved.serviceAccounts.set(step.key, created.id);
        // §27.5 rule 5: this outcome MUST carry the one-time client_secret —
        // create returns it and no later `get` ever will again.
        return { status: 'created', serviceAccountSecret: created.client_secret };
      }
      case 'update-service-account':
        await c.serviceAccounts.update(lookup(resolved.serviceAccounts, step.key, 'service account'), {
          description: step.description,
        });
        return undefined;
      case 'assign-role':
        await this.#assign(step, resolved);
        return undefined;
      case 'rebind-role':
        return this.#rebind(step, resolved);
    }
  }

  /** Look up the id `subjectKind` names on `step.subject`, from the right `resolved` map. */
  #subjectId(subjectKind: BindingSubjectKind, subjectKey: string, resolved: Resolved): string {
    switch (subjectKind) {
      case 'group':
        return lookup(resolved.groups, subjectKey, 'group');
      case 'user':
        return lookup(resolved.users, subjectKey, 'user');
      case 'service-account':
        return lookup(resolved.serviceAccounts, subjectKey, 'service account');
    }
  }

  /**
   * Assign `role` to a group/user/service-account subject (§27.6.1 item 2's
   * `Create` — the server holds no such binding yet). `inherit` is sent only
   * when `false` (§27.13 S-10 rule 1: an inheritable assignment's body stays
   * byte-for-byte a pre-1.51 body); `tenant_scope` is never sent here — it
   * is not part of a manifest binding in 1.51 (§27.6.1 item 2).
   */
  async #assign(
    step: Extract<Step, { kind: 'assign-role' }>,
    resolved: Resolved,
  ): Promise<void> {
    const roleId = lookup(resolved.roles, step.role, 'role');
    const resourceId = step.resource ? lookup(resolved.resources, step.resource, 'resource') : undefined;
    const subjectId = this.#subjectId(step.subjectKind, step.subject, resolved);
    const inherit = step.inherit ? undefined : false;
    switch (step.subjectKind) {
      case 'group':
        await this.#client.roles.assignToGroup(roleId, { group_id: subjectId, resource_id: resourceId, inherit });
        return;
      case 'user':
        await this.#client.roles.assignToUser(roleId, { user_id: subjectId, resource_id: resourceId, inherit });
        return;
      case 'service-account':
        await this.#client.roles.assignToServiceAccount(roleId, {
          service_account_id: subjectId,
          resource_id: resourceId,
          inherit,
        });
        return;
    }
  }

  /** `unassignFrom*` for `step.subjectKind`, at `resourceId` (undefined for the plain shape). */
  async #unassign(subjectKind: BindingSubjectKind, roleId: string, subjectId: string, resourceId: string | undefined): Promise<void> {
    switch (subjectKind) {
      case 'group':
        await this.#client.roles.unassignFromGroup(roleId, subjectId, resourceId);
        return;
      case 'user':
        await this.#client.roles.unassignFromUser(roleId, subjectId, resourceId);
        return;
      case 'service-account':
        await this.#client.roles.unassignFromServiceAccount(roleId, subjectId, resourceId);
        return;
    }
  }

  /** `assignTo*` for `step.subjectKind`, with an explicit resource/inherit/tenantScope — used by both the new binding and the restore path. */
  async #assignExplicit(
    subjectKind: BindingSubjectKind,
    roleId: string,
    subjectId: string,
    resourceId: string | undefined,
    inherit: boolean,
    tenantScope: string[] | undefined,
  ): Promise<void> {
    const body = {
      resource_id: resourceId,
      inherit: inherit ? undefined : false,
      tenant_scope: tenantScope,
    };
    switch (subjectKind) {
      case 'group':
        await this.#client.roles.assignToGroup(roleId, { group_id: subjectId, ...body });
        return;
      case 'user':
        await this.#client.roles.assignToUser(roleId, { user_id: subjectId, ...body });
        return;
      case 'service-account':
        await this.#client.roles.assignToServiceAccount(roleId, { service_account_id: subjectId, ...body });
        return;
    }
  }

  /**
   * §27.6.1 item 2's `Update`: there is no update endpoint, so this is
   * unassign then assign, and the subject holds NEITHER binding between the
   * two calls. `tenant_scope` is carried across from the server's existing
   * assignment unchanged (dropping it would silently widen an
   * organization-level account's reach, §5.2.3). If the assign half fails,
   * the SDK attempts to re-assign the PREVIOUS binding (same resource, same
   * `inherit`, same `tenant_scope`) and reports both outcomes — this is how
   * the admin console changes the flag (server T22.11b), and a manifest
   * must not be less careful than a form.
   */
  async #rebind(step: Extract<Step, { kind: 'rebind-role' }>, resolved: Resolved): Promise<StepOutcome> {
    const roleId = lookup(resolved.roles, step.role, 'role');
    const subjectId = this.#subjectId(step.subjectKind, step.subject, resolved);
    const newResourceId = step.resource ? lookup(resolved.resources, step.resource, 'resource') : undefined;

    await this.#unassign(step.subjectKind, roleId, subjectId, step.previous.resourceId);
    try {
      await this.#assignExplicit(
        step.subjectKind,
        roleId,
        subjectId,
        newResourceId,
        step.inherit,
        step.previous.tenantScope,
      );
      return { status: 'updated' };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      try {
        await this.#assignExplicit(
          step.subjectKind,
          roleId,
          subjectId,
          step.previous.resourceId,
          step.previous.inherit,
          step.previous.tenantScope,
        );
        return { status: 'rebind-failed', message, restoreSucceeded: true };
      } catch (restoreErr) {
        return {
          status: 'rebind-failed',
          message,
          restoreSucceeded: false,
          restoreMessage: restoreErr instanceof Error ? restoreErr.message : String(restoreErr),
        };
      }
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

/**
 * Read one role-side assignment (`RoleUserAssignment`/`RoleGroupAssignment`/
 * `RoleServiceAccountAssignment`) into the shape `#compute` compares
 * manifest bindings against. `models.roleAssignmentInherits` is the one
 * place `inherit` is read (§27.13 S-10 rule 3: absent means `true`, never a
 * decode failure and never `false` — see scripts/gen-management.mjs's
 * FORCE_OPTIONAL override, which is what makes the field optional here in
 * the first place).
 */
function bindingOf(assignment: { resource_id?: string | null; inherit?: boolean; tenant_scope?: string[] | null }): ExistingBinding {
  return {
    resourceId: assignment.resource_id ?? undefined,
    inherit: models.roleAssignmentInherits(assignment),
    tenantScope: assignment.tenant_scope ?? undefined,
  };
}

/**
 * Whether a manifest binding's resource/inherit drifted from the server's
 * existing one (§27.6.1 item 2: the binding's natural key is `(subject,
 * role)`, and its resource and `inherit` are fields — `NoChange` for the
 * same resource and `inherit`, `Update` otherwise).
 */
function bindingDrifted(desired: { resource?: string; inherit: boolean }, existing: ExistingBinding): boolean {
  return desired.resource !== existing.resourceId || desired.inherit !== existing.inherit;
}

/**
 * §27.6.1 item 1: JSON value equality of a resource's whole `metadata`
 * object — never a key-by-key merge. `JSON.stringify` on parsed JSON values
 * (never `undefined`, functions or symbols at any depth, since both sides
 * came off the wire or from a manifest literal) is a safe equality check
 * here precisely because object key order does not vary between two reads
 * of the same JSON value in this codebase's usage (it is never rebuilt
 * key-by-key in a different order); a general-purpose deep-equal would be
 * the more defensive choice for arbitrary caller-constructed objects, but
 * would add real cost to the hot path of a manifest with many resources for
 * a mismatch this narrow.
 */
function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
