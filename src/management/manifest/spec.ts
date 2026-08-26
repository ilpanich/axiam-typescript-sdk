/**
 * The desired shape of a tenant — CONTRACT.md §27.6.
 *
 * A manifest is a **value**. It is built before the things in it exist, so it
 * cannot name them by UUID; every spec carries a manifest-local `key` that
 * other specs refer to, and `plan` resolves those keys against the tenant's
 * current state.
 *
 * Nothing here touches the network and nothing here needs a client — which is
 * what makes a manifest something you can load from configuration, commit to a
 * repository, and diff.
 */

import type { Sensitive } from '../../core/sensitive.js';
import type { PermissionEffect } from '../models.js';

/** A scope, always beneath the resource that declares it. */
export interface ScopeSpec {
  /** Manifest-local identifier, referred to by a role's grants. */
  key: string;
  /** The scope's name — its natural key within its resource. */
  name: string;
  /** Human-readable description. The server requires one. */
  description: string;
}

/** A resource in the hierarchy, and the scopes beneath it. */
export interface ResourceSpec {
  /** Manifest-local identifier, referred to by `parent` and by grants. */
  key: string;
  /** The resource's name — its natural key within the tenant. */
  name: string;
  /** The server's `resource_type` discriminator. */
  resourceType: string;
  /** The `key` of this resource's parent, if it has one. */
  parent?: string;
  /** Scopes declared under this resource. */
  scopes?: ScopeSpec[];
}

/** A permission — an action, tenant-wide. */
export interface PermissionSpec {
  /** Manifest-local identifier, referred to by a role's grants. */
  key: string;
  /** The action — the permission's natural key within the tenant. */
  action: string;
  /** Human-readable description. The server requires one. */
  description: string;
}

/** One permission granted to a role, optionally narrowed to scopes. */
export interface GrantSpec {
  /** The `key` of the {@link PermissionSpec} being granted. */
  permission: string;
  /**
   * Allow or deny. Omitted lets the server default, which is allow.
   *
   * A `deny` grant overrides **every** allow, at any depth of the resource
   * hierarchy and at equal specificity — AXIAM's RBAC engine is deny-override,
   * not most-specific-wins.
   */
  effect?: PermissionEffect;
  /** The `key`s of scopes this grant is narrowed to. Empty means the whole resource. */
  scopes?: string[];
}

/** A role and the permissions granted to it. */
export interface RoleSpec {
  /** Manifest-local identifier, referred to by users and groups. */
  key: string;
  /** The role's name — its natural key within the tenant. */
  name: string;
  /** Human-readable description. The server requires one. */
  description: string;
  /** Whether the role applies tenant-wide rather than to a resource subtree. */
  isGlobal?: boolean;
  /** Permissions this role grants. */
  grants?: GrantSpec[];
}

/** A group and the roles its members inherit. */
export interface GroupSpec {
  /** Manifest-local identifier, referred to by users. */
  key: string;
  /** The group's name — its natural key within the tenant. */
  name: string;
  /** Human-readable description. The server requires one. */
  description: string;
  /** The `key`s of roles assigned to this group. */
  roles?: string[];
}

/** A user, their roles and their group memberships. */
export interface UserSpec {
  /** Manifest-local identifier. */
  key: string;
  /** The username — the user's natural key within the tenant. */
  username: string;
  /** The user's email address. */
  email: string;
  /**
   * The password to set **if this user has to be created**.
   *
   * Never used for a user that already exists: a manifest is a description of
   * shape, and silently resetting a live account's password because a config
   * file mentions one is not a shape change. `plan` fails before any request
   * when a user must be created and this is absent, rather than discovering it
   * halfway through an apply (§27.6 rule 1).
   */
  initialPassword?: Sensitive<string>;
  /** The `key`s of roles assigned directly to this user. */
  roles?: string[];
  /** The `key`s of groups this user belongs to. */
  groups?: string[];
}

/**
 * The shape a tenant should have.
 *
 * Deliberately covers only the namespaces that describe a tenant's *shape*.
 * Certificates, CA certificates, PGP keys and SCIM tokens are absent on
 * purpose (§27.6): they mint one-time secrets, and a declarative layer that
 * "ensures a certificate exists" either re-mints one on every run or silently
 * accepts drift. Both are worse than an imperative call made once, on purpose,
 * whose result the caller stores.
 */
export interface ManagementManifest {
  /** Resources, in any order — `plan` sorts them so a parent precedes its children. */
  resources?: ResourceSpec[];
  /** Permissions. What binds one to a resource is the scope list on a role's grant. */
  permissions?: PermissionSpec[];
  /** Roles and the permissions granted to them. */
  roles?: RoleSpec[];
  /** Groups and the roles their members inherit. */
  groups?: GroupSpec[];
  /** Users, their role assignments and their group memberships. */
  users?: UserSpec[];
}
