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
import type {
  PermissionEffect,
  RadiusServiceType,
  RadiusTerminationAction,
} from '../models.js';

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
  /**
   * Arbitrary JSON metadata (CONTRACT.md §27.6.1 item 1, contract 1.51).
   *
   * Sent on `Create`, and on `Update` when stated. Omitted means silent
   * (the manifest's general rule 3: a manifest that omits a field is
   * silent about it, never an assertion that it should be cleared) — an
   * omitted `metadata` never drifts, whatever the server holds.
   *
   * Drift is **JSON value equality of the whole object**, never a
   * key-by-key merge — the server replaces the whole object on an update
   * that states one, and a stated `{}` matches what the server returns for
   * a resource created with none. A merge would make `apply` unable to
   * remove a key, which would break `apply(m)` → `plan(m)` convergence
   * (rule 6) for any manifest that ever narrows its metadata.
   */
  metadata?: unknown;
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

/**
 * One role binding on a `groups`, `users` or `service_accounts` spec's
 * `roles[]` (CONTRACT.md §27.6.1 item 2, contract 1.51) — either shape:
 *
 * - a **role key** (a string) — the binding as every SDK had it before
 *   1.51: no resource, and so no inheritance question; or
 * - an **object** — `role` (a role key), and optionally `resource` (a
 *   resource key) and `inherit` (defaulting to `true`).
 *
 * Both forms are manifest-local keys, resolved to server UUIDs by `plan`
 * exactly like every other cross-reference. A plain string is not sugar for
 * `{ role }` in the sense of being converted to it — it IS one, for every
 * purpose `plan`/`apply` care about (`roleKeyOf`, `resourceKeyOf`,
 * `inheritOf` all read either shape identically); the union exists so a
 * manifest that has always written `roles: ['editor']` keeps compiling and
 * keeps meaning what it always meant, byte-for-byte, on the wire.
 */
export type RoleBinding =
  | string
  | {
      /** The `key` of the {@link RoleSpec} being bound. */
      role: string;
      /** The `key` of the {@link ResourceSpec} to scope the binding to. Omitted means a plain (tenant-wide) binding. */
      resource?: string;
      /** Whether the binding reaches the resource's descendants. Defaults to `true`; sent on the wire only when `false` (§27.13 S-10 rule 1). */
      inherit?: boolean;
    };

/** A group and the roles its members inherit. */
export interface GroupSpec {
  /** Manifest-local identifier, referred to by users. */
  key: string;
  /** The group's name — its natural key within the tenant. */
  name: string;
  /** Human-readable description. The server requires one. */
  description: string;
  /** Roles assigned to this group — a role key, or a resource-scoped `{ role, resource, inherit? }` (§27.6.1 item 2). */
  roles?: RoleBinding[];
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
  /** Roles assigned directly to this user — a role key, or a resource-scoped `{ role, resource, inherit? }` (§27.6.1 item 2). */
  roles?: RoleBinding[];
  /** The `key`s of groups this user belongs to. */
  groups?: string[];
}

/**
 * A service account and the roles assigned to it (CONTRACT.md §27.6.1 item
 * 3, contract 1.51).
 *
 * **The natural key is `name`, and the server does not enforce it being
 * unique.** A service account's only unique index is its `client_id`, so a
 * tenant can hold two accounts with the same name. `plan` fails with a
 * client-side error, before `apply` writes anything, when more than one
 * existing account matches a stated name — picking one would reconcile an
 * arbitrary account.
 *
 * Group membership of a service account is not a manifest field in 1.51.
 */
export interface ServiceAccountSpec {
  /** Manifest-local identifier, referred to by role bindings elsewhere in the manifest. */
  key: string;
  /** The service account's name — its natural key within the tenant, though the server does not enforce uniqueness on it. */
  name: string;
  /**
   * Human-readable description. The only field reconciled by `Update`
   * (sparse, §27.4 rule 5) — `status` is not a manifest field in 1.51.
   */
  description?: string;
  /** Roles assigned to this service account — a role key, or a resource-scoped `{ role, resource, inherit? }` (§27.6.1 item 2). */
  roles?: RoleBinding[];
}

/**
 * A network segment (CONTRACT.md §27.6.2 item 1, contract 1.62).
 *
 * **The natural key is `site` + `kind` + `name`**, where `kind` is the **wire**
 * spelling — `'access'` or `'quarantine'`, the value `createSegment` writes
 * and every segment read returns. This SDK keeps no mapping between it and
 * anything else and has no `zones` spelling (`zones` is a server-side path
 * segment). The three are never drift (a segment's kind, site and name do not
 * change, §36.3 rule 4); every other member is a field.
 *
 * A member left off is silent (rule 3): it never drifts, and an `Update`
 * carries the read's value for it. A member stated as `null` is "none" — the
 * key is left out of the write, which is how a replacement clears an optional
 * member.
 */
export interface NetworkSegmentSpec {
  /** Manifest-local identifier, referred to by a {@link NetworkProfileSpec}'s `segment`. */
  key: string;
  /** The segment's site — the wire `site_key`. A single-site tenant uses `default`. */
  site: string;
  /** `'access'` or `'quarantine'` — the wire spelling, and part of the natural key. */
  kind: 'access' | 'quarantine';
  /** The segment's name — with `site` and `kind`, its natural key. */
  name: string;
  /** The VLAN, 1 to 4094; the server judges it (§36.3 rule 5). */
  vlanId: number;
  /** The placement rank: required by the server for `access`, absent for `quarantine`. */
  rank?: number | null;
  /**
   * The segment's envelope: the `Filter-Id` names its profile may choose from.
   * **Compared as a set** (a reorder alone is never an `Update`, names compare
   * as exact strings); a name listed twice is refused by `plan` before any
   * request. When the SDK writes the segment it sends the names in the order
   * stated here.
   */
  filterIds?: string[];
  /** Whether the segment is a placement candidate. The server defaults it to `true` on create. */
  enabled?: boolean;
}

/**
 * A reply profile (CONTRACT.md §27.6.2 item 1, contract 1.62), **identified by
 * its segment**: it has no name or id of its own.
 *
 * Every stated member is compared with the **effective** profile as the read
 * returns it (§27.6.2 item 3): a `sessionTimeoutSecs` above the tenant's cap
 * differs from the read, `plan` shows an `Update`, and `apply` reports the
 * server's `403` refusal as that action's failure — nothing is lowered, retried
 * or adjusted by the SDK.
 */
export interface NetworkProfileSpec {
  /** The `key` of a {@link NetworkSegmentSpec} of the same manifest. */
  segment: string;
  /** `Session-Timeout`, seconds. */
  sessionTimeoutSecs: number;
  /** `Termination-Action`; the server defaults it to `radius_request` on create. */
  terminationAction?: RadiusTerminationAction | null;
  /** `Idle-Timeout`, seconds. */
  idleTimeoutSecs?: number | null;
  /** `Filter-Id`: one of the segment's `filterIds`. */
  filterId?: string | null;
  /** `Service-Type`; only `'framed_user'` is accepted. */
  serviceType?: RadiusServiceType | null;
}

/** The tenant's `Session-Timeout` cap — a singleton (CONTRACT.md §27.6.2 item 1). */
export interface NetworkPolicySpec {
  /** The cap on a reply profile's `Session-Timeout`, seconds (300 to 86 400). */
  sessionTimeoutMaxSecs: number;
}

/**
 * The `network` section of a manifest (CONTRACT.md §27.6.2, contract 1.62).
 *
 * Applied in this order: the policy, then the segments, then the profiles (a
 * profile follows its segment). The namespace is **human-only**: an `apply`
 * whose manifest has a `network` section needs a human caller, and a
 * service-account token meets `401` at the first network action.
 *
 * This SDK offers no pruning for any namespace, so nothing here is ever deleted.
 */
export interface NetworkSpec {
  /** The tenant's cap. At most one per manifest. It is never `Create`: the policy always exists. */
  policy?: NetworkPolicySpec;
  /** Segments, in any order within the section. */
  segments?: NetworkSegmentSpec[];
  /** Reply profiles, one per segment. */
  profiles?: NetworkProfileSpec[];
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
  /**
   * Service accounts and their role assignments (CONTRACT.md §27.6.1 item
   * 3, contract 1.51). Covered despite minting a one-time secret — see
   * `ServiceAccountSpec`'s doc and §27.5 rule 5 for what `apply` returns for
   * a `Create`.
   */
  serviceAccounts?: ServiceAccountSpec[];
  /**
   * Network segments, their reply profiles and the tenant's `Session-Timeout`
   * cap (CONTRACT.md §27.6.2, contract 1.62). Appended last in the plan: a
   * manifest without a `network` section plans, reads and applies exactly as it
   * did before.
   */
  network?: NetworkSpec;
}

/** The role key a {@link RoleBinding} names, whichever shape it is. */
export function roleKeyOf(binding: RoleBinding): string {
  return typeof binding === 'string' ? binding : binding.role;
}

/** The resource key a {@link RoleBinding} names, if it is the scoped shape. */
export function resourceKeyOf(binding: RoleBinding): string | undefined {
  return typeof binding === 'string' ? undefined : binding.resource;
}

/**
 * Whether a {@link RoleBinding} inherits (`true`, the default) or applies at
 * its resource only (`false`). A plain role-key string always inherits — it
 * names no resource to stop at, so the question does not arise.
 */
export function inheritOf(binding: RoleBinding): boolean {
  return typeof binding === 'string' ? true : (binding.inherit ?? true);
}
