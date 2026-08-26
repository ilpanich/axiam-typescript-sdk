/**
 * The declarative forms of a manifest — CONTRACT.md §27.7.
 *
 * §27.7 asks each SDK for the declarative form its users would expect. In
 * TypeScript that is two things, and this module has both:
 *
 * - {@link defineManifest}, an object literal with full type inference that
 *   also **validates at the point of declaration** rather than at `plan` time;
 * - class decorators, for codebases that already declare their domain that way
 *   (a NestJS app, most obviously).
 *
 * Both lower to the same {@link ManagementManifest} value and go through the
 * same `plan`/`apply`. A declarative form that talked to the network itself
 * would be a second implementation of §27.6, and the two would disagree.
 */

import type {
  GrantSpec,
  GroupSpec,
  ManagementManifest,
  PermissionSpec,
  ResourceSpec,
  RoleSpec,
  ScopeSpec,
  UserSpec,
} from './spec.js';
import { validate } from './plan.js';

/**
 * Declare a manifest, keeping literal types and checking it immediately.
 *
 * The `const` type parameter preserves the literal key strings, so editor
 * completion and go-to-definition work across the manifest's own
 * cross-references. The eager {@link validate} call is the part that earns its
 * keep: a dangling key, a duplicate, or a cycle in the resource parents fails
 * where the manifest is *written* rather than on the first `plan` against a
 * live tenant — which, for a manifest that lives in a config module, is
 * usually at import time.
 *
 * ```ts
 * export const tenantShape = defineManifest({
 *   resources: [
 *     { key: 'docs', name: 'documents', resourceType: 'collection',
 *       scopes: [{ key: 'draft', name: 'draft', description: 'Unpublished' }] },
 *   ],
 *   permissions: [{ key: 'read', action: 'document:read', description: 'Read' }],
 *   roles: [{ key: 'editor', name: 'Editor', description: 'Edits',
 *             grants: [{ permission: 'read', scopes: ['draft'] }] }],
 * });
 * ```
 *
 * @throws NetworkError if the manifest cannot be reconciled — see
 *   {@link validate} for what that covers.
 */
export function defineManifest<const T extends ManagementManifest>(manifest: T): T {
  validate(manifest);
  return manifest;
}

// ---------------------------------------------------------------------------
// Decorators
// ---------------------------------------------------------------------------

interface Bucket {
  resource?: ResourceSpec;
  scopes: ScopeSpec[];
  permissions: PermissionSpec[];
  role?: RoleSpec;
  grants: GrantSpec[];
  group?: GroupSpec;
  user?: UserSpec;
}

/**
 * What each decorated class has declared so far.
 *
 * A `WeakMap` keyed by the class rather than `reflect-metadata`: these are TS
 * 5 **standard** decorators, so they work without `experimentalDecorators`
 * (which this SDK's own tsconfig deliberately does not enable) and without
 * adding a runtime dependency for a feature not everyone uses.
 */
const buckets = new WeakMap<object, Bucket>();

function bucket(target: object): Bucket {
  let found = buckets.get(target);
  if (!found) {
    found = { scopes: [], permissions: [], grants: [] };
    buckets.set(target, found);
  }
  return found;
}

/**
 * A class decorator that works under **both** decorator protocols.
 *
 * TypeScript has two: the legacy `experimentalDecorators` form, which passes
 * the constructor as the only argument, and the TC39 standard form, which
 * passes `(value, context)`. This SDK's own tsconfig deliberately enables
 * neither — the same position `src/nestjs/decorators.ts` takes — so which one
 * a consumer gets depends entirely on their build. Supporting both costs one
 * branch and means the answer is "it works" rather than "it depends".
 *
 * Both forms are also plain functions, so they can be applied directly:
 * `AxiamResource(spec)(MyClass)` is exactly what `@AxiamResource(spec)` does.
 */
export type ClassDeco = (
  value: unknown,
  context?: { kind?: string; name?: string | undefined },
) => void;

function classDecorator(apply: (b: Bucket) => void): ClassDeco {
  return (value, context) => {
    // The standard form names its target kind; the legacy form passes no
    // context at all. Anything else is a decorator on the wrong thing.
    if (context?.kind !== undefined && context.kind !== 'class') {
      throw new TypeError(
        `AXIAM manifest decorators apply to classes only, not to a ${context.kind}`,
      );
    }
    if (typeof value !== 'function' && (typeof value !== 'object' || value === null)) {
      throw new TypeError('AXIAM manifest decorators apply to classes only');
    }
    apply(bucket(value as object));
  };
}

/**
 * Declare a resource on this class.
 *
 * Stack {@link AxiamScope} on the same class to declare scopes beneath it;
 * decorator order does not matter, because each one only records into the
 * class's bucket and {@link collectManifest} does the assembling.
 *
 * ```ts
 * \@AxiamResource({ key: 'docs', name: 'documents', resourceType: 'collection' })
 * \@AxiamScope({ key: 'draft', name: 'draft', description: 'Unpublished' })
 * class Documents {}
 * ```
 *
 * Decorator syntax needs your build to enable one of TypeScript's two
 * decorator modes. Where it does not, apply it directly — it is the same
 * call: `AxiamResource(spec)(Documents)`.
 */
export function AxiamResource(spec: ResourceSpec): ClassDeco {
  return classDecorator((b) => {
    b.resource = spec;
  });
}

/** Declare a scope, beneath whichever resource the same class declares. */
export function AxiamScope(spec: ScopeSpec): ClassDeco {
  return classDecorator((b) => b.scopes.push(spec));
}

/** Declare a permission. */
export function AxiamPermission(spec: PermissionSpec): ClassDeco {
  return classDecorator((b) => b.permissions.push(spec));
}

/**
 * Declare a role on this class.
 *
 * Stack {@link AxiamGrant} on the same class to grant permissions to it.
 */
export function AxiamRole(spec: RoleSpec): ClassDeco {
  return classDecorator((b) => {
    b.role = spec;
  });
}

/** Grant a permission to whichever role the same class declares. */
export function AxiamGrant(spec: GrantSpec): ClassDeco {
  return classDecorator((b) => b.grants.push(spec));
}

/** Declare a group. */
export function AxiamGroup(spec: GroupSpec): ClassDeco {
  return classDecorator((b) => {
    b.group = spec;
  });
}

/** Declare a user. */
export function AxiamUser(spec: UserSpec): ClassDeco {
  return classDecorator((b) => {
    b.user = spec;
  });
}

/**
 * Assemble a manifest from decorated classes.
 *
 * Validated on the way out, exactly as {@link defineManifest} is — a scope
 * decorated onto a class that declares no resource, or a grant on a class that
 * declares no role, is a mistake worth hearing about at assembly rather than
 * on the first `plan`.
 *
 * ```ts
 * const shape = collectManifest(Documents, ReadDocument, Editor, Staff, Alice);
 * await client.manifest.apply(shape);
 * ```
 *
 * @throws NetworkError if a decorator has nothing to attach to, or if the
 *   assembled manifest cannot be reconciled.
 */
export function collectManifest(...classes: object[]): ManagementManifest {
  const resources: ResourceSpec[] = [];
  const permissions: PermissionSpec[] = [];
  const roles: RoleSpec[] = [];
  const groups: GroupSpec[] = [];
  const users: UserSpec[] = [];

  for (const cls of classes) {
    const b = buckets.get(cls);
    if (!b) {
      throw new TypeError(
        `${name(cls)} carries no AXIAM manifest decorator; it declares nothing to collect`,
      );
    }
    if (b.scopes.length && !b.resource) {
      throw new TypeError(
        `${name(cls)} declares scopes with @AxiamScope but no resource with @AxiamResource; ` +
          `a scope has nowhere to live without one`,
      );
    }
    if (b.grants.length && !b.role) {
      throw new TypeError(
        `${name(cls)} declares grants with @AxiamGrant but no role with @AxiamRole; ` +
          `a grant has nothing to attach to without one`,
      );
    }
    if (b.resource) resources.push({ ...b.resource, scopes: [...(b.resource.scopes ?? []), ...b.scopes] });
    permissions.push(...b.permissions);
    if (b.role) roles.push({ ...b.role, grants: [...(b.role.grants ?? []), ...b.grants] });
    if (b.group) groups.push(b.group);
    if (b.user) users.push(b.user);
  }

  const manifest: ManagementManifest = { resources, permissions, roles, groups, users };
  validate(manifest);
  return manifest;
}

function name(cls: object): string {
  return typeof cls === 'function' && cls.name ? cls.name : String(cls);
}
