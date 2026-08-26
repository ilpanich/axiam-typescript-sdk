/**
 * Where `{org_id}` and `{tenant_id}` come from — CONTRACT §27.4 rule 3.
 *
 * Thirty of the 146 routes carry one or both, and in almost every call they
 * are the client's own. Making the caller restate them every time is ceremony
 * that gets wrapped in a helper anyway; making them impossible to override is
 * worse, because a platform-admin token legitimately administers a tenant
 * other than the one its client was built with. So they default from the
 * client, and every handle that needs one exposes an override.
 */

import { NetworkError } from '../core/errors.js';
import type { AxiamClient } from '../rest/client.js';

/** Per-handle overrides for the two implicit path parameters. */
export interface Scope {
  /** Override for `{org_id}`. Absent means "the client's". */
  orgId?: string;
  /** Override for `{tenant_id}`. Absent means "the client's". */
  tenantId?: string;
}

/**
 * Resolve `{org_id}`: the handle's override, else the client's.
 *
 * A client built with `orgSlug` and no `orgId` fails **here**, with no wire
 * call. §27.4 rule 3 forbids resolving the slug behind the caller's back: a
 * silent extra round-trip on an admin path is what §12.1 rule 2 refuses for
 * `/oauth2/*`, and for the same reason — the caller cannot see it, cannot
 * cache it, and pays for it on every call.
 *
 * @internal
 */
export function resolveOrg(client: AxiamClient, scope: Scope, operation: string): string {
  if (scope.orgId) return scope.orgId;
  const configured = client.session.orgId;
  if (configured) return configured;
  const slug = client.session.orgSlug;
  throw new NetworkError(
    slug
      ? `${operation}: this route needs an organization UUID, but the client was built with ` +
          `orgSlug ${JSON.stringify(slug)}. Rebuild it with orgId, or name one on the handle ` +
          `with .inOrg(...).`
      : `${operation}: this route needs an organization UUID and the client has none. Build ` +
          `the client with orgId, or name one on the handle with .inOrg(...).`,
  );
}

/**
 * Resolve `{tenant_id}` where it names the *context*, not the object.
 *
 * Namespaces where `{tenant_id}` names the thing being acted on — `tenants`,
 * and the signing CAs under `ca_certificates` — take it as an ordinary
 * argument instead and never reach this.
 *
 * @internal
 */
export function resolveTenant(client: AxiamClient, scope: Scope, operation: string): string {
  if (scope.tenantId) return scope.tenantId;
  const configured = client.session.tenantId ?? client.session.resolvedTenantId;
  if (configured) return configured;
  throw new NetworkError(
    `${operation}: this route needs a tenant UUID, but the client was built with ` +
      `tenantSlug ${JSON.stringify(client.session.tenantSlug)}. Rebuild it with tenantId, or ` +
      `name one on the handle with .forTenant(...).`,
  );
}
