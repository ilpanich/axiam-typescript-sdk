/**
 * The AXIAM management API — CONTRACT.md §27.
 *
 * Everything else in this SDK assumes a populated tenant. `login` signs a user
 * in, `checkAccess` asks about a resource, `verifyWebhook` checks a delivery
 * signature — and none of them can create the user, declare the resource or
 * register the webhook. This module is the part that can: **146 operations
 * across 24 namespaces**, which is the whole server API minus what other
 * contract sections own and minus organization creation and deletion, which
 * §27.0 keeps deliberately out of reach of a client library.
 *
 * ```ts
 * const page = await client.users.list({ limit: 50 });
 * const all  = await client.users.listAll({ limit: 200 });
 * const role = await client.roles.get(roleId);
 * ```
 *
 * Operations hang off **namespace handles**, not the client. §27.2 makes that
 * normative: twenty namespaces have a `list` and fourteen a `get`, so a flat
 * surface would need a disambiguating prefix invented once per operation, and
 * 146 more methods on `AxiamClient` would bury the eight most callers want.
 * Acquiring a handle performs no I/O.
 *
 * ## Four things worth knowing before you call anything
 *
 * **Reads retry; writes do not** (§27.4 rule 8). `certificates.generate()`
 * twice mints two certificates and `serviceAccounts.rotateSecret()` twice
 * invalidates the secret the first call returned and you already stored — so
 * no write here is retried, including the ones that look idempotent.
 *
 * **Some `PUT`s replace rather than patch.** Seventeen update bodies are
 * sparse: set the field you mean and nothing else changes. Four are
 * replacements — `settings.setOrg`, the organization email config, the
 * WebAuthn attestation policy and the mTLS trust anchor — where omitted fields
 * are not preserved. Their types have required fields, so a half-filled one
 * does not typecheck.
 *
 * **Seven operations return a secret exactly once.** No later `get` returns
 * that material again, and the `get` projection has no field where it was — so
 * nothing tells you it is missing.
 *
 * **404 means "absent, or not yours."** The server answers 404 for another
 * tenant's resource on purpose; both arrive as {@link NotFoundError}, which is
 * an `AuthzError`.
 *
 * ## Declarative management
 *
 * {@link ManagementManifest} describes the shape a tenant should have;
 * `client.manifest.plan()` says what would change and writes nothing;
 * `client.manifest.apply()` reconciles.
 *
 * ## How this module is built
 *
 * `models.ts` and `ops/` are **generated** by `scripts/gen-management.mjs`
 * from the vendored `management-registry.json` — §27.8 requires that, because
 * a hand-maintained table of 146 names is wrong by the next release. Everything
 * else here is written by hand. CI regenerates and diffs.
 */

export * from './errors.js';
export * from './models.js';
export * from './ops/index.js';
export * from './page.js';
export type { Scope } from './scope.js';
export * from './manifest/index.js';
export type { ManagementCall, ManagementMethod } from './request.js';
