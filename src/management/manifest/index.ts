/**
 * Declarative management — CONTRACT.md §27.6.
 *
 * The 147 operations of §27 are the floor, not the ceiling. What an
 * application actually does at start-up, in a migration, or in a test fixture
 * is **assert a shape**: this tenant has these resources, with these scopes,
 * these permissions, these roles, and these bindings. Written imperatively
 * that is forty calls wrapped in exists-checks, and it is wrong the second
 * time it runs.
 *
 * ```ts
 * const desired: ManagementManifest = {
 *   resources: [
 *     { key: 'docs', name: 'documents', resourceType: 'collection',
 *       scopes: [{ key: 'draft', name: 'draft', description: 'Unpublished' }] },
 *   ],
 *   permissions: [{ key: 'read', action: 'document:read', description: 'Read a document' }],
 *   roles: [{ key: 'editor', name: 'Editor', description: 'Edits documents',
 *             grants: [{ permission: 'read', scopes: ['draft'] }] }],
 * };
 *
 * const plan = await client.manifest.plan(desired);   // reads only — no writes
 * const report = await client.manifest.apply(desired);
 * ```
 *
 * ## The rules that matter
 *
 * **`plan` writes nothing.** Not "nothing important" — nothing. It issues
 * `GET`s only, which is what makes it safe to point at production, and which
 * has its own test asserting the transport saw no other verb.
 *
 * **Reconciliation is by natural key.** A manifest is written before the
 * things in it exist, so it cannot name them by id. Each spec carries the key
 * its namespace is unique on — a user's `username`, a role's `name`, a scope's
 * `name` within its resource — and cross-references use a manifest-local `key`
 * resolved during planning.
 *
 * **A field the manifest does not state is never a difference.** That is what
 * makes `apply` safe against a tenant that also holds hand-made state.
 *
 * **Nothing is ever deleted.** §27.6 rule 4 forbids deleting without an
 * explicit per-namespace opt-in; this SDK offers no such opt-in at all, so a
 * manifest that omits an existing role leaves it alone. A manifest is usually
 * a *subset* of a tenant's truth, and a prune would turn "make sure these
 * three roles exist" into "delete the other forty".
 *
 * **There is no transaction.** See {@link ApplyReport}.
 */

export * from './declarative.js';
export * from './plan.js';
export * from './spec.js';
export { ManifestApi } from './engine.js';
