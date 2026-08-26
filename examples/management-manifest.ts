// Declarative management — CONTRACT.md §27.6 and §27.7.
//
// The same tenant `management-basics.ts` builds call by call, declared
// instead. Both TypeScript declarative forms are here: the object literal that
// `defineManifest` validates at declaration time, and the decorators, which
// this file can use with real `@` syntax because examples/tsconfig.json
// enables a decorator mode (the SDK's own tsconfig deliberately does not — the
// decorators are dual-protocol plain functions for exactly that reason).
//
//   npx tsx examples/management-manifest.ts

import { AxiamClient } from 'axiam-sdk/rest';
import {
  AxiamGrant,
  AxiamPermission,
  AxiamResource,
  AxiamRole,
  AxiamScope,
  Sensitive,
  collectManifest,
  defineManifest,
} from 'axiam-sdk/rest';

// ---------------------------------------------------------------------------
// Form 1: an object literal, validated where it is written
// ---------------------------------------------------------------------------

const desired = defineManifest({
  resources: [
    { key: 'workspace', name: 'workspace', resourceType: 'collection' },
    {
      key: 'documents',
      name: 'documents',
      resourceType: 'collection',
      parent: 'workspace',
      scopes: [
        { key: 'drafts', name: 'draft', description: 'Unpublished documents' },
        { key: 'published', name: 'published', description: 'Published documents' },
      ],
    },
  ],
  permissions: [
    { key: 'read', action: 'document:read', description: 'Read a document' },
    { key: 'write', action: 'document:write', description: 'Write a document' },
  ],
  roles: [
    {
      key: 'editor',
      name: 'Editor',
      description: 'Edits drafts, reads everything',
      grants: [{ permission: 'read' }, { permission: 'write', scopes: ['drafts'] }],
    },
    {
      key: 'contractor',
      name: 'Contractor',
      description: 'Reads drafts only',
      grants: [
        { permission: 'read', scopes: ['drafts'] },
        // A deny grant overrides EVERY allow, at any depth of the hierarchy
        // and at equal specificity. AXIAM's engine is deny-override, not
        // most-specific-wins — so this is absolute, not a tie-break.
        { permission: 'write', effect: 'deny' },
      ],
    },
  ],
  groups: [{ key: 'staff', name: 'Staff', description: 'Everyone on the team', roles: ['editor'] }],
  users: [
    {
      key: 'alice',
      username: 'alice',
      email: 'alice@example.com',
      initialPassword: new Sensitive('correct horse battery staple'),
      groups: ['staff'],
    },
  ],
});

// `defineManifest` validated all of that as this module was imported. A typo in
// a cross-reference — `scopes: ['draft']` where the key is `drafts` — throws
// here, not on the first plan against a live tenant.

// ---------------------------------------------------------------------------
// Form 2: decorators, for codebases that already declare their domain that way
// ---------------------------------------------------------------------------

@AxiamResource({ key: 'reports', name: 'reports', resourceType: 'collection' })
@AxiamScope({ key: 'quarterly', name: 'quarterly', description: 'Quarterly reports' })
class Reports {}

@AxiamPermission({ key: 'report-read', action: 'report:read', description: 'Read a report' })
class ReadReport {}

@AxiamRole({ key: 'analyst', name: 'Analyst', description: 'Reads quarterly reports' })
@AxiamGrant({ permission: 'report-read', scopes: ['quarterly'] })
class Analyst {}

const declaredByDecorator = collectManifest(Reports, ReadReport, Analyst);

async function main(): Promise<void> {
  console.log(
    `literal form: ${desired.resources?.length} resources, ` +
      `${desired.permissions?.length} permissions, ${desired.roles?.length} roles, ` +
      `${desired.groups?.length} groups, ${desired.users?.length} users`,
  );
  console.log(
    `decorator form: ${declaredByDecorator.resources?.length} resources, ` +
      `${declaredByDecorator.roles?.length} roles`,
  );

  const client = new AxiamClient({
    baseUrl: 'https://iam.example.com',
    tenantId: '00000000-0000-0000-0000-000000000000',
    orgId: '00000000-0000-0000-0000-000000000000',
  });
  void client;

  console.log(`
Against a live, logged-in client:

    const plan = await client.manifest.plan(desired);
    for (const action of changes(plan)) {
      console.log(action.change, action.summary);
    }

\`plan\` issues GETs and nothing else, so it is safe to point at production. It
reads the tenant, matches each spec by its natural key — a user's username, a
role's name, a scope's name within its resource — and returns the ordered
actions that would reconcile it.

    const report = await client.manifest.apply(desired);
    if (!isComplete(report)) console.error(failure(report));

Four things worth knowing before you point this at a real tenant:

 1. Nothing is ever deleted. A manifest is usually a SUBSET of a tenant's
    truth; pruning would turn "make sure these roles exist" into "delete the
    other forty". There is no prune option, on purpose.

 2. A field the manifest does not state is never a difference, so this is safe
    against a tenant that also holds hand-made state.

 3. Applying twice converges: the second plan is all no-change. That is the
    property that makes re-running after a failure safe.

 4. There is no transaction across 146 independent HTTP endpoints, and
    ApplyReport does not pretend there is. If step 12 of 30 fails, steps 1-11
    have happened; the report says which, execution stops rather than
    continuing blindly, and there is no rollback — because the SDK could not
    honour one. Fix the cause and re-apply; (3) makes that safe.

Broken manifests are refused before the first request: dangling keys,
duplicate keys, a cycle in the resource parents, and a user that would have to
be created with no initialPassword all fail while nothing has changed.`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
