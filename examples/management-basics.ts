// The §27 management surface, imperatively — CONTRACT.md §27.
//
// Builds a small tenant by hand: a resource with a scope, a permission, a role
// that grants it, a group holding the role, and a user in the group. The
// declarative equivalent is `management-manifest.ts`, and is what you probably
// want for anything this shaped — this file exists to show the calls the
// declarative form makes on your behalf, and the rules that bite when you make
// them yourself.
//
//   npx tsx examples/management-basics.ts
//
// No network I/O: the calls are printed, not made.

import { AxiamClient } from 'axiam-sdk/rest';
import type { UpdateUserRequest } from 'axiam-sdk/rest';

async function main(): Promise<void> {
  const client = new AxiamClient({
    baseUrl: 'https://iam.example.com',
    tenantId: '00000000-0000-0000-0000-000000000000',
    orgId: '00000000-0000-0000-0000-000000000000',
  });
  // A real run logs in here. §27.4 rule 1 makes every management call fail
  // locally, with no request, until it does.
  void client;

  section('Namespaces, not 146 methods on the client');
  console.log('  client.users.list(...)          client.roles.assignToUser(...)');
  console.log('  client.tenants.create(...)      client.certificates.generate(...)');
  console.log();
  console.log('  Twenty namespaces have a `list` and fourteen a `get`. Flattened, every');
  console.log('  one would need a prefix invented per operation. Acquiring a handle costs');
  console.log('  nothing and makes no request. `client.management.users` is the same');
  console.log('  handle, for call sites where you would rather it read as a namespace.');

  section('Pagination: `total` is the set, not the page');
  console.log('  const page = await client.users.list({ limit: 50 });');
  console.log('  page.items.length  // up to 50');
  console.log('  page.total         // 4312 — the whole set');
  console.log();
  console.log('  For everything, `listAll` walks to exhaustion:');
  console.log('      await client.users.listAll({ limit: 200 })');
  console.log('  The SDK never truncates silently — if it returns one page, `total` says so.');

  section('Sparse update: what you leave out is left alone');
  const patch: UpdateUserRequest = { email: 'new@example.com' };
  console.log('  await client.users.update(id, { email: "new@example.com" });');
  console.log();
  console.log(`  Wire body: ${JSON.stringify(patch)}`);
  console.log('  One key. Not `username: null` — absent means unchanged, and this SDK');
  console.log('  cannot express "set it to null", which is the safe direction.');

  section('...but four PUTs are replacements, not patches');
  console.log('  settings.setOrg, emailConfig.setOrg, webauthnPolicy.set and');
  console.log('  caCertificates.setMtlsTrustAnchor REPLACE. Their request types have');
  console.log('  required fields, so a half-filled one does not typecheck — which is the');
  console.log('  point: sending a subset of SetOrgSettings resets the other eighteen.');
  console.log();
  console.log('  Read, change, send the whole thing back:');
  console.log('      const current = await client.settings.getOrg();');
  console.log('      await client.settings.setOrg({ ...current, max_failed_login_attempts: 10 });');

  section('404 means "absent, or not yours"');
  console.log('  try {');
  console.log('    await client.users.get(id);');
  console.log('  } catch (e) {');
  console.log('    if (e instanceof NotFoundError) { /* both cases, deliberately */ }');
  console.log('    else if (e instanceof ConflictError) { /* 409 — the name is taken */ }');
  console.log('    else if (e instanceof ValidationError) { for (const f of e.fields) {} }');
  console.log('  }');
  console.log();
  console.log('  All three are subclasses of the §2 types, so `e instanceof AuthzError`');
  console.log('  written before §27 still catches the first two.');

  section('Writes are never retried');
  console.log('  Reads retry under §16. Writes do not — not even the idempotent-looking');
  console.log('  ones. certificates.generate() twice mints two certificates, and');
  console.log('  serviceAccounts.rotateSecret() twice invalidates the secret the first');
  console.log('  call returned and you already stored.');

  section('Seven calls return a secret exactly once');
  console.log('  serviceAccounts.create / rotateSecret, oauth2Clients.create,');
  console.log('  scimTokens.create, certificates.generate, caCertificates.generate /');
  console.log('  .generateSigningCa, pgpKeys.generate.');
  console.log();
  console.log('  Each returns Sensitive<string>: JSON.stringify gives "[SENSITIVE]",');
  console.log('  .expose() gives the value. No later `get` returns it again, and the');
  console.log('  `get` projection has no field where it was.');
}

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
