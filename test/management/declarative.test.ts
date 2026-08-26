// CONTRACT §27.7 — the declarative forms.
//
// Both lower to the same ManagementManifest, so what needs testing is that
// they agree with the plain object literal, and that a declaration naming
// something undeclared says so where it is *written* rather than on the first
// plan against a live tenant.

import { describe, expect, it } from 'vitest';

import { Sensitive } from '../../src/core/sensitive.js';
import {
  AxiamGrant,
  AxiamGroup,
  AxiamPermission,
  AxiamResource,
  AxiamRole,
  AxiamScope,
  AxiamUser,
  collectManifest,
  defineManifest,
} from '../../src/management/manifest/index.js';

describe('defineManifest', () => {
  it('returns the manifest, with literal key types preserved', () => {
    const m = defineManifest({
      resources: [{ key: 'docs', name: 'documents', resourceType: 'collection' }],
      permissions: [{ key: 'read', action: 'document:read', description: 'Read' }],
      roles: [
        { key: 'editor', name: 'Editor', description: 'Edits', grants: [{ permission: 'read' }] },
      ],
    });
    expect(m.roles?.[0]?.grants?.[0]?.permission).toBe('read');
  });

  // The eager validation is the point: a dangling key fails at import time for
  // a manifest that lives in a config module, not on the first plan.
  it('throws at declaration time on a dangling reference', () => {
    expect(() =>
      defineManifest({
        roles: [{ key: 'editor', name: 'Editor', description: 'Edits', grants: [{ permission: 'ghost' }] }],
      }),
    ).toThrow(/ghost/);
  });

  it('throws at declaration time on a resource cycle', () => {
    expect(() =>
      defineManifest({
        resources: [
          { key: 'a', name: 'a', resourceType: 'collection', parent: 'b' },
          { key: 'b', name: 'b', resourceType: 'collection', parent: 'a' },
        ],
      }),
    ).toThrow(/cycle/);
  });
});

// Applied by direct call rather than with `@` syntax. This SDK's own tsconfig
// enables neither of TypeScript's decorator modes — the same position
// src/nestjs/decorators.ts takes — and esbuild passes `@` through
// untransformed, so `@AxiamResource(...)` would not parse under vitest.
// `AxiamResource(spec)(Cls)` is precisely what the syntax desugars to, which
// is why the decorators are dual-protocol plain functions in the first place.
describe('decorators', () => {
  class Documents {}
  AxiamResource({ key: 'docs', name: 'documents', resourceType: 'collection' })(Documents);
  AxiamScope({ key: 'draft', name: 'draft', description: 'Unpublished' })(Documents);

  class ReadDocument {}
  AxiamPermission({ key: 'read', action: 'document:read', description: 'Read a document' })(
    ReadDocument,
  );

  class Editor {}
  AxiamRole({ key: 'editor', name: 'Editor', description: 'Edits documents' })(Editor);
  AxiamGrant({ permission: 'read', scopes: ['draft'] })(Editor);

  class Staff {}
  AxiamGroup({ key: 'staff', name: 'Staff', description: 'All staff', roles: ['editor'] })(Staff);

  class Alice {}
  AxiamUser({
    key: 'alice',
    username: 'alice',
    email: 'alice@example.com',
    initialPassword: new Sensitive('correct horse battery staple'),
    groups: ['staff'],
  })(Alice);

  it('assembles the same manifest the object literal would', () => {
    const collected = collectManifest(Documents, ReadDocument, Editor, Staff, Alice);

    expect(collected.resources).toEqual([
      {
        key: 'docs',
        name: 'documents',
        resourceType: 'collection',
        scopes: [{ key: 'draft', name: 'draft', description: 'Unpublished' }],
      },
    ]);
    expect(collected.permissions).toEqual([
      { key: 'read', action: 'document:read', description: 'Read a document' },
    ]);
    expect(collected.roles?.[0]?.grants).toEqual([{ permission: 'read', scopes: ['draft'] }]);
    expect(collected.groups?.[0]?.roles).toEqual(['editor']);
    expect(collected.users?.[0]?.groups).toEqual(['staff']);
  });

  // Decorators apply bottom-up, so a form that depended on order would put the
  // scope before the resource it belongs to. Each one only records; the
  // assembling happens in collectManifest.
  it('does not depend on decorator order', () => {
    class ScopeFirst {}
    // `@` syntax applies bottom-up, so this is the order a stacked
    // `@AxiamScope` above `@AxiamResource` really produces.
    AxiamResource({ key: 'r', name: 'r', resourceType: 'collection' })(ScopeFirst);
    AxiamScope({ key: 's', name: 's', description: 'd' })(ScopeFirst);

    expect(collectManifest(ScopeFirst).resources?.[0]?.scopes).toHaveLength(1);
  });

  it('accepts the TC39 standard two-argument form too', () => {
    class Standard {}
    AxiamResource({ key: 'std', name: 'std', resourceType: 'collection' })(Standard, {
      kind: 'class',
      name: 'Standard',
    });
    expect(collectManifest(Standard).resources?.[0]?.key).toBe('std');
  });

  it('refuses to decorate anything but a class', () => {
    expect(() =>
      AxiamResource({ key: 'x', name: 'x', resourceType: 'collection' })(() => {}, {
        kind: 'method',
      }),
    ).toThrow(/classes only/);
  });

  it('rejects a class carrying no manifest decorator', () => {
    class Undecorated {}
    expect(() => collectManifest(Undecorated)).toThrow(/no AXIAM manifest decorator/);
  });

  it('rejects a scope with no resource to live in', () => {
    class Orphan {}
    AxiamScope({ key: 'orphan', name: 'orphan', description: 'nowhere' })(Orphan);
    expect(() => collectManifest(Orphan)).toThrow(/no resource/);
  });

  it('rejects a grant with no role to attach to', () => {
    class Floating {}
    AxiamGrant({ permission: 'read' })(Floating);
    expect(() => collectManifest(Floating)).toThrow(/no role/);
  });

  // The assembled manifest goes through the same validation as every other
  // form, so a cross-reference that does not resolve is caught here too.
  it('validates the assembled manifest', () => {
    class Lonely {}
    AxiamRole({ key: 'lonely', name: 'Lonely', description: 'x' })(Lonely);
    AxiamGrant({ permission: 'nonexistent' })(Lonely);
    expect(() => collectManifest(Lonely)).toThrow(/nonexistent/);
  });

  it('keeps a declared password out of every rendering', () => {
    // The whole set, because collectManifest validates what it assembles and
    // the chain is real: Alice needs Staff, Staff needs Editor, Editor's grant
    // needs its permission and the scope it is narrowed to. Passing a subset
    // is rejected — which is the behaviour, not an inconvenience.
    const collected = collectManifest(Documents, ReadDocument, Editor, Staff, Alice);
    expect(JSON.stringify(collected)).not.toContain('correct horse battery staple');
  });
});
