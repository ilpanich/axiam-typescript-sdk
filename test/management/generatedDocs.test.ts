// R-28 (contract 1.59 §34.3, review findings F-13 and F-14): documentation
// that contradicts the types it documents.
//
// - The generated "Every field of the body is required" sat on replacements
//   whose body has optional members (`scimTargets.update`, `ssf.updateStream`):
//   §27.4 rule 5 makes a replacement overwrite what is left out, it does not
//   make every member required.
// - The generated "sparse body … left unchanged" sat on every all-optional
//   type, `ParseSamlSpMetadata` among them, which is no update at all (§29.2:
//   exactly one of two members).
// - The README's mTLS section said "six" aliasable endpoints; §21.3.1's vector
//   has seven since contract 1.58.
//
// These read the generated sources and the README against the vendored
// registry and spec, so the generator's text cannot drift from the types again.

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import registry from '../../management-registry.json' with { type: 'json' };
import spec from '../../openapi.json' with { type: 'json' };

const root = new URL('../../', import.meta.url);
const read = (path: string): string => readFileSync(new URL(path, root), 'utf8');

type Schema = { properties?: Record<string, unknown>; required?: string[]; allOf?: Array<{ $ref?: string } & Schema> };
const schemas = (spec as unknown as { components: { schemas: Record<string, Schema> } }).components.schemas;

/** Properties and required set of a component schema, `allOf` resolved. */
function flatten(name: string): { props: string[]; required: Set<string> } {
  const props = new Set<string>();
  const required = new Set<string>();
  const absorb = (node: Schema & { $ref?: string }): void => {
    const n = node.$ref ? schemas[node.$ref.split('/').pop()!]! : node;
    for (const p of Object.keys(n.properties ?? {})) props.add(p);
    for (const r of n.required ?? []) required.add(r);
    for (const sub of n.allOf ?? []) absorb(sub);
  };
  absorb(schemas[name]!);
  return { props: [...props], required };
}

const camel = (s: string): string => s.replace(/_([a-z0-9])/g, (_m, c: string) => c.toUpperCase());

/** The TSDoc block directly above `async <method>(` in a generated namespace file. */
function methodDoc(source: string, method: string): string {
  const at = source.indexOf(`  async ${method}(`);
  expect(at, `${method} not found`).toBeGreaterThan(-1);
  const open = source.lastIndexOf('/**', at);
  return source.slice(open, at).replace(/\s*\*\s*/g, ' ');
}

/** The TSDoc block directly above `export interface <name> {` in models.ts. */
function interfaceDoc(models: string, name: string): string {
  const at = models.indexOf(`export interface ${name} {`);
  expect(at, `${name} not found`).toBeGreaterThan(-1);
  const open = models.lastIndexOf('/**', at);
  return models.slice(open, at).replace(/\s*\*\s*/g, ' ');
}

type Op = { update_style: string | null; request_schema: string | null };
const namespaces = (registry as unknown as { namespaces: Record<string, { operations: Record<string, Op> }> }).namespaces;

describe('R-28 — generated documentation agrees with the types', () => {
  it('"Every field of the body is required" only on a replacement whose every member is required', () => {
    let replacementsWithOptional = 0;
    for (const [ns, def] of Object.entries(namespaces)) {
      const source = read(`src/management/ops/${ns}.ts`);
      for (const [name, op] of Object.entries(def.operations)) {
        if (op.update_style !== 'replace' || !op.request_schema) continue;
        const doc = methodDoc(source, camel(name));
        expect(doc, `${ns}.${name}`).toContain('This is a replacement, not a patch');
        const { props, required } = flatten(op.request_schema);
        const allRequired = props.every((p) => required.has(p));
        if (!allRequired) replacementsWithOptional += 1;
        expect(doc.includes('Every field of the body is required'), `${ns}.${name}: claims every field is required`).toBe(
          allRequired,
        );
      }
    }
    // scim_targets.update and ssf.update_stream at least: the test is not vacuous.
    expect(replacementsWithOptional).toBeGreaterThanOrEqual(2);
  });

  it('the "sparse body" sentence only on the body of a sparse update', () => {
    const models = read('src/management/models.ts');
    const sparseBodies = new Set<string>();
    for (const def of Object.values(namespaces)) {
      for (const op of Object.values(def.operations)) {
        if (op.update_style === 'sparse' && op.request_schema) sparseBodies.add(op.request_schema);
      }
    }
    const claimed = [...models.matchAll(/this is a \*\*sparse\*\* body[\s\S]*?export interface (\w+) \{/g)].map(
      (m) => m[1]!,
    );
    expect(claimed.length).toBeGreaterThan(0);
    for (const name of claimed) expect(sparseBodies.has(name), `${name} is called a sparse body`).toBe(true);
    expect(interfaceDoc(models, 'ParseSamlSpMetadata')).not.toMatch(/sparse|left unchanged/);
  });
});

describe('R-28 — §21.3.1: seven aliasable endpoints', () => {
  it("the README's mTLS alias section counts seven and lists the CIBA endpoint", () => {
    const readme = read('README.md');
    const start = readme.indexOf('#### RFC 8705 §5 `mtls_endpoint_aliases`');
    expect(start).toBeGreaterThan(-1);
    const section = readme.slice(start, readme.indexOf('\n#', start + 1)).replace(/\s+/g, ' ');
    expect(section).not.toMatch(/\bsix\b/);
    expect(section).toContain('seven');
    expect(section).toContain('`backchannel_authentication_endpoint`');
  });
});
