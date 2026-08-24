import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Language-version support policy.
 *
 * "Which Node does this SDK support?" is declared in three independent places,
 * and nothing in the toolchain compares them:
 *
 *  1. `engines.node` in package.json — what npm warns (or, under
 *     `engine-strict`, refuses) on at install time;
 *  2. the `@types/node` devDependency — which runtime's API surface `tsc`
 *     believes exists while it typechecks;
 *  3. the `node` matrix in `.github/workflows/sdk-ci-typescript.yml` — the
 *     only one that is ever executed.
 *
 * Before this suite existed all three disagreed at once: `engines` said
 * `>=18` (EOL 2025-04-30), `@types/node` was pinned to `^26`, and CI built
 * nothing but 22. That combination typechecks the SDK against APIs that no
 * tested runtime provides, while promising installation on a runtime that is
 * never built. None of it fails on its own.
 *
 * The policy pinned here is floor + newest: the gating matrix runs exactly
 * the two ends of the supported range. The floor is what `engines` promises;
 * the newest is what `@types/node` types against.
 */

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

interface PackageJson {
  engines?: { node?: string };
  devDependencies?: Record<string, string>;
}

const pkg: PackageJson = JSON.parse(
  readFileSync(`${REPO_ROOT}/package.json`, 'utf8'),
);

const workflow = readFileSync(
  `${REPO_ROOT}/.github/workflows/sdk-ci-typescript.yml`,
  'utf8',
);

/**
 * `engines.node` is a single inclusive floor (`>=X`). If that ever becomes a
 * range or a disjunction, this should fail loudly rather than silently
 * interpret half of it.
 */
function enginesFloorMajor(): number {
  const raw = pkg.engines?.node;
  expect(raw, 'package.json declares no engines.node').toBeDefined();
  const match = /^>=\s*(\d+)(?:\.\d+)*$/.exec((raw as string).trim());
  expect(
    match,
    `engines.node is "${raw}", which this policy test cannot interpret. ` +
      'The support policy is a single inclusive floor (">=X"); if that has ' +
      'deliberately changed, update this test rather than loosening the regex.',
  ).not.toBeNull();
  return Number((match as RegExpExecArray)[1]);
}

/** The major of the `@types/node` devDependency range, e.g. `^26.1.1` -> 26. */
function typesNodeMajor(): number {
  const raw = pkg.devDependencies?.['@types/node'];
  expect(raw, 'package.json declares no @types/node devDependency').toBeDefined();
  const match = /(\d+)/.exec(raw as string);
  expect(match, `cannot read a major version out of "${raw}"`).not.toBeNull();
  return Number((match as RegExpExecArray)[1]);
}

/** The `node: ['22', '26']` list from the CI test matrix. */
function ciMatrixMajors(): number[] {
  const matches = [...workflow.matchAll(/^\s*node:\s*\[([^\]]*)\]\s*$/gm)];
  expect(
    matches.length,
    'expected exactly one `node:` matrix in sdk-ci-typescript.yml — a second ' +
      'would mean this test only checks one of them',
  ).toBe(1);
  return matches[0][1]
    .split(',')
    .map((entry) => entry.trim().replace(/^['"]|['"]$/g, ''))
    .filter((entry) => entry.length > 0)
    .map((entry) => Number(entry.split('.')[0]))
    .sort((a, b) => a - b);
}

describe('language-version support policy', () => {
  it('declares a floor that is a currently supported Node line', () => {
    // Node lines EOL on a published schedule; anything below 22 is
    // unsupported as of 2026-08. This is the assertion that would have caught
    // the `>=18` the SDK shipped with.
    expect(enginesFloorMajor()).toBeGreaterThanOrEqual(22);
  });

  it('runs the floor in CI, so `engines` is a promise something keeps', () => {
    const floor = enginesFloorMajor();
    expect(
      ciMatrixMajors(),
      `engines.node promises >=${floor} but CI never builds it`,
    ).toContain(floor);
  });

  it('gates on exactly floor + newest, not a subset and not all of them', () => {
    const matrix = ciMatrixMajors();
    expect(matrix.length).toBe(2);
    expect(matrix[0]).toBe(enginesFloorMajor());
    expect(matrix[1]).toBeGreaterThan(matrix[0]);
  });

  it('typechecks against the newest runtime it actually builds', () => {
    // A @types/node newer than every CI leg means `tsc` is validating the SDK
    // against APIs no tested runtime provides — the failure lands on a
    // consumer, not here. Older than the newest leg means the reverse: the
    // newest leg runs code `tsc` never saw the real types for.
    //
    // When a new Node line ships and Dependabot bumps @types/node ahead of
    // the matrix, this is the test that goes red, and adding the leg is the
    // correct response to it.
    const matrix = ciMatrixMajors();
    expect(typesNodeMajor()).toBe(matrix[matrix.length - 1]);
  });

  it('never builds a Node older than `engines` allows installing', () => {
    const floor = enginesFloorMajor();
    for (const major of ciMatrixMajors()) {
      expect(major, `CI builds Node ${major}, below the ${floor} floor`)
        .toBeGreaterThanOrEqual(floor);
    }
  });

  it('is running on a Node the policy declares supported', () => {
    // Whichever leg CI actually launched, `engines` covers it.
    const running = Number(process.versions.node.split('.')[0]);
    expect(running).toBeGreaterThanOrEqual(enginesFloorMajor());
  });
});
