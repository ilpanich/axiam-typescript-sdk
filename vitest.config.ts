import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // Browser-persona tests opt into jsdom per-file via:
    //   // @vitest-environment jsdom
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      // lcov is what coverallsapp/github-action ingests (coverage/lcov.info);
      // text keeps the summary readable in the CI log.
      reporter: ['text', 'lcov'],
      reportsDirectory: 'coverage',
      include: ['src/**/*.ts'],
      // src/gen is ts-proto output, not hand-written code — measuring it would
      // dilute the ratio without saying anything about the SDK's own tests.
      exclude: ['src/gen/**'],
      // Regression gate: fail `vitest run --coverage` if coverage drops below
      // the floor. Set a couple of points below the current level so it never
      // false-fails; ratchet upward as coverage rises.
      //
      // Raised with §27 (lines ~96.9%, statements ~96.3%, functions ~97.6%,
      // branches ~89.8%): the management surface arrived with its own
      // generated per-operation test plus hand-written semantics, which lifted
      // every ratio rather than diluting it. Leaving the old floor would have
      // let that margin be spent silently.
      thresholds: {
        lines: 95,
        statements: 95,
        functions: 96,
        branches: 88,
      },
    },
  },
});
