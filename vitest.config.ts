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
      // the floor. Set below the current level (lines ~95%, branches ~87%) so
      // it never false-fails; ratchet upward as coverage rises.
      thresholds: {
        lines: 93,
        statements: 92,
        functions: 95,
        branches: 84,
      },
    },
  },
});
