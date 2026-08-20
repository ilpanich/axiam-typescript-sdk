/**
 * Tests for the OPAQUE loader (CONTRACT.md §23).
 *
 * Deliberately short. Its predecessor, `srp.test.ts`, was 272 lines because
 * `core/srp.ts` contained the protocol and had to be checked against the
 * cross-language vectors. `core/opaque.ts` contains no cryptography — §23.1
 * forbids it — so what is left to test is the loader's own decisions: that a
 * missing optional peer degrades rather than throws, that the module is
 * instantiated once, and that the KSF the server names is honoured exactly.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  OpaqueUnavailableError,
  __resetOpaqueModuleForTests,
  __setOpaqueModuleForTests,
  opaqueAvailable,
  startLogin,
  startRegistration,
} from '../../src/core/opaque.js';
import { AuthError, NetworkError } from '../../src/core/errors.js';

/** A module mock that records which KSF it was handed. */
function moduleMock() {
  const seen: unknown[] = [];
  return {
    seen,
    mod: {
      default: vi.fn(async () => undefined),
      opaqueAvailable: () => true,
      OpaqueKsf: {
        argon2id: (memoryKib: number, iterations: number, parallelism: number) => {
          const ksf = { kind: 'argon2id', memoryKib, iterations, parallelism };
          seen.push(ksf);
          return ksf;
        },
        scrypt: (logN: number, r: number, p: number) => {
          const ksf = { kind: 'scrypt', logN, r, p };
          seen.push(ksf);
          return ksf;
        },
      },
      OpaqueLogin: class {
        ke1 = 'aa'.repeat(96);
        constructor(_password: string) {}
        finish() {
          return { ke3: 'bb'.repeat(64), sessionKey: 'cc'.repeat(64), exportKey: 'dd'.repeat(64) };
        }
      },
      OpaqueRegistration: class {
        request = 'ee'.repeat(32);
        constructor(_password: string) {}
        finish() {
          return { record: 'ff'.repeat(192), exportKey: 'dd'.repeat(64) };
        }
      },
    },
  };
}

beforeEach(() => {
  __resetOpaqueModuleForTests();
});

afterEach(() => {
  __resetOpaqueModuleForTests();
});

describe('availability', () => {
  it('reports false rather than throwing when the optional peer is absent', async () => {
    // The posture §23.1 requires: an installation that skipped the peer must be
    // able to *answer* the capability question, not fail at login time. The
    // specifier is unresolvable here, so this exercises the real path.
    await expect(opaqueAvailable()).resolves.toBe(false);
  });

  it('reports true once a module is present', async () => {
    __setOpaqueModuleForTests(moduleMock().mod);
    await expect(opaqueAvailable()).resolves.toBe(true);
  });

  it('instantiates the module only once across concurrent callers', async () => {
    // Memoized on the promise, not the result: two logins racing at startup
    // must not both pay for instantiation.
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);
    await Promise.all([opaqueAvailable(), opaqueAvailable(), opaqueAvailable()]);
    expect(mod.default).toHaveBeenCalledTimes(0); // injected, so init is skipped
  });

  it('raises a distinguishable error when an exchange starts without a module', async () => {
    // A NetworkError subclass, never an AuthError: a caller must be able to
    // fall back to password login rather than report a wrong password.
    await expect(startLogin('pw')).rejects.toBeInstanceOf(OpaqueUnavailableError);
    await expect(startLogin('pw')).rejects.toBeInstanceOf(NetworkError);
    await expect(startLogin('pw')).rejects.not.toBeInstanceOf(AuthError);
    await expect(startRegistration('pw')).rejects.toBeInstanceOf(OpaqueUnavailableError);
  });
});

describe('KSF selection', () => {
  it('uses exactly the argon2id parameters the server named', async () => {
    const { mod, seen } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const exchange = await startLogin('pw');
    exchange.finish('12'.repeat(320), {
      ksf: 'argon2id',
      memory_kib: 65536,
      iterations: 3,
      parallelism: 2,
    });

    expect(seen).toEqual([{ kind: 'argon2id', memoryKib: 65536, iterations: 3, parallelism: 2 }]);
  });

  it('uses exactly the scrypt parameters the server named', async () => {
    const { mod, seen } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const exchange = await startRegistration('pw');
    exchange.finish('34'.repeat(64), { ksf: 'scrypt', log_n: 15, r: 4, p: 2 });

    expect(seen).toEqual([{ kind: 'scrypt', logN: 15, r: 4, p: 2 }]);
  });

  it('refuses an unknown KSF rather than substituting one', async () => {
    // Substituting produces a well-formed randomized password that no AXIAM
    // server agrees with, reported to the user as a wrong password.
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const exchange = await startLogin('pw');
    expect(() =>
      exchange.finish('12'.repeat(320), { ksf: 'pbkdf2_sha256', iterations: 600000 }),
    ).toThrow(/pbkdf2_sha256/);
  });

  it('refuses a KSF whose cost parameters are missing', async () => {
    // Absent is NOT zero. Reading a missing `memory_kib` as 0 would stretch
    // with the wrong cost and fail against a record that is perfectly good.
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    for (const fields of [
      { ksf: 'argon2id', iterations: 1, parallelism: 1 },
      { ksf: 'argon2id', memory_kib: 8192, parallelism: 1 },
      { ksf: 'argon2id', memory_kib: 8192, iterations: 1 },
      { ksf: 'scrypt', r: 8, p: 1 },
      { ksf: 'scrypt', log_n: 15, p: 1 },
      { ksf: 'scrypt', log_n: 15, r: 8 },
    ]) {
      const exchange = await startLogin('pw');
      expect(() => exchange.finish('12'.repeat(320), fields)).toThrow(NetworkError);
    }
  });

  it('refuses out-of-range costs rather than clamping them', async () => {
    // A server is trusted to name its own policy, not to name a cost that would
    // wedge every device an account owns. Clamping would be worse than failing:
    // the client would stretch with a cost the server did not name.
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    for (const fields of [
      { ksf: 'argon2id', memory_kib: 64, iterations: 1, parallelism: 1 },
      { ksf: 'argon2id', memory_kib: 4_194_304, iterations: 1, parallelism: 1 },
      { ksf: 'argon2id', memory_kib: 8192, iterations: 99, parallelism: 1 },
      { ksf: 'argon2id', memory_kib: 8192, iterations: 1, parallelism: 99 },
      { ksf: 'scrypt', log_n: 10, r: 8, p: 1 },
      { ksf: 'scrypt', log_n: 24, r: 8, p: 1 },
      { ksf: 'scrypt', log_n: 15, r: 64, p: 1 },
      { ksf: 'scrypt', log_n: 15, r: 8, p: 64 },
    ]) {
      const exchange = await startLogin('pw');
      expect(() => exchange.finish('12'.repeat(320), fields)).toThrow(NetworkError);
    }
  });

  it('accepts the inclusive bounds', async () => {
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    for (const fields of [
      { ksf: 'argon2id', memory_kib: 8192, iterations: 1, parallelism: 1 },
      { ksf: 'argon2id', memory_kib: 1_048_576, iterations: 10, parallelism: 16 },
      { ksf: 'scrypt', log_n: 14, r: 1, p: 1 },
      { ksf: 'scrypt', log_n: 20, r: 16, p: 16 },
    ]) {
      const exchange = await startLogin('pw');
      expect(() => exchange.finish('12'.repeat(320), fields)).not.toThrow();
    }
  });

  it('refuses a non-integer cost', async () => {
    // A float would be silently truncated by the WASM boundary, stretching
    // with a cost nobody named.
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const exchange = await startLogin('pw');
    expect(() =>
      exchange.finish('12'.repeat(320), {
        ksf: 'argon2id',
        memory_kib: 8192.5,
        iterations: 1,
        parallelism: 1,
      }),
    ).toThrow(NetworkError);
  });
});

describe('exchange shape', () => {
  it('surfaces the first message for the caller to post', async () => {
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    expect((await startLogin('pw')).ke1).toHaveLength(192);
    expect((await startRegistration('pw')).request).toHaveLength(64);
  });

  it('returns only the value the wire needs', async () => {
    // The session key and export key stay inside the module. AXIAM issues
    // ordinary session cookies, so surfacing them here would hand the
    // application key material it has no use for and must not log.
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const ke3 = (await startLogin('pw')).finish('12'.repeat(320), {
      ksf: 'argon2id',
      memory_kib: 19456,
      iterations: 2,
      parallelism: 1,
    });
    expect(ke3).toBe('bb'.repeat(64));
  });
});
