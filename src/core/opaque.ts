/**
 * OPAQUE (RFC 9807) — the protocol half.
 *
 * This file contains **no cryptography**. Its predecessor, `core/srp.ts`, was
 * 419 lines of modular exponentiation, `PAD()` and SHA-256 transcript hashing,
 * because SRP is arithmetic every language can express and so every AXIAM
 * client wrote its own. OPAQUE is not — it needs an oblivious PRF,
 * `hash_to_curve`, `expand_message_xmd`, an envelope construction and a
 * three-message AKE — so CONTRACT.md §23.1 forbids an SDK from implementing
 * it, and this module is a loader around the one implementation the server and
 * every other SDK also use.
 *
 * # Loading
 *
 * `@axiam/opaque-wasm` is an **optional peer dependency**, resolved at runtime.
 * An installation that never touches the OPAQUE path should not be made to
 * carry a WebAssembly module, and a checkout without it must still build. When
 * it is absent, {@link opaqueAvailable} reports `false` and callers fall back
 * to password login — the posture §23.1 requires of an SDK whose native
 * artifact failed to load, and the reason it must *report* rather than throw at
 * login time.
 */

import { NetworkError } from './errors.js';

type OpaqueModule = typeof import('@axiam/opaque-wasm');

let modulePromise: Promise<OpaqueModule | null> | null = null;

/**
 * The package specifier, held in a variable so bundlers do not try to resolve
 * it statically.
 *
 * This is the mechanism behind the graceful degradation above: a static
 * `import('@axiam/opaque-wasm')` is a hard resolution failure in an
 * installation that skipped the optional peer, which would make the whole SDK
 * unloadable for consumers who never wanted OPAQUE.
 */
const WASM_PACKAGE = '@axiam/opaque-wasm';

/**
 * Load the WASM module once per process.
 *
 * Memoized on the *promise*, not the result, so two concurrent logins do not
 * instantiate the module twice. A failure is memoized too: retrying a package
 * that is not installed on every login would be a per-request cost for a file
 * that is not going to appear.
 */
async function loadModule(): Promise<OpaqueModule | null> {
  modulePromise ??= (async () => {
    try {
      const mod = (await import(/* @vite-ignore */ WASM_PACKAGE)) as OpaqueModule;
      await mod.default();
      return mod;
    } catch {
      return null;
    }
  })();
  return modulePromise;
}

/** Reset the memoized module. Test-only. */
export function __resetOpaqueModuleForTests(): void {
  modulePromise = null;
}

/**
 * Inject a module, bypassing the loader. Test-only.
 *
 * Exists because the dynamic specifier above is deliberately unresolvable at
 * build time, which also puts it out of reach of `vi.mock`.
 */
export function __setOpaqueModuleForTests(mod: unknown): void {
  modulePromise = Promise.resolve(mod as OpaqueModule);
}

/**
 * Whether this installation can perform OPAQUE at all (CONTRACT §23.2).
 *
 * Reports rather than throws, so a caller can decide to use the password path
 * before attempting a login rather than discovering it mid-exchange.
 */
export async function opaqueAvailable(): Promise<boolean> {
  const mod = await loadModule();
  return mod !== null && mod.opaqueAvailable();
}

/**
 * The key-stretching fields a `register/start` or `login/start` response
 * carries.
 *
 * Flat and optional, matching the wire format: the fields that do not apply to
 * the named function are **absent, not zero**. Reading an absent field as `0`
 * would stretch with the wrong cost and fail against a record that is
 * perfectly good — CONTRACT §23.4 rule 5.
 */
export interface OpaqueKsfFields {
  ksf: string;
  memory_kib?: number;
  iterations?: number;
  parallelism?: number;
  log_n?: number;
  r?: number;
  p?: number;
}

/** Accepted cost bands, matching `axiam_opaque::AxiamKsf` (§23.4 rule 4). */
const BOUNDS = {
  memory_kib: [8192, 1_048_576],
  iterations: [1, 10],
  parallelism: [1, 16],
  log_n: [14, 20],
  r: [1, 16],
  p: [1, 16],
} as const;

function requireInBand(name: keyof typeof BOUNDS, value: number | undefined, ksf: string): number {
  if (value === undefined) {
    throw new NetworkError(`OPAQUE: the server named ksf \`${ksf}\` without \`${name}\``);
  }
  const [min, max] = BOUNDS[name];
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new NetworkError(
      `OPAQUE: the server named ${name}=${value} for \`${ksf}\`, outside the accepted ${min}..${max}`,
    );
  }
  return value;
}

/**
 * Build the stretching function from what the **server** named.
 *
 * Never from local defaults, and never cached across exchanges: a credential
 * enrolled under one cost keeps working after a tenant raises its policy, so a
 * client that guessed would derive a different randomized password and fail
 * against a record that is perfectly good (§23.4 rule 2).
 *
 * An unrecognised function is refused, never substituted — substituting
 * produces a well-formed randomized password that no AXIAM server agrees with,
 * surfacing to the user as a wrong password (§23.4 rule 3). The refusal is a
 * `NetworkError`, deliberately not an `AuthError`, so it cannot be mistaken for
 * bad credentials.
 */
function buildKsf(mod: OpaqueModule, fields: OpaqueKsfFields) {
  switch (fields.ksf) {
    case 'argon2id':
      return mod.OpaqueKsf.argon2id(
        requireInBand('memory_kib', fields.memory_kib, fields.ksf),
        requireInBand('iterations', fields.iterations, fields.ksf),
        requireInBand('parallelism', fields.parallelism, fields.ksf),
      );
    case 'scrypt':
      return mod.OpaqueKsf.scrypt(
        requireInBand('log_n', fields.log_n, fields.ksf),
        requireInBand('r', fields.r, fields.ksf),
        requireInBand('p', fields.p, fields.ksf),
      );
    default:
      throw new NetworkError(
        `OPAQUE: this SDK cannot perform the key-stretching function the server named (\`${fields.ksf}\`)`,
      );
  }
}

/**
 * Raised when `@axiam/opaque-wasm` is not installed.
 *
 * A `NetworkError` subclass on purpose: §2 puts "this client cannot do the
 * thing" in the network/configuration bucket, never the credential one, so a
 * caller catching `NetworkError` falls back to password login without a special
 * case — while a caller that wants to tell "not installed" from "tenant has it
 * disabled" still can.
 */
export class OpaqueUnavailableError extends NetworkError {
  constructor() {
    super('OPAQUE is not available: install the optional peer dependency `@axiam/opaque-wasm`');
    this.name = 'OpaqueUnavailableError';
    // Re-set AFTER `super`, which pins the prototype to `NetworkError.prototype`
    // to survive transpilation to ES5. That is correct for `NetworkError` and
    // wrong for anything extending it: without this line
    // `err instanceof OpaqueUnavailableError` is false for an error that
    // demonstrably is one, and the distinction this class exists to draw
    // silently disappears.
    Object.setPrototypeOf(this, OpaqueUnavailableError.prototype);
  }
}

async function requireModule(): Promise<OpaqueModule> {
  const mod = await loadModule();
  if (mod === null) throw new OpaqueUnavailableError();
  return mod;
}

/** One in-flight registration. */
export interface RegistrationExchange {
  readonly request: string;
  finish(registrationResponse: string, ksf: OpaqueKsfFields): string;
}

/** Begin an enrolment. The returned `request` goes to `register/start`. */
export async function startRegistration(password: string): Promise<RegistrationExchange> {
  const mod = await requireModule();
  const state = new mod.OpaqueRegistration(password);
  return {
    request: state.request,
    finish(registrationResponse, ksfFields) {
      return state.finish(password, registrationResponse, buildKsf(mod, ksfFields)).record;
    },
  };
}

/** One in-flight login. */
export interface LoginExchange {
  readonly ke1: string;
  finish(ke2: string, ksf: OpaqueKsfFields): string;
}

/** Begin a login. The returned `ke1` goes to `login/start`. */
export async function startLogin(password: string): Promise<LoginExchange> {
  const mod = await requireModule();
  const state = new mod.OpaqueLogin(password);
  return {
    ke1: state.ke1,
    finish(ke2, ksfFields) {
      return state.finish(password, ke2, buildKsf(mod, ksfFields)).ke3;
    },
  };
}
