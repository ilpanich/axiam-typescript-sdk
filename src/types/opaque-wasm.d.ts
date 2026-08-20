/**
 * Ambient declaration for `@axiam/opaque-wasm`, the WebAssembly build of
 * AXIAM's OPAQUE (RFC 9807) client.
 *
 * Declared rather than imported for its types because the package is an
 * OPTIONAL peer dependency: an installation that never calls the OPAQUE path
 * should not be forced to carry a WebAssembly module, and `tsc` must still
 * typecheck a checkout where it is absent.
 *
 * The shape mirrors `crates/axiam-opaque-wasm/src/lib.rs` in the AXIAM
 * repository. If that changes, this must change with it; there is no generator
 * keeping them in step, which is the cost of not vendoring the artifact. The
 * cross-repo drift gate covers the Rust source, not this declaration.
 */
declare module '@axiam/opaque-wasm' {
  /** Instantiate the module. Must be awaited before anything else. */
  export default function init(): Promise<unknown>;

  /** True when the module instantiated. See CONTRACT §23.2. */
  export function opaqueAvailable(): boolean;

  /** Key-stretching parameters, as named by the server. */
  export class OpaqueKsf {
    static argon2id(memoryKib: number, iterations: number, parallelism: number): OpaqueKsf;
    static scrypt(logN: number, r: number, p: number): OpaqueKsf;
  }

  export class OpaqueRegistrationResult {
    readonly record: string;
    readonly exportKey: string;
  }

  export class OpaqueRegistration {
    constructor(password: string);
    readonly request: string;
    /** Consumes this object. */
    finish(
      password: string,
      registrationResponse: string,
      ksf: OpaqueKsf,
    ): OpaqueRegistrationResult;
  }

  export class OpaqueLoginResult {
    readonly ke3: string;
    readonly sessionKey: string;
    readonly exportKey: string;
  }

  export class OpaqueLogin {
    constructor(password: string);
    readonly ke1: string;
    /** Consumes this object. */
    finish(password: string, ke2: string, ksf: OpaqueKsf): OpaqueLoginResult;
  }
}
