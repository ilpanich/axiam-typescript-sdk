// Sensitive<T> — token-redaction wrapper (CONTRACT.md §7, D-26).
//
// Redacts to '[SENSITIVE]' across all three JS stringification surfaces:
// toString(), JSON.stringify() (via toJSON), and Node's
// util.inspect/console.log (via the well-known Symbol.for('nodejs.util.inspect.custom')
// symbol). The symbol is referenced directly (not via `import { inspect } from
// 'node:util'`) so core never imports node:util and stays runtime-agnostic —
// the symbol lookup is a documented no-op in browsers, where this class is
// never constructed anyway (D-06: browser persona holds no tokens).
//
// The raw value is reachable only via `expose()`, documented @internal.

export const REDACTED = '[SENSITIVE]';

const NODE_INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom');

/**
 * A redaction wrapper for token and secret material (CONTRACT.md §7).
 *
 * @remarks
 * The wrapped value is held in a private class field, so it cannot be reached
 * through any public property. All three JavaScript stringification surfaces
 * redact it to `"[SENSITIVE]"`: `toString()`, `JSON.stringify()` and
 * `console.log`/`util.inspect`. The raw value is available only via the
 * documented-`@internal` `expose()` accessor, which SDK-internal code calls at
 * the point of handing the value to the transport.
 *
 * Every field CONTRACT.md §12.5 names — `access_token`, `refresh_token`,
 * `id_token`, `client_secret`, `code_verifier` — is wrapped in this class. By
 * contrast `state` and `nonce` are **not** secrets (§12.3 rule 2) and stay
 * plain strings.
 *
 * @example
 * ```ts
 * const tokens = await oidc.oidcExchange({ code, codeVerifier, nonce, redirectUri });
 * console.log(tokens.accessToken);            // [SENSITIVE]
 * JSON.stringify(tokens);                     // {"accessToken":"[SENSITIVE]",…}
 * ```
 */
export class Sensitive<T> {
  readonly #value: T;

  /** Wrap `value` so it can never be logged or serialized by accident. */
  constructor(value: T) {
    this.#value = value;
  }

  /** @internal package-only accessor. Never pass the return value to a log/serialize sink. */
  expose(): T {
    return this.#value;
  }

  /** Returns the `"[SENSITIVE]"` placeholder — never the wrapped value. */
  toString(): string {
    return REDACTED;
  }

  /** Makes `JSON.stringify()` emit the `"[SENSITIVE]"` placeholder. */
  toJSON(): string {
    return REDACTED;
  }

  /** Makes `console.log`/`util.inspect` print the `"[SENSITIVE]"` placeholder. */
  [NODE_INSPECT_CUSTOM](): string {
    return REDACTED;
  }
}
