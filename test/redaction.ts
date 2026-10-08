// Shared helpers for the contract 1.53–1.58 redaction tests.
//
// Every secret these tests use is generated at run time (no credential, key or
// token literal in the repository), and a failing assertion never prints the
// secret, a fragment of it, or the rendering that may contain it: the failure
// message is fixed text plus an offset (CodeQL "cleartext logging").

import { randomBytes, randomUUID } from 'node:crypto';
import { inspect } from 'node:util';
import { expect } from 'vitest';

/** A fresh random secret, 43 base64url characters like the server's tokens. */
export function freshSecret(): string {
  return randomBytes(32).toString('base64url');
}

/** A fresh UUID. */
export function freshId(): string {
  return randomUUID();
}

/**
 * Assert that `haystack` contains no 8-character substring of `secret`.
 *
 * On failure the message names only the offset into the secret — never the
 * fragment or the haystack.
 */
export function assertNoFragment(haystack: string, secret: string, label = 'rendering'): void {
  for (let i = 0; i + 8 <= secret.length; i += 1) {
    const found = haystack.includes(secret.slice(i, i + 8));
    expect(found, `${label}: an 8-character fragment of the secret (offset ${i}) was found`).toBe(false);
  }
}

/** Every stringification sink a caller is likely to log: String(), JSON.stringify, util.inspect. */
export function renderings(value: unknown): string {
  let json: string;
  try {
    json = JSON.stringify(value) ?? '';
  } catch {
    json = '';
  }
  const asString = (() => {
    try {
      return String(value);
    } catch {
      return '';
    }
  })();
  return [asString, json, inspect(value, { depth: 10, showHidden: false }), inspect(value, { depth: 10, compact: false })].join('\n');
}

/** Renderings of an error, including its `cause` chain and own properties. */
export function errorRenderings(err: unknown): string {
  const e = err as Error & { cause?: unknown };
  return [
    String(e?.message ?? ''),
    String(e),
    String(e?.stack ?? ''),
    inspect(err, { depth: 10, showHidden: true }),
    renderings(e?.cause),
  ].join('\n');
}
