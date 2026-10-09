// Shared helpers for the contract 1.53–1.58 redaction tests.
//
// Every secret these tests use is generated at run time (no credential, key or
// token literal in the repository), and a failing assertion never prints the
// secret, a fragment of it, or the rendering that may contain it: the failure
// message is fixed text plus an offset (CodeQL "cleartext logging").

import { randomBytes, randomUUID } from 'node:crypto';
import { Console } from 'node:console';
import { Writable } from 'node:stream';
import { format, inspect } from 'node:util';
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

/**
 * Every string reachable from `root` by reflection — own string and symbol
 * keys, enumerable or not, through objects, arrays, `Map`s, `Set`s and byte
 * buffers (decoded as UTF-8 and Latin-1) — plus every key name.
 *
 * This is what a determined logger (a `depth: Infinity, showHidden: true`
 * inspect, a structured-logging serializer that walks the error, a crash
 * reporter) can reach, so a secret absent from it is absent from every
 * rendering. Getters are not invoked: reading one can have side effects, and a
 * value only a getter computes is not stored on the error.
 */
export function reachableStrings(root: unknown, limit = 200_000): string {
  const out: string[] = [];
  const seen = new Set<unknown>();
  const stack: unknown[] = [root];
  while (stack.length > 0 && seen.size < limit) {
    const value = stack.pop();
    if (typeof value === 'string') {
      out.push(value);
      continue;
    }
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) continue;
    if (seen.has(value)) continue;
    seen.add(value);
    if (ArrayBuffer.isView(value)) {
      const bytes = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
      out.push(bytes.toString('utf8'), bytes.toString('latin1'));
      continue;
    }
    if (value instanceof ArrayBuffer) {
      const bytes = Buffer.from(value);
      out.push(bytes.toString('utf8'), bytes.toString('latin1'));
      continue;
    }
    if (value instanceof Map) {
      for (const [k, v] of value) stack.push(k, v);
    } else if (value instanceof Set) {
      for (const v of value) stack.push(v);
    }
    for (const key of Reflect.ownKeys(value)) {
      out.push(typeof key === 'symbol' ? String(key.description ?? '') : key);
      const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
      if (descriptor && 'value' in descriptor) stack.push(descriptor.value);
    }
  }
  return out.join('\n');
}

/**
 * Every way an application is likely to print or serialize a thrown error,
 * joined: `String`, `toString`, `message`, `stack`, `JSON.stringify` of the
 * error and of its `cause`, `util.inspect` at the default depth and at
 * unlimited depth with hidden members, `util.format`'s `%s`/`%o`/`%O`/`%j`,
 * what `console.log` and `console.error` actually write, and
 * {@link reachableStrings} over the error.
 */
export function exhaustiveErrorRenderings(err: unknown): string {
  const e = err as Error & { cause?: unknown };
  const safe = (fn: () => unknown): string => {
    try {
      const v = fn();
      return typeof v === 'string' ? v : String(v);
    } catch {
      return '';
    }
  };
  let logged = '';
  const sink = new Writable({
    write(chunk: Buffer | string, _enc, cb) {
      logged += chunk.toString();
      cb();
    },
  });
  const logger = new Console({ stdout: sink, stderr: sink, colorMode: false });
  logger.log(err);
  logger.error(err);
  logger.log('%o', err);
  logger.dir(err, { depth: null, showHidden: true });
  return [
    safe(() => String(err)),
    safe(() => e.toString()),
    safe(() => e.message),
    safe(() => e.stack),
    safe(() => JSON.stringify(err)),
    safe(() => JSON.stringify(e.cause)),
    safe(() => inspect(err)),
    safe(() => inspect(err, { depth: Infinity, showHidden: true, getters: false })),
    safe(() => inspect(e.cause, { depth: Infinity, showHidden: true })),
    safe(() => format('%s %o %O %j', err, err, err, err)),
    logged,
    reachableStrings(err),
  ].join('\n');
}
