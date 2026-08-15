// AXIAM SDK — AMQP entry (`axiam-sdk/amqp`), Node-only opt-in subpath.
//
// Re-exports the HMAC sign/verify pair, server-identical message DTOs, and
// the verify-before-handler `consume()` function (D-12, CONTRACT.md §8).
// `Sensitive` is re-exported here too — `consume()`'s public signature
// requires callers to construct a `Sensitive<Buffer>` signing key, so this
// entry point must expose the class itself rather than forcing consumers
// to reach into `axiam-sdk`'s root/`rest` entry just to wrap a key.

export { Sensitive } from '../core/index.js';
export * from './hmac.js';
export * from './messages.js';
export * from './consumer.js';
// CONTRACT.md §22 reactor runtime. The same §8 HMAC, now in BOTH directions —
// the server signs the hook event, the reactor signs the allow/deny/mutate
// reply — with one canonicalization difference (`hmac_signature` is serialized
// as `null` inside a reactor body, not omitted) that the §22.13 vectors pin.
export * from './reactor/index.js';
