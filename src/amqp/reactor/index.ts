// Reactors — AMQP extension actors (CONTRACT.md §22).
//
// A Reactor is an external process that subscribes to named hook events on the
// AMQP bus and answers back — allow, deny, or a field-allow-listed mutation —
// inside a timeout the server declared. It is AXIAM's answer to Zitadel Actions
// and Keycloak SPIs, and the difference is the whole design: those load
// third-party code INTO the authorization server, and this keeps it outside,
// reachable only through a signed reply schema the server validates before it
// believes a word of it.
//
// ## The rule this module does not paper over
//
// A reply is an instruction to change a token or refuse a login, so an unsigned
// reply is not a weak reply — IT IS NOT A REPLY AT ALL. Both directions are
// signed, with the same §8 v2 primitives and the same tenant subkey. This
// runtime verifies every event before user code sees it, and signs every reply
// before it leaves.
//
// ## Hot-path exclusion (§22.7 — normative MUST NOT)
//
// `authz.check`, `authz.check_batch` and `token.introspect` are NOT hookable,
// and nothing in this module presents them as such: they appear in no constant,
// no registry row and no example. A reactor round-trip is milliseconds; the
// check path's budget is microseconds. An application that needs external input
// on an authorization decision writes a DENY GRANT, which the engine evaluates
// in the hot path at hot-path cost. There is deliberately no client-side
// interceptor, middleware hook or callback in this SDK offering itself as the
// reactor equivalent for those operations.

export * from './registry.js';
export * from './protocol.js';
export * from './runtime.js';
export * from './handlers.js';
