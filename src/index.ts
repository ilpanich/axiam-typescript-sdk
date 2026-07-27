// AXIAM SDK for TypeScript/JavaScript — root entry.
//
// Per D-01, the root `.` entry is the isomorphic REST core (browser-safe),
// identical to the `/rest` subpath. `axiam-sdk/grpc` and `axiam-sdk/amqp`
// are Node-only opt-in subpaths that augment the same AxiamClient.
//
// See CONTRACT.md §1–§12 for the cross-language behavioral contract.
// This SDK conforms to CONTRACT.md §1–§12 — the §12 OIDC/SSO relying-party
// helpers live on the Node-only `axiam-sdk/node` subpath (they need
// node:crypto + jose, so they must stay out of the browser-safe core).

export * from './rest/index.js';
