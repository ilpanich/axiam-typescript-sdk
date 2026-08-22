// AXIAM SDK — browser entry (`axiam-sdk/browser`).
//
// The WebAuthn platform ceremony (CONTRACT.md §24.6), and nothing else. It is
// a separate subpath so the isomorphic `/rest` core stays DOM-free: a Node
// consumer gets the §24.1 relying-party layer — which works perfectly well
// there — and simply does not have these symbols, which is §24.7's "absent
// rather than throwing" expressed as a module boundary.

export {
  isWebauthnSupported,
  isConditionalMediationAvailable,
  classifyWebauthnError,
  webauthnErrorMessage,
  webauthnRegister,
  webauthnLogin,
  webauthnDiscoverableLogin,
} from './webauthn.js';
export type { AuthenticatorKind, WebauthnCeremonyOptions, WebauthnFailure } from './webauthn.js';
export { base64UrlToBytes, bytesToBase64Url } from './base64url.js';
