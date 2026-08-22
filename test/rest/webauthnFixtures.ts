// Shared WebAuthn fixtures (CONTRACT.md §24.8).
//
// The creation challenge is deliberately "unusual but valid": every optional
// field populated, `userVerification: "required"`, a non-empty
// `excludeCredentials`, an `attestation` conveyance other than "none", a
// `timeout`, and a `pubKeyCredParams` entry (RS256) the SDK has no opinion
// about. §24.8's pass-through test is worthless against a minimal fixture —
// there is nothing there for an over-eager implementation to drop.

import type {
  WebauthnAuthenticationResponse,
  WebauthnCreationChallenge,
  WebauthnRegistrationResponse,
  WebauthnRequestChallenge,
} from '../../src/rest/index.js';

export const STATE_TOKEN = 'state-token-fixture-value-do-not-log';
export const CHALLENGE_TOKEN = 'challenge-token-fixture-value-do-not-log';
export const ACCESS_TOKEN = 'access-token-fixture-value-do-not-log';
export const REFRESH_TOKEN = 'refresh-token-fixture-value-do-not-log';

export const CREATION_CHALLENGE: WebauthnCreationChallenge = {
  publicKey: {
    challenge: 'Y2hhbGxlbmdlLWJ5dGVzLTAxMjM0NTY3ODk',
    rp: { id: 'axiam.test', name: 'AXIAM Test' },
    user: {
      id: 'dXNlci1oYW5kbGUtYnl0ZXM',
      name: 'alice@example.com',
      displayName: 'Alice Example',
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -8 },
      // The SDK has no opinion about RS256 and must not develop one.
      { type: 'public-key', alg: -257 },
    ],
    timeout: 60_000,
    excludeCredentials: [
      { id: 'ZXhpc3RpbmctY3JlZGVudGlhbC1pZA', type: 'public-key', transports: ['usb', 'nfc'] },
    ],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    },
    attestation: 'direct',
    extensions: { credProps: true },
    hints: ['security-key'],
  },
};

/** No `authenticatorSelection`, no `timeout` — §24.8's "no synthesized fields" case. */
export const MINIMAL_CREATION_CHALLENGE: WebauthnCreationChallenge = {
  publicKey: {
    challenge: 'bWluaW1hbC1jaGFsbGVuZ2U',
    rp: { name: 'AXIAM Test' },
    user: { id: 'dQ', name: 'bob', displayName: 'Bob' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  },
};

export const REQUEST_CHALLENGE: WebauthnRequestChallenge = {
  publicKey: {
    challenge: 'YXV0aC1jaGFsbGVuZ2UtYnl0ZXM',
    timeout: 60_000,
    rpId: 'axiam.test',
    allowCredentials: [{ id: 'ZXhpc3RpbmctY3JlZGVudGlhbC1pZA', type: 'public-key' }],
    userVerification: 'required',
  },
};

/** A discoverable challenge: `allowCredentials` empty, which is the point of one. */
export const DISCOVERABLE_CHALLENGE: WebauthnRequestChallenge = {
  publicKey: {
    challenge: 'ZGlzY292ZXJhYmxlLWNoYWxsZW5nZQ',
    timeout: 60_000,
    rpId: 'axiam.test',
    allowCredentials: [],
    userVerification: 'required',
  },
};

/**
 * A fixed authenticator answer.
 *
 * `clientDataJSON` deliberately ends in a base64url character set that would
 * change if anything re-encoded it, and `vendorSpecific` is an unknown key the
 * SDK must carry rather than strip.
 */
export const REGISTRATION_RESPONSE: WebauthnRegistrationResponse = {
  id: 'bmV3LWNyZWRlbnRpYWwtaWQ',
  rawId: 'bmV3LWNyZWRlbnRpYWwtaWQ',
  response: {
    clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
    attestationObject: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YQ',
    transports: ['internal', 'hybrid'],
    vendorSpecific: 'must-survive',
  },
  type: 'public-key',
  authenticatorAttachment: 'platform',
  clientExtensionResults: { credProps: { rk: true } },
};

export const AUTHENTICATION_RESPONSE: WebauthnAuthenticationResponse = {
  id: 'bmV3LWNyZWRlbnRpYWwtaWQ',
  rawId: 'bmV3LWNyZWRlbnRpYWwtaWQ',
  response: {
    clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0',
    authenticatorData: 'YXV0aGVudGljYXRvci1kYXRh',
    signature: 'c2lnbmF0dXJl',
    userHandle: 'dXNlci1oYW5kbGUtYnl0ZXM',
  },
  type: 'public-key',
  clientExtensionResults: {},
};

export const CREDENTIAL_WIRE = {
  id: '11111111-1111-1111-1111-111111111111',
  credential_id: 'bmV3LWNyZWRlbnRpYWwtaWQ',
  name: 'Alice’s laptop',
  credential_type: 'passkey',
  created_at: '2026-08-22T10:00:00Z',
  last_used_at: null,
};

export const LOGIN_WIRE = {
  access_token: ACCESS_TOKEN,
  refresh_token: REFRESH_TOKEN,
  session_id: '22222222-2222-2222-2222-222222222222',
  expires_in: 900,
};
