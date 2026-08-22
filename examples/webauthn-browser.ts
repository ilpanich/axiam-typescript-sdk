// Passkeys in a browser — CONTRACT.md §24.
//
// Three flows, in the order an application meets them:
//
//   1. Enrol a passkey for a signed-in user.
//   2. Sign in with a passkey as a SECOND factor, after a password login said
//      `mfa_required`.
//   3. Sign in with a passkey and NO username at all (a discoverable
//      credential), including passkey autofill.
//
// The SDK never touches WebAuthn crypto. The server generates the challenge,
// chooses `residentKey`/`userVerification`/attestation/exclusions, and verifies
// the result; this code carries the options to the authenticator unchanged and
// posts the answer back unchanged (§24.0). The one thing it adds is an
// `authenticatorAttachment` hint, and only because the caller asked for it.

import { AxiamClient } from 'axiam-sdk/rest';
import {
  classifyWebauthnError,
  isConditionalMediationAvailable,
  isWebauthnSupported,
  webauthnDiscoverableLogin,
  webauthnErrorMessage,
  webauthnLogin,
  webauthnRegister,
  type AuthenticatorKind,
} from 'axiam-sdk/browser';

const client = new AxiamClient({
  baseUrl: 'https://iam.example.com',
  orgSlug: 'globex',
  tenantSlug: 'acme',
});

// ---------------------------------------------------------------------------
// 1. Enrol a passkey (the user is already signed in)
// ---------------------------------------------------------------------------

async function enrol(name: string, kind: AuthenticatorKind): Promise<void> {
  // A query, not a try/catch: hide the button rather than offer one that
  // throws (§24.6b rule 6).
  if (!isWebauthnSupported()) return;

  try {
    const credential = await webauthnRegister(client, name, kind);
    console.log(`enrolled ${credential.credentialType} "${credential.name}"`);
  } catch (err) {
    const failure = classifyWebauthnError(err);
    // `already_registered` is the one worth separating: the authenticator
    // already holds a credential for this account and refused to mint a
    // second, so the remedy is a different device rather than another try.
    console.warn(failure, webauthnErrorMessage(failure));
  }
}

// ---------------------------------------------------------------------------
// 2. Passkey as a second factor
// ---------------------------------------------------------------------------

async function signInWithPassword(email: string, password: string): Promise<void> {
  const result = await client.login(email, password);

  switch (result.status) {
    case 'authenticated':
      return;

    case 'mfa_required':
      if (result.availableMethods.includes('webauthn') && isWebauthnSupported()) {
        // Leaves the client authenticated — §24.3 rule 1 is not "MAY adopt".
        await webauthnLogin(client, result.mfaToken);
        return;
      }
      // …otherwise fall back to TOTP with client.verifyMfa(...).
      return;

    case 'mfa_setup_required':
      // §25.2 rule 1: the tenant requires MFA and this account has none. An
      // outcome, not an error — see examples/account-lifecycle.ts.
      console.log('enrolment required before sign-in can complete');
      return;
  }
}

// ---------------------------------------------------------------------------
// 3. Usernameless sign-in, with and without autofill
// ---------------------------------------------------------------------------

/** The explicit "Sign in with a passkey" button. */
async function signInWithPasskey(): Promise<void> {
  // The workspace comes from the client's own configuration. A discoverable
  // credential is still resolved inside one tenant, and this endpoint accepts
  // slugs, so a slug-configured client can run the ceremony.
  const session = await webauthnDiscoverableLogin(client);
  console.log(`signed in, session ${session.sessionId}`);
}

/**
 * Passkey autofill: the browser offers saved passkeys from inside the username
 * field instead of behind a button.
 *
 * Everything about this degrades quietly. The promise may never settle — the
 * user simply may not pick a passkey — so the ceremony is abandoned on
 * navigation and a failure is never shown: an error banner for a prompt the
 * user never engaged with is noise (§24.6b rule 3).
 */
async function startPasskeyAutofill(): Promise<AbortController | undefined> {
  if (!(await isConditionalMediationAvailable())) return undefined;

  const controller = new AbortController();
  void webauthnDiscoverableLogin(client, undefined, {
    conditional: true,
    signal: controller.signal,
  })
    .then((session) => console.log(`autofill signed in, session ${session.sessionId}`))
    .catch(() => {
      /* abandoned, not failed */
    });
  return controller;
}

export { enrol, signInWithPassword, signInWithPasskey, startPasskeyAutofill };
