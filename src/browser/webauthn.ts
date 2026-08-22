// The WebAuthn platform ceremony (CONTRACT.md §24.6).
//
// This is the half of a passkey ceremony that talks to an *authenticator*, and
// the only half that needs a browser. It lives on its own subpath so the
// isomorphic `/rest` core stays free of DOM code: a Node consumer gets the
// §24.1 relying-party layer and nothing here, which is §24.7's posture for the
// Node build stated as a module boundary rather than as a runtime throw.
//
// ## What this module is allowed to change, which is almost nothing
//
// §24.0: the server picks every option and verifies every response, so the
// options reach `navigator.credentials` as the server sent them and the
// authenticator's answer goes back untouched. The two things that happen here
// look like exceptions and are not:
//
//   1. **base64url → ArrayBuffer.** The DOM API takes `BufferSource` where the
//      JSON form carries a base64url string. Those are the same bytes in the
//      representation each side demands, which is a transcription, not an
//      adjustment. Nothing is defaulted, dropped, reordered or re-derived —
//      the round-trip test asserts exactly that.
//   2. **`authenticatorAttachment`.** §24.6 rule 4's single permitted
//      addition, and only from an explicit caller argument. It selects which
//      authenticator the user is prompted for; it cannot weaken what the
//      server will accept. Without it, a user who asked for a security key is
//      prompted for the platform biometric instead.

import type {
  AxiamClient,
  WebauthnAuthenticationResponse,
  WebauthnCreationChallenge,
  WebauthnCreationOptionsJson,
  WebauthnCredential,
  WebauthnCredentialDescriptorJson,
  WebauthnLoginResult,
  WebauthnRegistrationResponse,
  WebauthnRequestChallenge,
  WebauthnRequestOptionsJson,
  WebauthnWorkspace,
} from '../rest/index.js';
import { base64UrlToBytes, bytesToBase64Url } from './base64url.js';

// §24.6b rule 5's classification lives in the isomorphic core, not here: an
// Android app catching a `CreateCredentialException` wants the same vocabulary,
// and it never loads this module. Re-exported so a browser consumer still finds
// it on the subpath it is already importing from.
export { classifyWebauthnError, webauthnErrorMessage } from '../rest/index.js';
export type { WebauthnFailure } from '../rest/index.js';

// ---------------------------------------------------------------------------
// Feature detection (§24.6 rule 6)
// ---------------------------------------------------------------------------

/**
 * Whether this runtime can perform a WebAuthn ceremony at all.
 *
 * A query, not an exception (§24.6 rule 6) — a caller hides the enrolment
 * button rather than offering one that throws. Answers `false` in Node, where
 * the §24.1 relying-party layer still works fine.
 */
export function isWebauthnSupported(): boolean {
  return (
    typeof globalThis !== 'undefined' &&
    typeof (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials?.get === 'function'
  );
}

/**
 * Whether this browser supports **conditional mediation** — passkey autofill,
 * where saved passkeys are offered from inside the username field rather than
 * behind a button.
 *
 * Returns `false` rather than throwing where the probe itself is missing
 * (§24.6 rule 3): conditional UI is a progressive enhancement, and its absence
 * must degrade to the explicit prompt, never to a broken sign-in page.
 */
export async function isConditionalMediationAvailable(): Promise<boolean> {
  if (!isWebauthnSupported()) return false;
  const ctor = (globalThis as { PublicKeyCredential?: { isConditionalMediationAvailable?: unknown } })
    .PublicKeyCredential;
  const probe = ctor?.isConditionalMediationAvailable;
  if (typeof probe !== 'function') return false;
  try {
    return await (probe as () => Promise<boolean>).call(ctor);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Composed helpers (§24.6 rule 1 — additive; the six wire ops stay public)
// ---------------------------------------------------------------------------

/**
 * Which kind of authenticator the user reached for.
 *
 * A hint only (§24.6 rule 4). `platform` is a passkey built into the device
 * (Touch ID, Windows Hello, a phone); `cross-platform` is a removable security
 * key.
 */
export type AuthenticatorKind = 'platform' | 'cross-platform';

/** Options shared by the two sign-in helpers. */
export interface WebauthnCeremonyOptions {
  /**
   * Use conditional mediation (passkey autofill) instead of a modal prompt.
   *
   * The returned promise may never settle — the user simply may not pick a
   * passkey — so a caller using this must be prepared to abandon it, and MUST
   * NOT surface an abandoned ceremony as an authentication failure (§24.6
   * rule 3). The browser aborts it when the page navigates.
   */
  conditional?: boolean;
  /** Abort the ceremony. Also how a conditional ceremony is abandoned. */
  signal?: AbortSignal;
}

/**
 * Enrol a passkey or security key for the signed-in user (§24.6).
 *
 * Runs the full ceremony: `register/start`, the authenticator, then
 * `register/finish`. The three steps stay individually callable on
 * `AxiamClient` — a caller driving a virtual authenticator in a test needs the
 * pair directly, which is why this helper is additive rather than the only way
 * in (§24.6 rule 1).
 *
 * @param kind optional `authenticatorAttachment` hint. Omitted entirely when
 *   not passed — the SDK never infers it and never defaults it.
 */
export async function webauthnRegister(
  client: AxiamClient,
  credentialName: string,
  kind?: AuthenticatorKind,
  options?: WebauthnCeremonyOptions,
): Promise<WebauthnCredential> {
  requireSupport('webauthnRegister');

  const { challenge, stateToken } = await client.webauthnRegisterStart();
  const credential = await createCredential(challenge, kind, options?.signal);
  return client.webauthnRegisterFinish(stateToken, credentialName, credential);
}

/**
 * Sign in with a passkey as a **second factor** (§24.6).
 *
 * `challengeToken` is the `mfaToken` from a `login()` that answered
 * `mfa_required` with `"webauthn"` among its methods.
 */
export async function webauthnLogin(
  client: AxiamClient,
  challengeToken: string,
  options?: WebauthnCeremonyOptions,
): Promise<WebauthnLoginResult> {
  requireSupport('webauthnLogin');

  const { challenge, stateToken } = await client.webauthnAuthenticateStart(challengeToken);
  const assertion = await getAssertion(challenge, options);
  return client.webauthnAuthenticateFinish(stateToken, assertion);
}

/**
 * Sign in with a passkey **without typing a username first** (§24.6).
 *
 * The workspace still has to be named — a discoverable credential is resolved
 * inside one tenant — but it comes from the client's own configuration unless
 * overridden, and slugs are accepted.
 */
export async function webauthnDiscoverableLogin(
  client: AxiamClient,
  workspace?: WebauthnWorkspace,
  options?: WebauthnCeremonyOptions,
): Promise<WebauthnLoginResult> {
  requireSupport('webauthnDiscoverableLogin');

  const { challenge, stateToken } = await client.webauthnDiscoverableStart(workspace);
  const assertion = await getAssertion(challenge, options);
  return client.webauthnDiscoverableFinish(stateToken, assertion);
}

// ---------------------------------------------------------------------------
// Ceremony internals
// ---------------------------------------------------------------------------

function requireSupport(operation: string): void {
  if (!isWebauthnSupported()) {
    throw new Error(
      `${operation}: this runtime has no WebAuthn authenticator. Check isWebauthnSupported() first, ` +
        'or use the relying-party operations on AxiamClient with a response produced elsewhere ' +
        '(CONTRACT.md §24.6).',
    );
  }
}

/** Run `navigator.credentials.create()` and return the JSON form of its answer. */
async function createCredential(
  challenge: WebauthnCreationChallenge,
  kind: AuthenticatorKind | undefined,
  signal: AbortSignal | undefined,
): Promise<WebauthnRegistrationResponse> {
  const credential = (await navigator.credentials.create({
    publicKey: toCreationOptions(challenge.publicKey, kind),
    ...(signal ? { signal } : {}),
  })) as PublicKeyCredential | null;

  if (!credential) {
    // Spec-wise unreachable — a rejection is how failure is reported — but a
    // `null` here would otherwise become a confusing property access.
    throw new Error('webauthnRegister: the authenticator returned no credential.');
  }

  const response = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof response.getTransports === 'function' ? response.getTransports() : undefined;

  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      attestationObject: bytesToBase64Url(response.attestationObject),
      ...(transports && transports.length > 0 ? { transports } : {}),
    },
    type: credential.type,
    ...(credential.authenticatorAttachment
      ? { authenticatorAttachment: credential.authenticatorAttachment }
      : {}),
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
  };
}

/** Run `navigator.credentials.get()` and return the JSON form of its answer. */
async function getAssertion(
  challenge: WebauthnRequestChallenge,
  options: WebauthnCeremonyOptions | undefined,
): Promise<WebauthnAuthenticationResponse> {
  const credential = (await navigator.credentials.get({
    publicKey: toRequestOptions(challenge.publicKey),
    ...(options?.conditional ? { mediation: 'conditional' as CredentialMediationRequirement } : {}),
    ...(options?.signal ? { signal: options.signal } : {}),
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error('webauthnLogin: the authenticator returned no assertion.');
  }

  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      signature: bytesToBase64Url(response.signature),
      ...(response.userHandle ? { userHandle: bytesToBase64Url(response.userHandle) } : {}),
    },
    type: credential.type,
    ...(credential.authenticatorAttachment
      ? { authenticatorAttachment: credential.authenticatorAttachment }
      : {}),
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
  };
}

/**
 * Transcribe the server's creation options into what the DOM API takes.
 *
 * Every optional field is forwarded **only if the server sent it** — §24.0
 * rule 1 forbids expanding an absent `authenticatorSelection` into an empty
 * object or supplying a `timeout` the server did not choose. The string enums
 * (`residentKey`, `userVerification`, `attestation`) are cast rather than
 * validated: §24.0 rule 2 says an SDK may fail to parse but must not refuse
 * options it parsed, and a client-side allow-list of acceptable values is a
 * second policy engine.
 */
function toCreationOptions(
  json: WebauthnCreationOptionsJson,
  kind: AuthenticatorKind | undefined,
): PublicKeyCredentialCreationOptions {
  const selection = json.authenticatorSelection;
  // The only place this module adds anything (§24.6 rule 4). When the caller
  // passed no kind and the server sent no selection, the key stays absent.
  const authenticatorSelection =
    selection || kind
      ? ({
          ...(selection?.residentKey ? { residentKey: selection.residentKey } : {}),
          ...(selection?.requireResidentKey !== undefined
            ? { requireResidentKey: selection.requireResidentKey }
            : {}),
          ...(selection?.userVerification
            ? { userVerification: selection.userVerification }
            : {}),
          ...(kind
            ? { authenticatorAttachment: kind }
            : selection?.authenticatorAttachment
              ? { authenticatorAttachment: selection.authenticatorAttachment }
              : {}),
        } as AuthenticatorSelectionCriteria)
      : undefined;

  return {
    challenge: base64UrlToBytes(json.challenge),
    rp: json.rp,
    user: {
      id: base64UrlToBytes(json.user.id),
      name: json.user.name,
      displayName: json.user.displayName,
    },
    pubKeyCredParams: json.pubKeyCredParams as PublicKeyCredentialParameters[],
    ...(json.timeout !== undefined ? { timeout: json.timeout } : {}),
    ...(json.excludeCredentials
      ? { excludeCredentials: json.excludeCredentials.map(toDescriptor) }
      : {}),
    ...(authenticatorSelection ? { authenticatorSelection } : {}),
    ...(json.attestation
      ? { attestation: json.attestation as AttestationConveyancePreference }
      : {}),
    ...(json.extensions
      ? { extensions: json.extensions as AuthenticationExtensionsClientInputs }
      : {}),
  };
}

/** The same transcription for an assertion challenge. */
function toRequestOptions(json: WebauthnRequestOptionsJson): PublicKeyCredentialRequestOptions {
  return {
    challenge: base64UrlToBytes(json.challenge),
    ...(json.timeout !== undefined ? { timeout: json.timeout } : {}),
    ...(json.rpId ? { rpId: json.rpId } : {}),
    ...(json.allowCredentials
      ? { allowCredentials: json.allowCredentials.map(toDescriptor) }
      : {}),
    ...(json.userVerification
      ? { userVerification: json.userVerification as UserVerificationRequirement }
      : {}),
    ...(json.extensions
      ? { extensions: json.extensions as AuthenticationExtensionsClientInputs }
      : {}),
  };
}

function toDescriptor(d: WebauthnCredentialDescriptorJson): PublicKeyCredentialDescriptor {
  return {
    id: base64UrlToBytes(d.id),
    type: d.type as PublicKeyCredentialType,
    ...(d.transports ? { transports: d.transports as AuthenticatorTransport[] } : {}),
  };
}
