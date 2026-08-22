// WebAuthn wire types (CONTRACT.md §24.1).
//
// These mirror `crates/axiam-api-rest/src/handlers/webauthn.rs` and, through
// it, `webauthn-rs-proto`'s JSON serialization — which is the standard
// WebAuthn Level 3 "JSON form" every browser and platform API also speaks.
//
// Declared here rather than pulled from `@simplewebauthn/types` on purpose.
// §24.0 says the SDK passes the server's options through untouched, so what it
// needs from these declarations is a *shape to carry*, not a model to
// manipulate — and a dependency whose version drifts from the server's is a
// way to acquire opinions about fields nobody should be adjusting. Every
// buffer below is a base64url string, unpadded, exactly as it arrives.

/** A reference to one credential, in the WebAuthn JSON form. */
export interface WebauthnCredentialDescriptorJson {
  /** The credential id, base64url. */
  id: string;
  /** Always `"public-key"` today. Forwarded rather than checked. */
  type: string;
  /** Transports the authenticator advertised (`"usb"`, `"internal"`, …), when known. */
  transports?: string[];
}

/**
 * `PublicKeyCredentialCreationOptions` in its JSON form — the server's
 * registration challenge.
 *
 * Every field is the server's choice and none of them is this SDK's to adjust
 * (§24.0).
 */
export interface WebauthnCreationOptionsJson {
  /** The challenge to sign, base64url. */
  challenge: string;
  /** The relying party this credential is scoped to. */
  rp: {
    /** The RP id — an effective domain. Absent means "this origin's domain". */
    id?: string;
    /** Human-readable RP name, shown by some authenticators. */
    name: string;
  };
  /** The account the credential is being enrolled for. */
  user: {
    /** Opaque user handle, base64url. Not the username, and not an email. */
    id: string;
    /** The account name the authenticator shows in a credential picker. */
    name: string;
    /** The friendly name shown alongside it. */
    displayName: string;
  };
  /** Signature algorithms the server accepts, in its order of preference. */
  pubKeyCredParams: Array<{
    /** Always `"public-key"`. */
    type: string;
    /** A COSE algorithm identifier (`-7` for ES256, `-8` for EdDSA, …). */
    alg: number;
  }>;
  /** Milliseconds the ceremony may take. Absent means the server chose not to set one. */
  timeout?: number;
  /**
   * Credentials this account already has.
   *
   * The authenticator refuses rather than silently minting a second one for
   * the same account — which surfaces as `already_registered`, not a failure.
   */
  excludeCredentials?: WebauthnCredentialDescriptorJson[];
  /** Constraints on which authenticator may answer. All of them are policy. */
  authenticatorSelection?: {
    /** `"platform"` or `"cross-platform"`. The one field §24.6 rule 4 lets a caller supply. */
    authenticatorAttachment?: string;
    /** `"required"`, `"preferred"` or `"discouraged"` — whether the credential is discoverable. */
    residentKey?: string;
    /** The pre-Level-2 spelling of `residentKey: "required"`. */
    requireResidentKey?: boolean;
    /** `"required"`, `"preferred"` or `"discouraged"` — whether the user must be verified. */
    userVerification?: string;
  };
  /** Attestation conveyance: `"none"`, `"indirect"`, `"direct"` or `"enterprise"`. */
  attestation?: string;
  /** Extension inputs the server asked for. Forwarded verbatim. */
  extensions?: Record<string, unknown>;
  /** WebAuthn Level 3 UI hints, when the server sends them. */
  hints?: string[];
}

/**
 * `PublicKeyCredentialRequestOptions` in its JSON form — the server's
 * authentication challenge.
 */
export interface WebauthnRequestOptionsJson {
  /** The challenge to sign, base64url. */
  challenge: string;
  /** Milliseconds the ceremony may take. */
  timeout?: number;
  /** The relying party id the credential must be scoped to. */
  rpId?: string;
  /**
   * Which credentials may answer.
   *
   * Empty or absent for a discoverable ceremony — which is the point of one:
   * the authenticator offers whatever it holds and the assertion identifies
   * the user.
   */
  allowCredentials?: WebauthnCredentialDescriptorJson[];
  /** `"required"`, `"preferred"` or `"discouraged"`. */
  userVerification?: string;
  /** Extension inputs the server asked for. Forwarded verbatim. */
  extensions?: Record<string, unknown>;
  /** WebAuthn Level 3 UI hints, when the server sends them. */
  hints?: string[];
}

/**
 * The registration challenge, exactly as the server sent it.
 *
 * Hand this to the authenticator **unchanged** (§24.0). The one addition this
 * SDK permits is `authenticatorSelection.authenticatorAttachment`, and only
 * from an explicit caller argument — see §24.6 rule 4.
 */
export interface WebauthnCreationChallenge {
  /** The options, in the one-key wrapper `navigator.credentials.create()` also takes. */
  publicKey: WebauthnCreationOptionsJson;
}

/** The authentication challenge, exactly as the server sent it. */
export interface WebauthnRequestChallenge {
  /** The options, in the one-key wrapper `navigator.credentials.get()` also takes. */
  publicKey: WebauthnRequestOptionsJson;
}

/**
 * The authenticator's answer to a registration challenge.
 *
 * This is `RegistrationResponseJSON` as every WebAuthn client library and
 * platform API produces it. It goes back to the server byte-for-byte: it is
 * the input to a signature check over bytes this SDK did not produce, and
 * re-encoding base64url "to be safe" is the most common way to break a
 * ceremony that was otherwise correct (§24.0 rule 3).
 */
export interface WebauthnRegistrationResponse {
  /** The credential id, base64url. */
  id: string;
  /** The same id as raw bytes, base64url. */
  rawId: string;
  /** The attestation the authenticator produced. */
  response: {
    /** The signed client data, base64url. */
    clientDataJSON: string;
    /** The CBOR attestation object, base64url. */
    attestationObject: string;
    /** Transports the authenticator reported, when it reported any. */
    transports?: string[];
    /** Anything else the platform included. Carried through untouched. */
    [extra: string]: unknown;
  };
  /** Always `"public-key"`. */
  type: string;
  /** Which kind of authenticator answered, when the platform says. */
  authenticatorAttachment?: string;
  /** Extension outputs, forwarded verbatim. */
  clientExtensionResults?: Record<string, unknown>;
  /** Anything else the platform included. Carried through untouched. */
  [extra: string]: unknown;
}

/** The authenticator's answer to an authentication challenge. */
export interface WebauthnAuthenticationResponse {
  /** The credential id, base64url. */
  id: string;
  /** The same id as raw bytes, base64url. */
  rawId: string;
  /** The assertion the authenticator produced. */
  response: {
    /** The signed client data, base64url. */
    clientDataJSON: string;
    /** The authenticator data that was signed, base64url. */
    authenticatorData: string;
    /** The signature over `authenticatorData || SHA-256(clientDataJSON)`, base64url. */
    signature: string;
    /** The user handle, present on a discoverable credential — this is what names the user. */
    userHandle?: string | null;
    /** Anything else the platform included. Carried through untouched. */
    [extra: string]: unknown;
  };
  /** Always `"public-key"`. */
  type: string;
  /** Which kind of authenticator answered, when the platform says. */
  authenticatorAttachment?: string;
  /** Extension outputs, forwarded verbatim. */
  clientExtensionResults?: Record<string, unknown>;
  /** Anything else the platform included. Carried through untouched. */
  [extra: string]: unknown;
}

/** A credential the user has enrolled — the `201` body of `register/finish`. */
export interface WebauthnCredential {
  /** The AXIAM record id (UUID). */
  id: string;
  /** base64url credential id, as the authenticator reported it. */
  credentialId: string;
  /** The caller-supplied label. */
  name: string;
  /** `"passkey"` or `"security_key"`, as the server classified it. */
  credentialType: string;
  /** RFC 3339 timestamp of enrolment. */
  createdAt: string;
  /** RFC 3339 timestamp of the last successful assertion, if there has been one. */
  lastUsedAt?: string;
}

/**
 * The workspace a discoverable ceremony runs inside.
 *
 * Unlike the five tenant-scoped `/oauth2/*` operations of §12.1 rule 2, this
 * endpoint **accepts slugs**, so a slug-only client can run a usernameless
 * sign-in. The SDK fills these from its own configured identity when the
 * caller passes nothing.
 */
export interface WebauthnWorkspace {
  /** Organization UUID. */
  orgId?: string;
  /** Organization slug — accepted here, unlike on the `/oauth2/*` operations. */
  orgSlug?: string;
  /** Tenant UUID. */
  tenantId?: string;
  /** Tenant slug. */
  tenantSlug?: string;
}
