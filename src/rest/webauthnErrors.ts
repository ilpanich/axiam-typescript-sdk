// Ceremony failure classification (CONTRACT.md §24.6b rule 5).
//
// Isomorphic on purpose. §24.6b rule 5's closing paragraph puts this in the
// core rather than beside the linked-API helper: an Android app catching a
// `CreateCredentialException`, or a Node service handed an error string by the
// handset that ran the ceremony, has the same five outcomes and the same reason
// to want one vocabulary for them. Nothing here touches the DOM — it reads the
// error's `name`, which is the only machine-readable part any platform gives.

/**
 * A ceremony failure a caller can say something useful about.
 *
 * Five outcomes, and the interesting ones are the first two.
 */
export type WebauthnFailure =
  | 'cancelled'
  | 'already_registered'
  | 'timeout'
  | 'unsupported'
  | 'unknown';

/**
 * Map a platform ceremony error to its canonical classification (§24.6b rule 5).
 *
 * Accepts anything: a browser `DOMException`, an Android
 * `CreateCredentialException` name relayed as a string, an
 * `ASAuthorizationError` code relayed by name. Everything unrecognized is
 * `unknown` rather than a throw — a classifier that can fail is one more thing
 * for an error handler to handle.
 */
export function classifyWebauthnError(err: unknown): WebauthnFailure {
  const name = errorName(err);
  switch (name) {
    // NotAllowedError covers BOTH an explicit refusal and a silent timeout.
    // The spec deliberately refuses to distinguish them, because telling a
    // website which one happened leaks whether an authenticator was present.
    // "cancelled" is therefore the honest label for both — and it must not be
    // recovered by timing the call.
    case 'NotAllowedError':
    case 'canceled':
    case 'cancelled':
      return 'cancelled';
    // The authenticator already holds a credential for this account: the
    // server sent it in `excludeCredentials` and the authenticator refused to
    // silently mint a second. That is the exclusion list working, not a
    // failure — and it is the only classification whose remedy is "use a
    // different device" rather than "try again".
    case 'InvalidStateError':
      return 'already_registered';
    case 'AbortError':
    case 'timeout':
      return 'timeout';
    case 'NotSupportedError':
    case 'SecurityError':
      return 'unsupported';
    default:
      return 'unknown';
  }
}

/**
 * Copy for each failure, safe to show a user.
 *
 * The `cancelled` string deliberately does not accuse anyone of cancelling: the
 * same classification covers a silent timeout, and the spec will not say which
 * happened.
 */
export function webauthnErrorMessage(failure: WebauthnFailure): string {
  switch (failure) {
    case 'cancelled':
      return 'The request was cancelled or timed out. You can try again.';
    case 'already_registered':
      return 'This device is already registered on your account. Try a different device, or remove the existing one first.';
    case 'timeout':
      return 'The request timed out before it completed. Please try again.';
    case 'unsupported':
      return 'This browser or device cannot be used for passkeys. Try a different browser, or use another sign-in method.';
    case 'unknown':
      return 'Something went wrong. Please try again.';
  }
}

/** The platform's own error name, however it arrived. */
function errorName(err: unknown): string | undefined {
  if (typeof err === 'string') return err;
  if (typeof err !== 'object' || err === null) return undefined;
  const name = (err as { name?: unknown }).name;
  return typeof name === 'string' ? name : undefined;
}
