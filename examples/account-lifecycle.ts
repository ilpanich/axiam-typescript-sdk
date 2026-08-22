// Account lifecycle and MFA enrolment — CONTRACT.md §25.
//
// The operations that get an account into the state §1's login/verifyMfa/
// refresh/logout already assume: email verification, both MFA enrolment paths,
// and password reset.

import { AxiamClient, Sensitive } from 'axiam-sdk/rest';

const client = new AxiamClient({
  baseUrl: 'https://iam.example.com',
  orgSlug: 'globex',
  tenantSlug: 'acme',
});

const TENANT_ID = '11111111-1111-1111-1111-111111111111';

// ---------------------------------------------------------------------------
// Voluntary MFA enrolment, by a signed-in user
// ---------------------------------------------------------------------------

/**
 * Two calls, and there is deliberately no one-call helper: the human step in
 * the middle — scanning the URI, reading a code off a phone — is not something
 * a composed helper can wait for, and one that returned after `mfaEnroll`
 * would report MFA as enabled when it is not (§25.2 rule 4).
 */
async function enrolTotp(readCodeFromUser: (uri: string) => Promise<string>): Promise<void> {
  const enrolment = await client.mfaEnroll();

  // `totpUri` CONTAINS the secret — it is `otpauth://…?secret=…`. Both are
  // Sensitive for that reason, and the URI is the one that actually reaches a
  // log, because it is the one you hand to a QR renderer (§25.3).
  const code = await readCodeFromUser(enrolment.totpUri.expose());

  const enabled = await client.mfaConfirm(code);
  console.log(enabled ? 'TOTP is now active' : 'TOTP is still inactive');
}

// ---------------------------------------------------------------------------
// Forced MFA enrolment, during login
// ---------------------------------------------------------------------------

/**
 * The tenant requires MFA and this account has none.
 *
 * The server answers `403` with a setup token. Before contract 1.28 every SDK
 * mapped that through §2 to `AuthzError` — telling the caller they lacked
 * permission to log in, when the server had said "finish setting up, here is
 * how". It is an outcome now (§25.2 rule 1), which is the whole reason this
 * function can be written at all.
 */
async function signIn(
  email: string,
  password: string,
  readCodeFromUser: (uri: string) => Promise<string>,
): Promise<void> {
  const result = await client.login(email, password);

  switch (result.status) {
    case 'authenticated':
      console.log(`signed in as ${result.user.username}`);
      return;

    case 'mfa_required':
      await client.verifyMfa(result.mfaToken, await readCodeFromUser(''));
      return;

    case 'mfa_setup_required': {
      const enrolment = await client.mfaSetupEnroll(result.setupToken);
      const code = await readCodeFromUser(enrolment.totpUri.expose());
      // This completes the login that was interrupted, and adopts credentials
      // exactly as `login()` would have (§25.2 rule 2).
      const done = await client.mfaSetupConfirm(result.setupToken, code);
      if (done.status === 'authenticated') {
        console.log(`enrolled and signed in as ${done.user.username}`);
      }
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

async function verifyEmail(tokenFromLink: string): Promise<void> {
  await client.verifyEmail(new Sensitive(tokenFromLink), TENANT_ID);
  console.log('email verified');
}

async function resendVerification(email: string): Promise<void> {
  await client.resendVerification(email, TENANT_ID);
}

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

/**
 * Ask for a reset mail.
 *
 * This resolves whether or not the address exists, and the SDK exposes no way
 * to tell the difference. That is the point: any signal distinguishing them —
 * including one inferred from timing — turns the endpoint into an account
 * enumeration oracle (§25.4).
 */
async function requestReset(email: string): Promise<void> {
  await client.requestPasswordReset({ email });
  console.log('if that address has an account, a reset mail is on its way');
}

/**
 * Set the new password.
 *
 * The context call is not optional on a tenant that might have OPAQUE enabled
 * (§23): the client has to build a registration record, and building one needs
 * parameters it cannot know before it has a token to ask with. Sending a
 * plaintext password to a tenant in `opaque_mode: required` is refused, and
 * refused late.
 */
async function confirmReset(tokenFromLink: string, newPassword: string): Promise<void> {
  const token = new Sensitive(tokenFromLink);
  const context = await client.passwordResetContext(token);

  const opaque = context.opaque
    ? ((await client.opaqueEnrollment(newPassword)) as unknown as Record<string, unknown>)
    : undefined;

  await client.confirmPasswordReset({
    token,
    newPassword: new Sensitive(newPassword),
    tenantId: TENANT_ID,
    ...(opaque ? { opaque } : {}),
  });
  console.log('password changed');
}

export { enrolTotp, signIn, verifyEmail, resendVerification, requestReset, confirmReset };
