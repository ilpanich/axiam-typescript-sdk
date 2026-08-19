/**
 * CONTRACT.md §23 — SRP-6a login, with the password-login fallback.
 *
 *   AXIAM_URL=https://axiam.example \
 *   AXIAM_ORG=acme AXIAM_TENANT=default \
 *   AXIAM_USER=alice AXIAM_PASSWORD='…' \
 *     npx tsx examples/srp-login.ts
 *
 * What is worth reading here is the ordering and the error handling, not the
 * happy path: SRP is attempted first so a tenant on `srp_mode: optional`
 * actually gets SRP logins, and the two failure modes that are not "wrong
 * password" are handled distinctly.
 */

import { AxiamClient } from 'axiam-sdk';

const client = new AxiamClient({
  baseUrl: process.env.AXIAM_URL!,
  orgSlug: process.env.AXIAM_ORG!,
  tenantSlug: process.env.AXIAM_TENANT!,
});

const user = process.env.AXIAM_USER!;
const password = process.env.AXIAM_PASSWORD!;

let result;
try {
  // SRP first, password second. The reverse order — password login, SRP only
  // when refused — would mean a tenant running `srp_mode: optional` never sees
  // a single SRP login, which is the mode operators run for the whole of a
  // migration.
  console.log('attempting SRP (the pause is the KDF, and it is the point)…');
  result = await client.loginSrp(user, password);
  console.log('signed in over SRP — the password never left this process');
} catch (err) {
  const message = err instanceof Error ? err.message : String(err);

  if (message.includes('does not offer Secure Remote Password')) {
    // A property of the tenant, not of the credentials — and reported as
    // NetworkError rather than AuthError precisely so it cannot be mistaken
    // for a bad password.
    console.log('tenant has SRP disabled — falling back to password login');
    result = await client.login(user, password);
  } else if (message.includes('failed to prove')) {
    // The endpoint that answered could not prove it holds this account's
    // verifier, so it is not the server it claims to be. Do NOT retry over the
    // password path: that hands the same endpoint the plaintext it just failed
    // to prove it deserves.
    console.error(`ABORTED: ${message}`);
    console.error('Not retrying with a password — this endpoint does not hold the verifier.');
    process.exit(1);
  } else {
    throw err;
  }
}

if (result.status === 'mfa_required') {
  console.log(`MFA required (${result.availableMethods.join(', ')})`);
  const code = process.env.AXIAM_MFA_CODE;
  if (!code) {
    console.error('set AXIAM_MFA_CODE to finish');
    process.exit(1);
  }
  result = await client.verifyMfa(result.mfaToken, code);
}

if (result.status === 'authenticated') {
  console.log(`signed in as ${result.user.username}, session ${result.sessionId}`);
}

// ── Enrolment ───────────────────────────────────────────────────────────────
//
// The server cannot compute a verifier — it never sees the plaintext — so one
// has to be sent with any request that sets a password. The tenant's group and
// KDF come from GET /api/v1/auth/me for an authenticated caller, or from
// GET /api/v1/auth/reset/context for a reset-token holder.

const enrollment = await client.srpEnrollment({
  // The USERNAME, always. `x` is derived over `username ":" password`; a user
  // may sign in with their email, but only the username is inside the KDF, so
  // enrolling against an email produces a verifier no login can satisfy.
  identity: user,
  password: 'the new password',
  group: 'rfc5054_4096',
  kdf: 'argon2id',
});
console.log('verifier ready to send as the request\'s `srp` field:', {
  group: enrollment.group,
  kdf: enrollment.kdf,
  salt: enrollment.salt.slice(0, 16) + '…',
});

await client.logout();
