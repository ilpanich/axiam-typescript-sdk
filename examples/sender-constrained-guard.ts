/**
 * Enforcing CONTRACT.md §10.1 rule 9 in a resource server — the full rule,
 * covering certificate-bound (RFC 8705) and DPoP-bound (RFC 9449) tokens.
 *
 * Run with:
 *
 * ```bash
 * npx tsx examples/sender-constrained-guard.ts
 * ```
 *
 * ## What rule 9 actually says
 *
 * A token carrying `cnf` is **not** a bearer token. Accepting one without
 * proving the caller holds the confirmed key converts it back into a bearer
 * token and discards the whole protection the operator turned on.
 *
 * Three cases are worth internalising, because they are the ones implemented
 * wrongly:
 *
 * 1. **An unbound token is still accepted** — no certificate, no proof. Rule 9
 *    is not "require evidence from everybody".
 * 2. **`cnf` naming both methods is a conjunction.** Two constraints means
 *    two; satisfying the more convenient one is not compliance.
 * 3. **A `cnf` this SDK cannot interpret is refused**, never read as
 *    unconstrained — including an *empty* one.
 *
 * ## Why this is a plain function, not an HTTPS server
 *
 * Rule 9 is about what you do with the token once the transport has told you
 * who the caller is, so the example takes that as an input rather than standing
 * up a server. Terminating TLS correctly is a separate job with its own
 * pitfalls — and an example that switched certificate validation off to keep
 * itself short would be teaching the wrong lesson in the middle of a security
 * guide. Wire `authorize` into Express, Fastify, Nest or a bare
 * `https.createServer` as you prefer.
 */
import {
  createVerifier,
  certificateThumbprintS256,
  verifyTokenBinding,
  verifyDpopProof,
  InMemoryJtiStore,
} from '../src/node/index.js';

// One store per process. InMemoryJtiStore is per-worker, so a deployment
// running more than one process needs a shared implementation (Redis, a
// database table) or each worker gets its own replay window.
const JTI_STORE = new InMemoryJtiStore();

const verifier = createVerifier(process.env.AXIAM_BASE_URL ?? 'https://axiam.example.com');

/** What the transport tells the guard about one request. */
interface IncomingRequest {
  /** The HTTP method, e.g. `'POST'`. */
  method: string;
  /** The absolute request URL, query string and all. */
  url: string;
  /** The raw `Authorization` header value. */
  authorization?: string | undefined;
  /**
   * The raw `DPoP` header value, when the caller sent one.
   *
   * This is the *proof*, not a thumbprint — it is verified below before
   * anything is believed about it.
   */
  dpop?: string | undefined;
  /**
   * The DER bytes of the peer's leaf certificate, from the TLS layer.
   *
   * Take this from the connection — under Node, `TLSSocket.getPeerCertificate().raw`
   * — or from a value a *trusted* terminating proxy forwarded over a channel
   * your application controls. **Never** from a caller-settable request header:
   * a forgeable input makes the whole mechanism decorative.
   */
  peerCertificateDer?: Uint8Array | undefined;
}

/**
 * Authorize one request, applying rules 1-9.
 *
 * @returns the authenticated subject
 * @throws {AuthError} if any rule rejects the request
 */
export async function authorize(req: IncomingRequest): Promise<string> {
  const token = (req.authorization ?? '').replace(/^(Bearer|DPoP) /i, '');

  // Rules 1-8: signature, expiry, issuer, audience. NOT rule 9 — this call has
  // no transport to ask, which is exactly why the binding check is separate
  // rather than something you can forget to opt into.
  const claims = await verifier.verifyAccessToken(token, {
    expectedTenantId: process.env.AXIAM_TENANT_ID,
  });

  const certificateThumbprint =
    req.peerCertificateDer !== undefined
      ? await certificateThumbprintS256(req.peerCertificateDer)
      : undefined;

  // All ten §21.7.2 checks. Returns the proof key's thumbprint, so the value
  // handed to rule 9 below could only have come from a proof that verified — a
  // thumbprint lifted off an *unverified* proof would let a proof captured from
  // any other endpoint authorize this one.
  const dpopThumbprint =
    req.dpop !== undefined
      ? await verifyDpopProof(req.dpop, {
          httpMethod: req.method,
          httpUri: req.url,
          accessToken: token,
          jtiStore: JTI_STORE,
        })
      : undefined;

  // Rule 9. Returns immediately for an unbound token, so adopting this does not
  // break existing deployments.
  verifyTokenBinding(claims, { certificateThumbprint, dpopThumbprint });

  return claims.sub;
}

// A worked call, with neither proof — the ordinary bearer case rule 9 leaves
// alone.
if (process.env.AXIAM_DEMO === '1') {
  authorize({
    method: 'GET',
    url: 'https://rs.example.com/v1/things',
    authorization: 'Bearer …the access token…',
  })
    .then((sub) => console.log(`subject ${sub} authorized`))
    .catch((err: unknown) => console.error(`refused: ${(err as Error).message}`));
}
