// AMQP transport security (CONTRACT.md §8b).
//
// HMAC signing (§8) gives authenticity and replay protection. It does not give
// confidentiality: a signed `AuthzRequest` still names a subject, a resource
// and an action in cleartext on the wire, and a signed reactor reply is still
// an instruction to change a token. TLS gives confidentiality; HMAC gives
// end-to-end authenticity across broker hops, which TLS cannot, because TLS
// terminates at the broker and the broker then re-sends. §8b's framing is
// exact: both are required, and neither substitutes for the other.
//
// This module is the one place in the SDK that turns a broker URL and some
// optional PEM material into arguments for `amqplib.connect`. Both AMQP entry
// points — `consume()` (§8) and `reactorServe()` (§22) — go through it, so
// there is a single answer to "what does this SDK accept as a broker URL"
// rather than one answer per call site.
//
// # Why this file exists at all
//
// It is a fix, not a feature. Both entry points previously called
// `amqp.connect(url)` with no scheme check and no TLS options, while their own
// doc comments stated that the URL "must be `amqps://` (§8b) — there is no
// verification-skip switch and no plaintext fallback". Every word of that was
// true of the intent and none of it was true of the code: a plaintext
// `amqp://` URL connected without complaint, and a privately-issued broker
// certificate — the common case for an in-cluster broker, and the whole reason
// §8b rule 2 is a MUST — could not be trusted at all, because there was no way
// to supply a CA bundle. Documented-but-unenforced is the worst of the three
// states: it reads as a guarantee at review time and behaves as an invitation
// at runtime.

import type { ConnectionOptions as TlsConnectionOptions } from 'node:tls';
import { NetworkError } from '../core/errors.js';
import { resolveClientIdentity } from '../core/config.js';

const PEM_CERT_MARKER = '-----BEGIN CERTIFICATE-----';

/**
 * TLS material for an `amqps://` broker connection (§8b).
 *
 * Every field is optional: with none set, an `amqps://` URL still connects and
 * still verifies, against Node's bundled root store. The fields exist for the
 * two cases that store cannot serve — a privately-issued broker certificate,
 * and mutual TLS toward the broker.
 *
 * # There is deliberately no verification-skip option
 *
 * Not as an omission to be filled in later. §8b rule 4 forbids surfacing one
 * under any name, and the reasoning is that such a switch is the single most
 * reliably misused option in TLS: it appears in a dev compose file, it works,
 * and it travels unchanged into production, where it turns TLS into an
 * expensive no-op against precisely the attacker TLS exists to stop.
 * {@link caCert} covers the legitimate reason people reach for it (rule 2)
 * without covering the rest.
 *
 * This paragraph names no concrete bypass flag, and that is not squeamishness:
 * CI greps `src/` for the literal disabling forms and fails the build on a hit.
 * A comment explaining why the SDK does not do the thing would trip the same
 * grep as code doing it — the check cannot tell prose from an assignment — so
 * the prose stays abstract and the check stays blunt. Both are better that way.
 *
 * `amqplib` would happily accept `rejectUnauthorized` in its socket options,
 * which is exactly why {@link buildAmqpConnectOptions} constructs that object
 * itself from these three fields rather than accepting a caller-supplied one.
 */
export interface AmqpTlsOptions {
  /**
   * PEM bundle of the CA(s) that issued the broker's certificate (§8b rule 2).
   *
   * Unset = verify against Node's bundled roots. Set this when the broker
   * certificate comes from a private CA — including one issued by AXIAM's own
   * organization CA, which is the recommended dogfooding path.
   *
   * Unlike the server's own `AXIAM__AMQP__TLS__CA_CERT_PATH`, this **replaces**
   * the trust set rather than adding to it: Node's `tls.connect` treats `ca` as
   * the complete root list. Supplying your broker's CA here therefore does
   * narrow trust to it, which is usually what someone setting this actually
   * wants.
   */
  readonly caCert?: string;
  /**
   * PEM client certificate chain, for mutual TLS toward the broker (§8b
   * rule 3).
   *
   * Must be supplied together with {@link clientKey}. Half a client identity is
   * never what anyone meant, and connecting anyway would silently drop the
   * mutual half of mutual TLS — so it is rejected before dialling.
   */
  readonly clientCert?: string;
  /** PEM private key matching {@link clientCert}. Secret material (§7). */
  readonly clientKey?: string;
}

/**
 * Reject any broker URL that is not `amqps://` (§8b rules 1 and 5).
 *
 * A plaintext URL is refused here rather than downgraded, and there is no
 * fallback path for it to take — rule 5 exists because a fallback that works
 * is a fallback that gets used, and the failure it produces is invisible
 * exactly when it matters.
 *
 * The `://` separator is load-bearing: matching on `amqps` alone would let a
 * hypothetical `amqpsomething://` through.
 *
 * @throws {NetworkError} when `url` is not an `amqps://` URL.
 */
export function assertAmqpsUrl(url: string, what = 'AMQP URL'): void {
  if (!url.trim().toLowerCase().startsWith('amqps://')) {
    throw new NetworkError(
      `${what} must use amqps:// (CONTRACT.md §8b rules 1 and 5) — got ` +
        `${JSON.stringify(url)}. Broker traffic carries authorization requests, ` +
        'audit events and reactor replies across a trust boundary; HMAC signing ' +
        'gives them authenticity and replay protection, not confidentiality. ' +
        'There is no plaintext fallback and no verification-skip switch — supply ' +
        "a private broker CA with `caCert` if the broker's certificate is not " +
        'publicly issued.',
    );
  }
}

/**
 * Validate `url` and build the socket options `amqplib.connect` should dial
 * with (§8b).
 *
 * `amqplib` forwards its second argument to `tls.connect` for an `amqps://`
 * URL, so the returned object is a `tls.ConnectionOptions` carrying at most
 * `ca`, `cert` and `key`. It never carries `rejectUnauthorized`, which leaves
 * Node's strict default (`true`) in force — see {@link AmqpTlsOptions}.
 *
 * The certificate/key pairing is validated by `resolveClientIdentity`, the same
 * §6.1 helper the REST and gRPC transports use, so mutual TLS is validated
 * identically on every transport this SDK speaks rather than once per protocol.
 *
 * @throws {NetworkError} when `url` is not `amqps://`.
 * @throws {Error} when the TLS material is internally inconsistent (a client
 *   certificate without its key, or PEM that is not PEM).
 */
export function buildAmqpConnectOptions(
  url: string,
  tls: AmqpTlsOptions = {},
  what = 'AMQP URL',
): TlsConnectionOptions | undefined {
  assertAmqpsUrl(url, what);

  if (tls.caCert !== undefined && !tls.caCert.includes(PEM_CERT_MARKER)) {
    throw new Error(
      `caCert must be a PEM-encoded certificate (expected to contain ` +
        `"${PEM_CERT_MARKER}") (CONTRACT.md §8b rule 2).`,
    );
  }

  // Reuses §6.1's all-or-nothing check and PEM validation rather than
  // re-implementing it: an SDK that validated a client identity two different
  // ways would eventually validate it two different amounts.
  const identity = resolveClientIdentity({
    clientCert: tls.clientCert,
    clientKey: tls.clientKey,
  });

  if (tls.caCert === undefined && identity === undefined) {
    // Nothing to configure. `undefined` lets amqplib use its own defaults,
    // which for an amqps:// URL means Node's bundled roots with verification
    // on — the correct behaviour for a publicly-issued broker certificate, and
    // the reason `caCert` is optional rather than required.
    return undefined;
  }

  return {
    ...(tls.caCert !== undefined ? { ca: tls.caCert } : {}),
    ...(identity !== undefined
      ? { cert: identity.cert, key: identity.key.expose() }
      : {}),
  };
}
