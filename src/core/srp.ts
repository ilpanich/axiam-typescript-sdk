// SRP-6a client — CONTRACT.md §23.
//
// Protocol only: no HTTP, no client, no session. That half has to agree
// byte-for-byte with ten other language implementations, and keeping it free of
// transport is what lets it be checked directly against the vendored
// `srp-test-vectors.json` with no server and no mock.
//
// ## What SRP buys, and what it does not
//
// The password never leaves this process. What crosses the wire is `A` and a
// proof, neither of which is useful to anyone who does not already hold the
// account's verifier — so a TLS-terminating proxy, an accidentally verbose
// request log, or a heap dump on the server can no longer capture a plaintext
// password, because the server never has one.
//
// It does **not** protect against a compromised AXIAM server, and in a browser
// it does not protect against AXIAM serving malicious JavaScript. Neither this
// file's documentation nor the README may claim otherwise.
//
// ## Runtime requirements
//
// `globalThis.crypto` (WebCrypto) for SHA-256, PBKDF2 and randomness — present
// in Node 18+, Deno, Bun and every browser. Argon2id comes from `hash-wasm`,
// which is a real dependency rather than optional: §23.3 rule 4 makes both KDFs
// mandatory, and `argon2id` is what AXIAM's default policy asks for.

import { NetworkError } from './errors.js';

// ─── Groups (RFC 5054 Appendix A) ────────────────────────────────────────────
//
// Embedded as constants and never taken from the server. A server-supplied
// modulus is a server-supplied trapdoor: a hostile server could hand over a
// group whose discrete logarithm it knows and recover `x` — and therefore the
// password — from the exchange. §23.4 makes embedding these mandatory.
//
// A transcription slip here is a silent, total break: client and server would
// still agree with each other while the hardness assumption the protocol rests
// on quietly vanished, and a round-trip test could not catch it because both
// sides share the same wrong value. `srp.test.ts` therefore asserts each
// modulus is the advertised width, prime, a safe prime, and that `g` generates
// the large subgroup.

const GROUPS = {
  rfc5054_2048: {
    N:
      'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050' +
      'A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50' +
      'E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8' +
      '55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B' +
      'CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748' +
      '544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6' +
      'AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6' +
      '94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73',
    g: 2n,
    byteLen: 256,
  },
  rfc5054_3072: {
    N:
      'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' +
      '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
      '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
      'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
      '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' +
      '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
      'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
      '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33' +
      'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
      'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' +
      'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2' +
      '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',
    g: 5n,
    byteLen: 384,
  },
  rfc5054_4096: {
    N:
      'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' +
      '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
      '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
      'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
      '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' +
      '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
      'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
      '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33' +
      'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
      'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' +
      'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2' +
      '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7' +
      '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8' +
      'DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
      '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9' +
      '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF',
    g: 5n,
    byteLen: 512,
  },
} as const;

/** A group name as it appears in a challenge response. */
export type SrpGroupName = keyof typeof GROUPS;

/** Whether `name` is a group this SDK implements. */
export function isKnownGroup(name: string): name is SrpGroupName {
  return Object.prototype.hasOwnProperty.call(GROUPS, name);
}

/**
 * Parse a group name from a challenge response.
 *
 * An unrecognised name is refused rather than guessed at (§23.4): the
 * alternative is computing in a group whose safety this SDK has not verified.
 * `NetworkError` rather than `AuthError` per §23.3 rule 4 — this is a
 * client-side capability gap, and calling it an authentication failure would
 * send a user off to reset a password that works.
 */
export function parseGroup(name: string): SrpGroupName {
  if (!isKnownGroup(name)) {
    throw new NetworkError(`this SDK does not implement the SRP group this tenant requires (${name})`);
  }
  return name;
}

// ─── Encoding ────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new NetworkError('SRP: expected hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt('0x' + bytesToHex(bytes));
}

/**
 * `PAD(x)`: big-endian bytes, left-padded with zeros to the group width.
 *
 * Every hash input in SRP-6a is padded to the modulus width. Skipping it is
 * *the* SRP interop bug — two implementations agree until a value happens to
 * carry a leading zero byte, and then roughly one login in 256 fails in a way
 * that reads as a flaky network rather than a defect. The vendored vectors are
 * built with a leading-zero salt and `x` specifically to catch it.
 */
function pad(value: bigint, byteLen: number): Uint8Array {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const raw = hexToBytes(hex);
  if (raw.length >= byteLen) return raw;
  const out = new Uint8Array(byteLen);
  out.set(raw, byteLen - raw.length);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Bytes as an `ArrayBuffer` WebCrypto will accept (never a SharedArrayBuffer). */
function buf(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', buf(concat(parts))));
}

/** Modular exponentiation. `BigInt` has no `modPow`, so square-and-multiply. */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

const utf8 = new TextEncoder();

// ─── KDF ─────────────────────────────────────────────────────────────────────

/** KDF parameters as they arrive in a challenge response. */
export interface SrpKdfParams {
  kdf: string;
  iterations: number;
  memoryKib?: number;
  parallelism?: number;
}

/**
 * Derive the SRP private key `x` from the password.
 *
 * `x = KDF(identity ":" password, salt)` (§23.3 rule 3) — a memory-hard KDF
 * rather than RFC 5054's bare hash, because a bare-hash verifier would be
 * *cheaper* to attack offline than the Argon2id hashes AXIAM already stores,
 * making adoption a net regression at rest.
 *
 * `identity` MUST be the value from the challenge response, never what the user
 * typed (§23.3 rule 2): a user may sign in with a username *or* an email while
 * only one of the two is bound into `x`.
 *
 * An unknown KDF is refused, never substituted (§23.3 rule 4). Substituting
 * derives a different `x` and surfaces as "invalid password" — the single most
 * misleading failure this code could produce.
 *
 * **This is deliberately slow.** Argon2id at AXIAM's defaults allocates 19 MiB
 * and takes tens to hundreds of milliseconds. That cost is what makes a stolen
 * verifier expensive to attack; in a browser, consider a Web Worker.
 */
export async function deriveX(
  identity: string,
  password: string,
  saltHex: string,
  params: SrpKdfParams,
): Promise<Uint8Array> {
  const salt = hexToBytes(saltHex);
  const secret = utf8.encode(`${identity}:${password}`);

  if (params.kdf === 'argon2id') {
    // Imported lazily so a consumer who never calls SRP does not pay the wasm
    // payload at module-load time.
    const { argon2id } = await import('hash-wasm');
    const hex = await argon2id({
      password: secret,
      salt,
      parallelism: params.parallelism ?? 1,
      iterations: params.iterations,
      memorySize: params.memoryKib ?? 19456,
      hashLength: 32,
      outputType: 'hex',
    });
    return hexToBytes(hex);
  }

  if (params.kdf === 'pbkdf2_sha256') {
    const key = await globalThis.crypto.subtle.importKey('raw', buf(secret), 'PBKDF2', false, ['deriveBits']);
    const bits = await globalThis.crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: buf(salt), iterations: params.iterations },
      key,
      256,
    );
    return new Uint8Array(bits);
  }

  throw new NetworkError(
    `this SDK cannot perform the key-derivation function this tenant requires (${params.kdf})`,
  );
}

// ─── Protocol ────────────────────────────────────────────────────────────────

/** `k = H(N | PAD(g))` — depends only on the group. */
async function multiplier(group: (typeof GROUPS)[SrpGroupName]): Promise<bigint> {
  const N = BigInt('0x' + group.N);
  return bytesToBigInt(await sha256([pad(N, group.byteLen), pad(group.g, group.byteLen)]));
}

/**
 * Compute the verifier `v = g^x mod N` for enrolment.
 *
 * This is the only value derived from the password that the server ever
 * receives, and it is computationally infeasible to invert.
 */
export async function computeVerifier(group: SrpGroupName, x: Uint8Array): Promise<string> {
  const params = GROUPS[group];
  const N = BigInt('0x' + params.N);
  return bytesToHex(pad(modPow(params.g, bytesToBigInt(x) % N, N), params.byteLen));
}

/** The two proofs a finished exchange produces. */
export interface SrpClientProofs {
  /** `M1`, lowercase hex — send this to `/auth/srp/verify`. */
  clientProof: string;
  /**
   * The `M2` the server must return.
   *
   * A caller MUST compare the server's `server_proof` against this and discard
   * the session on mismatch (§23.3 rule 6). Skipping it keeps the half of SRP
   * that authenticates the client to the server and throws away the half that
   * authenticates the server to the client — leaving an endpoint that never
   * knew the verifier indistinguishable from the real one.
   */
  expectedServerProof: string;
}

/** An SRP exchange in progress. */
export interface SrpClientSession {
  /** `A = g^a mod N`, lowercase hex — send with the challenge request. */
  readonly clientPublic: string;
  finish(args: {
    identity: string;
    saltHex: string;
    serverPublicHex: string;
    x: Uint8Array;
  }): Promise<SrpClientProofs>;
}

/**
 * Start an exchange: pick a fresh `a` and compute `A = g^a mod N`.
 *
 * `a` is 256 bits from the platform CSPRNG, fresh per exchange (§23.3 rule 7).
 * Reusing it would leak the relationship between two session secrets, which is
 * why there is no way to supply one.
 */
export async function beginClientSession(group: SrpGroupName): Promise<SrpClientSession> {
  return beginWithEphemeral(group, (bytes) => globalThis.crypto.getRandomValues(bytes));
}

/**
 * Conformance seam: build a session with a caller-chosen `a`.
 *
 * §23.7 requires reproducing the shared vectors, and a vector pins `a` so the
 * exchange is deterministic. Without this, a conformance test would have to
 * reimplement `finish` — testing a copy of the code rather than the code.
 *
 * @internal Never call this from application code. Reusing `a` across
 * exchanges is a real weakness, which is why `beginClientSession` offers no
 * way to do it.
 */
export async function __beginWithFixedEphemeral(
  group: SrpGroupName,
  aPrivHex: string,
): Promise<SrpClientSession> {
  const fixed = hexToBytes(aPrivHex);
  return beginWithEphemeral(group, (bytes) => {
    bytes.set(fixed.subarray(0, bytes.length));
    return bytes;
  });
}

async function beginWithEphemeral(
  groupName: SrpGroupName,
  fill: (bytes: Uint8Array) => Uint8Array,
): Promise<SrpClientSession> {
  const group = GROUPS[groupName];
  const N = BigInt('0x' + group.N);

  const aBytes = fill(new Uint8Array(32));
  const a = bytesToBigInt(aBytes);
  const A = modPow(group.g, a, N);

  return {
    clientPublic: bytesToHex(pad(A, group.byteLen)),

    async finish({ identity, saltHex, serverPublicHex, x }) {
      const B = BigInt('0x' + serverPublicHex);
      // B ≡ 0 (mod N) means a broken or hostile server, not a wrong password
      // (§23.3 rule 5). Refuse before doing any work with it.
      if (B % N === 0n) {
        throw new NetworkError('SRP: the server returned an invalid public value (B ≡ 0 mod N)');
      }

      const k = await multiplier(group);
      const xInt = bytesToBigInt(x) % N;
      const salt = hexToBytes(saltHex);

      const u = bytesToBigInt(await sha256([pad(A, group.byteLen), pad(B, group.byteLen)]));
      if (u === 0n) {
        throw new NetworkError('SRP: the server returned an invalid scrambling parameter (u = 0)');
      }

      // S = (B - k*g^x)^(a + u*x) mod N. `+ N` before the subtraction: k*g^x
      // can exceed B, and JavaScript's `%` does not normalise a negative
      // BigInt the way the protocol needs.
      const kgx = (k * modPow(group.g, xInt, N)) % N;
      const base = ((B % N) + N - kgx) % N;
      const S = modPow(base, a + u * xInt, N);
      const K = await sha256([pad(S, group.byteLen)]);

      const hN = await sha256([pad(N, group.byteLen)]);
      const hg = await sha256([pad(group.g, group.byteLen)]);
      const xored = new Uint8Array(32);
      for (let i = 0; i < 32; i++) xored[i] = hN[i]! ^ hg[i]!;
      const hI = await sha256([utf8.encode(identity)]);

      const M1 = await sha256([xored, hI, salt, pad(A, group.byteLen), pad(B, group.byteLen), K]);
      const M2 = await sha256([pad(A, group.byteLen), M1, K]);

      return { clientProof: bytesToHex(M1), expectedServerProof: bytesToHex(M2) };
    },
  };
}

/**
 * Constant-time comparison of the server's proof against the expected one.
 *
 * `M2` is not a secret the client guards, so constant-time here is
 * belt-and-braces — but it costs nothing and keeps the habit intact where it
 * does matter.
 */
export function verifyServerProof(expected: string, actual: string | undefined): boolean {
  if (!actual || expected.length !== actual.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ actual.charCodeAt(i);
  return diff === 0;
}

/** Generate a fresh 32-byte salt for enrolment, as lowercase hex (§23.3 rule 11). */
export function generateSalt(): string {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

/** @internal Test seam for `srp.test.ts`. */
export const __testing = { pad, sha256, modPow, bytesToHex, hexToBytes, multiplier, GROUPS };
