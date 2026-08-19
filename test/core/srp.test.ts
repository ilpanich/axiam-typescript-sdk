// CONTRACT.md §23.7 conformance: replay the cross-language SRP vectors.
//
// `srp-test-vectors.json` is generated from the AXIAM server implementation and
// vendored into every SDK. Eleven independent SRP implementations do not
// interoperate by accident; this is the file that says whether this one does.
//
// §23.7 rule 1 requires every intermediate to be reproduced, not only the final
// proof — an SDK that gets `u` wrong should find out at `u` rather than at
// "login sometimes fails".

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import {
  __beginWithFixedEphemeral,
  __testing,
  beginClientSession,
  computeVerifier,
  deriveX,
  generateSalt,
  isKnownGroup,
  parseGroup,
  verifyServerProof,
  type SrpGroupName,
} from '../../src/core/srp.js';
import { NetworkError } from '../../src/core/errors.js';

const { pad, sha256, modPow, bytesToHex, hexToBytes, multiplier, GROUPS } = __testing;

interface Vector {
  group: string;
  identity: string;
  salt: string;
  x: string;
  k: string;
  verifier: string;
  a_priv: string;
  a_pub: string;
  b_priv: string;
  b_pub: string;
  u: string;
  session_secret: string;
  session_key: string;
  client_proof: string;
  server_proof: string;
}

const vectors: Vector[] = JSON.parse(
  readFileSync(new URL('../../srp-test-vectors.json', import.meta.url), 'utf8'),
).vectors;

function toBigInt(hex: string): bigint {
  return hex.length === 0 ? 0n : BigInt('0x' + hex);
}

/** Miller-Rabin with fixed bases — deterministic, and strong at these sizes. */
function isProbablePrime(n: bigint): boolean {
  const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
  if (n < 2n) return false;
  for (const p of bases) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let r = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    r += 1n;
  }
  for (const a of bases) {
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let passed = false;
    for (let i = 0n; i < r - 1n; i++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        passed = true;
        break;
      }
    }
    if (!passed) return false;
  }
  return true;
}

describe('§23.4 group constants', () => {
  // A transcription slip here is a silent, total break: client and server
  // would still agree with each other while the discrete-log hardness the
  // protocol rests on quietly vanished. A round-trip test cannot catch it,
  // because both sides share the same wrong constant.
  it.each(Object.keys(GROUPS))('%s is a safe prime of the advertised width', (name) => {
    const group = GROUPS[name as SrpGroupName];
    const N = toBigInt(group.N);
    expect(N.toString(2).length).toBe(group.byteLen * 8);
    expect(isProbablePrime(N)).toBe(true);
    expect(isProbablePrime((N - 1n) / 2n)).toBe(true);
    // g generates the order-q subgroup iff g^q == N-1 for a safe prime.
    expect(modPow(group.g, (N - 1n) / 2n, N)).toBe(N - 1n);
  });

  it('refuses an unrecognised group rather than guessing', () => {
    // Guessing would mean computing in a group whose safety this SDK has not
    // verified — potentially one whose discrete log the server knows.
    expect(isKnownGroup('rfc5054_1024')).toBe(false);
    expect(() => parseGroup('rfc5054_1024')).toThrow(NetworkError);
    // NetworkError, not AuthError: this is a client capability gap, and
    // calling it an auth failure would send a user to reset a working password.
    expect(() => parseGroup('rfc5054_1024')).toThrow(/does not implement/);
  });
});

describe('PAD()', () => {
  it('left-pads to the group width', () => {
    expect(bytesToHex(pad(1n, 4))).toBe('00000001');
  });

  it('leaves an already-wide value alone', () => {
    expect(bytesToHex(pad(0x0102n, 2))).toBe('0102');
  });
});

describe('§23.7 cross-language vectors', () => {
  it('the fixtures cover the cases they exist for', () => {
    // If these stop holding, everything below silently stops testing the two
    // things it was built to test.
    expect(vectors.length).toBeGreaterThan(0);
    expect(vectors.some((v) => v.salt.startsWith('00'))).toBe(true);
    expect(vectors.some((v) => v.x.startsWith('00'))).toBe(true);
    expect(vectors.some((v) => !/^[\x00-\x7F]*$/.test(v.identity))).toBe(true);
    for (const group of ['rfc5054_2048', 'rfc5054_3072', 'rfc5054_4096']) {
      expect(vectors.some((v) => v.group === group)).toBe(true);
    }
  });

  it.each(vectors.map((v) => [`${v.group}/${v.identity}`, v] as const))(
    '%s reproduces every intermediate',
    async (_label, v) => {
      const group = parseGroup(v.group);
      const params = GROUPS[group];
      const N = toBigInt(params.N);
      const x = toBigInt(v.x) % N;

      // k = H(N | PAD(g))
      expect(bytesToHex(pad(await multiplier(params), 32))).toBe(v.k);

      // v = g^x mod N
      expect(await computeVerifier(group, hexToBytes(v.x))).toBe(v.verifier);

      // A = g^a mod N, B = (k*v + g^b) mod N
      const a = toBigInt(v.a_priv);
      const b = toBigInt(v.b_priv);
      const A = modPow(params.g, a, N);
      expect(bytesToHex(pad(A, params.byteLen))).toBe(v.a_pub);

      const k = await multiplier(params);
      const B = (k * modPow(params.g, x, N) + modPow(params.g, b, N)) % N;
      expect(bytesToHex(pad(B, params.byteLen))).toBe(v.b_pub);

      // u = H(PAD(A) | PAD(B))
      const u = toBigInt(bytesToHex(await sha256([pad(A, params.byteLen), pad(B, params.byteLen)])));
      expect(bytesToHex(pad(u, 32))).toBe(v.u);

      // S and K, from the client's derivation.
      const kgx = (k * modPow(params.g, x, N)) % N;
      const base = ((B % N) + N - kgx) % N;
      const S = modPow(base, a + u * x, N);
      expect(bytesToHex(pad(S, params.byteLen))).toBe(v.session_secret);
      expect(bytesToHex(await sha256([pad(S, params.byteLen)]))).toBe(v.session_key);
    },
  );

  it.each(vectors.map((v) => [`${v.group}/${v.identity}`, v] as const))(
    '%s produces the contract M1 and M2 through the public API',
    async (_label, v) => {
      // Drives the real session rather than the helpers, with `a` pinned to the
      // vector's value — otherwise this only tests the internals.
      const session = await __beginWithFixedEphemeral(parseGroup(v.group), v.a_priv);
      expect(session.clientPublic).toBe(v.a_pub);

      const proofs = await session.finish({
        identity: v.identity,
        saltHex: v.salt,
        serverPublicHex: v.b_pub,
        x: hexToBytes(v.x),
      });
      expect(proofs.clientProof).toBe(v.client_proof);
      expect(proofs.expectedServerProof).toBe(v.server_proof);
    },
  );
});

describe('§23.3 protocol refusals', () => {
  it('refuses a server public value congruent to zero', async () => {
    // The classic SRP break. A client that accepts B ≡ 0 derives a predictable
    // S and would authenticate against a server that never knew the verifier.
    const session = await beginClientSession('rfc5054_2048');
    await expect(
      session.finish({
        identity: 'alice',
        saltHex: '00'.repeat(32),
        serverPublicHex: '0'.repeat(512),
        x: new Uint8Array(32).fill(1),
      }),
    ).rejects.toThrow(/invalid public value/i);
  });

  it('uses a fresh client ephemeral for every exchange', async () => {
    const first = await beginClientSession('rfc5054_2048');
    const second = await beginClientSession('rfc5054_2048');
    expect(first.clientPublic).not.toBe(second.clientPublic);
  });

  it('refuses an unknown KDF rather than substituting the other one', async () => {
    // Substituting derives a different x and surfaces as "invalid password" —
    // the single most misleading failure this code could produce.
    await expect(deriveX('alice', 'pw', '00'.repeat(32), { kdf: 'scrypt', iterations: 1 })).rejects.toThrow(
      NetworkError,
    );
    await expect(deriveX('alice', 'pw', '00'.repeat(32), { kdf: 'scrypt', iterations: 1 })).rejects.toThrow(
      /scrypt/,
    );
  });
});

describe('KDF', () => {
  it('binds identity, password and salt', async () => {
    // Every one of these must change the output, or a verifier would be
    // replayable against a different account or a different salt.
    const params = { kdf: 'pbkdf2_sha256', iterations: 1000 };
    const salt = 'ab'.repeat(32);
    const base = await deriveX('alice', 'pw', salt, params);
    expect(base.length).toBe(32);
    expect(bytesToHex(await deriveX('alice', 'pw', salt, params))).toBe(bytesToHex(base));
    expect(bytesToHex(await deriveX('bob', 'pw', salt, params))).not.toBe(bytesToHex(base));
    expect(bytesToHex(await deriveX('alice', 'pw2', salt, params))).not.toBe(bytesToHex(base));
    expect(bytesToHex(await deriveX('alice', 'pw', 'cd'.repeat(32), params))).not.toBe(bytesToHex(base));
  });

  it('runs argon2id, the default the server asks for', async () => {
    // Low memory so the test stays fast; the code path is identical to the
    // 19 MiB production parameters.
    const x = await deriveX('alice', 'pw', 'ab'.repeat(32), {
      kdf: 'argon2id',
      iterations: 1,
      memoryKib: 8192,
      parallelism: 1,
    });
    expect(x.length).toBe(32);
  });
});

describe('§23.3 rule 6 — server proof', () => {
  it('accepts a match and rejects everything else', () => {
    const proof = vectors[0]!.server_proof;
    expect(verifyServerProof(proof, proof)).toBe(true);
    expect(verifyServerProof(proof, proof.slice(0, -1) + (proof.endsWith('a') ? 'b' : 'a'))).toBe(false);
    expect(verifyServerProof(proof, proof.slice(0, 32))).toBe(false);
    expect(verifyServerProof(proof, '')).toBe(false);
    expect(verifyServerProof(proof, undefined)).toBe(false);
  });
});

describe('enrolment', () => {
  it('generates a fresh 32-byte salt each time', () => {
    // A reused salt would make every verifier in a tenant equally attackable
    // with one precomputation.
    const first = generateSalt();
    const second = generateSalt();
    expect(first).toHaveLength(64);
    expect(first).not.toBe(second);
  });
});
