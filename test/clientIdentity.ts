// A real, throwaway client identity (self-signed P-256 cert + PKCS#8 key) for
// tests that configure clientCert/clientKey but never complete a handshake.
//
// Marker-only placeholders stopped being enough with msw 3: it intercepts at
// the socket layer, below the https.Agent, so the agent really builds a TLS
// secure context and OpenSSL must be able to parse both PEMs. As in
// test/node/mtls.test.ts, the material is generated at run time by shelling
// out to `openssl` into an OS temp dir; nothing is committed.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface ClientIdentity {
  cert: string;
  key: string;
}

let cached: ClientIdentity | undefined;

/** Generated once per test file (vitest isolates modules per file) and reused. */
export function testClientIdentity(): ClientIdentity {
  if (cached) return cached;
  const dir = mkdtempSync(join(tmpdir(), 'axiam-client-identity-'));
  try {
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
        '-keyout', 'client.key', '-out', 'client.crt', '-days', '2', '-subj', '/CN=axiam-test-client'],
      { cwd: dir, stdio: 'pipe' },
    );
    cached = {
      cert: readFileSync(join(dir, 'client.crt'), 'utf8'),
      key: readFileSync(join(dir, 'client.key'), 'utf8'),
    };
    return cached;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
