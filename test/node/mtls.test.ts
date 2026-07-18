// §6.1 mutual-TLS end-to-end (Node only): a real TLS socket, so msw (which
// intercepts at the fetch/XHR layer) cannot cover this. We stand up a Node
// https server that REQUIRES a client certificate (requestCert +
// rejectUnauthorized) and prove that:
//   - an AxiamClient configured with customCa (server trust) + clientCert/
//     clientKey (client identity) completes a request (200), and
//   - the same client WITHOUT a client certificate fails the handshake and
//     the failure is mapped to NetworkError (§2).
//
// The test PKI is generated at run time by shelling out to `openssl` into an
// OS temp dir; nothing is committed. This file is Node-only (default vitest
// environment: node) — it require()s node:https / node:child_process directly.

import { execFileSync } from 'node:child_process';
import { createServer, type Server } from 'node:https';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AxiamClient } from '../../src/rest/client.js';
import { NetworkError } from '../../src/core/index.js';

interface Pki {
  caCert: string;
  serverKey: string;
  serverCert: string;
  clientKey: string;
  clientCert: string;
}

function openssl(args: string[], cwd: string): void {
  execFileSync('openssl', args, { cwd, stdio: 'pipe' });
}

/** Generate a CA plus a server cert (SAN IP:127.0.0.1) and a client cert, all CA-signed. */
function generatePki(dir: string): Pki {
  // Root CA.
  openssl(
    ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt',
      '-days', '2', '-subj', '/CN=AXIAM Test CA'],
    dir,
  );
  // Server cert with a 127.0.0.1 SAN so the client can verify the hostname.
  openssl(
    ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr',
      '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'],
    dir,
  );
  openssl(
    ['x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
      '-out', 'server.crt', '-days', '2', '-copy_extensions', 'copyall'],
    dir,
  );
  // Client identity cert, signed by the same CA.
  openssl(
    ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'client.key', '-out', 'client.csr',
      '-subj', '/CN=axiam-device-1'],
    dir,
  );
  openssl(
    ['x509', '-req', '-in', 'client.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
      '-out', 'client.crt', '-days', '2'],
    dir,
  );
  const read = (f: string): string => readFileSync(join(dir, f), 'utf8');
  return {
    caCert: read('ca.crt'),
    serverKey: read('server.key'),
    serverCert: read('server.crt'),
    clientKey: read('client.key'),
    clientCert: read('client.crt'),
  };
}

// A minimal well-formed login-success body so client.login() resolves to the
// authenticated branch on the mTLS-authenticated request.
const LOGIN_SUCCESS_BODY = JSON.stringify({
  user: { id: 'device-1', username: 'axiam-device-1', email: 'device-1@axiam.test' },
  session_id: 'sess-1',
  expires_in: 900,
});

describe('mutual TLS end-to-end (§6.1, Node only)', () => {
  let dir: string;
  let pki: Pki;
  let server: Server;
  let baseUrl: string;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'axiam-mtls-'));
    pki = generatePki(dir);

    server = createServer(
      {
        key: pki.serverKey,
        cert: pki.serverCert,
        ca: pki.caCert, // CA the presented client cert must chain to
        requestCert: true,
        rejectUnauthorized: true, // reject any client that does not present a valid cert
      },
      (_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(LOGIN_SUCCESS_BODY);
      },
    );

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    baseUrl = `https://127.0.0.1:${port}`;
  });

  afterAll(() => {
    server?.close();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a client presenting its certificate completes the request (200)', async () => {
    const client = new AxiamClient({
      baseUrl,
      tenantSlug: 'acme',
      customCa: pki.caCert,
      clientCert: pki.clientCert,
      clientKey: pki.clientKey,
    });

    const result = await client.login('device-1@axiam.test', 'irrelevant');
    expect(result.status).toBe('authenticated');
  });

  it('a client WITHOUT a client certificate fails the handshake (mapped to NetworkError)', async () => {
    const client = new AxiamClient({
      baseUrl,
      tenantSlug: 'acme',
      customCa: pki.caCert,
      // no clientCert/clientKey — the server requires one
    });

    await expect(client.login('device-1@axiam.test', 'irrelevant')).rejects.toBeInstanceOf(
      NetworkError,
    );
  });
});
