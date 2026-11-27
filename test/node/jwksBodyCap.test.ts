// #176 — the JWKS response body is capped at 50 KiB (the cap the Java SDK
// applies, `MAX_JWKS_BYTES`; CONTRACT.md §12.4 states none) on BOTH Node fetch
// paths: the global `fetch` (plain http / no TLS material) and the `node:https`
// path used when TLS material is configured. A real local server stands in
// for a hostile endpoint, so memory and promptness are observed on the wire:
// an oversized body (streamed without end, or declared by Content-Length) is
// refused promptly, and the server is not allowed to push more than a bounded
// amount before the client hangs up. A body of exactly the cap is accepted.

import { execFileSync } from 'node:child_process';
import { createServer as createHttp, type Server as HttpServer, type ServerResponse } from 'node:http';
import { createServer as createHttps, type Server as HttpsServer } from 'node:https';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createVerifier } from '../../src/node/jwks.js';

const CAP = 50 * 1024;
const KID = 'cap-kid';

type Mode = 'at-cap' | 'over-cap' | 'chunked-endless' | 'content-length-huge';

describe('#176 — JWKS body cap on both Node fetch paths', () => {
  let dir: string;
  let ca: string;
  let token: string;
  let validJson: string;
  const state = { mode: 'at-cap' as Mode, written: 0 };
  let http: HttpServer;
  let https: HttpsServer;
  let httpUrl: string;
  let httpsUrl: string;

  const handler = (_q: unknown, res: ServerResponse): void => {
    state.written = 0;
    res.setHeader('content-type', 'application/json');
    const pad = (n: number): string => validJson + ' '.repeat(n - Buffer.byteLength(validJson));
    if (state.mode === 'at-cap') {
      res.end(pad(CAP));
    } else if (state.mode === 'over-cap') {
      res.end(pad(CAP + 1));
    } else if (state.mode === 'content-length-huge') {
      res.setHeader('content-length', String(200 * 1024 * 1024));
      res.flushHeaders();
      const chunk = Buffer.alloc(64 * 1024, 0x20);
      const t = setInterval(() => {
        state.written += chunk.length;
        res.write(chunk);
      }, 5);
      res.on('close', () => clearInterval(t));
    } else {
      // chunked, never ends: `{"keys":[` then endless padding
      res.write('{"keys":[');
      const chunk = Buffer.alloc(64 * 1024, 0x20);
      const t = setInterval(() => {
        state.written += chunk.length;
        res.write(chunk);
      }, 5);
      res.on('close', () => clearInterval(t));
    }
  };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'axiam-jwks-cap-'));
    const o = (a: string[]): void => void execFileSync('openssl', a, { cwd: dir, stdio: 'pipe' });
    o(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '2', '-subj', '/CN=Cap CA']);
    o(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 's.key', '-out', 's.csr', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1']);
    o(['x509', '-req', '-in', 's.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 's.crt', '-days', '2', '-copy_extensions', 'copyall']);
    ca = readFileSync(join(dir, 'ca.crt'), 'utf8');
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    const jwk = await exportJWK(publicKey);
    jwk.kid = KID;
    jwk.alg = 'EdDSA';
    validJson = JSON.stringify({ keys: [jwk] });
    token = await new SignJWT({ tenant_id: 't-1' }).setProtectedHeader({ alg: 'EdDSA', kid: KID }).setSubject('u').setIssuer('axiam').setExpirationTime('1h').sign(privateKey);
    http = createHttp(handler);
    https = createHttps({ key: readFileSync(join(dir, 's.key')), cert: readFileSync(join(dir, 's.crt')) }, handler);
    https.on('tlsClientError', () => undefined);
    await Promise.all([http, https].map((s) => new Promise<void>((r) => s.listen(0, '127.0.0.1', r))));
    httpUrl = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
    httpsUrl = `https://127.0.0.1:${(https.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    http.closeAllConnections();
    https.closeAllConnections();
    await Promise.all([http, https].map((s) => new Promise((r) => s.close(r))));
    rmSync(dir, { recursive: true, force: true });
  });

  const paths: Array<[string, () => ReturnType<typeof createVerifier>]> = [
    ['global fetch', () => createVerifier(httpUrl)],
    ['node:https (customCa)', () => createVerifier(httpsUrl, { ca })],
  ];

  for (const [label, make] of paths) {
    describe(label, () => {
      const verify = (): Promise<unknown> => make().verifyAccessToken(token, { expectedTenantId: 't-1' });

      it('accepts a body of exactly the cap', async () => {
        state.mode = 'at-cap';
        await expect(verify()).resolves.toMatchObject({ sub: 'u' });
      });

      it('refuses a body one byte over the cap', async () => {
        state.mode = 'over-cap';
        await expect(verify()).rejects.toThrow();
      });

      it('refuses an endless chunked body promptly, with bounded server output', async () => {
        state.mode = 'chunked-endless';
        const t0 = Date.now();
        await expect(verify()).rejects.toThrow();
        expect(Date.now() - t0).toBeLessThan(2_000); // not the 5 s deadline
        await new Promise((r) => setTimeout(r, 300));
        const settled = state.written;
        await new Promise((r) => setTimeout(r, 300));
        expect(state.written).toBe(settled); // the client hung up: nothing more is sent
        expect(state.written).toBeLessThan(8 * 1024 * 1024); // bounded (socket buffers), not unbounded
      });

      it('refuses a Content-Length over the cap before reading the body', async () => {
        state.mode = 'content-length-huge';
        const t0 = Date.now();
        await expect(verify()).rejects.toThrow();
        expect(Date.now() - t0).toBeLessThan(2_000);
        await new Promise((r) => setTimeout(r, 300));
        expect(state.written).toBeLessThan(CAP * 4); // refused on the headers, not after consuming a stream
      });
    });
  }
});
