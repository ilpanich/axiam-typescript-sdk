// RFC 7592 client configuration — CONTRACT.md §28.12.6's five required tests.
//
// Against a REAL loopback HTTP server rather than msw: "the SDK session is not
// attached" is a claim about the jar cookie, and the jar's Cookie header is
// injected inside the cookie agent's addRequest(), a layer msw never reaches
// (see test/node/webauthnSetupRegister.test.ts). A control test proves the
// session cookie DOES ride on an ordinary call over this very transport, so
// the negative results are not vacuous.
//
// Every token is generated at run time; no failure message prints one.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { CookieJar } from 'tough-cookie';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { NetworkError, OAuthProtocolError, Sensitive } from '../../src/core/index.js';
import { ValidationError } from '../../src/management/errors.js';
import { ACCESS_COOKIE, CSRF_COOKIE, wrapAxios } from '../../src/node/cookieJar.js';
import { createVerifier } from '../../src/node/jwks.js';
import { NodeSession } from '../../src/node/session.js';
import { TokenManager } from '../../src/node/tokenManager.js';
import { AxiamClient } from '../../src/rest/client.js';
import {
  checkRegistrationUri,
  clientRegistrationFromJson,
  clientRegistrationUpdateBody,
  type ClientRegistration,
} from '../../src/rest/clientRegistration.js';
import { installInterceptors } from '../../src/rest/interceptors.js';
import { createSession } from '../../src/rest/session.js';
import { assertNoFragment, errorRenderings, freshSecret, renderings } from '../redaction.js';

const CLIENT = 'dcr-client-1';
const TENANT = '22222222-2222-4222-8222-222222222222';

interface Seen {
  method: string;
  path: string;
  query: string;
  authorization: string | undefined;
  cookie: string | undefined;
  csrf: string | undefined;
  body: string;
}

type Responder = (req: IncomingMessage, res: ServerResponse, body: string) => void;

let server: Server;
let baseUrl: string;
let seen: Seen[] = [];
let refreshes = 0;
const responders = new Map<string, Responder>();

function respondJson(status: number, body?: unknown, headers: Record<string, string> = {}): Responder {
  return (_req, res) => {
    if (body === undefined) {
      res.writeHead(status, headers);
      res.end();
      return;
    }
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(JSON.stringify(body));
  };
}

beforeAll(async () => {
  server = createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString('utf8')));
    req.on('end', () => {
      const url = new URL(req.url ?? '/', 'http://x');
      if (url.pathname === '/api/v1/auth/refresh') {
        refreshes += 1;
        res.writeHead(500);
        res.end();
        return;
      }
      seen.push({
        method: req.method ?? '',
        path: url.pathname,
        query: url.search.replace(/^\?/, ''),
        authorization: req.headers.authorization,
        cookie: req.headers.cookie,
        csrf: req.headers['x-csrf-token'] as string | undefined,
        body,
      });
      const responder = responders.get(`${req.method} ${url.pathname}`);
      if (responder) responder(req, res, body);
      else respondJson(200, { ok: true })(req, res, body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

beforeEach(() => {
  seen = [];
  refreshes = 0;
  responders.clear();
});

const registrationPath = `/oauth2/register/${CLIENT}`;
const registrationUri = (): string => `${baseUrl}${registrationPath}?tenant_id=${TENANT}`;

function registrationBody(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    client_id: CLIENT,
    client_id_issued_at: 1_700_000_000,
    client_name: 'Agent',
    redirect_uris: ['https://agent.example.test/cb'],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'private_key_jwt',
    scope: 'openid',
    registration_client_uri: registrationUri(),
    jwks_uri: 'https://agent.example.test/jwks',
    ...extra,
  };
}

/** A plain client (retry on), no session. */
function plainClient(): AxiamClient {
  return new AxiamClient({ baseUrl, tenantId: TENANT });
}

/**
 * A client holding a real SDK session: jar cookies (access + CSRF), an
 * authenticated flag, a CSRF token store and an adopted SDK bearer — every
 * credential the session could leak.
 */
async function clientWithSession(sdkBearer: string): Promise<AxiamClient> {
  const jar = new CookieJar();
  await jar.setCookie(`${ACCESS_COOKIE}=${sdkBearer}; Path=/`, baseUrl);
  await jar.setCookie(`${CSRF_COOKIE}=csrf-session-value; Path=/`, baseUrl);
  const base = createSession({ baseUrl, tenantId: TENANT });
  wrapAxios(base.axios, jar);
  const session = new NodeSession(
    { baseUrl, tenantId: TENANT },
    base,
    new TokenManager(jar, baseUrl, base.tenantHeaderValue),
    createVerifier(baseUrl),
    jar,
  );
  installInterceptors(session.axios, session);
  session.authenticated = true;
  session.csrfToken = 'csrf-session-value';
  return new AxiamClient({ baseUrl, tenantId: TENANT }, session);
}

// ── 1. Origin refusal ───────────────────────────────────────────────────────

describe('§28.12.6 (1) — a URI at another origin is refused locally', () => {
  it('another host, another port, and http against an https base: ValidationError, no request', async () => {
    const client = plainClient();
    const token = new Sensitive(freshSecret());
    const { port } = server.address() as AddressInfo;
    const otherHost = `http://localhost:${port}${registrationPath}`;
    const otherPort = `http://127.0.0.1:${port + 1}${registrationPath}`;
    for (const uri of [otherHost, otherPort, '/oauth2/register/x', `ftp://127.0.0.1:${port}/x`]) {
      await expect(client.readClientRegistration(uri, token)).rejects.toBeInstanceOf(ValidationError);
      await expect(client.deleteClientRegistration(uri, token)).rejects.toBeInstanceOf(ValidationError);
      await expect(
        client.updateClientRegistration(uri, token, clientRegistrationFromJson({ client_id: CLIENT })),
      ).rejects.toBeInstanceOf(ValidationError);
    }

    const httpsClient = new AxiamClient({ baseUrl: 'https://iam.example.test', tenantId: TENANT });
    const err = await httpsClient
      .readClientRegistration('http://iam.example.test/oauth2/register/x', token)
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ValidationError);
    expect((err as ValidationError).status).toBe(400);

    // http is refused even at the same origin unless that origin is loopback.
    const plainHttp = new AxiamClient({ baseUrl: 'http://iam.example.test', tenantId: TENANT });
    await expect(
      plainHttp.readClientRegistration('http://iam.example.test/oauth2/register/x', token),
    ).rejects.toBeInstanceOf(ValidationError);

    expect(seen).toHaveLength(0);
  });

  it('accepts the same origin and keeps the query verbatim', async () => {
    responders.set(`GET ${registrationPath}`, respondJson(200, registrationBody()));
    const client = plainClient();
    await client.readClientRegistration(registrationUri(), freshSecret());
    expect(seen[0]?.query).toBe(`tenant_id=${TENANT}`);
  });
});

describe('checkRegistrationUri', () => {
  it('compares scheme, host (any case) and port-or-default', () => {
    const u = checkRegistrationUri('https://IAM.example.test', 'https://iam.example.test:443/r/c?tenant_id=t', 'op');
    expect(u.search).toBe('?tenant_id=t');
    expect(() => checkRegistrationUri('http://[::1]:8080', 'http://[::1]:8080/r', 'op')).not.toThrow();
    expect(() => checkRegistrationUri('not a url', 'https://x/r', 'op')).toThrow(ValidationError);
  });
});

// ── 2. Header only ──────────────────────────────────────────────────────────

describe('§28.12.6 (2) — read and delete send the bearer only', () => {
  it('control: an ordinary session call DOES carry the jar cookie over this transport', async () => {
    const sdkBearer = freshSecret();
    const client = await clientWithSession(sdkBearer);
    await client.session.axios.post('/api/v1/echo', {});
    expect(seen.at(-1)?.cookie?.includes(sdkBearer), 'control call carried no cookie').toBe(true);
  });

  it('no SDK session token, no cookie, no CSRF, no body, and the URI query verbatim', async () => {
    const sdkBearer = freshSecret();
    const client = await clientWithSession(sdkBearer);
    // An adopted SDK bearer too (§6.1's device token rides every session call).
    client.session.deviceAccessToken = new Sensitive(sdkBearer);
    responders.set(`GET ${registrationPath}`, respondJson(200, registrationBody()));
    responders.set(`DELETE ${registrationPath}`, respondJson(204));
    const token = freshSecret();

    const read = await client.readClientRegistration(registrationUri(), new Sensitive(token));
    expect(read.client_id).toBe(CLIENT);
    expect(read.registration_access_token).toBeUndefined();
    await expect(client.deleteClientRegistration(registrationUri(), new Sensitive(token))).resolves.toBeUndefined();

    expect(seen.map((s) => s.method)).toEqual(['GET', 'DELETE']);
    for (const s of seen) {
      expect(s.authorization === `Bearer ${token}`, 'Authorization is not exactly the registration bearer').toBe(
        true,
      );
      expect(s.cookie, 'a session cookie rode along').toBeUndefined();
      expect(s.csrf, 'a CSRF header rode along').toBeUndefined();
      expect(s.body).toBe('');
      expect(s.query).toBe(`tenant_id=${TENANT}`);
      expect(s.query.includes(token), 'the token reached the query').toBe(false);
    }
  });
});

// ── 3. Update body ──────────────────────────────────────────────────────────

describe('§28.12.6 (3) — update', () => {
  it('drops the five server-stated members, keeps client_id and unknown members, returns the rotated token', async () => {
    const rotated = freshSecret();
    responders.set(
      `PUT ${registrationPath}`,
      respondJson(200, registrationBody({ registration_access_token: rotated })),
    );
    const metadata = clientRegistrationFromJson(
      registrationBody({
        registration_access_token: freshSecret(),
        client_secret: freshSecret(),
        client_secret_expires_at: 0,
        backchannel_token_delivery_mode: 'poll',
      }),
    );
    metadata.client_name = 'Agent v2';

    const updated = await plainClient().updateClientRegistration(registrationUri(), freshSecret(), metadata);
    expect(updated.registration_access_token?.expose() === rotated, 'the rotated token was not returned').toBe(true);

    expect(seen).toHaveLength(1);
    const body = JSON.parse(seen[0]!.body) as Record<string, unknown>;
    for (const gone of [
      'registration_access_token',
      'registration_client_uri',
      'client_secret_expires_at',
      'client_id_issued_at',
      'client_secret',
    ]) {
      expect(gone in body, `${gone} must not be sent`).toBe(false);
    }
    expect(body.client_id).toBe(CLIENT);
    expect(body.client_name).toBe('Agent v2');
    expect(body.jwks_uri).toBe('https://agent.example.test/jwks');
    expect(body.backchannel_token_delivery_mode).toBe('poll');
  });

  it('a 503 on update is not retried, even with retry enabled', async () => {
    responders.set(`PUT ${registrationPath}`, respondJson(503));
    const metadata = clientRegistrationFromJson(registrationBody());
    const err = await plainClient()
      .updateClientRegistration(registrationUri(), freshSecret(), metadata)
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(seen).toHaveLength(1);
  });

  it('a 503 on delete is not retried; a read MAY be (§16)', async () => {
    responders.set(`DELETE ${registrationPath}`, respondJson(503));
    responders.set(`GET ${registrationPath}`, respondJson(503));
    const client = plainClient();
    await expect(client.deleteClientRegistration(registrationUri(), freshSecret())).rejects.toBeInstanceOf(
      NetworkError,
    );
    expect(seen.filter((s) => s.method === 'DELETE')).toHaveLength(1);
    await expect(client.readClientRegistration(registrationUri(), freshSecret())).rejects.toBeInstanceOf(
      NetworkError,
    );
    expect(seen.filter((s) => s.method === 'GET').length).toBeGreaterThan(1);
  });

  it('a bodiless 400 on read is not retried, although §2 maps it to NetworkError', async () => {
    responders.set(`GET ${registrationPath}`, respondJson(400));
    await expect(plainClient().readClientRegistration(registrationUri(), freshSecret())).rejects.toBeInstanceOf(
      NetworkError,
    );
    expect(seen).toHaveLength(1);
  });

  // Contract 1.59 §34.2 P12.4 (R-23, review F-5b): the replacement is built
  // from what the read carried. A list the read lacked is not sent — never as
  // `[]`, which the server would store as "no redirect URIs" — and a list of an
  // unexpected shape goes back exactly as read.
  it('sends no list the read lacked, and a list of an unexpected shape as read', async () => {
    responders.set(`PUT ${registrationPath}`, respondJson(200, registrationBody()));
    const sparse = clientRegistrationFromJson({ client_id: CLIENT, client_name: 'Agent' });
    await plainClient().updateClientRegistration(registrationUri(), freshSecret(), sparse);
    const sent = JSON.parse(seen[0]!.body) as Record<string, unknown>;
    for (const absent of ['redirect_uris', 'grant_types', 'response_types']) {
      expect(absent in sent, `${absent} was sent although the read lacked it`).toBe(false);
    }
    expect(sent).toEqual({ client_id: CLIENT, client_name: 'Agent' });

    const odd = clientRegistrationFromJson({
      client_id: CLIENT,
      redirect_uris: ['https://agent.example.test/cb', 7],
      grant_types: 'authorization_code',
      response_types: ['code'],
    });
    const body = clientRegistrationUpdateBody(odd);
    expect(body.redirect_uris).toEqual(['https://agent.example.test/cb', 7]);
    expect(body.grant_types).toBe('authorization_code');
    expect(body.response_types).toEqual(['code']);
  });

  it('decodes tolerantly: unknown and mistyped members are kept, the two secrets wrapped', () => {
    const r = clientRegistrationFromJson({
      client_id: 'c1',
      client_secret: freshSecret(),
      registration_access_token: freshSecret(),
      backchannel_token_delivery_mode: 'poll',
      client_id_issued_at: 'not-a-number',
      redirect_uris: ['https://a', 7],
      jwks: { keys: [] },
      client_name: null,
    });
    expect(r.extra.backchannel_token_delivery_mode).toBe('poll');
    expect(r.extra.client_id_issued_at).toBe('not-a-number');
    // §34.2 P12.4: a list with an item of an unexpected type is kept as read, not filtered.
    expect(r.redirect_uris).toBeUndefined();
    expect(r.extra.redirect_uris).toEqual(['https://a', 7]);
    expect(r.client_secret).toBeInstanceOf(Sensitive);
    expect(r.registration_access_token).toBeInstanceOf(Sensitive);
    const body = clientRegistrationUpdateBody(r);
    expect('client_id_issued_at' in body).toBe(false);
    expect(body.jwks).toEqual({ keys: [] });
    expect(() => clientRegistrationFromJson([])).toThrow(NetworkError);
    expect(() => clientRegistrationFromJson({ x: 1 })).toThrow(NetworkError);
  });
});

// ── 4. Errors ───────────────────────────────────────────────────────────────

describe('§28.12.6 (4) — errors', () => {
  it('a 401 invalid_token is an OAuthProtocolError and the §9 guard is not entered', async () => {
    const client = await clientWithSession(freshSecret());
    responders.set(
      `GET ${registrationPath}`,
      respondJson(401, { error: 'invalid_token', error_description: 'no' }, {
        'www-authenticate': 'Bearer error="invalid_token"',
      }),
    );
    const err = await client.readClientRegistration(registrationUri(), freshSecret()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('invalid_token');
    expect(refreshes).toBe(0);
    expect(client.session.authenticated).toBe(true);
  });

  it('a 401 without error_description still dispatches on error', async () => {
    responders.set(`DELETE ${registrationPath}`, respondJson(401, { error: 'invalid_token' }));
    const err = await plainClient().deleteClientRegistration(registrationUri(), freshSecret()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).errorDescription).toBe('');
    expect((err as OAuthProtocolError).message).toBe('invalid_token');
  });

  it('a 400 invalid_client_metadata is an OAuthProtocolError', async () => {
    responders.set(
      `PUT ${registrationPath}`,
      respondJson(400, { error: 'invalid_client_metadata', error_description: 'scope' }),
    );
    const err = await plainClient()
      .updateClientRegistration(registrationUri(), freshSecret(), clientRegistrationFromJson(registrationBody()))
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OAuthProtocolError);
    expect((err as OAuthProtocolError).error).toBe('invalid_client_metadata');
  });

  it('a 204 on delete resolves, and a closed client refuses', async () => {
    responders.set(`DELETE ${registrationPath}`, respondJson(204));
    const client = plainClient();
    await expect(client.deleteClientRegistration(registrationUri(), freshSecret())).resolves.toBeUndefined();
    client.close();
    await expect(client.readClientRegistration(registrationUri(), freshSecret())).rejects.toBeInstanceOf(
      NetworkError,
    );
  });

  it('a transport failure is a NetworkError', async () => {
    const { port } = server.address() as AddressInfo;
    // Same origin as the base, but nothing listens there: reuse an unbound port.
    const dead = new AxiamClient({ baseUrl: `http://127.0.0.1:${port + 7}`, tenantId: TENANT, retryEnabled: false });
    await expect(
      dead.deleteClientRegistration(`http://127.0.0.1:${port + 7}/oauth2/register/x`, freshSecret()),
    ).rejects.toBeInstanceOf(NetworkError);
  });
});

// ── 5. Redaction ────────────────────────────────────────────────────────────

describe('§28.12.6 (5) — redaction', () => {
  it('neither the token nor the secret reaches any rendering of a ClientRegistration or an error', async () => {
    const token = freshSecret();
    const secret = freshSecret();
    const registration: ClientRegistration = clientRegistrationFromJson(
      registrationBody({ registration_access_token: token, client_secret: secret }),
    );
    const rendered = renderings(registration);
    assertNoFragment(rendered, token, 'ClientRegistration');
    assertNoFragment(rendered, secret, 'ClientRegistration');

    responders.set(`GET ${registrationPath}`, respondJson(401, { error: 'invalid_token' }));
    const client = plainClient();
    const err = await client.readClientRegistration(registrationUri(), new Sensitive(token)).catch((e: unknown) => e);
    assertNoFragment(errorRenderings(err), token, 'server error');

    const refused = await client
      .readClientRegistration('https://elsewhere.example.test/r', new Sensitive(token))
      .catch((e: unknown) => e);
    assertNoFragment(errorRenderings(refused), token, 'local refusal');

    const { port } = server.address() as AddressInfo;
    const dead = new AxiamClient({ baseUrl: `http://127.0.0.1:${port + 7}`, tenantId: TENANT, retryEnabled: false });
    const transport = await dead
      .deleteClientRegistration(`http://127.0.0.1:${port + 7}/r`, new Sensitive(token))
      .catch((e: unknown) => e);
    assertNoFragment(errorRenderings(transport), token, 'transport error');
  });
});
