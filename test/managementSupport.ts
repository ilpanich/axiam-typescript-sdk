// Shared harness for the CONTRACT §27 management tests.
//
// Every management operation requires an authenticated session (§27.4 rule 1
// refuses to make a wire call without one), so each test needs a client that
// believes it has logged in. Driving a real login 147 times would test the
// login path 147 times and the management path once each; the precondition has
// its own dedicated test in `management.semantics.test.ts` instead.

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, afterEach } from 'vitest';

import registry from '../management-registry.json' with { type: 'json' };
import { AxiamClient } from '../src/rest/client.js';

/** The origin every management test's mock server answers on. */
export const BASE_URL = 'https://axiam.test';
/** The tenant every harness client is built with, as a UUID. */
export const TENANT_ID = '22222222-2222-4222-8222-222222222222';
/** The organization every harness client is built with. */
export const ORG_ID = '33333333-3333-4333-8333-333333333333';
/** The id the generated surface test substitutes into every path parameter. */
export const EXAMPLE_ID = '11111111-1111-4111-8111-111111111111';

const server = setupServer();
let listening = false;

afterEach(() => server.resetHandlers());
afterAll(() => {
  if (listening) server.close();
});

/**
 * A client with tenant and organization UUIDs, already authenticated.
 *
 * UUIDs rather than slugs on purpose: §27.4 rule 3 makes a slug-only client
 * fail locally on any route carrying `{tenant_id}`, and that refusal has its
 * own test rather than being the default everywhere.
 */
export function managementClient(): AxiamClient {
  const client = new AxiamClient({
    baseUrl: BASE_URL,
    tenantId: TENANT_ID,
    orgId: ORG_ID,
    // §16 is exercised by its own tests; leaving retry on here would make a
    // deliberate 5xx fixture take three round-trips and seconds of backoff.
    retryEnabled: false,
  });
  client.session.authenticated = true;
  return client;
}

/** A client that has *not* authenticated — for the §27.4 rule 1 assertions. */
export function anonymousClient(overrides: Record<string, unknown> = {}): AxiamClient {
  return new AxiamClient({
    baseUrl: BASE_URL,
    tenantId: TENANT_ID,
    orgId: ORG_ID,
    retryEnabled: false,
    ...overrides,
  } as ConstructorParameters<typeof AxiamClient>[0]);
}

/** Mount one canned JSON response for `method` at `path`. */
export function mountJson(
  target: typeof server,
  method: string,
  path: string,
  status: number,
  body: unknown,
): void {
  const verb = method.toLowerCase() as 'get' | 'post' | 'put' | 'delete';
  target.use(
    http[verb](`${BASE_URL}${path}`, () =>
      body === undefined
        ? new HttpResponse(null, { status })
        : HttpResponse.json(body as Record<string, unknown>, { status }),
    ),
  );
}

/**
 * Run `fn` against a fresh handler set and an authenticated client.
 *
 * `onUnhandledRequest: 'error'` is load-bearing: without it a request to a
 * path the test forgot to mount passes through to the real network and the
 * assertion becomes a timeout in CI rather than a message.
 */
export async function withServer(
  fn: (target: typeof server, client: AxiamClient) => Promise<void>,
): Promise<void> {
  if (!listening) {
    server.listen({ onUnhandledRequest: 'error' });
    listening = true;
  }
  await fn(server, managementClient());
}

/** The shared msw server, for tests that mount their own handlers. */
export function mockServer(): typeof server {
  if (!listening) {
    server.listen({ onUnhandledRequest: 'error' });
    listening = true;
  }
  return server;
}

/**
 * The operations `management-registry.json` names, `namespace.operation`.
 *
 * Read from the vendored registry at test time rather than restated, so this
 * cannot drift from the file the generator reads.
 */
export function expectedSurface(): string[] {
  const out: string[] = [];
  const namespaces = (registry as { namespaces: Record<string, { operations: Record<string, unknown> }> })
    .namespaces;
  for (const [namespace, def] of Object.entries(namespaces)) {
    for (const operation of Object.keys(def.operations)) out.push(`${namespace}.${operation}`);
  }
  return out.sort();
}
