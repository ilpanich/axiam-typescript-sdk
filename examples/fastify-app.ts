// Fastify example — axiamPlugin guarding a protected route (D-27, §10).
//
// Illustrative/compilable: constructs a Node persona session, registers the
// SDK's Fastify plugin (a preHandler hook), and defines one protected GET
// route reading `request.axiamUser`. Does not require a live AXIAM server
// to type-check; running it for real traffic requires a reachable
// AXIAM_BASE_URL (for the plugin's JWKS fetch on cache-miss).
//
// Run: `npx tsx examples/fastify-app.ts` — not part of the automated test
// suite; the compile check (`tsc --noEmit -p examples/tsconfig.json`) is
// the SC#4 gate.

import Fastify from 'fastify';
import { createNodeSession } from 'axiam-sdk/grpc';
import { AxiamClient } from 'axiam-sdk/rest';
import {
  axiamPlugin,
  fromParam,
  requireAccessHook,
  requireRoleHook,
  type AuthzVerifiableSession,
  type AxiamFastifyRequest,
} from 'axiam-sdk/middleware';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantSlug = process.env.AXIAM_TENANT_SLUG ?? 'default';
const listenAddr = process.env.AXIAM_LISTEN_ADDR ?? '127.0.0.1:8081';

const session = createNodeSession({ baseUrl, tenantSlug });

// Declarative authorization helpers (CONTRACT.md §11) additionally need an
// authz-capable client on the session — `AxiamClient`'s session-injection
// constructor adopts the SAME `NodeSession` built above, so
// `requireAccessHook` and the base `axiamPlugin` share one cookie
// jar/refresh guard for this app.
const authzSession: AuthzVerifiableSession = {
  ...session,
  authzClient: new AxiamClient({ baseUrl, tenantSlug }, session),
};

const app = Fastify();

async function main(): Promise<void> {
  await app.register(axiamPlugin(session));

  app.get('/protected', async (request) => {
    const axiamUser = (request as AxiamFastifyRequest).axiamUser;
    return {
      message: `Hello, user ${axiamUser?.userId} (tenant ${axiamUser?.tenantId})`,
      roles: axiamUser?.roles ?? [],
    };
  });

  // `requireAccessHook` (CONTRACT.md §11) — the Fastify `preHandler`
  // counterpart to Express's `requireAccess`; see src/middleware/express.ts
  // for the full §11 semantics (401/403/400/503 mapping, subjectId
  // propagation, no decision caching).
  app.get(
    '/documents/:id',
    { preHandler: requireAccessHook(authzSession, 'read', fromParam('id')) },
    async (request) => {
      const { id } = request.params as { id: string };
      return { documentId: id, message: 'access granted' };
    },
  );

  // `requireRoleHook` (CONTRACT.md §11, MAY) — local, no server round-trip.
  app.get('/admin', { preHandler: requireRoleHook(session, 'admin') }, async () => ({
    message: 'admin-only route',
  }));

  const [host, port] = listenAddr.split(':');
  await app.listen({ host, port: Number(port) });
  console.log(`Listening on http://${listenAddr} — GET /protected requires an AXIAM session`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
