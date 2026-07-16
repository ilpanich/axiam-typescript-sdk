// Express example — axiamMiddleware guarding a protected route (D-27, §10).
//
// Illustrative/compilable: constructs a Node persona session, registers the
// SDK's Express middleware, and defines one protected GET route reading
// `req.axiamUser`. Does not require a live AXIAM server to type-check;
// running it for real traffic requires a reachable AXIAM_BASE_URL (for the
// middleware's JWKS fetch on cache-miss).
//
// Run: `npx tsx examples/express-app.ts` (after `npm run build`, or against
// source directly with a suitable loader) — not part of the automated test
// suite; the compile check (`tsc --noEmit -p examples/tsconfig.json`) is
// the SC#4 gate.

import express from 'express';
import type { Request, Response } from 'express';
import { createNodeSession } from 'axiam-sdk/grpc';
import { AxiamClient } from 'axiam-sdk/rest';
import {
  axiamMiddleware,
  fromParam,
  requireAccess,
  requireRole,
  type AuthzVerifiableSession,
  type AxiamRequest,
} from 'axiam-sdk/middleware';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantSlug = process.env.AXIAM_TENANT_SLUG ?? 'default';
const listenAddr = process.env.AXIAM_LISTEN_ADDR ?? '127.0.0.1:8080';

const session = createNodeSession({ baseUrl, tenantSlug });

// Declarative authorization helpers (CONTRACT.md §11) additionally need an
// authz-capable client on the session — `AxiamClient`'s session-injection
// constructor adopts the SAME `NodeSession` built above (rather than
// `createNodeClient`, which would build an independent one), so
// `requireAccess` and the base `axiamMiddleware` share one cookie
// jar/refresh guard for this app.
const authzSession: AuthzVerifiableSession = {
  ...session,
  authzClient: new AxiamClient({ baseUrl, tenantSlug }, session),
};

const app = express();

app.use(axiamMiddleware(session));

app.get('/protected', (req: Request, res: Response) => {
  const axiamUser = (req as AxiamRequest).axiamUser;
  res.json({
    message: `Hello, user ${axiamUser?.userId} (tenant ${axiamUser?.tenantId})`,
    roles: axiamUser?.roles ?? [],
  });
});

// `requireAccess` (CONTRACT.md §11) — a per-route authorization guard layered
// on top of the `axiamMiddleware` above: it reads `req.axiamUser` (already
// injected by the app.use() above) and calls `checkAccess({ action: 'read',
// resourceId: <the :id route param>, subjectId: axiamUser.userId })`. 401 if
// unauthenticated, 403 if denied, 400 if `:id` is missing, 503 (fail closed)
// if the authz check itself is unreachable.
app.get(
  '/documents/:id',
  requireAccess(authzSession, 'read', fromParam('id')),
  (req: Request, res: Response) => {
    res.json({ documentId: req.params.id, message: 'access granted' });
  },
);

// `requireRole` (CONTRACT.md §11, MAY) — a local, no-server-round-trip check
// against the verified token's roles. Cheaper but coarser than
// `requireAccess`; NOT a substitute for a resource-level check.
app.get('/admin', requireRole(session, 'admin'), (_req: Request, res: Response) => {
  res.json({ message: 'admin-only route' });
});

const [host, port] = listenAddr.split(':');
app.listen(Number(port), host, () => {
  console.log(`Listening on http://${listenAddr} — GET /protected requires an AXIAM session`);
});
