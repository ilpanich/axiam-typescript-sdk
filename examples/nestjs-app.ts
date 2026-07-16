// NestJS example — `@RequireAccess`/`@RequireRole` decorators enforced by
// `AxiamGuard` (CONTRACT.md §11, Tier 2, `axiam-sdk/nestjs`).
//
// Illustrative/compilable: `tsc --noEmit -p examples/tsconfig.json` (which
// enables `experimentalDecorators`/`emitDecoratorMetadata` for this
// directory ONLY, matching what every real Nest app's own tsconfig already
// does — the SDK's own src/**/*.ts deliberately does not). Does not require
// a live AXIAM server to type-check; running it for real traffic requires a
// reachable AXIAM_BASE_URL.
//
// Run: `npx tsx examples/nestjs-app.ts` — not part of the automated test
// suite; the compile check above is the SC#4-equivalent gate.

import 'reflect-metadata';
import { Controller, Get, Module, Param } from '@nestjs/common';
import { APP_GUARD, NestFactory, Reflector } from '@nestjs/core';
import { createNodeSession } from 'axiam-sdk/grpc';
import { AxiamClient } from 'axiam-sdk/rest';
import { axiamMiddleware } from 'axiam-sdk/middleware';
import {
  AXIAM_SESSION,
  AxiamGuard,
  RequireAccess,
  RequireRole,
  type AuthzVerifiableSession,
} from 'axiam-sdk/nestjs';

const baseUrl = process.env.AXIAM_BASE_URL ?? 'https://localhost:8443';
const tenantSlug = process.env.AXIAM_TENANT_SLUG ?? 'default';

// `axiamMiddleware` (CONTRACT.md §10) still does the actual token
// extraction/verification — mounted on the underlying HTTP adapter below
// (Nest runs on top of Express by default). `AxiamGuard` (§11) never
// duplicates that: it only reads `request.axiamUser`, which this middleware
// injects, and layers the declarative per-route authorization check on top.
const session = createNodeSession({ baseUrl, tenantSlug });
const authzSession: AuthzVerifiableSession = {
  ...session,
  authzClient: new AxiamClient({ baseUrl, tenantSlug }, session),
};

@Controller('documents')
class DocumentsController {
  @RequireAccess('read', { param: 'id' })
  @Get(':id')
  getDocument(@Param('id') id: string): { documentId: string; message: string } {
    return { documentId: id, message: 'access granted' };
  }

  @RequireRole('admin')
  @Get()
  listDocuments(): { message: string } {
    return { message: 'admin-only listing' };
  }
}

@Module({
  controllers: [DocumentsController],
  providers: [
    { provide: AXIAM_SESSION, useValue: authzSession },
    {
      provide: APP_GUARD,
      // AxiamGuard is a plain class (no `@Injectable()`/`@Inject()` of its
      // own — see src/nestjs/guard.ts), so it is wired in via an explicit
      // factory provider rather than Nest's implicit constructor injection.
      useFactory: (reflector: Reflector) => new AxiamGuard(reflector, authzSession),
      inject: [Reflector],
    },
  ],
})
class AppModule {}

async function main(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  app.use(axiamMiddleware(session));
  await app.listen(3000);
  console.log('Listening on http://localhost:3000 — GET /documents/:id requires an AXIAM session + read access');
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
