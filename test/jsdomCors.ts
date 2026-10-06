// CORS for msw handlers serving jsdom (browser-persona) tests.
//
// msw 3 intercepts at the socket layer, below jsdom's XMLHttpRequest, so jsdom
// now applies the real CORS algorithm: its document origin (http://localhost:3000)
// differs from the SDK's baseUrl, so a request carrying X-CSRF-Token/X-Tenant-ID
// is preflighted, and every response must grant the (credentialed) origin.
// These helpers make the mocked server answer the way a correctly configured
// AXIAM deployment would.

import { http, HttpResponse } from 'msw';

/** CORS response headers granting the request's own origin, with credentials. */
export function corsHeaders(request: Request): Record<string, string> {
  return {
    'access-control-allow-origin': request.headers.get('origin') ?? '*',
    'access-control-allow-credentials': 'true',
    'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE',
    'access-control-allow-headers': request.headers.get('access-control-request-headers') ?? '*',
  };
}

/** Answers every preflight; register it alongside the real handlers. */
export const corsPreflight = http.options('*', ({ request }) => {
  return new HttpResponse(null, { status: 204, headers: corsHeaders(request) });
});
