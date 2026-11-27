# Login glue: browser binding and `returnTo`

Design notes for the "Login with AXIAM" glue's browser binding (CONTRACT.md §12.8, contract
1.68; audit findings C7 and C6). This SDK is the reference implementation; the Python, Java,
Kotlin, C# and PHP glues port from this document. Where this document and CONTRACT.md §12.8
disagree, the contract wins.

Code: `src/middleware/oidcLoginCore.ts` (the framework-neutral core), with the cookie I/O in
`src/middleware/express.ts` (`oidcLoginHandlers`) and `src/middleware/fastify.ts`
(`oidcLoginPlugin`). Tests: `test/middleware/oidcLoginBinding.test.ts`, which runs every case
against both adapters, and `test/middleware/oidcLoginRedirectEncoding.test.ts`, which drives both
inside the real frameworks for Decision 7.

## The defect

Through contract 1.67 the glue stored the in-flight tuple (`state`, `nonce`, `code_verifier`,
`redirect_uri`, `return_to`) keyed by `state` alone, and the callback checked only that a live
`state` existed. An attacker started a login, signed in to AXIAM as themselves, stopped before
the callback, and had a victim's browser load `callback?state=…&code=…`. The victim's request
completed the attacker's login: PKCE and the nonce both passed, because the store held the
attacker's verifier and nonce, and `onSuccess`, where the application creates its session, ran
during the victim's request (login CSRF; RFC 6749 §10.12). Separately, the callback redirected to
the stored `return_to` unvalidated (open redirect).

## Decision 1: the cookie

| Property | Value | Why |
|---|---|---|
| Name | `__Host-axiam_oidc_bind` | The `__Host-` prefix makes the browser refuse the cookie unless it is `Secure`, `Path=/` and has no `Domain`, so a sibling subdomain cannot plant or overwrite it. The name follows the server's own `__Host-axiam_fed_bind` (§12.1 rule 12b). |
| Value | 32 bytes from a CSPRNG, base64url without padding (43 characters) | Unguessable; URL- and cookie-safe with no quoting. |
| Attributes | `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600` | `HttpOnly`: scripts never see it. `Lax`, not `Strict`: the callback arrives as a top-level cross-site navigation from AXIAM, on which a `Strict` cookie is not sent. `Max-Age` equals the store's maximum TTL, ten minutes. |
| What is stored | `binding_digest` = lower-case hex SHA-256 of the ASCII bytes of the value | The store never holds the value itself, so a read of the store does not yield a usable cookie. The digest is not secret, but it is not logged either. |
| Per login | A new value every time; a cookie the login request presents is never reused | A value the attacker could have set beforehand must not become the binding. |

The core builds the whole `Set-Cookie` string, so the adapters cannot drift on attributes:

```
__Host-axiam_oidc_bind=<value>; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600
```

### The fallback name, and only where it applies

A browser does not store a `Secure` cookie set over plain HTTP, so `__Host-` cannot work in local
development on `http://localhost`. The rule:

- `redirect_uri` is `http:` **and** its host is `localhost`, `127.0.0.1` or `[::1]`: the name is
  `axiam_oidc_bind`, attributes `Path=/; HttpOnly; SameSite=Lax` (no `Secure`).
- Every other `redirect_uri` — every `https:` one, and plain HTTP to any other host: the name is
  `__Host-axiam_oidc_bind`. On plain HTTP to a non-loopback host the browser drops the cookie and
  every callback fails closed. That is intended: the fallback must never be selectable off
  loopback, by configuration or otherwise.

The choice is a pure function of the configured `redirect_uri` (`oidcBindingCookieName`). The login
sets the name it returns, and the callback reads **only** that name: a `__Host-` cookie presented
on a loopback deployment, or the loopback name on an HTTPS one, is treated as no cookie. Ports may
offer the integrator a switch that forces the `__Host-` name everywhere (the contract allows it);
none may offer one that selects the fallback elsewhere. This SDK offers neither.

## Decision 2: the order at the callback

```
1. IdP returned error=…            → 401 (IdP message)          clear cookie
2. state or code missing           → 400 invalid_request         clear cookie
3. entry = store.consume(state)    ← ALWAYS before the binding check
4. entry is none                   → 401 uniform                 clear cookie
5. cookie missing, entry has no binding_digest,
   or SHA-256(cookie) ≠ binding_digest (constant time)
                                   → 401 uniform                 clear cookie
                                     no token request, no onSuccess
6. oidc_exchange (with the §12.4 checks) fails
                                   → 401 / 503 as before          clear cookie
7. onSuccess(tokens, entry, request)
8. redirect to success_redirect, else a return_to that passes the rule, else the JSON summary
                                                                  clear cookie
```

Why **consume first, then compare**: the `state` must be single-use whatever happens next. If
the binding were checked first and a mismatch left the entry in place, the attacker's state would
survive a refused attempt, and a callback refused for one reason could be retried for another.
Consuming first also means a refused callback cannot be told apart, by timing of a later attempt,
from a used one.

Why **one 401 for steps 4 and 5**: same status, same body
(`{"error":"authentication_failed","message":"unknown, expired, or already-used login state"}`).
A refusal that said "wrong browser" would confirm to the attacker that the state was live.

Why **no token request on a binding failure**: the code is the attacker's; exchanging it would
spend it and, on a server that logs the exchange, attribute a sign-in to the victim's request.

The comparison is constant time over the two 64-character hex digests (a length mismatch — a
malformed digest — fails before comparing). An entry with no `binding_digest`, which a store
written for 1.67 or an entry saved by older glue produces, is refused like a missing cookie.

**Clearing.** Every callback response — success, the uniform `401`, and every other error —
carries `Set-Cookie: <name>=; <same attributes>; Max-Age=0`. The login response is the only one
that sets a value.

**Clearing on the error path.** "Every other error" includes an error that is not a login
outcome: the store's `consume` fails (a database or cache outage), or the application's
`onSuccess` throws (its own session write fails). The core does not turn these into an outcome;
they propagate unchanged, so the application's error handling still sees them, and by then the
state is already consumed. The adapter therefore sends the clearing header on the error path
itself: it wraps the call to the core and, when it throws and the response has not started,
appends the clearing `Set-Cookie` and re-throws (Express `res.append`, Fastify `reply.header`; the
framework's error response keeps headers already set). A port may instead set the clearing header
before running anything, as long as no error handler in its framework discards response headers.
The test matrix carries one test per adapter for each of the two throws.

**Concurrent sign-ins.** Two logins started in one browser: the second overwrites the cookie, so
the first callback is refused and the user starts again (§12.8 rule 1 (g)). Accepted cost.

## Decision 3: the store interface

The entry gains one **optional** member, `binding_digest` (`bindingDigest?: string` here). It is
optional so that a store written against 1.67 still compiles and an entry without it can still be
read; the callback then refuses it. Consequences:

- A caller-supplied store MUST persist the member and return it unchanged. A store that rebuilds
  entries from a fixed column list and drops unknown members refuses every sign-in after the
  upgrade — loudly, which is the safe failure.
- Nothing else in the store contract changes: `save(entry)`, single-use atomic `consume(state)`,
  the 10-minute TTL clamp, lazy expiry.
- Sign-ins in flight across the deploy fail once (their entries have no digest) and restart.

The reference `MemoryOidcStateStore` also gains a bound (10 000 entries by default, oldest
evicted first): the login route is unauthenticated and every call saves one entry.

## Decision 4: where the cookie I/O lives

The core is framework-neutral (§12.8 rule 1 (f)). It does not read or write cookies:

- `beginOidcLogin(options, returnTo?)` returns the redirect outcome with a `setCookie` string.
- `completeOidcLogin(options, query, context)` takes `context.bindingCookie`, the value the
  adapter read from the request's `Cookie` header under `oidcBindingCookieName(redirectUri)`, and
  `context.request`, which it passes to `onSuccess`. Every outcome carries a clearing `setCookie`.
- A caller that passes no `bindingCookie` has every callback refused. There is no "binding
  disabled" option.

Each adapter adds exactly two things: send `outcome.setCookie` when present (Express
`res.append('Set-Cookie', …)`, Fastify `reply.header('set-cookie', …)`, which accumulates), and
read the one cookie name on the callback. Ports whose glue can reach the request directly (Django,
Spring, Ktor, ASP.NET Core, PHP) may set and read the cookie in place, but should keep the same
split of decisions: the name, the attributes and the comparison belong to one shared function per
SDK, not to each framework integration.

## Decision 5: the success callback receives the request

`onSuccess(tokens, entry, request)`. The application creates its session on the request that
completed the sign-in without ambient context (`AsyncLocalStorage`, `contextvars`,
`RequestContextHolder`). It runs only after steps 3–6 above have all succeeded. In TypeScript the
third parameter is additive (a two-parameter callback is still assignable); a port where adding a
parameter breaks the published signature adds an overload or a second hook and keeps the old one.

## Decision 6: `return_to`

One shared predicate per SDK (`isSafeReturnTo` here), applied **when storing** (a failing value is
dropped and the entry is saved without it) **and before redirecting** (a stored value that fails
is not followed — the store may be the integrator's, or the entry older glue's). A value passes
only when it:

- starts with a single `/`;
- does not start with `//` or `/\`;
- contains no `\` anywhere and no control character (U+0000–U+001F, U+007F).

A dropped value is treated as if none had been given: `success_redirect`, else the JSON summary.
`success_redirect`, which the integrator configures, still wins over a valid `return_to`.

An integrator predicate (`allowReturnTo`) MAY widen the rule — for example to an allowlist of the
application's other origins. It is consulted at both points and **only** for values the default
rule refuses; a predicate that throws accepts nothing. No SDK ships a default predicate that
accepts absolute URLs.

## Decision 7: the redirect target is encoded by the adapter

**The rule.** The `Location` header of the callback's `302` carries the **percent-encoded form** of
the destination (the configured `success_redirect`, or the accepted `return_to`). The **adapter**
produces that form, at the point where it writes the header, in every adapter — whether or not the
framework's own redirect helper would do it. The **application is never asked to encode** and the
application hooks never see or alter the encoded value: `allowReturnTo` receives the raw value,
`onSuccess` runs before any redirect is built, `success_redirect` is configured raw. The core
returns the raw destination (`kind: 'redirect'`, `url`); encoding happens once, in the adapter.

**Why.** `isSafeReturnTo` (Decision 6) deliberately accepts any path that starts with a single `/`
and holds no `\` or control character, so `/日本`, `/café` and `/a b` are valid stored values: the
framework has already percent-*decoded* the query parameter the login received. A header value may
hold only visible ASCII. Express's `res.redirect` encodes (it uses `encodeurl`); Fastify's
`reply.header('location', …)` does not, and Node refuses a header value holding a character above
U+00FF, so the write throws **after `onSuccess` has run** and the user, signed in, gets a bare `500`
without the clearing `Set-Cookie` (a rule 1 (d) miss); a character in U+0080–U+00FF is sent as a
raw latin1 byte the browser cannot read as UTF-8, and lands on the wrong path. A destination an
integrator's `allowReturnTo` admitted may even hold CR/LF, which must never reach a header.

**What the `Location` value must be.** These four rules are **normative**; they are the
specification, and a framework's redirect helper or a library encoder (`encodeurl`,
`encodeURI`, `Uri.EscapeUriString`, `URLEncoder`, …) is acceptable only where it gives the same
result. The reference implementation is `encodeRedirectLocation`, `src/middleware/oidcLoginCore.ts`.

1. **Characters.** Every character outside the URL-safe set is UTF-8 percent-encoded with
   upper-case hex digits: space becomes `%20`, `é` `%C3%A9`, `€` `%E2%82%AC`, CR `%0D`, LF `%0A`,
   `"` `%22`, `<` `%3C`, `>` `%3E`, `` ` `` `%60`, `{` `%7B`, `}` `%7D`, DEL `%7F`, every other
   control character `%XX`. The URL-safe set, which MUST be left as it is, is exactly:
   `A-Z a-z 0-9` and `! # $ % & ' ( ) * + , - . / : ; = ? @ [ \ ] ^ _ | ~`. A backslash is in the
   set and is kept as `\` (the default `returnTo` rule refuses one before it can get here; a value
   an integrator's predicate admitted keeps it).
2. **Existing escapes.** A `%` followed by two hex digits (either case) is a well-formed escape
   and is **kept as it is**, so an encoded value is not encoded twice (`/a%20b` stays `/a%20b`,
   `/%%41` becomes `/%25%41`). Any other `%` becomes `%25` (`/a%2` becomes `/a%252`).
3. **Input that is not valid Unicode.** Whatever the language's string model, every part of the
   destination that is not valid Unicode is replaced by U+FFFD (encoded `%EF%BF%BD`) **before**
   encoding, one replacement per invalid unit, and the encoder MUST NOT throw on any input. In a
   byte-string language (PHP, C) that means one U+FFFD per **maximal subpart** of an ill-formed
   UTF-8 sequence (the Unicode / WHATWG substitution): `\xE2\x82` is one, `\xF0\x9F\x98` is one,
   `\xFF` is one, `\xC0\x80` is two and `\xED\xA0\x80` is three. `returnTo=%FF` arrives as the
   single byte `0xFF` and becomes `%EF%BF%BD`. In a language whose strings are UTF-16 (JavaScript,
   Java, C#) or hold code points (Python `str`) it means each unpaired surrogate, however many are
   adjacent (`/\uD800\uD800` becomes `/%EF%BF%BD%EF%BF%BD`). A valid surrogate pair is one character
   (`/😀` becomes `/%F0%9F%98%80`).
4. **Result.** Pure ASCII: no byte below `0x21` and none above `0x7E`, so no space, CR or LF; a
   CR/LF in the destination cannot split the header or inject another one.

**Where `encodeurl` (Express's `res.redirect`) differs from these rules**, as observed with the
`encodeurl` Express 5 ships: `/%%41` becomes `/%25%2541` (a well-formed escape is double-encoded,
against rule 2); `/a%2` stays `/a%2` (a truncated escape is kept, against rule 2); and two adjacent
lone surrogates (`/\uD800\uD800`) make it throw `URIError` (against rule 3). On every other row
below it agrees with the rules. Both adapters here therefore
run `encodeRedirectLocation` first, and `res.redirect`'s own pass then finds nothing to change. A
port on a framework whose helper encodes must do the same, or show with the matrix below that the
helper meets the four rules.

Test it per adapter, against the real framework, not a response double (a double that records the
`url` passed to a redirect helper hides this defect): `/a b` gives `/a%20b`; `/café` gives
`/caf%C3%A9`; `/€` gives `/%E2%82%AC`; a lone surrogate gives `%EF%BF%BD`, and so do two adjacent
ones (`/\uD800\uD800`, `/\uDC00\uDC00`) without an exception, and so does a raw byte `0xFF` in a
byte-string language (`returnTo=%2F%FF`, which arrives as `/` and the byte `0xFF`, gives
`/%EF%BF%BD`); `/a%20b` is unchanged; `/%%41` gives
`/%25%41`; `/a%2` gives `/a%252`;
a CR/LF value admitted through `allowReturnTo` gives `%0D%0A` and injects no header; a non-ASCII
`success_redirect` is encoded too. Each of these answers `302`, with the binding cookie cleared and
`onSuccess` called once.

## Test matrix (per adapter)

| Case | Expected |
|---|---|
| Login response | sets the `__Host-` name with `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain`, `Max-Age` ≤ 600; the entry's digest is SHA-256 of the value |
| `http://localhost` `redirect_uri` | sets `axiam_oidc_bind` without `Secure`; the `__Host-` name is not read there |
| `http://` non-loopback `redirect_uri` | still the `__Host-` name |
| Valid state, **no** cookie | uniform `401`, zero token-endpoint requests, `onSuccess` not called, cookie cleared; a retry with the right cookie is `401` (consumed) |
| Valid state, **another login's** cookie | the same |
| Matching cookie | success; `onSuccess` gets the request; cookie cleared; replay is `401` |
| Entry stored with no digest | `401`, no exchange |
| Every other callback error | clears the cookie |
| Exchange fails (`AuthError` → `401`, `NetworkError` → `503`) | clears the cookie; `onSuccess` not called |
| `onSuccess` throws, or the store's `consume` rejects | the framework's error response (default handler, and an application error handler that receives the same error) clears the cookie |
| `return_to` `https://evil.example/x`, `//evil.example/x`, `/\evil.example`, `/a\b`, `/a` + CR, `/a` + NUL, `/a` + DEL | dropped at login; stored directly, not followed |
| `return_to` `/dashboard?tab=1` | stored and followed |
| Predicate accepting `https://app.example/x` | that value followed; `https://evil.example/x` still not |
| `return_to` holding a space, a non-ASCII character, a lone surrogate or an invalid UTF-8 byte (`0xFF`), an existing `%XX`; a CR/LF value admitted by `allowReturnTo`; a non-ASCII `success_redirect` (Decision 7) | `302`; `Location` is the percent-encoded form, pure ASCII, no injected header; cookie cleared; `onSuccess` called once |
