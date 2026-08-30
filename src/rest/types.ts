// Wire types + public result types for REST auth/authz (D-18, FND-04, §1).
//
// Wire* types mirror crates/axiam-api-rest/src/handlers/auth.rs and
// authz_check.rs exactly (snake_case, server response shapes). The public
// LoginResult discriminated union renames challenge_token -> mfaToken per
// §1's camelCase convention and deliberately carries no session token field
// anywhere — tokens arrive exclusively via Set-Cookie (D-05/T-17-07).

import type { AccessDecision } from '../core/index.js';
import type { Sensitive } from '../core/index.js';

// ---------------------------------------------------------------------------
// Wire types (snake_case, mirror server handlers)
// ---------------------------------------------------------------------------

export interface LoginUserInfoWire {
  id: string;
  username: string;
  email: string;
  /**
   * CONTRACT.md §5.2. Absent on a server older than contract 1.31, and `false`
   * is the safe reading of absent: the client then offers no cross-tenant
   * action rather than one that would 403.
   */
  organization_level?: boolean;
  /** CONTRACT.md §5.2.2 — the tenant being **acted on**. */
  tenant_id?: string;
  /**
   * CONTRACT.md §5.2.2 — the tenant this principal's record **lives in**.
   *
   * Absent on a server older than contract 1.34, which cannot switch the
   * acting tenant either, so absent reads as equal to `tenant_id` rather than
   * as unknown.
   */
  principal_tenant_id?: string;
  /** CONTRACT.md §5.2.2 — slug of `principal_tenant_id`. */
  principal_tenant_slug?: string | null;
  /** CONTRACT.md §5.2.2 — the caller's organization, as a UUID. */
  org_id?: string | null;
  /** CONTRACT.md §5.2.3 — the tenants this caller's roles reach, if narrowed. */
  reachable_tenant_ids?: string[] | null;
}

/** 200 OK body from /api/v1/auth/login, /api/v1/auth/mfa/verify, and (subset) /api/v1/auth/refresh. */
export interface LoginSuccessResponseWire {
  user: LoginUserInfoWire;
  session_id: string;
  expires_in: number;
}

/** 202 Accepted body from /api/v1/auth/login when MFA is required. */
export interface MfaRequiredResponseWire {
  mfa_required: boolean;
  challenge_token: string;
  available_methods: string[];
}

/**
 * 403 Forbidden body from /api/v1/auth/login when the tenant requires MFA and
 * this account has none (CONTRACT.md §25.2).
 */
export interface MfaSetupRequiredResponseWire {
  mfa_setup_required: boolean;
  setup_token: string;
}

/** 200 OK body from /api/v1/auth/refresh. */
export interface RefreshSuccessResponseWire {
  expires_in: number;
}

// ---------------------------------------------------------------------------
// Public API types (camelCase, D-18)
// ---------------------------------------------------------------------------

/** The authenticated user's identity, as returned by `login()`/`verifyMfa()` on success. */
export interface AxiamUserInfo {
  /** The user's unique identifier (UUID). */
  id: string;
  /** The user's login username. */
  username: string;
  /** The user's email address. */
  email: string;
  /**
   * Whether this is an **organization-level** principal — CONTRACT.md §5.2.
   *
   * Such a principal's record lives in its organization's reserved tenant, so
   * its global grants apply in every tenant of that organization, and it can
   * act on a different one by sending a different `X-Axiam-Tenant` on the next
   * request — no re-login, because it already is a principal of every tenant
   * there.
   *
   * An ordinary tenant principal is a principal of exactly one tenant, and the
   * same header change for one of those produces a `403`. Check this *before*
   * offering a tenant switch, rather than discovering the answer from a failed
   * request.
   *
   * `false` against a server older than contract 1.31, which is the safe
   * direction: no cross-tenant action offered.
   *
   * Since contract 1.35 that reach can be narrowed per assignment, so this
   * flag alone no longer decides what to offer — consult
   * {@link AxiamUserInfo.reachableTenantIds} as well (§5.2.3 rule 3).
   */
  organizationLevel: boolean;
  /** The tenant this session is **acting on** — CONTRACT.md §5.2.2. */
  tenantId?: string;
  /**
   * The tenant this principal's record **lives in** — CONTRACT.md §5.2.2.
   *
   * This is where the account's own credentials belong, and what a §23
   * registration record for *this* account must be sealed against — see
   * `opaqueEnrollmentForSelf`.
   *
   * Falls back to {@link AxiamUserInfo.tenantId} when the server omits it,
   * which is exactly right there: a server older than contract 1.34 cannot
   * switch the acting tenant, so the two cannot differ.
   */
  principalTenantId?: string;
  /**
   * Slug of {@link AxiamUserInfo.principalTenantId} — `"organization"` for an
   * organization-level principal.
   */
  principalTenantSlug?: string;
  /**
   * The caller's organization as a UUID — CONTRACT.md §5.2.2 rule 3.
   *
   * Read this rather than resolving a slug through `GET
   * /api/v1/organizations`, which is `super-admin`-only and returns only the
   * caller's own organization.
   */
  orgId?: string;
  /**
   * The tenants this caller's roles reach, when narrowed — CONTRACT.md §5.2.3.
   *
   * `undefined` means **unrestricted**, which is both the common case and the
   * only thing a server older than contract 1.35 can mean. A present list is a
   * deliberately narrowed organization-level account: confine any tenant
   * switch to it, because naming anything outside is refused at the header
   * (§5.2.3 rule 4).
   *
   * Note the pairing with {@link AxiamUserInfo.organizationLevel}: a narrowed
   * account still reports `true` there, so gating on that flag alone offers
   * tenants the server will refuse.
   */
  reachableTenantIds?: string[];
}

/**
 * The outcome of AxiamClient.login()/verifyMfa() (D-18).
 *
 * No raw session-token field exists here or anywhere else in the public
 * REST API surface — AXIAM delivers tokens exclusively via `Set-Cookie`
 * (T-17-07).
 */
export type LoginResult =
  | {
      /** Discriminant: MFA is required to complete the login. */
      status: 'mfa_required';
      /** Opaque challenge token to pass to `verifyMfa(mfaToken, code)`. */
      mfaToken: string;
      /** The MFA methods the user has enrolled and may complete the challenge with. */
      availableMethods: string[];
    }
  | {
      /**
       * Discriminant: the tenant requires MFA, this account has none, and the
       * server handed back the token to finish setting one up (§25.2 rule 1).
       *
       * This is an **outcome, not an error**. The server answers `403` here,
       * which §2 would map to `AuthzError` — telling the caller they lack
       * permission to log in, when what the server said was recoverable and
       * came with the means to recover. Pass `setupToken` to `mfaSetupEnroll`,
       * show the user the resulting URI, then `mfaSetupConfirm`, which
       * completes this login.
       */
      status: 'mfa_setup_required';
      /** Opaque token authorizing the `mfaSetupEnroll`/`mfaSetupConfirm` pair. */
      setupToken: Sensitive<string>;
    }
  | {
      /** Discriminant: login completed and a session was established. */
      status: 'authenticated';
      /** The authenticated user's identity. */
      user: AxiamUserInfo;
      /** Opaque session identifier for this authenticated session. */
      sessionId: string;
      /** Access token lifetime in seconds from the time of this response. */
      expiresIn: number;
    };

// ---------------------------------------------------------------------------
// Authz types (FND-04, D-08)
// ---------------------------------------------------------------------------

/** A single access check request, as passed to `checkAccess()`/`can()`/`batchCheck()`. */
export interface AccessCheck {
  /** The action being performed (e.g. `"read"`, `"write"`, `"delete"`). */
  action: string;
  /** The identifier of the resource the action targets. */
  resourceId: string;
  /** Optional sub-resource scope for finer-grained checks. */
  scope?: string;
  /** Optional subject (user/service account) identifier to check on behalf of; defaults to the caller's own identity when omitted. */
  subjectId?: string;
}

/**
 * The result of a REST access check (mirrors `CheckAccessResponseWire`).
 * Shared verbatim with the gRPC transport's `AuthzGrpcClient` result shape
 * (SDK-Q10, C2) — defined once in `core/authz.ts` and re-exported here so
 * both `axiam-sdk/rest` and `axiam-sdk/grpc` consumers see the identical
 * `AccessDecision` type.
 */
export type { AccessDecision };

/** Wire body for POST /api/v1/authz/check (mirrors CheckAccessBody). */
export interface CheckAccessBodyWire {
  action: string;
  resource_id: string;
  scope?: string;
  subject_id?: string;
}

/** Wire response for POST /api/v1/authz/check (mirrors CheckAccessResponse). */
export interface CheckAccessResponseWire {
  allowed: boolean;
  reason?: string;
  /** B1 deny-override decision reason (CONTRACT.md §11 rule 9). */
  reason_code?: string;
}

/** Wire body for POST /api/v1/authz/check/batch. */
export interface BatchCheckAccessBodyWire {
  checks: CheckAccessBodyWire[];
}

/** Wire response for POST /api/v1/authz/check/batch — results in input order. */
export interface BatchCheckAccessResponseWire {
  results: CheckAccessResponseWire[];
}
