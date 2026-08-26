/**
 * The §27.4 rule 7 error sub-types.
 *
 * §2 fixes the taxonomy at three error types and §27 does not widen it. What
 * it adds is a *classification* inside two of them, because a management
 * surface produces refusals §2 never had to describe — §2 has no 404 row at
 * all, since nothing before §27 could return one.
 *
 * TypeScript has real subclassing, so these are subclasses: every
 * `catch (e) { if (e instanceof AuthzError) … }` written before §27 keeps
 * working, and a caller who needs the distinction narrows further.
 */

import { AuthzError, NetworkError } from '../core/errors.js';

/** One field-level complaint inside a {@link ValidationError}. */
export interface FieldError {
  /** The offending field's name, as the server names it. */
  field: string;
  /** What is wrong with it. */
  message: string;
}

/**
 * HTTP 404 — the resource does not exist, **or** belongs to another tenant.
 *
 * The server answers identically in both cases on purpose: a distinguishable
 * "exists but not yours" lets a caller enumerate another tenant's ids. That is
 * why this is an {@link AuthzError} rather than a category of its own — in a
 * multi-tenant IAM the two really are one outcome.
 */
export class NotFoundError extends AuthzError {
  /** The registry operation that found nothing, e.g. `"users.get"`. */
  readonly operation: string;

  constructor(operation: string, message: string) {
    super(message);
    this.name = 'NotFoundError';
    this.operation = operation;
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

/**
 * HTTP 409 — a uniqueness or state conflict, such as a role name already taken.
 *
 * Never retried (§27.4 rule 8): a 409 is the server telling the truth, not a
 * transient fault, and a retry produces the identical answer one round-trip
 * later.
 */
export class ConflictError extends AuthzError {
  /** The registry operation that conflicted. */
  readonly operation: string;

  constructor(operation: string, message: string) {
    super(message);
    this.name = 'ConflictError';
    this.operation = operation;
    Object.setPrototypeOf(this, ConflictError.prototype);
  }
}

/**
 * HTTP 400/422 — the request was rejected.
 *
 * §2 maps 400 to `NetworkError`, described as an "SDK programming error". That
 * description was written when nothing but the SDK itself could produce a 400.
 * On this surface a 400 is usually a *user's* invalid input — an email that is
 * not an email, a slug already taken — and an application needs to tell that
 * from a broken socket without matching on message text. The parent type is
 * inherited from §2 rather than chosen here.
 */
export class ValidationError extends NetworkError {
  /** The HTTP status the server answered with — 400 or 422. */
  readonly status: number;
  /** The registry operation that was rejected. */
  readonly operation: string;
  /** Per-field detail, where the server sent any. Empty is normal. */
  readonly fields: FieldError[];

  constructor(operation: string, status: number, message: string, fields: FieldError[]) {
    super(message);
    this.name = 'ValidationError';
    this.status = status;
    this.operation = operation;
    this.fields = fields;
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

/**
 * Pull field-level detail out of an error body, on a best-effort basis.
 *
 * Two shapes are recognised — an array of `{field, message}` and an object
 * keyed by field name. A body in neither shape yields no fields rather than an
 * error: failing to parse an error body would replace a useful message with a
 * useless one.
 *
 * @internal
 */
export function parseFieldErrors(body: unknown): FieldError[] {
  if (!body || typeof body !== 'object') return [];
  const errors = (body as { errors?: unknown }).errors;
  if (Array.isArray(errors)) {
    return errors.filter(
      (e): e is FieldError =>
        !!e && typeof e === 'object' && typeof (e as FieldError).field === 'string',
    );
  }
  if (errors && typeof errors === 'object') {
    return Object.entries(errors as Record<string, unknown>)
      .filter(([, v]) => typeof v === 'string')
      .map(([field, message]) => ({ field, message: message as string }));
  }
  return [];
}
