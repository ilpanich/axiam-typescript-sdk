/**
 * Pagination for the §27 management surface.
 *
 * Twenty of the 146 operations take `offset`/`limit` and answer with the
 * envelope `{ items, total, offset, limit }`. The other thirteen collection
 * reads answer with a bare array and are **not** paginated — §27.4 rule 4
 * forbids modelling those as a page, because a `Page` reporting
 * `total === items.length` is indistinguishable from a real one right up to
 * the moment a caller relies on `total`.
 */

/**
 * Where a paginated read starts, and how much of it to take.
 *
 * `limit` is deliberately optional with no SDK-side default: §27.4 rule 4
 * forbids silently truncating, and a client-side default does exactly that
 * while leaving the caller no way to tell a short page from a complete one.
 */
export interface PageRequest {
  /** How many items to skip. Defaults to `0`. */
  offset?: number;
  /** How many items to take. Omitted lets the server decide. */
  limit?: number;
}

/** One page of a paginated management read. */
export interface Page<T> {
  /** The items on this page. */
  items: T[];
  /** How many items exist in the whole set, across every page. */
  total: number;
  /** The offset this page starts at. */
  offset: number;
  /** The page size the server applied. */
  limit: number;
}

/**
 * The query parameters a {@link PageRequest} contributes.
 *
 * `limit` is omitted entirely when unset rather than sent as `0` — the server
 * reads `limit=0` as "none", which would return an empty page.
 *
 * @internal
 */
export function pageQuery(page: PageRequest): Record<string, string | undefined> {
  return {
    offset: String(page.offset ?? 0),
    limit: page.limit === undefined ? undefined : String(page.limit),
  };
}

/** Whether another page follows `page`. */
export function hasMore<T>(page: Page<T>): boolean {
  return page.items.length > 0 && page.offset + page.items.length < page.total;
}

/**
 * Walk a paginated read to exhaustion, concatenating every page.
 *
 * The `list_all` shape §27.4 rule 4 requires. The walk stops on an empty page
 * even when `total` disagrees, so a misreporting server costs one wasted
 * request rather than an unbounded loop.
 *
 * @internal — each generated `list` exposes this as its own `…All` method.
 */
export async function collectPages<T>(
  start: PageRequest,
  fetch: (page: PageRequest) => Promise<Page<T>>,
): Promise<T[]> {
  let request: PageRequest = { offset: start.offset ?? 0, limit: start.limit };
  const out: T[] = [];
  for (;;) {
    const page = await fetch(request);
    out.push(...page.items);
    const next = page.offset + page.items.length;
    if (page.items.length === 0 || next >= page.total) return out;
    request = { offset: next, limit: request.limit };
  }
}
