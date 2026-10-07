/**
 * Bounded, paged PostgREST reads.
 *
 * The API caps every response at `max_rows` (supabase/config.toml: 1000) and
 * does so silently: a `.limit(2000)` request simply comes back with 1000 rows.
 * Callers that need more than one page read with `.range()` page by page, up
 * to an explicit bound, and get told when rows were left out so the UI can
 * say so instead of presenting a partial list as complete.
 */

/** Matches `max_rows` in supabase/config.toml. */
export const API_MAX_ROWS = 1000;

type PageResult = PromiseLike<{
	data: unknown;
	error: unknown;
	count?: number | null;
}>;

export type PagedRead =
	| {
			ok: true;
			rows: unknown[];
			/** Total matching rows reported by the server, when it reported one. */
			total: number | null;
			/** True when matching rows exist beyond `rows` (bound or server cap reached). */
			truncated: boolean;
	  }
	| { ok: false };

/**
 * Read up to `max` rows. `page(from, to)` must build the query with a stable
 * order (add a unique tie-breaker such as `id`), `.range(from, to)` and, on the
 * first page at least, `{ count: "exact" }` so truncation is detected even if
 * the server cap is lower than {@link API_MAX_ROWS}.
 */
export async function readAllPages(
	page: (from: number, to: number) => PageResult,
	max: number,
	pageSize: number = API_MAX_ROWS,
): Promise<PagedRead> {
	const rows: unknown[] = [];
	let total: number | null = null;
	for (let from = 0; from < max; from += pageSize) {
		const to = Math.min(from + pageSize, max) - 1;
		const { data, error, count } = await page(from, to);
		if (error || !Array.isArray(data)) return { ok: false };
		if (from === 0 && typeof count === "number" && Number.isSafeInteger(count) && count >= 0)
			total = count;
		rows.push(...data);
		if (data.length < to - from + 1) break;
		if (total !== null && rows.length >= total) break;
	}
	const truncated = total !== null ? total > rows.length : rows.length >= max;
	return { ok: true, rows, total, truncated };
}
