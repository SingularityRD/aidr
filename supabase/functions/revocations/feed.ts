export const MAX_REVOCATION_ROWS = 5000;
const UUID_TEXT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type RevocationRow = {
	kind: string;
	value: string;
	tenant_id: string | null;
};

type QueryResult = { data: RevocationRow[] | null; error: unknown; count: number | null };

export type RevocationTable = {
	select(columns: string, options: { count: "exact" }): {
		or(filters: string): {
			order(column: string, options: { ascending: boolean }): {
				limit(count: number): PromiseLike<QueryResult>;
			};
		};
	};
};

export async function loadRevocationRows(
	table: RevocationTable,
	tenantId: string,
): Promise<{ ok: true; rows: RevocationRow[] } | { ok: false; error: string }> {
	if (!UUID_TEXT.test(tenantId)) return { ok: false, error: "invalid_revocation_tenant" };
	// Apply scope before the cap. A global cap followed by in-memory tenant
	// filtering could sign an incomplete feed when other tenants add rows.
	const { data, error, count } = await table.select("kind,value,tenant_id", { count: "exact" })
		.or(`tenant_id.is.null,tenant_id.eq.${tenantId}`)
		.order("id", { ascending: false })
		.limit(MAX_REVOCATION_ROWS + 1);
	if (error || !Array.isArray(data) || !Number.isSafeInteger(count) || Number(count) < 0) {
		return { ok: false, error: "db_error" };
	}
	if (Number(count) > MAX_REVOCATION_ROWS) {
		return { ok: false, error: "revocation_feed_capacity_exceeded" };
	}
	// PostgREST can impose a lower server-side max_rows than our requested
	// limit. The exact count prevents signing a silently truncated response.
	if (data.length !== count) return { ok: false, error: "revocation_feed_incomplete" };
	if (data.some((row) => row.tenant_id !== null && row.tenant_id !== tenantId)) {
		return { ok: false, error: "revocation_scope_mismatch" };
	}
	return { ok: true, rows: data };
}
