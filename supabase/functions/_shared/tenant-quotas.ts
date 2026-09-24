// Per-tenant storage-byte reservation for the private audit-export bucket.
//
// `consume_tenant_rate_limit` covers request counts. Stored bytes are a
// different resource: the object outlives the request that created it, so the
// size is reserved in the database *before* the object is uploaded and released
// when the retention ledger row is deleted. Failures are availability failures,
// never an implicit allow, and a quota rejection is never retried against a
// different limiter.

export type TenantStorageQuotaResult =
	| { ok: true; remainingBytes: number }
	| {
			ok: false;
			status: 409 | 413 | 429 | 503;
			error: "legal_hold_active" | "export_page_too_large" | "tenant_storage_quota_exceeded" | "export_retention_unavailable";
			remainingBytes: number;
	  };

type RpcResult = { data: unknown; error: unknown };
type RpcClient = {
	rpc(name: string, parameters: Record<string, unknown>): PromiseLike<RpcResult>;
};

/** Largest single export page the route will store (matches the caller's 413 check). */
export const AUDIT_EXPORT_MAX_OBJECT_BYTES = 8 * 1024 * 1024;

/** Default per-tenant byte budget for stored exports when the operator sets none. */
const AUDIT_EXPORT_TENANT_BYTES_DEFAULT = 512 * 1024 * 1024;

/** Hard ceiling the database enforces: a configured budget may not exceed it. */
const AUDIT_EXPORT_TENANT_BYTES_CEILING = 1024 * 1024 * 1024 * 1024;

/**
 * Reads the operator-configured tenant byte budget. An unset, malformed or
 * out-of-range value falls back to the documented default instead of disabling
 * the quota.
 */
export function tenantStorageLimitBytes(readEnv: (name: string) => string | null | undefined): number {
	const raw = (readEnv("AIDR_AUDIT_EXPORT_TENANT_BYTES") ?? "").trim();
	if (!/^[0-9]{1,15}$/.test(raw)) return AUDIT_EXPORT_TENANT_BYTES_DEFAULT;
	const parsed = Number(raw);
	return Number.isSafeInteger(parsed) && parsed >= 1 && parsed <= AUDIT_EXPORT_TENANT_BYTES_CEILING
		? parsed
		: AUDIT_EXPORT_TENANT_BYTES_DEFAULT;
}

function rpcRow(value: unknown): Record<string, unknown> | null {
	if (Array.isArray(value) && value.length !== 1) return null;
	const row = Array.isArray(value) ? value[0] : value;
	return row && typeof row === "object" && !Array.isArray(row)
		? (row as Record<string, unknown>)
		: null;
}

/**
 * Reserves `bytes` of the tenant's storage budget through one atomic RPC and
 * records the reservation in the retention ledger the caller's upload path
 * already depends on. A rejection is authoritative (429); an unreadable or
 * malformed result fails closed (503).
 */
export async function registerAuditExportObject(
	database: unknown,
	input: {
		tenantId: string;
		actorUserId: string;
		path: string;
		bytes: number;
		limitBytes: number;
	},
): Promise<TenantStorageQuotaResult> {
	const unavailable = {
		ok: false,
		status: 503,
		error: "export_retention_unavailable",
		remainingBytes: 0,
	} as const;
	if (
		!input.tenantId ||
		!input.actorUserId ||
		!/^[0-9a-f-]{36}\/[0-9a-f-]{36}\.(csv|json)$/i.test(input.path) ||
		!Number.isSafeInteger(input.bytes) ||
		input.bytes < 1 ||
		!Number.isSafeInteger(input.limitBytes) ||
		input.limitBytes < 1 ||
		input.limitBytes > AUDIT_EXPORT_TENANT_BYTES_CEILING
	) {
		return unavailable;
	}
	if (input.bytes > AUDIT_EXPORT_MAX_OBJECT_BYTES) {
		return { ok: false, status: 413, error: "export_page_too_large", remainingBytes: 0 };
	}

	let result: RpcResult;
	try {
		result = await (database as RpcClient).rpc("register_audit_export_object", {
			p_tenant_id: input.tenantId,
			p_actor_user_id: input.actorUserId,
			p_path: input.path,
			p_bytes: input.bytes,
			p_limit_bytes: input.limitBytes,
		});
	} catch {
		return unavailable;
	}
	if (!result || typeof result !== "object") return unavailable;
	if (result.error) {
		const error = result.error as { code?: unknown; message?: unknown };
		return error.code === "55000" && error.message === "active_legal_hold"
			? { ok: false, status: 409, error: "legal_hold_active", remainingBytes: 0 }
			: unavailable;
	}

	const row = rpcRow(result.data);
	const remaining = row?.remaining_bytes;
	if (
		!row ||
		typeof row.allowed !== "boolean" ||
		typeof remaining !== "number" ||
		!Number.isSafeInteger(remaining) ||
		remaining < 0
	) {
		return unavailable;
	}
	if (!row.allowed) {
		return {
			ok: false,
			status: 429,
			error: "tenant_storage_quota_exceeded",
			remainingBytes: remaining,
		};
	}
	return { ok: true, remainingBytes: remaining };
}
