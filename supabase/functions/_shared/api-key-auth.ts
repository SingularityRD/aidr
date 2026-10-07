import { retiredSecretActive } from "./key-rotation.ts";
import { membershipActive, sha256 } from "./runtime-policy.ts";

type QueryResult = {
	data: unknown;
	error: unknown;
};

type QueryBuilder = PromiseLike<QueryResult> & {
	select(columns: string): QueryBuilder;
	eq(column: string, value: unknown): QueryBuilder;
	maybeSingle(): PromiseLike<QueryResult>;
};

type DatabaseClient = {
	from(relation: string): QueryBuilder;
	rpc(name: string, args: Record<string, unknown>): PromiseLike<QueryResult>;
};

type ApiKeyRow = {
	id?: string;
	user_id: string;
	tenant_id: string;
	revoked: boolean;
	agent_id?: string | null;
};

type MembershipRow = {
	role: string;
	expires_at: string | null;
};

const API_KEY_MEMBER_ROLES = new Set(["owner", "admin", "member"]);

export type TenantApiKeyAuthResult =
	| { ok: true; userId: string; tenantId: string; apiKeyId?: string; agentId?: string | null }
	| {
		ok: false;
		status: 401 | 403 | 503;
		error: "invalid_api_key" | "tenant_access_denied" | "authorization_unavailable";
	};

function apiKeyRow(value: unknown): ApiKeyRow | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const row = value as Record<string, unknown>;
	if (
		("id" in row && (typeof row.id !== "string" || !row.id)) ||
		typeof row.user_id !== "string" ||
		!row.user_id ||
		typeof row.tenant_id !== "string" ||
		!row.tenant_id ||
		typeof row.revoked !== "boolean" ||
		("agent_id" in row && row.agent_id !== null && typeof row.agent_id !== "string")
	) {
		return null;
	}
	const parsed: ApiKeyRow = {
		user_id: row.user_id,
		tenant_id: row.tenant_id,
		revoked: row.revoked,
	};
	if (typeof row.id === "string") parsed.id = row.id;
	if ("agent_id" in row) parsed.agent_id = row.agent_id as string | null;
	return parsed;
}

function membershipRow(value: unknown): MembershipRow | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const row = value as Record<string, unknown>;
	const expiresAt = row.expires_at;
	if (typeof row.role !== "string") return null;
	if (expiresAt !== null && (typeof expiresAt !== "string" || !expiresAt.trim())) return null;
	return { role: row.role, expires_at: expiresAt };
}

/** API keys are write-capable tenant credentials, so read-only roles fail closed. */
function apiKeyMembershipActive(value: unknown, now = Date.now()): boolean {
	const membership = membershipRow(value);
	return membershipActive(membership, now) && API_KEY_MEMBER_ROLES.has(membership?.role ?? "");
}

function tenantIsActive(value: unknown): boolean {
	return Boolean(
		value &&
			typeof value === "object" &&
			!Array.isArray(value) &&
			(value as Record<string, unknown>).status === "active",
	);
}

/**
 * Authenticates a hash-only API key and binds it to an active tenant membership
 * whose role is allowed to create and operate write-capable keys.
 * Service-role callers must use this guard before reading tenant-scoped data.
 *
 * A renewed key keeps working through its retired hash only while the bounded
 * overlap window recorded by the renew action is still open. A hash that was
 * never recorded, or a window that has closed, is an invalid credential.
 */
export async function authenticateTenantApiKey(
	database: unknown,
	plaintextKey: string,
	now = Date.now(),
): Promise<TenantApiKeyAuthResult> {
	const presentedHash = await sha256(plaintextKey);
	return authenticateTenantApiKeyHash(database, presentedHash, now);
}

/** Re-authenticate a hash held only in trusted server storage. */
export async function authenticateTenantApiKeyHash(
	database: unknown,
	presentedHash: string,
	now = Date.now(),
): Promise<TenantApiKeyAuthResult> {
	if (!/^[a-f0-9]{64}$/.test(presentedHash)) {
		return { ok: false, status: 401, error: "invalid_api_key" };
	}
	const db = database as DatabaseClient;
	let keyResult: QueryResult;
	try {
		keyResult = await db
			.from("api_keys")
			.select("id,user_id,tenant_id,revoked,agent_id")
			.eq("key_hash", presentedHash)
			.maybeSingle();
	} catch {
		return { ok: false, status: 503, error: "authorization_unavailable" };
	}

	if (keyResult.error) {
		return { ok: false, status: 503, error: "authorization_unavailable" };
	}
	let key = apiKeyRow(keyResult.data);

	// Only a miss on the active hash consults the retired hash. A row that
	// matched by its active hash but is revoked is refused outright, so a
	// revoked key can never become resolvable again through an overlap window.
	if (!key) {
		let previousResult: QueryResult;
		try {
			previousResult = await db
				.from("api_keys")
				.select("id,user_id,tenant_id,revoked,agent_id,previous_hash,previous_hash_expires_at")
				.eq("previous_hash", presentedHash)
				.maybeSingle();
		} catch {
			return { ok: false, status: 503, error: "authorization_unavailable" };
		}
		if (previousResult.error) {
			return { ok: false, status: 503, error: "authorization_unavailable" };
		}
		const retired = apiKeyRow(previousResult.data);
		if (retired && !retired.revoked && retiredSecretActive(previousResult.data, presentedHash, now)) {
			key = retired;
		}
	}

	if (!key || key.revoked) {
		return { ok: false, status: 401, error: "invalid_api_key" };
	}

	let membershipResult: QueryResult;
	let tenantResult: QueryResult;
	try {
		[membershipResult, tenantResult] = await Promise.all([
			db
				.from("tenant_members")
				.select("role,expires_at")
				.eq("tenant_id", key.tenant_id)
				.eq("user_id", key.user_id)
				.maybeSingle(),
			db.from("tenants").select("status").eq("id", key.tenant_id).maybeSingle(),
		]);
	} catch {
		return { ok: false, status: 503, error: "authorization_unavailable" };
	}

	if (membershipResult.error || tenantResult.error) {
		return { ok: false, status: 503, error: "authorization_unavailable" };
	}
	if (
		!apiKeyMembershipActive(membershipResult.data, now) ||
		!tenantIsActive(tenantResult.data)
	) {
		return { ok: false, status: 403, error: "tenant_access_denied" };
	}

	// A previously issued key must stop working when its trial expires or an
	// operator revokes its licensed admission. The database also enforces this at
	// event write time, closing the race between this read and ingest.
	let admission: QueryResult;
	try {
		admission = await db.rpc("tenant_admission_capacity", { p_tenant_id: key.tenant_id });
	} catch {
		return { ok: false, status: 503, error: "authorization_unavailable" };
	}
	if (admission.error || !Number.isSafeInteger(admission.data) || (admission.data as number) < 0) {
		return { ok: false, status: 503, error: "authorization_unavailable" };
	}
	if (admission.data === 0) {
		return { ok: false, status: 403, error: "tenant_access_denied" };
	}

	return {
		ok: true,
		userId: key.user_id,
		tenantId: key.tenant_id,
		...(key.id ? { apiKeyId: key.id } : {}),
		...("agent_id" in key ? { agentId: key.agent_id ?? null } : {}),
	};
}

// ---------------------------------------------------------------------------
// Unresolved-credential budget for machine endpoints.
//
// Every machine endpoint hashes the bearer value and looks it up (up to two
// indexed reads, then membership/tenant/admission reads). A flood of random
// bearer values would otherwise turn into unbounded credential lookups. Before
// the lookup, one cheap read checks a deployment-wide, per-endpoint budget of
// *unresolved* credentials in the current minute; only a bearer value that
// resolves to no key is charged to it. Valid keys never consume the budget, so
// ordinary fleet traffic cannot exhaust it; under a flood larger than the budget
// the endpoint answers 429 until the window rolls over (fail closed - a
// documented availability trade-off, bounded per endpoint). Storage errors are
// 503, never an implicit allow.

export const UNRESOLVED_API_KEY_LIMIT_ENV = "AIDR_UNRESOLVED_API_KEY_RL_PER_MIN";
export const DEFAULT_UNRESOLVED_API_KEY_LIMIT_PER_MINUTE = 6000;
const UNRESOLVED_WINDOW_MS = 60_000;

export type BudgetedApiKeyAuthResult =
	| TenantApiKeyAuthResult
	| { ok: false; status: 429 | 503; error: "rate_limited" | "rate_limit_unavailable" };

function readEnv(name: string): string | undefined {
	try {
		const value = (globalThis as { Deno?: { env?: { get(name: string): string | undefined } } }).Deno?.env?.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests fall back to process.env.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
}

/** Configured per-endpoint budget; null when the configured value is invalid. */
export function unresolvedApiKeyLimit(raw = readEnv(UNRESOLVED_API_KEY_LIMIT_ENV)): number | null {
	if (raw === undefined || raw.trim() === "") return DEFAULT_UNRESOLVED_API_KEY_LIMIT_PER_MINUTE;
	if (!/^\d{1,7}$/.test(raw.trim())) return null;
	const value = Number(raw.trim());
	return Number.isSafeInteger(value) && value >= 1 && value <= 1_000_000 ? value : null;
}

export function unresolvedApiKeyBucket(endpoint: string): string {
	return `api-key:v1:unresolved:${endpoint}`;
}

/**
 * authenticateTenantApiKey behind the unresolved-credential budget for
 * `endpoint`. Returns 429 `rate_limited` before any key lookup once the budget
 * is spent, and charges the budget only when the bearer value resolves to no key.
 */
export async function authenticateTenantApiKeyBudgeted(
	database: unknown,
	plaintextKey: string,
	endpoint: string,
	now = Date.now(),
): Promise<BudgetedApiKeyAuthResult> {
	const unavailable = { ok: false, status: 503, error: "rate_limit_unavailable" } as const;
	const limit = unresolvedApiKeyLimit();
	if (limit === null || !/^[a-z0-9-]{1,48}$/.test(endpoint) || !Number.isFinite(now)) return unavailable;
	const db = database as DatabaseClient;
	const key = unresolvedApiKeyBucket(endpoint);
	const windowStart = Math.floor(now / UNRESOLVED_WINDOW_MS);
	let spent: QueryResult;
	try {
		spent = await db.from("rate_limits").select("count").eq("key", key).eq("window_start", windowStart).maybeSingle();
	} catch {
		return unavailable;
	}
	if (spent.error) return unavailable;
	const count = spent.data === null || spent.data === undefined ? 0 : (spent.data as { count?: unknown }).count;
	if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 0) return unavailable;
	if (count >= limit) return { ok: false, status: 429, error: "rate_limited" };

	const result = await authenticateTenantApiKey(database, plaintextKey, now);
	if (!result.ok && result.status === 401) {
		try {
			const charged = await db.rpc("increment_rate_limit", { p_key: key, p_window_start: windowStart, p_delta: 1 });
			if (charged.error) return unavailable;
		} catch {
			return unavailable;
		}
	}
	return result;
}
