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
export function apiKeyMembershipActive(value: unknown, now = Date.now()): boolean {
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
