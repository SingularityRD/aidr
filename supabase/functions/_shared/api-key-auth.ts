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
};

type ApiKeyRow = {
	user_id: string;
	tenant_id: string;
	revoked: boolean;
};

type MembershipRow = {
	expires_at: string | null;
};

export type TenantApiKeyAuthResult =
	| { ok: true; userId: string; tenantId: string }
	| {
		ok: false;
		status: 401 | 403 | 503;
		error: "invalid_api_key" | "tenant_access_denied" | "authorization_unavailable";
	};

function apiKeyRow(value: unknown): ApiKeyRow | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const row = value as Record<string, unknown>;
	if (
		typeof row.user_id !== "string" ||
		!row.user_id ||
		typeof row.tenant_id !== "string" ||
		!row.tenant_id ||
		typeof row.revoked !== "boolean"
	) {
		return null;
	}
	return {
		user_id: row.user_id,
		tenant_id: row.tenant_id,
		revoked: row.revoked,
	};
}

function membershipRow(value: unknown): MembershipRow | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const expiresAt = (value as Record<string, unknown>).expires_at;
	if (expiresAt !== null && (typeof expiresAt !== "string" || !expiresAt.trim())) return null;
	return { expires_at: expiresAt };
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
 * Authenticates a hash-only API key and binds it to an active tenant membership.
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
	const db = database as DatabaseClient;
	const presentedHash = await sha256(plaintextKey);
	let keyResult: QueryResult;
	try {
		keyResult = await db
			.from("api_keys")
			.select("user_id,tenant_id,revoked")
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
				.select("user_id,tenant_id,revoked,previous_hash,previous_hash_expires_at")
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
				.select("expires_at")
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
	if (!membershipActive(membershipRow(membershipResult.data), now) || !tenantIsActive(tenantResult.data)) {
		return { ok: false, status: 403, error: "tenant_access_denied" };
	}

	return { ok: true, userId: key.user_id, tenantId: key.tenant_id };
}
