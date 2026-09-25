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

/**
 * Key types. `tenant` is the write-capable tenant credential used by the
 * endpoint connectors. `ingest:browser_guard` is the Browser Guard telemetry
 * key (supabase/migrations/20260925000061_browser_guard_ingest_keys.sql): it
 * is only honoured by /v1/ingest, for counts-only `privacy_scan` and
 * `shadow_ai_usage` events from the `browser_guard` runtime, up to its
 * installation limit.
 */
const API_KEY_SCOPES = ["tenant", "ingest:browser_guard"] as const;
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number];
export const BROWSER_GUARD_INGEST_SCOPE: ApiKeyScope = "ingest:browser_guard";

function isApiKeyScope(value: unknown): value is ApiKeyScope {
	return typeof value === "string" && (API_KEY_SCOPES as readonly string[]).includes(value);
}

type ApiKeyRow = {
	id?: string;
	user_id: string;
	tenant_id: string;
	revoked: boolean;
	agent_id?: string | null;
	scope: ApiKeyScope;
	install_limit: number | null;
};

const API_KEY_COLUMNS = "id,user_id,tenant_id,revoked,agent_id,scope,install_limit";

type MembershipRow = {
	role: string;
	expires_at: string | null;
};

const API_KEY_MEMBER_ROLES = new Set(["owner", "admin", "member"]);

export type TenantApiKeyAuthResult =
	| {
		ok: true;
		userId: string;
		tenantId: string;
		apiKeyId?: string;
		agentId?: string | null;
		scope: ApiKeyScope;
		installLimit: number | null;
	}
	| {
		ok: false;
		status: 401 | 403 | 503;
		error:
			| "invalid_api_key"
			| "tenant_access_denied"
			| "authorization_unavailable"
			| "api_key_scope_denied";
	};

export type TenantApiKeyAuthOptions = {
	/**
	 * Key types the calling endpoint honours. Defaults to `tenant` only, so a
	 * narrower key is refused everywhere that does not opt in explicitly.
	 */
	allowedScopes?: readonly ApiKeyScope[];
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
		("agent_id" in row && row.agent_id !== null && typeof row.agent_id !== "string") ||
		// The type is always selected; a row without a known one is not a credential.
		!isApiKeyScope(row.scope)
	) {
		return null;
	}
	const installLimit = row.install_limit ?? null;
	if (row.scope === "tenant" ? installLimit !== null
		: !Number.isSafeInteger(installLimit) || (installLimit as number) < 1) {
		return null;
	}
	const parsed: ApiKeyRow = {
		user_id: row.user_id,
		tenant_id: row.tenant_id,
		revoked: row.revoked,
		scope: row.scope,
		install_limit: installLimit as number | null,
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
	options: TenantApiKeyAuthOptions = {},
): Promise<TenantApiKeyAuthResult> {
	const presentedHash = await sha256(plaintextKey);
	return authenticateTenantApiKeyHash(database, presentedHash, now, options);
}

/** Re-authenticate a hash held only in trusted server storage. */
export async function authenticateTenantApiKeyHash(
	database: unknown,
	presentedHash: string,
	now = Date.now(),
	options: TenantApiKeyAuthOptions = {},
): Promise<TenantApiKeyAuthResult> {
	const allowedScopes = options.allowedScopes ?? ["tenant"];
	if (!/^[a-f0-9]{64}$/.test(presentedHash)) {
		return { ok: false, status: 401, error: "invalid_api_key" };
	}
	const db = database as DatabaseClient;
	let keyResult: QueryResult;
	try {
		keyResult = await db
			.from("api_keys")
			.select(API_KEY_COLUMNS)
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
				.select(`${API_KEY_COLUMNS},previous_hash,previous_hash_expires_at`)
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
	// Refuse a narrower key before any tenant state is read on its behalf. An
	// ingest key must carry its row id: the installation cap is bound to it.
	if (!allowedScopes.includes(key.scope) || (key.scope !== "tenant" && !key.id)) {
		return { ok: false, status: 403, error: "api_key_scope_denied" };
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
		scope: key.scope,
		installLimit: key.install_limit,
	};
}
