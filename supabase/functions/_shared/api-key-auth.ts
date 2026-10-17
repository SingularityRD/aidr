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
	/** NULL for a tenant-owned device key minted through a fleet enrollment key. */
	user_id: string | null;
	fleet_key_id: string | null;
	tenant_id: string;
	revoked: boolean;
	agent_id?: string | null;
	scope: ApiKeyScope;
	install_limit: number | null;
	expires_at: string | null;
};

const API_KEY_COLUMNS = "id,user_id,tenant_id,revoked,agent_id,scope,install_limit,expires_at,fleet_key_id";

/**
 * True when the key row carries an expiry that has passed (CP-8). A row without
 * the column (NULL or absent) never expires; a present but unparseable value is
 * treated as expired so a corrupt expiry fails closed.
 */
export function apiKeyExpired(expiresAt: string | null, now: number): boolean {
	if (expiresAt === null) return false;
	const at = Date.parse(expiresAt);
	return !Number.isFinite(at) || at <= now;
}

type MembershipRow = {
	role: string;
	expires_at: string | null;
};

const API_KEY_MEMBER_ROLES = new Set(["owner", "admin", "member"]);

export type TenantApiKeyAuthResult =
	| {
		ok: true;
		/**
		 * The person who owns a personal key. `null` for a tenant-owned device
		 * key (see `fleetKeyId`): no person's membership authorizes it.
		 */
		userId: string | null;
		/** Set only for a tenant-owned device key: the fleet key that minted it. */
		fleetKeyId?: string;
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
	const fleetKeyId = row.fleet_key_id ?? null;
	if (fleetKeyId !== null && (typeof fleetKeyId !== "string" || !fleetKeyId)) return null;
	// Exactly one owner. A tenant-owned key is a full, agent-bound device key
	// with a row id (20261016000300_fleet_keys_tenant_owned.sql).
	if (fleetKeyId === null
		? typeof row.user_id !== "string" || !row.user_id
		: row.user_id !== null || typeof row.id !== "string" || !row.id ||
			typeof row.agent_id !== "string" || !row.agent_id || row.scope !== "tenant") {
		return null;
	}
	if (
		("id" in row && (typeof row.id !== "string" || !row.id)) ||
		typeof row.tenant_id !== "string" ||
		!row.tenant_id ||
		typeof row.revoked !== "boolean" ||
		("agent_id" in row && row.agent_id !== null && typeof row.agent_id !== "string") ||
		// The type is always selected; a row without a known one is not a credential.
		!isApiKeyScope(row.scope) ||
		(row.expires_at !== undefined && row.expires_at !== null && typeof row.expires_at !== "string")
	) {
		return null;
	}
	const installLimit = row.install_limit ?? null;
	if (row.scope === "tenant" ? installLimit !== null
		: !Number.isSafeInteger(installLimit) || (installLimit as number) < 1) {
		return null;
	}
	const parsed: ApiKeyRow = {
		user_id: fleetKeyId === null ? (row.user_id as string) : null,
		fleet_key_id: fleetKeyId,
		tenant_id: row.tenant_id,
		revoked: row.revoked,
		scope: row.scope,
		install_limit: installLimit as number | null,
		expires_at: typeof row.expires_at === "string" ? row.expires_at : null,
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

/** The fleet key row exists in the key's tenant and has not been revoked. */
function fleetKeyActive(value: unknown, fleetKeyId: string, tenantId: string): boolean {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as Record<string, unknown>;
	return row.id === fleetKeyId && row.tenant_id === tenantId && row.revoked_at === null;
}

/**
 * Rate-limit subject for an authenticated key: the owning person for a
 * personal key, the device key itself for a tenant-owned one.
 */
export function apiKeyRateSubject(auth: { userId: string | null; apiKeyId?: string }): string {
	return auth.userId ?? `api_key:${auth.apiKeyId}`;
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
 * whose role is allowed to create and operate write-capable keys, or, for a
 * tenant-owned device key minted by a fleet enrollment key (`userId` null,
 * `fleetKeyId` set), to that fleet key being unrevoked. Either way the tenant
 * must be active and admitted.
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

	// An expired key is an invalid credential for its active and retired secret
	// alike; clients already treat `invalid_api_key` as "stop and re-enroll".
	if (!key || key.revoked || apiKeyExpired(key.expires_at, now)) {
		return { ok: false, status: 401, error: "invalid_api_key" };
	}
	// Refuse a narrower key before any tenant state is read on its behalf. An
	// ingest key must carry its row id: the installation cap is bound to it.
	if (!allowedScopes.includes(key.scope) || (key.scope !== "tenant" && !key.id)) {
		return { ok: false, status: 403, error: "api_key_scope_denied" };
	}

	// A personal key is authorized by its owner's live membership. A
	// tenant-owned device key is authorized by its unrevoked fleet key instead,
	// so removing or deprovisioning the person who issued that fleet key does
	// not take the fleet down. Both need an active tenant.
	const fleetKeyId = key.fleet_key_id;
	let ownerResult: QueryResult;
	let tenantResult: QueryResult;
	try {
		[ownerResult, tenantResult] = await Promise.all([
			fleetKeyId === null
				? db
					.from("tenant_members")
					.select("role,expires_at")
					.eq("tenant_id", key.tenant_id)
					.eq("user_id", key.user_id)
					.maybeSingle()
				: db
					.from("fleet_enrollment_keys")
					.select("id,tenant_id,revoked_at")
					.eq("id", fleetKeyId)
					.eq("tenant_id", key.tenant_id)
					.maybeSingle(),
			db.from("tenants").select("status").eq("id", key.tenant_id).maybeSingle(),
		]);
	} catch {
		return { ok: false, status: 503, error: "authorization_unavailable" };
	}

	if (ownerResult.error || tenantResult.error) {
		return { ok: false, status: 503, error: "authorization_unavailable" };
	}
	const ownerActive = fleetKeyId === null
		? apiKeyMembershipActive(ownerResult.data, now)
		: fleetKeyActive(ownerResult.data, fleetKeyId, key.tenant_id);
	if (!ownerActive || !tenantIsActive(tenantResult.data)) {
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
		...(fleetKeyId !== null ? { fleetKeyId } : {}),
		tenantId: key.tenant_id,
		...(key.id ? { apiKeyId: key.id } : {}),
		...("agent_id" in key ? { agentId: key.agent_id ?? null } : {}),
		scope: key.scope,
		installLimit: key.install_limit,
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

const UNRESOLVED_API_KEY_LIMIT_ENV = "AIDR_UNRESOLVED_API_KEY_RL_PER_MIN";
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
	options: TenantApiKeyAuthOptions = {},
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

	const result = await authenticateTenantApiKey(database, plaintextKey, now, options);
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
