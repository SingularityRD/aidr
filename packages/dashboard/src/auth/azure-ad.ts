/**
 * Azure AD (Microsoft Entra ID) SSO integration for AIDR Dashboard.
 *
 * Provides OAuth 2.0 authentication via Supabase's built-in Azure provider,
 * ID token validation. Directory group-to-role provisioning is not available
 * from the browser; tenant access is granted by server-side membership only.
 *
 * ## Configuration
 *
 * Requires the following environment variables:
 * - `VITE_AZURE_AD_TENANT_ID` – Azure AD tenant ID (or "common" for multi-tenant)
 *
 * The Azure AD application must be registered in the Azure Portal and configured
 * as an OAuth provider in the Supabase dashboard under Authentication > Providers > Azure.
 *
 * ## Verified Groups
 *
 * Group claims in browser session metadata are not authoritative. The dashboard
 * reads a caller-scoped server projection; any returned role is display-only and
 * protected actions must re-authorize server-side membership.
 *
 * @module
 */

import { supabase } from "../lib/supabase";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Configuration options for the Azure AD authentication flow.
 */
export interface AzureADConfig {
	/** The Azure AD tenant ID. Use "common" for multi-tenant or a specific GUID. */
	tenantId: string;
	/** URL to redirect to after authentication. Defaults to `${origin}/auth/callback`. */
	redirectTo: string;
	/** OAuth scopes to request. Defaults to OpenID, profile, and email. */
	scopes: string[];
}

/**
 * A directory group returned by the server-owned verified projection.
 */
interface AzureADGroup {
	/** The immutable directory external ID. Never derive this from displayName. */
	id: string;
	/** The same immutable external ID in the server response. */
	externalId: string;
	/** The display name returned by the verified server projection. */
	displayName: string;
	/** Optional display-only mapping; browser code must not use it for authorization. */
	role?: "admin" | "member" | "viewer";
	/** The control-plane tenant owning this verified group. */
	tenantId: string;
	description?: string;
}

/**
 * Azure AD user information extracted from the authenticated session.
 */
export interface AzureADUser {
	/** The user's unique identifier in our system (Supabase user ID). */
	id: string;
	/** The user's email address. */
	email: string;
	/** The Azure AD tenant ID the user belongs to. */
	tenantId: string;
	/** Verified directory groups. Empty until server-side group sync is enabled. */
	groups: AzureADGroup[];
}

/**
 * Represents a caller-scoped read of the server-owned group projection.
 */
export interface GroupSyncResult {
	/** The groups returned by the verified projection. */
	syncedGroups: AzureADGroup[];
	/** The authenticated user ID the projection was returned for. */
	userId: string;
	/** Projection-generation timestamp; this is not a directory sync claim. */
	syncedAt: string;
}

// ---------------------------------------------------------------------------
// Custom Error
// ---------------------------------------------------------------------------

/**
 * Error thrown when Azure AD authentication operations fail.
 *
 * Carries a machine-readable `code` and optional HTTP `status` in addition to
 * the human-readable `message`.
 */
export class AzureADError extends Error {
	/** A machine-readable error code (e.g. "SIGN_IN_FAILED", "TOKEN_INVALID"). */
	public readonly code: string;
	/** The HTTP status code if the error originated from an HTTP request. */
	public readonly status?: number;

	constructor(message: string, code: string, status?: number) {
		super(message);
		this.name = "AzureADError";
		this.code = code;
		this.status = status;
	}
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_SCOPES: string[] = ["openid", "profile", "email"];
const MAX_VERIFIED_GROUPS = 500;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const CALLBACK_PATH = "/auth/callback";

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Reads the Azure AD tenant ID from the environment.
 *
 * Checks `import.meta.env` first (Vite build-time replacement), then falls
 * back to `process.env` (runtime), and ultimately defaults to `"common"`
 * for multi-tenant applications.
 */
function readTenantId(): string {
	const runtimeTenant =
		typeof process !== "undefined" ? process.env.VITE_AZURE_AD_TENANT_ID : undefined;
	return (
		(import.meta.env as Record<string, string | undefined>).VITE_AZURE_AD_TENANT_ID ??
		runtimeTenant ??
		"common"
	);
}

/**
 * Returns the default configuration merged with environment variables.
 *
 * The redirect URL defaults to a relative path so it works regardless of
 * the current origin. Supabase resolves relative redirect URLs against the
 * application's origin automatically. Callers may pass an explicit
 * `redirectTo` to override this.
 */
function getDefaultConfig(): AzureADConfig {
	return {
		tenantId: readTenantId(),
		redirectTo: CALLBACK_PATH,
		scopes: [...DEFAULT_SCOPES],
	};
}

/**
 * Validates that a session object contains the expected Azure AD claims.
 *
 * Checks for the presence of required fields and returns a parsed
 * `AzureADUser` if valid. Throws `AzureADError` if validation fails.
 *
 * @param session - The Supabase session to validate.
 * @returns A validated `AzureADUser` with group information.
 * @throws {AzureADError} If the session is missing required Azure AD claims.
 */
function validateAzureADSession(
	session: NonNullable<Awaited<ReturnType<typeof supabase.auth.getSession>>["data"]["session"]>,
): AzureADUser {
	const { user } = session;
	const provider = user.app_metadata?.provider;

	if (provider !== "azure") {
		throw new AzureADError("Session was not created via Azure AD authentication", "WRONG_PROVIDER");
	}

	const email = user.email;
	if (!email) {
		throw new AzureADError("Azure AD session is missing email claim", "MISSING_EMAIL");
	}

	const tenantId = String(user.app_metadata?.issuer ?? "")
		.replace("https://login.microsoftonline.com/", "")
		.replace("/v2.0", "")
		.replace("/", "");

	if (!tenantId) {
		throw new AzureADError("Azure AD session is missing tenant ID", "MISSING_TENANT_ID");
	}

	return {
		id: user.id,
		email,
		tenantId,
		// Never turn client-visible metadata into a trusted directory membership.
		groups: [],
	};
}

function invalidGroupsResponse(): never {
	throw new AzureADError("The verified group response was invalid.", "GROUPS_RESPONSE_INVALID");
}

function canonicalString(item: Record<string, unknown>, key: string): string | null {
	const value = item[key];
	return typeof value === "string" && value.trim() === value ? value : null;
}

function verifiedRole(item: Record<string, unknown>): AzureADGroup["role"] {
	if (item.role === undefined) return undefined;
	if (item.role !== "admin" && item.role !== "member" && item.role !== "viewer")
		return invalidGroupsResponse();
	return item.role;
}

function verifiedGroup(raw: unknown): AzureADGroup {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return invalidGroupsResponse();
	const item = raw as Record<string, unknown>;
	if (["externalId", "displayName", "tenantId"].some((key) => Object.hasOwn(item, key)))
		return invalidGroupsResponse();
	const immutableId = canonicalString(item, "external_id");
	const displayName = canonicalString(item, "display_name");
	const resourceId = canonicalString(item, "id");
	const tenantId = canonicalString(item, "tenant_id");
	if (
		!immutableId ||
		immutableId.length > 255 ||
		displayName === null ||
		resourceId !== immutableId ||
		tenantId === null ||
		!UUID.test(tenantId)
	)
		return invalidGroupsResponse();
	const role = verifiedRole(item);
	return {
		id: immutableId,
		externalId: immutableId,
		displayName,
		tenantId,
		...(role ? { role } : {}),
	};
}

function parseVerifiedGroups(data: unknown, userId: string): GroupSyncResult {
	if (!data || typeof data !== "object" || Array.isArray(data)) return invalidGroupsResponse();
	const payload = data as {
		ok?: unknown;
		user_id?: unknown;
		groups?: unknown;
		synced_at?: unknown;
	};
	if (
		payload.ok !== true ||
		payload.user_id !== userId ||
		!Array.isArray(payload.groups) ||
		payload.groups.length > MAX_VERIFIED_GROUPS ||
		typeof payload.synced_at !== "string" ||
		Number.isNaN(Date.parse(payload.synced_at))
	)
		return invalidGroupsResponse();
	const syncedGroups = payload.groups.map(verifiedGroup);
	const groupKeys = syncedGroups.map((group) => `${group.tenantId}:${group.externalId}`);
	if (new Set(groupKeys).size !== groupKeys.length) return invalidGroupsResponse();
	return { syncedGroups, userId, syncedAt: payload.synced_at };
}

async function fetchVerifiedGroups() {
	try {
		return await supabase.functions.invoke<{ groups?: unknown; synced_at?: unknown }>(
			"azure-ad-groups",
			{ method: "GET" },
		);
	} catch {
		throw new AzureADError("Failed to fetch verified directory groups.", "GROUPS_FETCH_FAILED");
	}
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Initiates the Azure AD OAuth 2.0 sign-in flow via Supabase Auth.
 *
 * Redirects the browser to the Microsoft login page. After successful
 * authentication, the user is returned to the configured `redirectTo` URL
 * (defaults to `/auth/callback`), where `handleAzureADCallback` should be
 * called to complete the flow.
 *
 * @param config - Optional overrides for tenant ID, redirect URL, or OAuth scopes.
 *
 * @throws {AzureADError} If the OAuth redirect fails.
 *
 * @example
 * ```ts
 * import { signInWithAzureAD } from "../auth/azure-ad";
 *
 * function LoginButton() {
 *   return <button onClick={() => signInWithAzureAD()}>Sign in with Microsoft</button>;
 * }
 * ```
 */
export async function signInWithAzureAD(config?: Partial<AzureADConfig>): Promise<void> {
	const merged: AzureADConfig = { ...getDefaultConfig(), ...config };
	const { tenantId, redirectTo, scopes } = merged;

	const { error } = await supabase.auth.signInWithOAuth({
		provider: "azure",
		options: {
			redirectTo,
			scopes: scopes.join(" "),
			queryParams: tenantId !== "common" ? { domain_hint: tenantId } : undefined,
		},
	});

	if (error) {
		throw new AzureADError(error.message, "SIGN_IN_FAILED", error.status);
	}
}

/**
 * Completes the Azure AD authentication flow by validating the current
 * Supabase session and extracting Azure AD user details.
 *
 * This function should be called after the OAuth callback redirects back
 * to the application (typically from `AuthCallbackPage` or a dedicated
 * Azure AD callback handler).
 *
 * It validates that:
 * - The session was created via the Azure AD provider
 * - Required claims (email, tenant ID) are present
 *
 * Directory groups are fetched separately through `getAzureADGroups`, which
 * reads only the server-owned verified projection.
 *
 * @returns A validated `AzureADUser` with group information.
 *
 * @throws {AzureADError} If there is no active session, the provider is not Azure AD,
 *                        or required claims are missing.
 *
 * @example
 * ```ts
 * import { handleAzureADCallback } from "../auth/azure-ad";
 *
 * async function onCallback() {
 *   try {
 *     const user = await handleAzureADCallback();
 *     console.log(`Authenticated ${user.email} in tenant ${user.tenantId}`);
 *     console.log(`Groups:`, user.groups.map(g => g.displayName));
 *   } catch (err) {
 *     console.error("Azure AD callback failed:", err);
 *   }
 * }
 * ```
 */
export async function handleAzureADCallback(): Promise<AzureADUser> {
	const { data, error } = await supabase.auth.getSession();

	if (error) {
		throw new AzureADError(error.message, "SESSION_FETCH_FAILED", error.status);
	}

	if (!data.session) {
		throw new AzureADError(
			"No active session found. Ensure `signInWithAzureAD` was called first " +
				"and the OAuth callback has completed.",
			"NO_SESSION",
		);
	}

	return validateAzureADSession(data.session);
}

/**
 * Fetches the read-only, server-verified directory groups for the session user.
 *
 * The browser session is used only to authenticate the request and to guard
 * against rendering a different user's response. Group membership, roles,
 * display names, and immutable external IDs all come from the Edge response;
 * user/app metadata is never consulted as an authority source.
 *
 * @param userId - The Supabase user ID expected in the current session.
 * @returns A verified group projection. An empty array is a valid response.
 * @throws {AzureADError} If the session or verified response cannot be trusted.
 */
export async function getAzureADGroups(userId: string): Promise<GroupSyncResult> {
	const { data: sessionData, error: sessionError } = await supabase.auth.getSession();

	if (sessionError) {
		throw new AzureADError(sessionError.message, "SESSION_FETCH_FAILED", sessionError.status);
	}

	if (!sessionData.session) {
		throw new AzureADError(
			"No active session found. User must be signed in to fetch groups.",
			"NO_SESSION",
		);
	}

	const { user } = sessionData.session;
	if (user.id !== userId) {
		throw new AzureADError(
			"User ID mismatch: the authenticated user does not match the requested user ID.",
			"USER_ID_MISMATCH",
		);
	}

	const result = await fetchVerifiedGroups();
	if (!result || typeof result !== "object") {
		throw new AzureADError(
			"The verified group response was unavailable.",
			"GROUP_SYNC_UNAVAILABLE",
		);
	}
	if (result.error) {
		throw new AzureADError(
			"Failed to fetch verified directory groups.",
			"GROUPS_FETCH_FAILED",
			result.error.status,
		);
	}
	return parseVerifiedGroups(result.data, user.id);
}

/**
 * Legacy compatibility hook. Group display names are not a valid authority
 * source, so this never grants a tenant role.
 *
 * @param groupDisplayName - The display name of the Azure AD group.
 * @returns The mapped team role, or `undefined` if no mapping exists.
 *
 */
export function mapGroupToRole(
	_groupDisplayName: string,
): "admin" | "member" | "viewer" | undefined {
	return undefined;
}
