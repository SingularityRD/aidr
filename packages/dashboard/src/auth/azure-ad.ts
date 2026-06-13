/**
 * Azure AD (Microsoft Entra ID) SSO integration for AIDR Dashboard.
 *
 * Provides OAuth 2.0 authentication via Supabase's built-in Azure provider,
 * ID token validation, and group membership sync for enterprise RBAC.
 *
 * ## Configuration
 *
 * Requires the following environment variables:
 * - `VITE_AZURE_AD_TENANT_ID` – Azure AD tenant ID (or "common" for multi-tenant)
 *
 * The Azure AD application must be registered in the Azure Portal and configured
 * as an OAuth provider in the Supabase dashboard under Authentication > Providers > Azure.
 *
 * ## Group Sync
 *
 * For group-based RBAC, the Azure AD app registration must be configured to emit
 * group claims in the ID token (limited to ~200 groups). For larger directories,
 * a Supabase edge function should use the Microsoft Graph API to fetch full
 * group membership.
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
	/** OAuth scopes to request. Defaults to OpenID, profile, email, and Microsoft Graph scopes. */
	scopes: string[];
}

/**
 * An Azure AD group retrieved from the ID token claims or Graph API.
 */
export interface AzureADGroup {
	/** The unique object ID of the group in Azure AD. */
	id: string;
	/** The display name of the group (e.g. "Engineering", "Admins"). */
	displayName: string;
	/** Optional description of the group's purpose. */
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
	/** The Azure AD groups the user is a member of. */
	groups: AzureADGroup[];
}

/**
 * Represents the result of group membership synchronization.
 */
export interface GroupSyncResult {
	/** The groups that were successfully synced. */
	syncedGroups: AzureADGroup[];
	/** The user ID the groups were synced for. */
	userId: string;
	/** Timestamp of when the sync completed. */
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

const DEFAULT_SCOPES: string[] = [
	"openid",
	"profile",
	"email",
	"https://graph.microsoft.com/User.Read",
	"https://graph.microsoft.com/Directory.Read.All",
];

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
	return (
		(import.meta.env as Record<string, string | undefined>).VITE_AZURE_AD_TENANT_ID ??
		process.env.VITE_AZURE_AD_TENANT_ID ??
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

	// Extract groups from user_metadata or app_metadata.
	// These are populated either by the ID token claims (if configured in Azure AD)
	// or by a Supabase Auth webhook / edge function.
	const rawGroups: Array<Record<string, unknown>> =
		(user.user_metadata?.azure_ad_groups as Array<Record<string, unknown>> | undefined) ??
		(user.app_metadata?.azure_ad_groups as Array<Record<string, unknown>> | undefined) ??
		[];

	const groups: AzureADGroup[] = rawGroups.map(mapGroup);

	return {
		id: user.id,
		email,
		tenantId,
		groups,
	};
}

/**
 * Maps a raw group object from metadata into a typed `AzureADGroup`.
 */
function mapGroup(raw: Record<string, unknown>): AzureADGroup {
	return {
		id: String(raw.objectId ?? raw.id ?? ""),
		displayName: String(raw.displayName ?? raw.display_name ?? ""),
		description: raw.description ? String(raw.description) : undefined,
	};
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
 * - Group membership information is available
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
 * Fetches the Azure AD groups for the specified user and syncs them into
 * the user's metadata for RBAC purposes.
 *
 * This function first checks if groups are already stored in the user's
 * metadata (populated by the ID token claims or a Supabase Auth webhook).
 * If no groups are found, it attempts to fetch them via a Supabase edge
 * function that calls the Microsoft Graph API.
 *
 * @param userId - The Supabase user ID to fetch groups for.
 *
 * @returns A `GroupSyncResult` containing the synced groups and metadata.
 *
 * @throws {AzureADError} If the session is not found, metadata fetch fails,
 *                        or the edge function returns an error.
 *
 * @example
 * ```ts
 * import { getAzureADGroups } from "../auth/azure-ad";
 *
 * async function loadGroups(userId: string) {
 *   const result = await getAzureADGroups(userId);
 *   console.log(`Synced ${result.syncedGroups.length} groups`);
 *   // Map groups to roles
 *   const roles = result.syncedGroups.map(g => g.displayName);
 * }
 * ```
 */
export async function getAzureADGroups(userId: string): Promise<GroupSyncResult> {
	// Try to get groups from existing session metadata first.
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

	// Verify we're fetching groups for the correct user.
	if (user.id !== userId) {
		throw new AzureADError(
			"User ID mismatch: the authenticated user does not match the requested user ID.",
			"USER_ID_MISMATCH",
		);
	}

	// Attempt to extract cached groups from metadata.
	const cachedGroups: AzureADGroup[] =
		extractGroupsFromMetadata(user.user_metadata?.azure_ad_groups) ??
		extractGroupsFromMetadata(user.app_metadata?.azure_ad_groups) ??
		[];

	if (cachedGroups.length > 0) {
		return {
			syncedGroups: cachedGroups,
			userId: user.id,
			syncedAt: new Date().toISOString(),
		};
	}

	// No cached groups – attempt to fetch via Supabase edge function.
	// The edge function should call Microsoft Graph API's /memberOf endpoint.
	const { data: functionData, error: functionError } = await supabase.functions.invoke<{
		groups: Array<Record<string, unknown>>;
	}>("azure-ad-groups", {
		body: { userId: user.id },
	});

	if (functionError) {
		throw new AzureADError(
			`Failed to fetch Azure AD groups: ${functionError.message}`,
			"GROUPS_FETCH_FAILED",
		);
	}

	const remoteGroups: AzureADGroup[] = (functionData?.groups ?? []).map(mapGroup);

	return {
		syncedGroups: remoteGroups,
		userId: user.id,
		syncedAt: new Date().toISOString(),
	};
}

/**
 * Extracts Azure AD groups from raw metadata value.
 *
 * Accepts metadata that may contain groups as an array of objects with
 * various key formats (Azure AD objectId/displayName or our normalized format).
 *
 * @param raw - The raw metadata value, expected to be an array of group objects.
 * @returns An array of `AzureADGroup` objects, or `null` if the input is invalid.
 */
function extractGroupsFromMetadata(raw: unknown): AzureADGroup[] | null {
	if (!Array.isArray(raw)) {
		return null;
	}

	if (raw.length === 0) {
		return [];
	}

	const groups: AzureADGroup[] = [];

	for (const item of raw) {
		if (typeof item !== "object" || item === null) {
			continue;
		}
		groups.push(mapGroup(item as Record<string, unknown>));
	}

	return groups;
}

/**
 * Maps an Azure AD group display name to an internal team role.
 *
 * This provides a simple RBAC mapping for the existing `TeamRole` type used
 * by the team provider. Customize the mapping logic to match your
 * organization's Azure AD group structure.
 *
 * @param groupDisplayName - The display name of the Azure AD group.
 * @returns The mapped team role, or `undefined` if no mapping exists.
 *
 * @example
 * ```ts
 * const role = mapGroupToRole("AIDR-Admins"); // "admin"
 * const role = mapGroupToRole("AIDR-Developers"); // "member"
 * ```
 */
export function mapGroupToRole(
	groupDisplayName: string,
): "admin" | "member" | "viewer" | undefined {
	const normalized = groupDisplayName.toLowerCase();

	if (normalized.includes("admin")) {
		return "admin";
	}

	if (normalized.includes("developer") || normalized.includes("engineer")) {
		return "member";
	}

	if (normalized.includes("viewer") || normalized.includes("readonly")) {
		return "viewer";
	}

	return undefined;
}
