/**
 * Tests for Azure AD SSO integration.
 *
 * Covers:
 * - signInWithAzureAD: OAuth initiation, error handling
 * - handleAzureADCallback: session validation, claim extraction, error states
 * - getAzureADGroups: metadata extraction, edge function fallback, user mismatch
 * - mapGroupToRole: display name to role mapping
 */

import type * as SupabaseModule from "@supabase/supabase-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Hoist mock variables so they're available when vi.mock factories run (vitest hoists those).
const { mockSignInWithOAuth, mockGetSession, mockFunctionsInvoke } = vi.hoisted(() => ({
	mockSignInWithOAuth: vi.fn(),
	mockGetSession: vi.fn(),
	mockFunctionsInvoke: vi.fn(),
}));

// Mock the supabase module before importing anything under test
vi.mock("@supabase/supabase-js", async () => {
	const actual = await vi.importActual<typeof SupabaseModule>("@supabase/supabase-js");
	return {
		...actual,
		createClient: vi.fn(),
	};
});

vi.mock("../../lib/supabase", () => ({
	supabase: {
		auth: {
			signInWithOAuth: mockSignInWithOAuth,
			getSession: mockGetSession,
		},
		functions: {
			invoke: mockFunctionsInvoke,
		},
	},
	supabaseEnvError: null,
}));

import {
	AzureADError,
	getAzureADGroups,
	handleAzureADCallback,
	mapGroupToRole,
	signInWithAzureAD,
} from "../../auth/azure-ad";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function createMockSession(userOverrides?: Record<string, unknown>) {
	return {
		access_token: "mock-access-token",
		refresh_token: "mock-refresh-token",
		expires_in: 3600,
		expires_at: Date.now() / 1000 + 3600,
		token_type: "bearer",
		user: {
			id: "user-123",
			aud: "authenticated",
			role: "authenticated",
			email: "admin@contoso.com",
			created_at: "2025-01-01T00:00:00Z",
			app_metadata: {
				provider: "azure",
				issuer: "https://login.microsoftonline.com/tenant-guid/v2.0",
			},
			user_metadata: {
				azure_ad_groups: [
					{ id: "group-admin", displayName: "AIDR-Admins" },
					{ id: "group-dev", displayName: "AIDR-Developers" },
				],
			},
			...userOverrides,
		},
	};
}

interface SupabaseSession {
	access_token: string;
	refresh_token: string;
	expires_in: number;
	expires_at?: number;
	token_type: string;
	user: {
		id: string;
		aud: string;
		role: string;
		email: string | null;
		created_at: string;
		app_metadata: Record<string, unknown>;
		user_metadata: Record<string, unknown>;
		[prop: string]: unknown;
	};
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
	process.env.VITE_AZURE_AD_TENANT_ID = "tenant-guid";
	mockSignInWithOAuth.mockClear();
	mockGetSession.mockClear();
	mockFunctionsInvoke.mockClear();
});

afterEach(() => {
	delete process.env.VITE_AZURE_AD_TENANT_ID;
	vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// signInWithAzureAD
// ---------------------------------------------------------------------------

describe("signInWithAzureAD", () => {
	it("calls supabase.auth.signInWithOAuth with azure provider and default config", async () => {
		mockSignInWithOAuth.mockResolvedValueOnce({ error: null });

		await signInWithAzureAD();

		expect(mockSignInWithOAuth).toHaveBeenCalledOnce();
		expect(mockSignInWithOAuth).toHaveBeenCalledWith({
			provider: "azure",
			options: {
				redirectTo: "/auth/callback",
				scopes: expect.stringContaining("openid"),
				queryParams: { domain_hint: "tenant-guid" },
			},
		});
	});

	it("passes custom tenant and redirect URL", async () => {
		mockSignInWithOAuth.mockResolvedValueOnce({ error: null });

		await signInWithAzureAD({
			tenantId: "custom-tenant",
			redirectTo: "https://other.app/callback",
		});

		expect(mockSignInWithOAuth).toHaveBeenCalledWith({
			provider: "azure",
			options: {
				redirectTo: "https://other.app/callback",
				scopes: expect.stringContaining("openid"),
				queryParams: { domain_hint: "custom-tenant" },
			},
		});
	});

	it("omits domain_hint when tenant is common", async () => {
		mockSignInWithOAuth.mockResolvedValueOnce({ error: null });
		process.env.VITE_AZURE_AD_TENANT_ID = "common";

		await signInWithAzureAD();

		expect(mockSignInWithOAuth).toHaveBeenCalledWith({
			provider: "azure",
			options: {
				redirectTo: "/auth/callback",
				scopes: expect.stringContaining("openid"),
				queryParams: undefined,
			},
		});
	});

	it("throws AzureADError when OAuth fails", async () => {
		mockSignInWithOAuth.mockResolvedValueOnce({
			error: { message: "Provider not configured", status: 400 },
		});

		const promise = signInWithAzureAD();
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toThrow("Provider not configured");
	});

	it("throws AzureADError with SIGN_IN_FAILED code on failure", async () => {
		mockSignInWithOAuth.mockResolvedValueOnce({
			error: { message: "Invalid provider", status: 400 },
		});

		const promise = signInWithAzureAD();
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toHaveProperty("code", "SIGN_IN_FAILED");
		await expect(promise).rejects.toHaveProperty("status", 400);
	});
});

// ---------------------------------------------------------------------------
// handleAzureADCallback
// ---------------------------------------------------------------------------

describe("handleAzureADCallback", () => {
	it("returns validated AzureADUser for a valid Azure AD session", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession() },
			error: null,
		});

		const result = await handleAzureADCallback();

		expect(result.id).toBe("user-123");
		expect(result.email).toBe("admin@contoso.com");
		expect(result.tenantId).toBe("tenant-guid");
		expect(result.groups).toHaveLength(2);
		const firstGroup = result.groups[0];
		expect(firstGroup).toBeDefined();
		expect(firstGroup?.id).toBe("group-admin");
		expect(firstGroup?.displayName).toBe("AIDR-Admins");
	});

	it("throws AzureADError when there is no active session", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: null },
			error: null,
		});

		const promise = handleAzureADCallback();
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toThrow("No active session");
	});

	it("throws AzureADError when session fetch errors", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: null },
			error: { message: "Network error", status: 500 },
		});

		const promise = handleAzureADCallback();
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toThrow("Network error");
	});

	it("throws AzureADError when provider is not azure", async () => {
		const session = createMockSession({
			app_metadata: { provider: "google" },
		});
		mockGetSession.mockResolvedValueOnce({
			data: { session },
			error: null,
		});

		const promise = handleAzureADCallback();
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toThrow("Session was not created via Azure AD");
	});

	it("throws AzureADError when email is missing", async () => {
		const session = createMockSession({ email: null });
		mockGetSession.mockResolvedValueOnce({
			data: { session },
			error: null,
		});

		const promise = handleAzureADCallback();
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toThrow("missing email");
	});

	it("throws AzureADError when tenant ID cannot be determined", async () => {
		const session = createMockSession({
			app_metadata: { provider: "azure" },
		});
		mockGetSession.mockResolvedValueOnce({
			data: { session },
			error: null,
		});

		const promise = handleAzureADCallback();
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toThrow("missing tenant ID");
	});

	it("handles empty groups array gracefully", async () => {
		const session = createMockSession({
			user_metadata: {},
		});
		mockGetSession.mockResolvedValueOnce({
			data: { session },
			error: null,
		});

		const result = await handleAzureADCallback();
		expect(result.groups).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// getAzureADGroups
// ---------------------------------------------------------------------------

describe("getAzureADGroups", () => {
	it("returns cached groups from user metadata", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession() },
			error: null,
		});

		const result = await getAzureADGroups("user-123");

		expect(result.userId).toBe("user-123");
		expect(result.syncedGroups).toHaveLength(2);
		const firstSynced = result.syncedGroups[0];
		expect(firstSynced).toBeDefined();
		expect(firstSynced?.displayName).toBe("AIDR-Admins");
		expect(result.syncedAt).toBeDefined();
	});

	it("throws AzureADError when no active session exists", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: null },
			error: null,
		});

		const promise = getAzureADGroups("user-123");
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toThrow("No active session");
	});

	it("throws AzureADError on user ID mismatch", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession() },
			error: null,
		});

		const promise = getAzureADGroups("user-456");
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toThrow("User ID mismatch");
	});

	it("falls back to edge function when metadata has no groups", async () => {
		const session = createMockSession({
			user_metadata: {},
		});
		mockGetSession.mockResolvedValueOnce({
			data: { session },
			error: null,
		});
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: {
				groups: [{ id: "group-func-1", displayName: "Graph-Admins" }],
			},
			error: null,
		});

		const result = await getAzureADGroups("user-123");

		expect(result.syncedGroups).toHaveLength(1);
		const graphGroup = result.syncedGroups[0];
		expect(graphGroup).toBeDefined();
		expect(graphGroup?.displayName).toBe("Graph-Admins");
		expect(mockFunctionsInvoke).toHaveBeenCalledWith("azure-ad-groups", {
			body: { userId: "user-123" },
		});
	});

	it("throws AzureADError when edge function fails", async () => {
		const session = createMockSession({
			user_metadata: {},
		});
		mockGetSession.mockResolvedValueOnce({
			data: { session },
			error: null,
		});
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: null,
			error: { message: "Function not found" },
		});

		const promise = getAzureADGroups("user-123");
		await expect(promise).rejects.toThrow(AzureADError);
		await expect(promise).rejects.toThrow("Failed to fetch Azure AD groups");
	});

	it("handles edge function returning empty groups array", async () => {
		const session = createMockSession({
			user_metadata: {},
		});
		mockGetSession.mockResolvedValueOnce({
			data: { session },
			error: null,
		});
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: { groups: [] },
			error: null,
		});

		const result = await getAzureADGroups("user-123");
		expect(result.syncedGroups).toEqual([]);
	});

	it("extracts groups from app_metadata when user_metadata is empty", async () => {
		const session = createMockSession({
			user_metadata: {},
			app_metadata: {
				provider: "azure",
				issuer: "https://login.microsoftonline.com/tenant-guid/v2.0",
				azure_ad_groups: [{ id: "app-group-1", displayName: "App-Group" }],
			},
		});
		mockGetSession.mockResolvedValueOnce({
			data: { session },
			error: null,
		});

		const result = await getAzureADGroups("user-123");
		expect(result.syncedGroups).toHaveLength(1);
		const appGroup = result.syncedGroups[0];
		expect(appGroup).toBeDefined();
		expect(appGroup?.displayName).toBe("App-Group");
	});

	it("prefers user_metadata groups over app_metadata groups", async () => {
		const session = createMockSession({
			user_metadata: {
				azure_ad_groups: [{ id: "um-1", displayName: "UserMeta-Group" }],
			},
			app_metadata: {
				provider: "azure",
				issuer: "https://login.microsoftonline.com/tenant-guid/v2.0",
				azure_ad_groups: [{ id: "am-1", displayName: "AppMeta-Group" }],
			},
		});
		mockGetSession.mockResolvedValueOnce({
			data: { session },
			error: null,
		});

		const result = await getAzureADGroups("user-123");
		expect(result.syncedGroups).toHaveLength(1);
		const umGroup = result.syncedGroups[0];
		expect(umGroup).toBeDefined();
		expect(umGroup?.id).toBe("um-1");
	});
});

// ---------------------------------------------------------------------------
// mapGroupToRole
// ---------------------------------------------------------------------------

describe("mapGroupToRole", () => {
	it('maps "AIDR-Admins" to admin', () => {
		expect(mapGroupToRole("AIDR-Admins")).toBe("admin");
	});

	it('maps "AIDR-Developers" to member', () => {
		expect(mapGroupToRole("AIDR-Developers")).toBe("member");
	});

	it('maps "Engineering" to member', () => {
		expect(mapGroupToRole("Engineering")).toBe("member");
	});

	it('maps "ReadOnly-Viewers" to viewer', () => {
		expect(mapGroupToRole("ReadOnly-Viewers")).toBe("viewer");
	});

	it("returns undefined for unmapped group names", () => {
		expect(mapGroupToRole("Everyone")).toBeUndefined();
	});

	it("is case-insensitive", () => {
		expect(mapGroupToRole("aidr-admins")).toBe("admin");
		expect(mapGroupToRole("AIDR-ADMINS")).toBe("admin");
	});
});

// ---------------------------------------------------------------------------
// AzureADError
// ---------------------------------------------------------------------------

describe("AzureADError", () => {
	it("sets name to AzureADError", () => {
		const err = new AzureADError("test", "TEST_CODE");
		expect(err.name).toBe("AzureADError");
	});

	it("preserves code and status", () => {
		const err = new AzureADError("Not found", "NOT_FOUND", 404);
		expect(err.code).toBe("NOT_FOUND");
		expect(err.status).toBe(404);
	});

	it("defaults status to undefined when not provided", () => {
		const err = new AzureADError("test", "TEST");
		expect(err.status).toBeUndefined();
	});
});
