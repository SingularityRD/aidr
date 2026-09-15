/**
 * Tests for Azure AD SSO integration.
 *
 * Covers:
 * - signInWithAzureAD: OAuth initiation, error handling
 * - handleAzureADCallback: session validation without trusting metadata groups
 * - getAzureADGroups: server-verified groups, metadata rejection, and user mismatch
 * - mapGroupToRole: no role grant from unverified display names
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
		expect(result.groups).toEqual([]);
		expect(mockFunctionsInvoke).not.toHaveBeenCalled();
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
	it("ignores browser metadata groups, including an admin-like name, and reads the server projection", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession() },
			error: null,
		});
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: {
				ok: true,
				user_id: "user-123",
				groups: [
					{
						id: "verified-id",
						external_id: "verified-id",
						display_name: "Verified Group",
						tenant_id: "11111111-1111-4111-8111-111111111111",
					},
				],
				synced_at: "2026-09-13T00:00:00.000Z",
			},
			error: null,
		});

		await expect(getAzureADGroups("user-123")).resolves.toMatchObject({
			syncedGroups: [
				{ id: "verified-id", externalId: "verified-id", displayName: "Verified Group" },
			],
		});
		expect(mockFunctionsInvoke).toHaveBeenCalledWith("azure-ad-groups", { method: "GET" });
	});

	it("does not treat an app_metadata group as an authority source", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: {
				session: createMockSession({
					user_metadata: {},
					app_metadata: {
						provider: "azure",
						issuer: "https://login.microsoftonline.com/tenant-guid/v2.0",
						azure_ad_groups: [{ id: "attacker", displayName: "AIDR-Admins" }],
					},
				}),
			},
			error: null,
		});
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: {
				ok: true,
				user_id: "user-123",
				groups: [],
				synced_at: "2026-09-13T00:00:00.000Z",
			},
			error: null,
		});
		await expect(getAzureADGroups("user-123")).resolves.toMatchObject({ syncedGroups: [] });
		expect(mockFunctionsInvoke).toHaveBeenCalledOnce();
	});

	it("rejects when no active session exists", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: null },
			error: null,
		});
		await expect(getAzureADGroups("user-123")).rejects.toMatchObject({ code: "NO_SESSION" });
	});

	it("rejects user ID mismatch before fetching the server projection", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession() },
			error: null,
		});
		await expect(getAzureADGroups("user-456")).rejects.toMatchObject({ code: "USER_ID_MISMATCH" });
	});
});

describe("verified getAzureADGroups response", () => {
	it("uses the read-only Edge response and preserves immutable external ids", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession({ user_metadata: {} }) },
			error: null,
		});
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: {
				ok: true,
				user_id: "user-123",
				groups: [
					{
						id: "immutable-group-id",
						external_id: "immutable-group-id",
						display_name: "Renamed Admins",
						tenant_id: "11111111-1111-4111-8111-111111111111",
						role: "admin",
					},
				],
				synced_at: "2026-09-13T00:00:00.000Z",
			},
			error: null,
		});

		await expect(getAzureADGroups("user-123")).resolves.toEqual({
			syncedGroups: [
				{
					id: "immutable-group-id",
					externalId: "immutable-group-id",
					displayName: "Renamed Admins",
					tenantId: "11111111-1111-4111-8111-111111111111",
					role: "admin",
				},
			],
			userId: "user-123",
			syncedAt: "2026-09-13T00:00:00.000Z",
		});
		expect(mockFunctionsInvoke).toHaveBeenCalledWith("azure-ad-groups", { method: "GET" });
	});

	it("rejects a server envelope bound to a different user", async () => {
		mockGetSession.mockResolvedValueOnce({ data: { session: createMockSession() }, error: null });
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: { ok: true, user_id: "other-user", groups: [], synced_at: "2026-09-13T00:00:00.000Z" },
			error: null,
		});
		await expect(getAzureADGroups("user-123")).rejects.toMatchObject({
			code: "GROUPS_RESPONSE_INVALID",
		});
	});

	it("does not return forged browser metadata when the server projection is empty", async () => {
		mockGetSession.mockResolvedValueOnce({ data: { session: createMockSession() }, error: null });
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: {
				ok: true,
				user_id: "user-123",
				groups: [],
				synced_at: "2026-09-13T00:00:00.000Z",
			},
			error: null,
		});

		await expect(getAzureADGroups("user-123")).resolves.toMatchObject({ syncedGroups: [] });
		expect(mockFunctionsInvoke).toHaveBeenCalledOnce();
	});

	it("rejects a malformed server group instead of falling back to display name", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession({ user_metadata: {} }) },
			error: null,
		});
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: { groups: [{ display_name: "AIDR-Admins" }] },
			error: null,
		});
		await expect(getAzureADGroups("user-123")).rejects.toMatchObject({
			code: "GROUPS_RESPONSE_INVALID",
		});
	});

	it("rejects an internal resource id when the immutable external id is absent", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession({ user_metadata: {} }) },
			error: null,
		});
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: { groups: [{ id: "internal-row-id", display_name: "Verified" }] },
			error: null,
		});
		await expect(getAzureADGroups("user-123")).rejects.toMatchObject({
			code: "GROUPS_RESPONSE_INVALID",
		});
	});

	it.each([
		{
			external_id: "group-a",
			externalId: "group-b",
			display_name: "Conflict",
			id: "group-a",
			tenant_id: "11111111-1111-4111-8111-111111111111",
		},
		{
			external_id: "",
			externalId: "group-a",
			display_name: "Empty alias",
			id: "group-a",
			tenant_id: "11111111-1111-4111-8111-111111111111",
		},
		{
			external_id: "group-a",
			display_name: "Conflict",
			displayName: "Other",
			id: "group-a",
			tenant_id: "11111111-1111-4111-8111-111111111111",
		},
		{
			external_id: "group-a",
			display_name: "Invalid role",
			role: "owner",
			id: "group-a",
			tenant_id: "11111111-1111-4111-8111-111111111111",
		},
		{
			external_id: "group-a",
			display_name: "Invalid tenant",
			id: "group-a",
			tenant_id: "not-a-uuid",
		},
	])("rejects an inconsistent verified group response", async (group) => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession({ user_metadata: {} }) },
			error: null,
		});
		mockFunctionsInvoke.mockResolvedValueOnce({
			data: {
				ok: true,
				user_id: "user-123",
				groups: [group],
				synced_at: "2026-09-13T00:00:00.000Z",
			},
			error: null,
		});
		await expect(getAzureADGroups("user-123")).rejects.toMatchObject({
			code: "GROUPS_RESPONSE_INVALID",
		});
	});
});

// ---------------------------------------------------------------------------
// mapGroupToRole
// ---------------------------------------------------------------------------

describe("mapGroupToRole", () => {
	it.each([
		"AIDR-Admins",
		"AIDR-ADMINS",
		"Engineering",
		"ReadOnly-Viewers",
		"Everyone",
	])("does not grant a tenant role from display name %s", (name) => {
		expect(mapGroupToRole(name)).toBeUndefined();
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
