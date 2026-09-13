/**
 * Tests for Azure AD SSO integration.
 *
 * Covers:
 * - signInWithAzureAD: OAuth initiation, error handling
 * - handleAzureADCallback: session validation without trusting metadata groups
 * - getAzureADGroups: explicit unsupported state and user mismatch
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
	it("rejects browser metadata groups, including an admin-like name, without calling an absent Edge function", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession() },
			error: null,
		});

		await expect(getAzureADGroups("user-123")).rejects.toMatchObject({
			code: "GROUP_SYNC_UNAVAILABLE",
		});
		expect(mockFunctionsInvoke).not.toHaveBeenCalled();
	});

	it("rejects an app_metadata group as an authority source", async () => {
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
		await expect(getAzureADGroups("user-123")).rejects.toMatchObject({
			code: "GROUP_SYNC_UNAVAILABLE",
		});
		expect(mockFunctionsInvoke).not.toHaveBeenCalled();
	});

	it("rejects when no active session exists", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: null },
			error: null,
		});
		await expect(getAzureADGroups("user-123")).rejects.toMatchObject({ code: "NO_SESSION" });
	});

	it("rejects user ID mismatch before reporting unsupported sync", async () => {
		mockGetSession.mockResolvedValueOnce({
			data: { session: createMockSession() },
			error: null,
		});
		await expect(getAzureADGroups("user-456")).rejects.toMatchObject({ code: "USER_ID_MISMATCH" });
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
