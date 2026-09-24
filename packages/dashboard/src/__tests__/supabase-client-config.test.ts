import { describe, expect, it } from "vitest";
import { DASHBOARD_AUTH_OPTIONS } from "../lib/supabase";

describe("dashboard Supabase auth client", () => {
	it("requires explicit callback exchange and uses the PKCE code flow", () => {
		expect(DASHBOARD_AUTH_OPTIONS).toMatchObject({
			flowType: "pkce",
			detectSessionInUrl: false,
			persistSession: true,
			autoRefreshToken: true,
		});
	});
});
