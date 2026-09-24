// @vitest-environment jsdom

import { afterEach, describe, expect, it } from "vitest";
import {
	buildReturnToFromRequest,
	sanitizeReturnTo,
	setPostAuthReturnTo,
	takePostAuthReturnTo,
} from "../ui/return-to";

const STORAGE_KEY = "aidr.postAuthReturnTo.v1";

describe("post-auth return paths", () => {
	afterEach(() => localStorage.clear());

	it("preserves an internal route, query, and fragment", () => {
		expect(sanitizeReturnTo("/enterprise?invite=abc#accept")).toBe("/enterprise?invite=abc#accept");
	});

	it.each([
		"https://attacker.example/",
		"//attacker.example/",
		"/\\\\attacker.example/",
		"/%2f%2fattacker.example/",
		"/admin%0d%0aLocation:%20https://attacker.example/",
	])("rejects unsafe return path %s", (value) => {
		expect(sanitizeReturnTo(value)).toBe("/onboarding");
	});

	it("takes a pending path once and falls back if storage was tampered with", () => {
		setPostAuthReturnTo("/dashboard?tab=agents");
		expect(takePostAuthReturnTo()).toBe("/dashboard?tab=agents");
		expect(takePostAuthReturnTo()).toBeNull();

		localStorage.setItem(STORAGE_KEY, "//attacker.example/");
		expect(takePostAuthReturnTo()).toBeNull();
		expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
	});

	it("builds the protected request path without accepting its origin", () => {
		expect(
			buildReturnToFromRequest(new Request("https://dashboard.example/settings?tab=security")),
		).toBe("/settings?tab=security");
	});
});
