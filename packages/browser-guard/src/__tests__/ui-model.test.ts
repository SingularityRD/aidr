import { describe, expect, it } from "vitest";
import { ADAPTERS } from "../sites/index";
import { ENTITY_TYPES, type GuardPolicy, type GuardStats, type LiteralRule } from "../types";
import { formatMessage } from "../ui/i18n";
import {
	ENTITY_GROUPS,
	errorKeyFor,
	expectOk,
	GuardRequestError,
	LITERAL_MAX_COUNT,
	policyFromResponse,
	protectionStatus,
	SUPPORTED_SITES,
	siteForUrl,
	statsFromResponse,
	toggleEntity,
	toggleSite,
	topEntityTypes,
	validateLiteral,
	validateTelemetry,
} from "../ui/model";
import { blockedSiteFromUrl } from "../ui/render-blocked";
import { restoreToggle } from "../ui/render-popup";

const POLICY: GuardPolicy = {
	version: 1,
	mode: "auto",
	enabledEntities: ["EMAIL", "IBAN"],
	neverRestore: ["SECRET"],
	literals: [],
	exactData: [],
	detectSignals: true,
	signalAction: "warn",
	blockedSites: [],
	disabledSites: [],
	allowUserPause: true,
	allowSendAnyway: true,
	maskPaste: true,
	fileHandling: "scan",
	maxFileBytes: 5 * 1024 * 1024,
	restoreResponses: true,
	useNativeHost: false,
	telemetry: null,
	language: "auto",
	managedKeys: [],
	policyId: "aidr-browser-guard-default",
};

const STATS: GuardStats = {
	site: null,
	protectedPrompts: 0,
	maskedItems: 0,
	blockedSends: 0,
	byType: {},
	pausedUntil: null,
	nativeHost: "disabled",
};

describe("validateLiteral", () => {
	it("accepts a trimmed single-line term of 2..256 characters", () => {
		expect(validateLiteral("  Project Falcon  ", "INTERNAL", [])).toEqual({
			ok: true,
			rule: { value: "Project Falcon", type: "INTERNAL" },
		});
		expect(validateLiteral("ab", "PERSON", []).ok).toBe(true);
		expect(validateLiteral("x".repeat(256), "INTERNAL", []).ok).toBe(true);
	});

	it("rejects too short, too long and multi-line terms", () => {
		expect(validateLiteral("a", "INTERNAL", [])).toEqual({ ok: false, error: "too_short" });
		expect(validateLiteral("   ", "INTERNAL", [])).toEqual({ ok: false, error: "too_short" });
		expect(validateLiteral("x".repeat(257), "INTERNAL", [])).toEqual({
			ok: false,
			error: "too_long",
		});
		expect(validateLiteral("line one\nline two", "INTERNAL", [])).toEqual({
			ok: false,
			error: "multiline",
		});
	});

	it("counts UTF-16 code units like the background validator", () => {
		// 129 emoji = 258 code units: over the limit even though it is 129 characters.
		expect(validateLiteral("\u{1F600}".repeat(129), "INTERNAL", [])).toEqual({
			ok: false,
			error: "too_long",
		});
	});

	it("rejects case-insensitive duplicates and a full list", () => {
		const existing: LiteralRule[] = [{ value: "Falcon", type: "INTERNAL" }];
		expect(validateLiteral("fALCON", "PERSON", existing)).toEqual({
			ok: false,
			error: "duplicate",
		});
		const full = Array.from({ length: LITERAL_MAX_COUNT }, (_v, i) => ({
			value: `term-${i}`,
			type: "INTERNAL" as const,
		}));
		expect(validateLiteral("new term", "INTERNAL", full)).toEqual({ ok: false, error: "limit" });
	});
});

describe("validateTelemetry", () => {
	it("accepts https and normalises the URL", () => {
		expect(validateTelemetry(" https://aidr.example.com/api/ ", "key-12345678", null)).toEqual({
			ok: true,
			config: { controlPlaneUrl: "https://aidr.example.com/api", apiKey: "key-12345678" },
		});
	});

	it("allows plain http only for a localhost control plane", () => {
		expect(validateTelemetry("http://localhost:8787", "key-12345678", null).ok).toBe(true);
		expect(validateTelemetry("http://127.0.0.1:8787", "key-12345678", null).ok).toBe(true);
		expect(validateTelemetry("http://aidr.example.com", "key-12345678", null)).toEqual({
			ok: false,
			error: "url_insecure",
		});
	});

	it("rejects malformed URLs, other schemes, credentials, queries and fragments", () => {
		for (const url of [
			"",
			"aidr.example.com",
			"ftp://aidr.example.com",
			"https://user:pw@aidr.example.com",
			"https://aidr.example.com/?tenant=1",
			"https://aidr.example.com/#x",
		]) {
			expect(validateTelemetry(url, "key-12345678", null)).toEqual({
				ok: false,
				error: "url_invalid",
			});
		}
	});

	it("keeps the saved key when the key field is empty and validates the key format", () => {
		const current = { controlPlaneUrl: "https://aidr.example.com", apiKey: "saved-key-1234" };
		expect(validateTelemetry("https://aidr.example.com", "", current)).toEqual({
			ok: true,
			config: current,
		});
		expect(validateTelemetry("https://aidr.example.com", "", null)).toEqual({
			ok: false,
			error: "key_missing",
		});
		expect(validateTelemetry("https://aidr.example.com", "short", null)).toEqual({
			ok: false,
			error: "key_invalid",
		});
		expect(validateTelemetry("https://aidr.example.com", "has space inside", null)).toEqual({
			ok: false,
			error: "key_invalid",
		});
		expect(validateTelemetry("https://aidr.example.com", "k".repeat(513), null)).toEqual({
			ok: false,
			error: "key_invalid",
		});
	});
});

describe("sites", () => {
	it("lists exactly the supported site adapters", () => {
		expect(SUPPORTED_SITES.map((site) => site.id)).toEqual(ADAPTERS.map((adapter) => adapter.id));
		expect(SUPPORTED_SITES.some((site) => (site.id as string) === "other")).toBe(false);
	});

	it("maps tab URLs with the content script's exact-host rules", () => {
		expect(siteForUrl("https://chatgpt.com/c/123")).toBe("chatgpt");
		expect(siteForUrl("https://gemini.google.com/app")).toBe("gemini");
		expect(siteForUrl("https://www.perplexity.ai/")).toBe("perplexity");
		expect(siteForUrl("http://chatgpt.com/")).toBeNull();
		expect(siteForUrl("https://evil.chatgpt.com.attacker.test/")).toBeNull();
		expect(siteForUrl("https://example.com/")).toBeNull();
		expect(siteForUrl("chrome://extensions")).toBeNull();
		expect(siteForUrl(undefined)).toBeNull();
	});
});

describe("protectionStatus", () => {
	const now = 1_700_000_000_000;

	it("reports unsupported pages", () => {
		expect(protectionStatus(POLICY, STATS, null, now)).toEqual({ kind: "unsupported" });
	});

	it("prefers the site reported by the worker over the URL", () => {
		expect(protectionStatus(POLICY, { ...STATS, site: "claude" }, "chatgpt", now)).toEqual({
			kind: "protected",
			site: "claude",
		});
	});

	it("orders block > disabled > paused > monitoring > protected", () => {
		const paused = { ...STATS, pausedUntil: now + 60_000 };
		const everything: GuardPolicy = {
			...POLICY,
			mode: "monitor",
			blockedSites: ["chatgpt"],
			disabledSites: ["chatgpt"],
		};
		expect(protectionStatus(everything, paused, "chatgpt", now).kind).toBe("blocked");
		expect(protectionStatus({ ...everything, blockedSites: [] }, paused, "chatgpt", now).kind).toBe(
			"disabled-user",
		);
		expect(
			protectionStatus(
				{ ...everything, blockedSites: [], managedKeys: ["disabledSites"] },
				paused,
				"chatgpt",
				now,
			).kind,
		).toBe("disabled-policy");
		expect(protectionStatus({ ...POLICY, mode: "monitor" }, paused, "chatgpt", now)).toEqual({
			kind: "paused",
			site: "chatgpt",
			until: now + 60_000,
		});
		expect(
			protectionStatus(
				{ ...POLICY, mode: "monitor" },
				{ ...STATS, pausedUntil: now - 1 },
				"chatgpt",
				now,
			).kind,
		).toBe("monitoring");
		expect(protectionStatus(POLICY, STATS, "chatgpt", now).kind).toBe("protected");
	});
});

describe("restoreToggle", () => {
	it("is available only on a supported site when restoring is enabled", () => {
		expect(restoreToggle(POLICY, { kind: "protected", site: "chatgpt" }).available).toBe(true);
		expect(restoreToggle(POLICY, { kind: "unsupported" })).toEqual({
			available: false,
			descriptionKey: "restore_visible_no_site",
		});
		expect(
			restoreToggle({ ...POLICY, restoreResponses: false }, { kind: "protected", site: "chatgpt" }),
		).toEqual({ available: false, descriptionKey: "restore_visible_off" });
		expect(
			restoreToggle(
				{ ...POLICY, restoreResponses: false, managedKeys: ["restoreResponses"] },
				{ kind: "protected", site: "chatgpt" },
			),
		).toEqual({ available: false, descriptionKey: "restore_visible_off_managed" });
	});
});

describe("list helpers", () => {
	it("topEntityTypes sorts by count and ignores zero/invalid counts", () => {
		expect(
			topEntityTypes({ IBAN: 2, EMAIL: 5, PHONE: 0, SECRET: Number.NaN, PERSON: 2 }, 5),
		).toEqual([
			{ type: "EMAIL", count: 5 },
			{ type: "PERSON", count: 2 },
			{ type: "IBAN", count: 2 },
		]);
		expect(topEntityTypes({ EMAIL: 1, IBAN: 1, PHONE: 1 }, 2)).toHaveLength(2);
	});

	it("toggleEntity keeps canonical order and toggleSite adds/removes", () => {
		expect(toggleEntity(["IBAN", "EMAIL"], "PERSON", true)).toEqual(["PERSON", "EMAIL", "IBAN"]);
		expect(toggleEntity(["IBAN", "EMAIL"], "EMAIL", false)).toEqual(["IBAN"]);
		expect(toggleSite(["claude"], "chatgpt", false)).toEqual(["claude", "chatgpt"]);
		expect(toggleSite(["claude", "chatgpt"], "chatgpt", true)).toEqual(["claude"]);
	});

	it("entity groups cover every entity type exactly once", () => {
		const grouped = ENTITY_GROUPS.flatMap((group) => group.types);
		expect([...grouped].sort()).toEqual([...ENTITY_TYPES].sort());
		expect(ENTITY_GROUPS.map((group) => group.id)).toEqual([
			"identity",
			"contact",
			"financial",
			"technical",
			"organization",
			"other",
		]);
	});
});

describe("background replies", () => {
	it("unwraps ok replies", () => {
		expect(policyFromResponse({ ok: true, policy: POLICY })).toBe(POLICY);
		expect(statsFromResponse({ ok: true, stats: STATS })).toBe(STATS);
		expect(expectOk({ ok: true })).toEqual({ ok: true });
	});

	it("treats missing, malformed and error replies as failures", () => {
		expect(() => expectOk(undefined)).toThrow(GuardRequestError);
		expect(() => expectOk({})).toThrow(/BAD_RESPONSE/);
		expect(() => policyFromResponse({ ok: true, policy: { mode: "yolo" } })).toThrow(
			/BAD_RESPONSE/,
		);
		expect(() => statsFromResponse({ ok: true })).toThrow(/BAD_RESPONSE/);
		try {
			expectOk({ ok: false, error: "LOCKED_KEYS", keys: ["mode"] });
			expect.unreachable();
		} catch (error) {
			expect(error).toBeInstanceOf(GuardRequestError);
			expect((error as GuardRequestError).code).toBe("LOCKED_KEYS");
			expect((error as GuardRequestError).keys).toEqual(["mode"]);
		}
	});

	it("maps worker error codes to user messages", () => {
		expect(errorKeyFor(new GuardRequestError("LOCKED_KEYS"))).toBe("error_locked");
		expect(errorKeyFor(new GuardRequestError("PAUSE_DISABLED"))).toBe("error_pause_disabled");
		expect(errorKeyFor(new GuardRequestError("INVALID_SETTINGS"))).toBe("error_invalid");
		expect(errorKeyFor(new Error("boom"))).toBe("error_save");
	});
});

describe("formatMessage", () => {
	const messages = {
		greet: {
			message: "Hi $NAME$, $COUNT$ items ($$)",
			placeholders: { name: { content: "$1" }, count: { content: "$2" } },
		},
	};

	it("substitutes named placeholders like chrome.i18n", () => {
		expect(formatMessage(messages, "greet", ["Ada", "3"])).toBe("Hi Ada, 3 items ($)");
		expect(formatMessage(messages, "missing")).toBe("");
	});
});

describe("blockedSiteFromUrl", () => {
	it("returns the label of a known site id only", () => {
		expect(blockedSiteFromUrl("chrome-extension://abc/blocked.html?site=chatgpt")).toBe("ChatGPT");
		expect(blockedSiteFromUrl("chrome-extension://abc/blocked.html?site=%3Cscript%3E")).toBeNull();
		expect(blockedSiteFromUrl("chrome-extension://abc/blocked.html")).toBeNull();
	});
});
