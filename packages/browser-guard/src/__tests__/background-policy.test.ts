import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
	DEFAULT_POLICY,
	evaluatePolicy,
	GUARD_MODES,
	MANAGED_POLICY_KEYS,
	mergePolicy,
	normalizeControlPlaneUrl,
	PROTECTION_SETTING_KEYS,
	SITE_ID_LIST,
	USER_SETTING_KEYS,
	validateUserSettings,
} from "../background/policy.js";
import { ENTITY_TYPES } from "../types.js";

const HEX = "a".repeat(64);
/** Managed input with user overrides allowed: isolates per-key validation from the lock. */
const open = (managed: Record<string, unknown>) => ({ ...managed, allowUserOverrides: true });
const KEY = "c2VjcmV0LWtleS0xMjM0NTY3OA==";

describe("DEFAULT_POLICY", () => {
	it("matches the documented defaults", () => {
		expect(DEFAULT_POLICY.mode).toBe("auto");
		expect(DEFAULT_POLICY.enabledEntities).not.toContain("USERNAME");
		expect(DEFAULT_POLICY.enabledEntities).not.toContain("LOCATION");
		expect(DEFAULT_POLICY.enabledEntities).toHaveLength(ENTITY_TYPES.length - 2);
		expect(DEFAULT_POLICY.neverRestore).toEqual(["SECRET", "PRIVATE_KEY"]);
		expect(DEFAULT_POLICY).toMatchObject({
			version: 1,
			detectSignals: true,
			signalAction: "warn",
			maskPaste: true,
			fileHandling: "scan",
			maxFileBytes: 5 * 1024 * 1024,
			restoreResponses: true,
			allowUserPause: true,
			allowSendAnyway: true,
			useNativeHost: false,
			telemetry: null,
			language: "auto",
			policyId: "aidr-browser-guard-default",
			managedKeys: [],
			blockedSites: [],
			disabledSites: [],
		});
	});

	it("is deeply frozen", () => {
		expect(Object.isFrozen(DEFAULT_POLICY)).toBe(true);
		expect(Object.isFrozen(DEFAULT_POLICY.enabledEntities)).toBe(true);
	});

	it("mergePolicy with nothing returns the defaults", () => {
		expect(mergePolicy(undefined, undefined)).toEqual(DEFAULT_POLICY);
	});
});

describe("mergePolicy", () => {
	it("applies user settings over defaults", () => {
		const p = mergePolicy(undefined, { mode: "confirm", maskPaste: false, language: "tr" });
		expect(p.mode).toBe("confirm");
		expect(p.maskPaste).toBe(false);
		expect(p.language).toBe("tr");
		expect(p.managedKeys).toEqual([]);
	});

	it("managed keys override user settings and are listed in managedKeys", () => {
		const managed = { mode: "block", maskPaste: true, policyId: "acme-2026" };
		const user = { mode: "monitor", maskPaste: false, restoreResponses: false } as const;
		const p = mergePolicy(open(managed), user);
		expect(p.mode).toBe("block");
		expect(p.maskPaste).toBe(true);
		expect(p.restoreResponses).toBe(false);
		expect(p.policyId).toBe("acme-2026");
		expect(p.managedKeys).toEqual(expect.arrayContaining(["mode", "maskPaste", "policyId"]));
		// Without allowUserOverrides, the user's restoreResponses is locked too.
		const locked = mergePolicy(managed, user);
		expect(locked.restoreResponses).toBe(true);
		expect(locked.managedKeys).toContain("restoreResponses");
	});

	it("ignores unknown and wrong-typed managed keys with warnings, never throwing", () => {
		const { policy, warnings } = evaluatePolicy(
			{
				mode: "yolo",
				maskPaste: "yes",
				maxFileBytes: 60 * 1024 * 1024,
				somethingElse: 1,
				signalAction: "block",
			},
			undefined,
		);
		expect(policy.mode).toBe("auto");
		expect(policy.maskPaste).toBe(true);
		expect(policy.maxFileBytes).toBe(DEFAULT_POLICY.maxFileBytes);
		expect(policy.signalAction).toBe("block");
		// signalAction is managed; the protection keys are locked at their defaults.
		expect(policy.managedKeys).toEqual(["signalAction", ...PROTECTION_SETTING_KEYS]);
		expect(warnings).toEqual(
			expect.arrayContaining([
				'managed: invalid value for "mode" ignored',
				'managed: invalid value for "maskPaste" ignored',
				'managed: invalid value for "maxFileBytes" ignored',
				'managed: unknown key "somethingElse" ignored',
			]),
		);
	});

	it("survives hostile managed input", () => {
		for (const managed of [null, 42, "x", [1, 2], { __proto__: { mode: "block" } }]) {
			expect(() => mergePolicy(managed, undefined)).not.toThrow();
		}
		expect(evaluatePolicy([1], undefined).warnings).toEqual([
			"managed: policy is not an object; ignored",
		]);
	});

	it("warnings never contain values", () => {
		const { warnings } = evaluatePolicy(
			{ telemetry: { controlPlaneUrl: "http://evil.example", apiKey: "aidr_supersecret" } },
			{ telemetry: { controlPlaneUrl: "ftp://x", apiKey: "aidr_usersecret" } },
		);
		expect(warnings.join("\n")).not.toMatch(/supersecret|usersecret|evil|ftp/);
		expect(warnings.length).toBe(2);
	});

	it("validates enabledEntities/neverRestore/site lists as a whole", () => {
		const p = mergePolicy(
			{
				enabledEntities: ["EMAIL", "EMAIL", "IBAN"],
				neverRestore: ["SECRET", "NOPE"],
				blockedSites: ["chatgpt", "grok"],
				disabledSites: ["myspace"],
			},
			undefined,
		);
		expect(p.enabledEntities).toEqual(["EMAIL", "IBAN"]);
		expect(p.neverRestore).toEqual(DEFAULT_POLICY.neverRestore);
		expect(p.blockedSites).toEqual(["chatgpt", "grok"]);
		expect(p.managedKeys).not.toContain("neverRestore");
	});

	it("enforces literal limits", () => {
		expect(
			mergePolicy({ literals: [{ value: "Project Falcon", type: "INTERNAL" }] }, undefined)
				.literals,
		).toEqual([{ value: "Project Falcon", type: "INTERNAL" }]);
		const tooShort = mergePolicy(open({ literals: [{ value: "a", type: "INTERNAL" }] }), undefined);
		expect(tooShort.literals).toEqual([]);
		expect(tooShort.managedKeys).not.toContain("literals");
		const tooLong = [{ value: "x".repeat(257), type: "INTERNAL" }];
		expect(mergePolicy(open({ literals: tooLong }), undefined).managedKeys).toEqual([]);
		const tooMany = Array.from({ length: 1025 }, (_, i) => ({
			value: `term-${i}`,
			type: "INTERNAL",
		}));
		expect(mergePolicy(open({ literals: tooMany }), undefined).managedKeys).toEqual([]);
		const extraKey = [{ value: "abc", type: "INTERNAL", note: "x" }];
		expect(mergePolicy(open({ literals: extraKey }), undefined).managedKeys).toEqual([]);
		const max = Array.from({ length: 1024 }, (_, i) => ({ value: `term-${i}`, type: "INTERNAL" }));
		expect(mergePolicy({ literals: max }, undefined).literals).toHaveLength(1024);
	});

	it("enforces exact-data limits and normalises fingerprints", () => {
		const ds = (id: string, n: number) => ({
			datasetId: id,
			keyB64: KEY,
			fingerprints: Array.from({ length: n }, (_, i) => i.toString(16).padStart(64, "0")),
			type: "PERSON",
		});
		const ok = mergePolicy(
			open({ exactData: [{ ...ds("hr", 1), fingerprints: [HEX.toUpperCase()] }] }),
			undefined,
		);
		expect(ok.exactData[0]?.fingerprints).toEqual([HEX]);
		expect(ok.managedKeys).toEqual(["exactData"]);
		// 100k total is allowed, 100k + 1 is not.
		expect(
			mergePolicy(open({ exactData: [ds("a", 50_000), ds("b", 50_000)] }), undefined).managedKeys,
		).toEqual(["exactData"]);
		expect(
			mergePolicy(open({ exactData: [ds("a", 50_000), ds("b", 50_001)] }), undefined).managedKeys,
		).toEqual([]);
		const seventeen = Array.from({ length: 17 }, (_, i) => ds(`d${i}`, 1));
		expect(mergePolicy(open({ exactData: seventeen }), undefined).managedKeys).toEqual([]);
		for (const bad of [
			{ ...ds("x", 1), fingerprints: ["zz"] },
			{ ...ds("x", 1), keyB64: "not base64!" },
			{ ...ds("x", 1), datasetId: "-bad" },
			{ ...ds("x", 1), type: "NOPE" },
		]) {
			expect(mergePolicy({ exactData: [bad] }, undefined).exactData).toEqual([]);
		}
		expect(mergePolicy({ exactData: [ds("dup", 1), ds("dup", 1)] }, undefined).exactData).toEqual(
			[],
		);
	});

	it("accepts https telemetry and http only for localhost/127.0.0.1", () => {
		const t = (controlPlaneUrl: string) =>
			mergePolicy({ telemetry: { controlPlaneUrl, apiKey: "aidr_live_0123456789" } }, undefined)
				.telemetry;
		expect(t("https://cp.example.com/")).toEqual({
			controlPlaneUrl: "https://cp.example.com",
			apiKey: "aidr_live_0123456789",
		});
		expect(t("http://localhost:54321")?.controlPlaneUrl).toBe("http://localhost:54321");
		expect(t("http://127.0.0.1:54321")?.controlPlaneUrl).toBe("http://127.0.0.1:54321");
		expect(t("http://cp.example.com")).toBeNull();
		expect(t("http://localhost.evil.com")).toBeNull();
		expect(t("https://user:pw@cp.example.com")).toBeNull();
		expect(t("https://cp.example.com/?x=1")).toBeNull();
		expect(t("javascript:alert(1)")).toBeNull();
		expect(
			mergePolicy(
				{ telemetry: { controlPlaneUrl: "https://a.b", apiKey: "has space in it" } },
				undefined,
			).telemetry,
		).toBeNull();
		expect(mergePolicy(open({ telemetry: null }), undefined).managedKeys).toEqual([]);
		expect(normalizeControlPlaneUrl("https://cp.example.com/base//")).toBe(
			"https://cp.example.com/base",
		);
	});

	it("managed telemetry wins over the user's enrollment", () => {
		const managed = { controlPlaneUrl: "https://admin.example", apiKey: "aidr_admin_key_1" };
		const user = { controlPlaneUrl: "https://user.example", apiKey: "aidr_user_key_1" };
		const p = mergePolicy({ telemetry: managed }, { telemetry: user });
		expect(p.telemetry).toEqual(managed);
		expect(p.managedKeys).toContain("telemetry");
		expect(mergePolicy(undefined, { telemetry: user }).telemetry).toEqual(user);
		expect(mergePolicy(undefined, { telemetry: null }).telemetry).toBeNull();
	});

	it("a managed mode locks disabledSites so users cannot switch the guard off per site", () => {
		const { policy, warnings } = evaluatePolicy(open({ mode: "confirm" }), {
			disabledSites: ["chatgpt"],
		});
		expect(policy.disabledSites).toEqual([]);
		expect(policy.managedKeys).toEqual(["mode", "disabledSites"]);
		expect(warnings).toContain('user: "disabledSites" ignored because "mode" is managed');
		const both = mergePolicy(open({ mode: "confirm", disabledSites: ["grok"] }), {
			disabledSites: ["chatgpt"],
		});
		expect(both.disabledSites).toEqual(["grok"]);
		expect(mergePolicy(undefined, { disabledSites: ["chatgpt"] }).disabledSites).toEqual([
			"chatgpt",
		]);
	});

	it("user settings cannot set managed-only keys", () => {
		const { policy, warnings } = evaluatePolicy(undefined, {
			blockedSites: ["chatgpt"],
			allowUserPause: false,
			mode: "monitor",
		});
		expect(policy.blockedSites).toEqual([]);
		expect(policy.mode).toBe("monitor");
		expect(warnings).toEqual(
			expect.arrayContaining([
				'user: unknown key "blockedSites" ignored',
				'user: unknown key "allowUserPause" ignored',
			]),
		);
	});

	it("result is frozen", () => {
		const p = mergePolicy({ mode: "block" }, { literals: [{ value: "abc", type: "INTERNAL" }] });
		expect(Object.isFrozen(p)).toBe(true);
		expect(Object.isFrozen(p.literals)).toBe(true);
		expect(Object.isFrozen(p.managedKeys)).toBe(true);
	});
});

describe("validateUserSettings", () => {
	it("splits valid, unknown and invalid keys", () => {
		const r = validateUserSettings({ mode: "auto", language: "de", bogus: true });
		expect(r.settings).toEqual({ mode: "auto" });
		expect(r.unknownKeys).toEqual(["bogus"]);
		expect(r.invalidKeys).toEqual(["language"]);
		expect(validateUserSettings("nope").invalidKeys).toEqual(["*"]);
		expect(USER_SETTING_KEYS).toEqual([
			"mode",
			"enabledEntities",
			"literals",
			"disabledSites",
			"maskPaste",
			"restoreResponses",
			"language",
			"telemetry",
		]);
	});
});

describe("managed policy locks protection-reducing user settings (L2)", () => {
	const weakening = {
		mode: "monitor",
		enabledEntities: [],
		literals: [],
		maskPaste: false,
		restoreResponses: false,
		disabledSites: ["chatgpt", "gemini"],
		language: "tr",
	} as const;

	it("any managed policy locks every protection key at the managed or built-in value", () => {
		const { policy, warnings } = evaluatePolicy(
			{ policyId: "acme", literals: [{ value: "Project Falcon", type: "INTERNAL" }] },
			weakening,
		);
		expect(policy.mode).toBe(DEFAULT_POLICY.mode);
		expect(policy.enabledEntities).toEqual(DEFAULT_POLICY.enabledEntities);
		expect(policy.literals).toEqual([{ value: "Project Falcon", type: "INTERNAL" }]);
		expect(policy.maskPaste).toBe(true);
		expect(policy.restoreResponses).toBe(DEFAULT_POLICY.restoreResponses);
		expect(policy.disabledSites).toEqual([]);
		// Not protection-reducing: stays the user's.
		expect(policy.language).toBe("tr");
		for (const key of PROTECTION_SETTING_KEYS) expect(policy.managedKeys).toContain(key);
		expect(policy.managedKeys).not.toContain("language");
		for (const key of ["mode", "enabledEntities", "maskPaste", "restoreResponses", "disabledSites"])
			expect(warnings).toContain(
				`user: "${key}" ignored because a managed policy locks user overrides`,
			);
	});

	it("allowUserOverrides: true lets users change the protection keys the policy does not set", () => {
		const policy = mergePolicy({ policyId: "acme", allowUserOverrides: true }, weakening);
		expect(policy.mode).toBe("monitor");
		expect(policy.enabledEntities).toEqual([]);
		expect(policy.maskPaste).toBe(false);
		expect(policy.restoreResponses).toBe(false);
		expect(policy.disabledSites).toEqual(["chatgpt", "gemini"]);
		expect(policy.managedKeys).toEqual(["policyId"]);
		expect(policy).not.toHaveProperty("allowUserOverrides");
	});

	it("allowUserOverrides: false (or an invalid value) keeps the lock", () => {
		expect(mergePolicy({ allowUserOverrides: false }, weakening).mode).toBe("auto");
		const { policy, warnings } = evaluatePolicy({ allowUserOverrides: "yes" }, weakening);
		expect(policy.maskPaste).toBe(true);
		expect(warnings).toContain('managed: invalid value for "allowUserOverrides" ignored');
	});

	it("fails closed: a managed policy whose keys are all invalid still locks", () => {
		const policy = mergePolicy({ mode: "yolo", typo: 1 }, weakening);
		expect(policy.mode).toBe("auto");
		expect(policy.enabledEntities).toEqual(DEFAULT_POLICY.enabledEntities);
		expect(mergePolicy([1], weakening).maskPaste).toBe(true);
	});

	it("no managed policy (absent or empty) leaves user settings alone", () => {
		for (const managed of [undefined, null, {}]) {
			const policy = mergePolicy(managed, weakening);
			expect(policy.mode).toBe("monitor");
			expect(policy.enabledEntities).toEqual([]);
			expect(policy.managedKeys).toEqual([]);
		}
	});
});

describe("static/managed_schema.json", () => {
	const schema = JSON.parse(
		readFileSync(new URL("../../static/managed_schema.json", import.meta.url), "utf8"),
	) as {
		type: string;
		properties: Record<string, Record<string, unknown>>;
	};
	const props = schema.properties;

	it("declares exactly the managed policy keys", () => {
		expect(schema.type).toBe("object");
		expect(Object.keys(props).sort()).toEqual([...MANAGED_POLICY_KEYS].sort());
	});

	it("uses the same enums as the validator", () => {
		expect(props.mode?.enum).toEqual([...GUARD_MODES]);
		expect((props.enabledEntities?.items as { enum: string[] }).enum).toEqual([...ENTITY_TYPES]);
		expect((props.neverRestore?.items as { enum: string[] }).enum).toEqual([...ENTITY_TYPES]);
		expect((props.blockedSites?.items as { enum: string[] }).enum).toEqual([...SITE_ID_LIST]);
		expect((props.disabledSites?.items as { enum: string[] }).enum).toEqual([...SITE_ID_LIST]);
		expect(props.signalAction?.enum).toEqual(["off", "warn", "block"]);
		expect(props.fileHandling?.enum).toEqual(["scan", "block", "allow"]);
		expect(props.language?.enum).toEqual(["auto", "en", "tr"]);
		expect(props.maxFileBytes).toMatchObject({ type: "integer", minimum: 1, maximum: 52428800 });
		for (const key of [
			"detectSignals",
			"allowUserPause",
			"allowSendAnyway",
			"maskPaste",
			"restoreResponses",
			"useNativeHost",
		])
			expect(props[key]?.type).toBe("boolean");
	});

	it("patterns agree with the validator on representative values", () => {
		const pattern = (p: unknown) => new RegExp(p as string);
		const telemetry = props.telemetry?.properties as Record<string, { pattern: string }>;
		const url = pattern(telemetry.controlPlaneUrl?.pattern);
		for (const u of ["https://cp.example.com", "http://localhost:54321", "http://127.0.0.1"]) {
			expect(url.test(u)).toBe(true);
			expect(normalizeControlPlaneUrl(u)).not.toBeNull();
		}
		for (const u of ["http://cp.example.com", "ftp://x"]) {
			expect(url.test(u)).toBe(false);
			expect(normalizeControlPlaneUrl(u)).toBeNull();
		}
		expect(pattern(props.policyId?.pattern).test("acme-2026")).toBe(true);
		expect(pattern(props.policyId?.pattern).test("-bad")).toBe(false);
		const exact = (
			props.exactData?.items as { properties: Record<string, Record<string, unknown>> }
		).properties;
		expect(pattern((exact.fingerprints?.items as { pattern: string }).pattern).test(HEX)).toBe(
			true,
		);
		expect(pattern(exact.keyB64?.pattern).test(KEY)).toBe(true);
		const literal = (props.literals?.items as { properties: Record<string, { pattern: string }> })
			.properties;
		expect(pattern(literal.value?.pattern).test("a")).toBe(false);
		expect(pattern(literal.value?.pattern).test("ab")).toBe(true);
		expect(pattern(literal.value?.pattern).test("x".repeat(257))).toBe(false);
	});
});
