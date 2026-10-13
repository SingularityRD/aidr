import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
	DEFAULT_POLICY,
	EXACT_DATA_PLACEHOLDER_KEY,
	evaluatePolicy,
	GUARD_MODES,
	MANAGED_OFF_BY_DEFAULT_KEYS,
	MANAGED_POLICY_KEYS,
	mergePolicy,
	normalizeControlPlaneUrl,
	PROTECTION_SETTING_KEYS,
	SITE_ID_LIST,
	USER_SETTING_KEYS,
	validateUserSettings,
} from "../background/policy.js";
import { sha256Hex } from "../background/sha256.js";
import { ENTITY_TYPES } from "../types.js";

const HEX = "a".repeat(64);
/** Managed input with user overrides allowed: isolates per-key validation from the lock. */
const open = (managed: Record<string, unknown>) => ({ ...managed, allowUserOverrides: true });
const KEY = "c2VjcmV0LWtleS0xMjM0NTY3OA==";
/** Keys every managed policy adds (pause and send-original off unless set). */
const OFF = [...MANAGED_OFF_BY_DEFAULT_KEYS];

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
			documentHandling: "mask",
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

describe("documentHandling", () => {
	it("is a managed-only key validated against mask/block/allow", () => {
		const managed = evaluatePolicy({ documentHandling: "block" }, undefined);
		expect(managed.policy.documentHandling).toBe("block");
		expect(managed.policy.managedKeys).toContain("documentHandling");
		const invalid = evaluatePolicy({ documentHandling: "scan" }, undefined);
		// Fail safe: an invalid value takes the strictest one, never the "mask" default.
		expect(invalid.policy.documentHandling).toBe("block");
		expect(invalid.policy.policyErrors).toEqual(["documentHandling"]);
		expect(invalid.warnings).toContain(
			'managed: invalid value for "documentHandling"; fail-safe value applied',
		);
		const user = evaluatePolicy(undefined, { documentHandling: "allow" });
		expect(user.policy.documentHandling).toBe("mask");
		expect(user.warnings).toContain('user: unknown key "documentHandling" ignored');
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

	it("fails safe on wrong-typed managed keys and ignores unknown ones, never throwing", () => {
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
		expect(policy.mode).toBe("block");
		expect(policy.maskPaste).toBe(true);
		// No safe value to invent: the built-in limit stays.
		expect(policy.maxFileBytes).toBe(DEFAULT_POLICY.maxFileBytes);
		expect(policy.signalAction).toBe("block");
		expect(policy.policyErrors).toEqual(["mode", "maskPaste", "maxFileBytes"]);
		// The fail-safe keys are locked; the other protection keys are locked at their defaults.
		expect(policy.managedKeys).toEqual([
			"mode",
			"maskPaste",
			"signalAction",
			// A managed mode (here the fail-safe one) locks disabledSites first.
			"disabledSites",
			"enabledEntities",
			"literals",
			"restoreResponses",
			...OFF,
		]);
		expect(warnings).toEqual(
			expect.arrayContaining([
				'managed: invalid value for "mode"; fail-safe value applied',
				'managed: invalid value for "maskPaste"; fail-safe value applied',
				'managed: invalid value for "maxFileBytes" ignored',
				'managed: unknown key "somethingElse" ignored',
			]),
		);
	});

	it("survives hostile managed input", () => {
		for (const managed of [null, 42, "x", [1, 2], { __proto__: { mode: "block" } }]) {
			expect(() => mergePolicy(managed, undefined)).not.toThrow();
		}
		const notObject = evaluatePolicy([1], undefined);
		expect(notObject.warnings).toEqual(["managed: policy is not an object; ignored"]);
		expect(notObject.policy.policyErrors).toEqual(["*"]);
	});

	it("warnings never contain values", () => {
		const { warnings } = evaluatePolicy(
			{ telemetry: { controlPlaneUrl: "http://evil.example", apiKey: "aidr_supersecret" } },
			{ telemetry: { controlPlaneUrl: "ftp://x", apiKey: "aidr_usersecret" } },
		);
		expect(warnings.join("\n")).not.toMatch(/supersecret|usersecret|evil|ftp/);
		expect(warnings.length).toBe(2);
	});

	it("keeps the valid entries of a site list and widens an invalid entity list to all types", () => {
		const p = mergePolicy(
			{
				enabledEntities: ["EMAIL", "EMAIL", "IBAN"],
				neverRestore: ["SECRET", "NOPE"],
				blockedSites: ["chatgpt", "grok"],
				disabledSites: ["myspace", "gemini"],
			},
			undefined,
		);
		expect(p.enabledEntities).toEqual(["EMAIL", "IBAN"]);
		// An unknown type in neverRestore: the strictest list (never restore anything).
		expect(p.neverRestore).toEqual(ENTITY_TYPES);
		expect(p.managedKeys).toContain("neverRestore");
		expect(p.blockedSites).toEqual(["chatgpt", "grok"]);
		// One unknown id no longer drops the valid ones.
		expect(p.disabledSites).toEqual(["gemini"]);
		expect(p.policyErrors).toEqual(["neverRestore", "disabledSites"]);
	});

	it("enforces literal limits", () => {
		expect(
			mergePolicy({ literals: [{ value: "Project Falcon", type: "INTERNAL" }] }, undefined)
				.literals,
		).toEqual([{ value: "Project Falcon", type: "INTERNAL" }]);
		// Out-of-bounds rules are dropped one by one; the valid ones stay (and stay locked).
		const tooShort = mergePolicy(
			open({
				literals: [
					{ value: "a", type: "INTERNAL" },
					{ value: "Project Falcon", type: "INTERNAL" },
				],
			}),
			undefined,
		);
		expect(tooShort.literals).toEqual([{ value: "Project Falcon", type: "INTERNAL" }]);
		expect(tooShort.managedKeys).toContain("literals");
		expect(tooShort.policyErrors).toEqual(["literals"]);
		const tooLong = [{ value: "x".repeat(257), type: "INTERNAL" }];
		expect(mergePolicy(open({ literals: tooLong }), undefined).literals).toEqual([]);
		const tooMany = Array.from({ length: 1025 }, (_, i) => ({
			value: `term-${i}`,
			type: "INTERNAL",
		}));
		const capped = mergePolicy(open({ literals: tooMany }), undefined);
		expect(capped.literals).toHaveLength(1024);
		expect(capped.policyErrors).toEqual(["literals"]);
		const extraKey = [{ value: "abc", type: "INTERNAL", note: "x" }];
		expect(mergePolicy(open({ literals: extraKey }), undefined).literals).toEqual([]);
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
		expect(ok.managedKeys).toEqual(["exactData", ...OFF]);
		expect(ok.policyErrors).toEqual([]);
		// 100k total is allowed; a dataset that would exceed it is dropped, the others stay.
		const full = mergePolicy(open({ exactData: [ds("a", 50_000), ds("b", 50_000)] }), undefined);
		expect(full.exactData.map((d) => d.datasetId)).toEqual(["a", "b"]);
		expect(full.policyErrors).toEqual([]);
		const over = mergePolicy(open({ exactData: [ds("a", 50_000), ds("b", 50_001)] }), undefined);
		expect(over.exactData.map((d) => d.datasetId)).toEqual(["a"]);
		expect(over.policyErrors).toEqual(["exactData"]);
		const seventeen = Array.from({ length: 17 }, (_, i) => ds(`d${i}`, 1));
		expect(mergePolicy(open({ exactData: seventeen }), undefined).exactData).toHaveLength(16);
		for (const bad of [
			{ ...ds("x", 1), fingerprints: ["zz"] },
			{ ...ds("x", 1), keyB64: "not base64!" },
			{ ...ds("x", 1), datasetId: "-bad" },
			{ ...ds("x", 1), type: "NOPE" },
		]) {
			expect(mergePolicy({ exactData: [bad] }, undefined).exactData).toEqual([]);
		}
		expect(
			mergePolicy({ exactData: [ds("dup", 1), ds("dup", 1)] }, undefined).exactData.map(
				(d) => d.datasetId,
			),
		).toEqual(["dup"]);
	});

	it("refuses the example placeholder exact-data key by name, never as a usable key", () => {
		const real = { datasetId: "real", keyB64: KEY, fingerprints: [HEX], type: "PERSON" };
		const placeholder = {
			datasetId: "crm-customers-example",
			keyB64: EXACT_DATA_PLACEHOLDER_KEY,
			fingerprints: ["REPLACE_WITH_FINGERPRINTS_FROM_FINGERPRINT_DATASET"],
			type: "PERSON",
		};
		const warning =
			'managed: "exactData" still holds the example placeholder key; ignored. Build each dataset with fingerprint-dataset.mjs';
		expect(EXACT_DATA_PLACEHOLDER_KEY).toMatch(/^REPLACE_WITH_/);
		// Copied unchanged: the whole managed value is ignored, other managed keys still apply.
		const copied = evaluatePolicy({ mode: "block", exactData: [placeholder] }, undefined);
		expect(copied.warnings).toEqual([warning]);
		expect(copied.policy.exactData).toEqual([]);
		expect(copied.policy.mode).toBe("block");
		expect(copied.policy.managedKeys).toContain("mode");
		expect(copied.policy.managedKeys).not.toContain("exactData");
		// A real dataset next to a leftover placeholder does not switch the placeholder on.
		const mixed = evaluatePolicy({ exactData: [real, placeholder] }, undefined);
		expect(mixed.warnings).toEqual([warning]);
		expect(mixed.policy.exactData).toEqual([]);
		// A real key with placeholder fingerprints, or any REPLACE_WITH_ key variant, is refused too.
		for (const bad of [
			{ ...real, fingerprints: ["REPLACE_WITH_FINGERPRINTS_FROM_FINGERPRINT_DATASET"] },
			{ ...real, keyB64: "replace_with_my_key" },
			{ ...real, keyB64: ` ${EXACT_DATA_PLACEHOLDER_KEY}` },
		]) {
			expect(evaluatePolicy({ exactData: [bad] }, undefined).warnings).toEqual([warning]);
		}
		// Once replaced, the dataset is accepted without warnings.
		const replaced = evaluatePolicy({ exactData: [real] }, undefined);
		expect(replaced.warnings).toEqual([]);
		expect(replaced.policy.exactData).toEqual([real]);
	});

	it("refuses the retired example dataset (published key or its fingerprints) by name", () => {
		const warning =
			'managed: "exactData" uses the retired example dataset key (crm-customers-example), which was published in the deployment examples and is compromised; ignored. Build each dataset with fingerprint-dataset.mjs and a fresh key';
		const real = { datasetId: "real", keyB64: KEY, fingerprints: [HEX], type: "PERSON" };
		// The retired key itself is never kept in the repository (only its SHA-256), so the
		// example's fingerprints, which shipped with it, stand in for it here.
		const retired = {
			datasetId: "crm-customers-example",
			keyB64: KEY,
			fingerprints: ["DACE37DF0E61D972CE461B5887CC8EF241DF0749DD737ADC7DE1B118305D89B2"],
			type: "PERSON",
		};
		for (const exactData of [[retired], [real, retired]]) {
			const evaluation = evaluatePolicy({ mode: "block", exactData }, undefined);
			expect(evaluation.warnings).toEqual([warning]);
			expect(evaluation.policy.exactData).toEqual([]);
			expect(evaluation.policy.managedKeys).not.toContain("exactData");
			expect(evaluation.policy.mode).toBe("block");
		}
		expect(evaluatePolicy({ exactData: [real] }, undefined).warnings).toEqual([]);
	});

	it("hashes like SHA-256 (the retired-key check compares digests)", () => {
		for (const text of [
			"",
			"abc",
			"a".repeat(55),
			"a".repeat(56),
			"b".repeat(64),
			"ğüşİ".repeat(99),
		])
			expect(sha256Hex(text)).toBe(createHash("sha256").update(text).digest("hex"));
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
		const nullTelemetry = mergePolicy(open({ telemetry: null }), undefined);
		expect(nullTelemetry.managedKeys).toEqual(OFF);
		expect(nullTelemetry.policyErrors).toEqual(["telemetry"]);
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
		expect(policy.managedKeys).toEqual(["mode", "disabledSites", ...OFF]);
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
			"useNativeHost",
			"language",
			"telemetry",
		]);
	});

	it("lets a user opt in to the native host unless the administrator set it", () => {
		expect(evaluatePolicy(undefined, { useNativeHost: true }).policy.useNativeHost).toBe(true);
		// Opting in only adds detection, so a managed policy without overrides does not lock it.
		const managed = evaluatePolicy({ mode: "auto" }, { useNativeHost: true }).policy;
		expect(managed.useNativeHost).toBe(true);
		expect(managed.managedKeys).not.toContain("useNativeHost");
		const locked = evaluatePolicy({ useNativeHost: false }, { useNativeHost: true }).policy;
		expect(locked.useNativeHost).toBe(false);
		expect(locked.managedKeys).toContain("useNativeHost");
	});
});

describe("requireNativeNer (managed only)", () => {
	it("defaults to false and leaves useNativeHost alone", () => {
		expect(DEFAULT_POLICY.requireNativeNer).toBe(false);
		expect(evaluatePolicy(undefined, undefined).policy.requireNativeNer).toBe(false);
		expect(evaluatePolicy({ requireNativeNer: false }, undefined).policy.useNativeHost).toBe(false);
	});

	it("forces and locks useNativeHost on, whatever the managed or user value", () => {
		for (const managed of [
			{ requireNativeNer: true },
			{ requireNativeNer: true, useNativeHost: false },
			open({ requireNativeNer: true }),
		]) {
			const { policy, warnings } = evaluatePolicy(managed, { useNativeHost: false });
			expect(policy.requireNativeNer).toBe(true);
			expect(policy.useNativeHost).toBe(true);
			expect(policy.managedKeys).toContain("requireNativeNer");
			expect(policy.managedKeys).toContain("useNativeHost");
			expect(policy.managedKeys.filter((k) => k === "useNativeHost")).toHaveLength(1);
			expect(warnings.some((w) => w.includes("requireNativeNer"))).toBe(true);
		}
	});

	it("fails safe on a non-boolean value (required) and is not a user setting", () => {
		const { policy, warnings } = evaluatePolicy({ requireNativeNer: "yes" }, undefined);
		expect(policy.requireNativeNer).toBe(true);
		expect(policy.useNativeHost).toBe(true);
		expect(policy.policyErrors).toEqual(["requireNativeNer"]);
		expect(warnings).toContain(
			'managed: invalid value for "requireNativeNer"; fail-safe value applied',
		);
		expect(USER_SETTING_KEYS).not.toContain("requireNativeNer");
		const user = evaluatePolicy(undefined, { requireNativeNer: true });
		expect(user.policy.requireNativeNer).toBe(false);
		expect(user.warnings).toContain('user: unknown key "requireNativeNer" ignored');
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
		// Pause and send-original stay off: allowUserOverrides covers user settings only.
		expect(policy.managedKeys).toEqual(["policyId", ...OFF]);
		expect(policy.allowUserPause).toBe(false);
		expect(policy.allowSendAnyway).toBe(false);
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
		expect(policy.mode).toBe("block");
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
		expect(props.documentHandling?.enum).toEqual(["mask", "block", "allow"]);
		expect(props.language?.enum).toEqual(["auto", "en", "tr"]);
		expect(props.maxFileBytes).toMatchObject({ type: "integer", minimum: 1, maximum: 52428800 });
		for (const key of [
			"detectSignals",
			"allowUserPause",
			"allowSendAnyway",
			"maskPaste",
			"restoreResponses",
			"useNativeHost",
			"requireNativeNer",
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

describe("invalid managed values fail safe (BG-4)", () => {
	// The GA audit reproduction: typos and registry-typed values once produced the most
	// permissive configuration (auto mode, pause and send-original on, nothing blocked).
	const managed = {
		mode: "Block",
		allowUserPause: "false",
		allowSendAnyway: 0,
		requireNativeNer: "true",
		blockedSites: ["deepseek", "chatgtp"],
		shadowAi: { mode: "block-unsanctioned", sanctioned: ["chatgpt"], blocked: ["deepseek", "Foo"] },
		fileHandling: "Block",
	};

	it("uses the strictest value per key and keeps the valid list entries", () => {
		const { policy, warnings } = evaluatePolicy(managed, { mode: "monitor" });
		expect(policy.mode).toBe("block");
		expect(policy.allowUserPause).toBe(false);
		expect(policy.allowSendAnyway).toBe(false);
		expect(policy.requireNativeNer).toBe(true);
		expect(policy.useNativeHost).toBe(true);
		expect(policy.blockedSites).toEqual(["deepseek"]);
		expect(policy.shadowAi).toEqual({
			mode: "block-unsanctioned",
			sanctioned: ["chatgpt"],
			blocked: ["deepseek"],
		});
		expect(policy.fileHandling).toBe("block");
		for (const key of Object.keys(managed)) expect(policy.managedKeys).toContain(key);
		expect([...(policy.policyErrors ?? [])].sort()).toEqual(Object.keys(managed).sort());
		expect(warnings.join("\n")).not.toMatch(/chatgtp|Foo|Block/);
	});

	it("an invalid shadowAi mode becomes block-unsanctioned; a non-object keeps nothing sanctioned", () => {
		expect(
			mergePolicy({ shadowAi: { mode: "audit", sanctioned: ["chatgpt", "Bad Id"] } }, undefined)
				.shadowAi,
		).toEqual({ mode: "block-unsanctioned", sanctioned: ["chatgpt"], blocked: [] });
		expect(mergePolicy({ shadowAi: "monitor" }, undefined).shadowAi).toEqual({
			mode: "block-unsanctioned",
			sanctioned: [],
			blocked: [],
		});
	});

	it("valid custom sites survive an invalid neighbour", () => {
		const good = { id: "gpt", label: "ACME GPT", hosts: ["gpt.acme.example"] };
		const policy = mergePolicy(
			{ customSites: [good, { id: "bad", label: "x", hosts: ["http://x.example"] }] },
			undefined,
		);
		expect(policy.customSites.map((s) => s.id)).toEqual(["gpt"]);
		expect(policy.policyErrors).toEqual(["customSites"]);
	});

	it("a valid managed policy reports no errors", () => {
		const valid = evaluatePolicy({ mode: "block", blockedSites: ["grok"] }, undefined);
		expect(valid.policy.policyErrors).toEqual([]);
		expect(evaluatePolicy(undefined, undefined).policy.policyErrors).toEqual([]);
	});

	it("unreadable managed storage locks like a managed policy and reports a whole-policy error", () => {
		const { policy, warnings } = evaluatePolicy(
			undefined,
			{ mode: "monitor", maskPaste: false },
			{ managedUnavailable: true },
		);
		expect(policy.mode).toBe("auto");
		expect(policy.maskPaste).toBe(true);
		expect(policy.allowUserPause).toBe(false);
		expect(policy.allowSendAnyway).toBe(false);
		expect(policy.policyErrors).toEqual(["*"]);
		expect(warnings).toContain("managed: policy storage unavailable; user settings suspended");
	});
});

describe("pause and send-original under a managed policy (BG-6)", () => {
	it("are off under any managed policy unless the administrator sets them", () => {
		for (const managed of [{ policyId: "acme" }, open({ policyId: "acme" }), { typo: 1 }]) {
			const policy = mergePolicy(managed, undefined);
			expect(policy.allowUserPause).toBe(false);
			expect(policy.allowSendAnyway).toBe(false);
			for (const key of OFF) expect(policy.managedKeys).toContain(key);
		}
	});

	it("an explicit administrator value wins", () => {
		const policy = mergePolicy({ allowUserPause: true, allowSendAnyway: true }, undefined);
		expect(policy.allowUserPause).toBe(true);
		expect(policy.allowSendAnyway).toBe(true);
	});

	it("without a managed policy the consumer defaults stay", () => {
		for (const managed of [undefined, null, {}]) {
			const policy = mergePolicy(managed, undefined);
			expect(policy.allowUserPause).toBe(true);
			expect(policy.allowSendAnyway).toBe(true);
		}
	});
});
