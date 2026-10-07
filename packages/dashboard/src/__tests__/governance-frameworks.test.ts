// Governance framework control mapping (governance/frameworks/*.yaml): every
// referenced capability and evidence source exists in this repository, the
// dashboard embed matches the YAML, identifiers follow each framework's scheme,
// the text carries no banned commercial claim, and coverage is computed only
// from the tenant's deployment signals.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { frameworkCoverage, SIGNAL_KEYS, type SignalKey } from "../lib/governance";
import { GOVERNANCE_MAPPING } from "../lib/governance-frameworks.generated";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

interface SyncModule {
	loadGovernanceFrameworks(): { sources: Array<{ file: string; text: string }> };
	validateGovernanceFrameworks(mapping?: unknown): string[];
	governanceFrameworksSource(mapping?: unknown): string;
	CAPABILITY_SIGNALS: readonly string[];
}

async function sync(): Promise<SyncModule> {
	return (await import(
		pathToFileURL(resolve(ROOT, "scripts/sync-governance-frameworks.mjs")).href
	)) as SyncModule;
}

const allSignals = (value: boolean) =>
	Object.fromEntries(SIGNAL_KEYS.map((key) => [key, value])) as Record<SignalKey, boolean>;

describe("governance framework mapping", () => {
	it("references only capabilities and evidence sources that exist in the repository", async () => {
		const mod = await sync();
		expect(mod.validateGovernanceFrameworks()).toEqual([]);
	});

	it("is embedded in the dashboard exactly as the YAML says", async () => {
		const mod = await sync();
		const embedded = readFileSync(
			resolve(ROOT, "packages/dashboard/src/lib/governance-frameworks.generated.ts"),
			"utf8",
		);
		expect(embedded.replaceAll("\r\n", "\n")).toBe(mod.governanceFrameworksSource());
		// Repository paths stay out of the browser bundle.
		expect(embedded).not.toContain('"paths"');
	});

	it("uses the scorecard's signals, and the SQL returns every one of them", async () => {
		const mod = await sync();
		const sql = readFileSync(
			resolve(ROOT, "supabase/migrations/20260927000060_governance_scorecard.sql"),
			"utf8",
		);
		const tenantSignals = mod.CAPABILITY_SIGNALS.filter(
			(s) => s !== "always" && s !== "local_only",
		);
		expect([...tenantSignals].sort()).toEqual([...SIGNAL_KEYS].sort());
		for (const signal of tenantSignals) expect(sql).toContain(`'${signal}',`);
	});

	it("covers the four frameworks with their own identifier schemes", () => {
		expect(GOVERNANCE_MAPPING.frameworks.map((f) => f.id)).toEqual([
			"nist-ai-rmf",
			"iso-iec-42001",
			"eu-ai-act",
			"kvkk-gdpr",
		]);
		const ids = (id: string) =>
			GOVERNANCE_MAPPING.frameworks.find((f) => f.id === id)?.controls.map((c) => c.id) ?? [];
		expect(ids("nist-ai-rmf")).toEqual(
			expect.arrayContaining(["GOVERN 1.6", "MAP 3.5", "MEASURE 2.4", "MANAGE 4.1"]),
		);
		expect(ids("iso-iec-42001")).toEqual(expect.arrayContaining(["A.6.2.8", "A.9.2", "A.10.3"]));
		expect(ids("eu-ai-act")).toEqual(
			expect.arrayContaining(["Art. 4", "Art. 14", "Art. 26(2)", "Art. 26(6)"]),
		);
		expect(ids("kvkk-gdpr")).toEqual(
			expect.arrayContaining(["GDPR Art. 25", "GDPR Art. 32", "KVKK Art. 12"]),
		);
	});

	it("maps human-oversight controls to the approval and oversight analytics capabilities", () => {
		const control = (framework: string, id: string) =>
			GOVERNANCE_MAPPING.frameworks
				.find((f) => f.id === framework)
				?.controls.find((c) => c.id === id);
		for (const [framework, id] of [
			["nist-ai-rmf", "MAP 3.5"],
			["eu-ai-act", "Art. 14"],
			["eu-ai-act", "Art. 26(2)"],
		] as const) {
			expect(control(framework, id)?.capabilities).toEqual(
				expect.arrayContaining(["human-approval", "oversight-analytics"]),
			);
		}
		expect(control("iso-iec-42001", "A.3.2")?.capabilities).toContain("human-approval");
		expect(control("eu-ai-act", "Art. 4")?.capabilities).toContain("acceptable-use-notice");
	});

	it("carries honest notes and no banned commercial claims", async () => {
		const mod = await sync();
		const registry = JSON.parse(
			readFileSync(
				resolve(ROOT, "docs/production-readiness/commercial-go-evidence-registry.json"),
				"utf8",
			),
		) as { claimPatterns: Array<{ id: string; pattern: string }> };
		const text = mod
			.loadGovernanceFrameworks()
			.sources.map((s) => s.text)
			.join("\n");
		for (const claim of registry.claimPatterns) {
			expect(new RegExp(claim.pattern, "i").test(text), claim.id).toBe(false);
		}
		expect(text).not.toMatch(/AI Infra Guard|\bAIG\b/);
		for (const framework of GOVERNANCE_MAPPING.frameworks) {
			for (const control of framework.controls) expect(control.note.length).toBeGreaterThan(40);
		}
	});
});

describe("framework coverage", () => {
	it("is zero in place for a workspace that deployed nothing, but never counts customer controls", () => {
		const none = frameworkCoverage(allSignals(false));
		const all = frameworkCoverage(allSignals(true));
		for (const [index, framework] of none.entries()) {
			// Built-in capabilities (audit log, tenant isolation, ...) are always in place.
			const deployed = all[index];
			if (!deployed) throw new Error("missing framework");
			expect(framework.inPlacePercent).toBeLessThan(deployed.inPlacePercent);
			expect(deployed.inPlacePercent).toBeLessThanOrEqual(deployed.availablePercent);
			expect(framework.availablePercent).toBe(deployed.availablePercent);
			expect(framework.counts.customer).toBe(
				framework.controls.filter((c) => c.control.coverage === "customer-responsibility").length,
			);
		}
	});

	it("follows the signals of the mapped capabilities", () => {
		const eu = (signals: Record<SignalKey, boolean>) =>
			frameworkCoverage(signals).find((f) => f.framework.id === "eu-ai-act");
		const article4 = (signals: Record<SignalKey, boolean>) =>
			eu(signals)?.controls.find((c) => c.control.id === "Art. 4");
		expect(article4(allSignals(false))?.status).toBe("not_deployed");
		expect(article4({ ...allSignals(false), acceptable_use_acknowledged: true })?.status).toBe(
			"partly_in_place",
		);
		expect(article4(allSignals(true))?.status).toBe("in_place");
		expect(eu(allSignals(true))?.controls.find((c) => c.control.id === "Art. 5")?.status).toBe(
			"customer",
		);
	});
});
