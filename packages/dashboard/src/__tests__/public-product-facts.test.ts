// The public landing and editions pages quote countable facts (rule counts, AI Security
// Posture dataset size, supported sites, edition terms). These tests bind each number to
// the repository so stale marketing copy fails the build. Prices are never published.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { QUOTE_CONTACT_EMAIL } from "../billing/commercial";
import { retentionTerms, seatTerms } from "../billing/plans";
import {
	AGENT_CONNECTORS,
	AIG_AI_COMPONENTS,
	AIG_CVE_RULES_FLOOR,
	BROWSER_GUARD_SITES,
	POSTURE_MCP_RISK_CATEGORIES,
	POSTURE_SKILL_RISK_CODES,
	PUBLIC_PLANS,
	QUOTE_NOTE,
	SHIPPED_THREAT_RULES,
	THREAT_RULE_FILES,
} from "../ui/pages/public/product-facts";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");

function yamlFiles(dir: string, recursive = false): string[] {
	return readdirSync(join(repoRoot, dir), { recursive })
		.map(String)
		.filter((name) => /\.ya?ml$/.test(name));
}

describe("public product facts", () => {
	it("matches the shipped threat rule count", () => {
		const files = yamlFiles("threats");
		const rules = files
			.map((name) => readFileSync(join(repoRoot, "threats", name), "utf8"))
			.reduce((total, text) => total + (text.match(/^- id:/gm)?.length ?? 0), 0);
		expect(files).toHaveLength(THREAT_RULE_FILES);
		expect(rules).toBe(SHIPPED_THREAT_RULES);
	});

	it("matches the bundled AI Security Posture vulnerability and fingerprint dataset", () => {
		expect(yamlFiles("vendor/ai-infra-guard/data/vuln", true).length).toBeGreaterThanOrEqual(
			AIG_CVE_RULES_FLOOR,
		);
		expect(yamlFiles("vendor/ai-infra-guard/data/fingerprints", true)).toHaveLength(
			AIG_AI_COMPONENTS,
		);
	});

	it("matches the MCP risk categories and the skill-scan taxonomy", () => {
		const categories = readFileSync(
			join(repoRoot, "packages/core/src/mcp-aig-categories.ts"),
			"utf8",
		);
		const ids = new Set(categories.match(/\bid: "mcp-\d{2}"/g));
		expect(ids.size).toBe(POSTURE_MCP_RISK_CATEGORIES);
		const skillRules = readFileSync(join(repoRoot, "threats/skill-scan.yaml"), "utf8");
		const codes = [...new Set(skillRules.match(/SKILL-T\d{2}/g)?.map((id) => id.slice(6)))].sort();
		expect(codes).toEqual([...POSTURE_SKILL_RISK_CODES]);
	});

	// Shared site modules that are not a dedicated adapter for one AI product:
	// the registry, the generic fallback, the Shadow AI catalog, admin-defined internal sites
	// and the frame-host list for adapters that also run in subframes.
	const NON_ADAPTER_SITE_FILES = new Set(["index.ts", "generic.ts", "catalog.ts", "custom.ts", "frames.ts"]);

	it("lists exactly the Browser Guard sites that have a dedicated adapter", () => {
		const adapters = readdirSync(join(repoRoot, "packages/browser-guard/src/sites"))
			.filter((name) => name.endsWith(".ts") && !NON_ADAPTER_SITE_FILES.has(name))
			.map((name) => name.replace(/\.ts$/, ""))
			.sort();
		expect(BROWSER_GUARD_SITES.map((site) => site.toLowerCase()).sort()).toEqual(adapters);
	});

	it("names every connector in the sold support matrix", () => {
		const matrix = JSON.parse(
			readFileSync(join(repoRoot, "deploy/native/support-matrix.json"), "utf8"),
		) as { soldConnectorScope: string[] };
		const shown = AGENT_CONNECTORS.map((name) =>
			name.toLowerCase().replace(" cli", "").replace(/\s+/g, "-"),
		).map((id) => (id === "vs-code" ? "vscode" : id));
		expect(shown.sort()).toEqual([...matrix.soldConnectorScope].sort());
	});

	it("publishes the edition ladder from the catalog mirror with quote-only pricing", () => {
		expect(PUBLIC_PLANS.map((plan) => plan.displayName)).toEqual([
			"Free",
			"Team",
			"Business",
			"Enterprise",
		]);
		const plan = (name: string) => {
			const found = PUBLIC_PLANS.find((candidate) => candidate.displayName === name);
			if (!found) throw new Error(`missing plan ${name}`);
			return found;
		};
		expect(plan("Free").includedAgents).toBe(1);
		expect(seatTerms(plan("Free"))).toBe("1 protected agent");
		expect(seatTerms(plan("Team"))).toBe("Minimum 3 developers");
		expect(seatTerms(plan("Business"))).toBe("Minimum 25 developers");
		expect(retentionTerms(plan("Enterprise"))).toBe("Contractual retention");
		for (const edition of PUBLIC_PLANS) {
			expect(Object.keys(edition).some((key) => /price|currency/i.test(key))).toBe(false);
		}
		expect(QUOTE_NOTE).toMatch(/^Prices are not published\./);
		expect(QUOTE_NOTE).not.toMatch(/list price|COM-001|\$|USD/i);
		expect(QUOTE_CONTACT_EMAIL).toBe("anil@singularityrd.com");
	});
});
