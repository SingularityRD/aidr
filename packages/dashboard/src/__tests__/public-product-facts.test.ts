// The public landing and pricing pages quote countable facts (rule counts, AIG
// catalog size, supported sites, list prices). These tests bind each number to
// the repository so stale marketing copy fails the build.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { headlinePrice, priceTerms } from "../billing/plans";
import {
	AGENT_CONNECTORS,
	AIG_AI_COMPONENTS,
	AIG_CVE_RULES_FLOOR,
	BROWSER_GUARD_SITES,
	LIST_PRICE_NOTE,
	PUBLIC_PLANS,
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

	it("matches the vendored AI Infra Guard catalog", () => {
		expect(yamlFiles("vendor/ai-infra-guard/data/vuln", true).length).toBeGreaterThanOrEqual(
			AIG_CVE_RULES_FLOOR,
		);
		expect(yamlFiles("vendor/ai-infra-guard/data/fingerprints", true)).toHaveLength(
			AIG_AI_COMPONENTS,
		);
	});

	it("lists exactly the Browser Guard sites that have a dedicated adapter", () => {
		const adapters = readdirSync(join(repoRoot, "packages/browser-guard/src/sites"))
			.filter((name) => name.endsWith(".ts") && name !== "index.ts" && name !== "generic.ts")
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

	it("publishes the plan ladder from the catalog mirror with the approval caveat", () => {
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
		const free = plan("Free");
		const team = plan("Team");
		const business = plan("Business");
		const enterprise = plan("Enterprise");
		expect(headlinePrice(free)).toBe("$0");
		expect(free.includedAgents).toBe(1);
		expect(headlinePrice(team)).toBe("$24");
		expect(priceTerms(team)).toMatch(/\$20 per developer \/ month billed annually/);
		expect(team.minSeats).toBe(3);
		expect(headlinePrice(business)).toBe("$45");
		expect(priceTerms(business)).toMatch(/billed annually/);
		expect(business.minSeats).toBe(25);
		expect(headlinePrice(enterprise)).toBe("Custom");
		expect(LIST_PRICE_NOTE).toMatch(/subject to COM-001 approval/);
	});
});
