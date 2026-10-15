/**
 * Production must never render mock/demo/sample data as if it were real.
 *
 * Walks the module graph reachable from the production entry (src/main.tsx),
 * following static imports, re-exports and dynamic import() calls, and fails
 * when a production module
 *   - lives in a test/fixture/mock/demo location or is named like one,
 *   - imports a fake-data or request-mocking package, or
 *   - contains a fake-data generator or a demo-mode switch.
 * Synthetic data, if ever needed, belongs in __tests__/ or behind a DEV-only
 * module that this graph cannot reach.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = resolve(__dirname, "..");
const ENTRY = resolve(SRC, "main.tsx");

const SPECIFIER =
	/(?:import|export)\s[^"'`;]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)|import\s+["']([^"']+)["']/g;

function resolveModule(from: string, specifier: string): string | null {
	const base = resolve(dirname(from), specifier);
	for (const candidate of [
		base,
		`${base}.ts`,
		`${base}.tsx`,
		resolve(base, "index.ts"),
		resolve(base, "index.tsx"),
	]) {
		if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
	}
	return null;
}

function productionGraph(): { files: string[]; packages: Set<string> } {
	const seen = new Set<string>();
	const packages = new Set<string>();
	const queue = [ENTRY];
	while (queue.length > 0) {
		const file = queue.pop() as string;
		if (seen.has(file)) continue;
		seen.add(file);
		if (!/\.(ts|tsx)$/.test(file)) continue;
		const text = readFileSync(file, "utf8");
		for (const match of text.matchAll(SPECIFIER)) {
			const specifier = match[1] ?? match[2] ?? match[3];
			if (!specifier) continue;
			if (specifier.startsWith(".")) {
				const target = resolveModule(file, specifier);
				if (target) queue.push(target);
			} else packages.add(specifier);
		}
	}
	return { files: [...seen], packages };
}

const FAKE_PACKAGES =
	/^(@faker-js\/|faker$|casual$|chance$|msw(\/|$)|miragejs$|json-server$|@mswjs\/|lorem)/;
const FAKE_PATH =
	/(^|[\\/])(__tests__|__mocks__|fixtures?|mocks?|demo|stories)([\\/]|$)|[.-](mock|demo|fixture|fake|stories)\.[jt]sx?$/i;
const FAKE_CONTENT: Array<[RegExp, string]> = [
	[/\bMath\.random\s*\(/, "Math.random() (invented values)"],
	[/\bfaker\./, "faker generator"],
	[/lorem ipsum/i, "lorem ipsum filler"],
	[
		/\b(mock|demo|fake|sample|dummy)(Data|Agents|Events|Incidents|Metrics|Rows|Stats)\b/,
		"named fake dataset",
	],
	[/\b(DEMO_MODE|demoMode|isDemo|VITE_DEMO|VITE_MOCK|useMockData)\b/, "demo-mode switch"],
];

describe("production module graph carries no demo or mock data", () => {
	const graph = productionGraph();
	const files = graph.files.map((file) => relative(SRC, file));

	it("reaches the real pages from the entry", () => {
		// Guards the walker itself: a broken resolver would make every check vacuous.
		for (const page of [
			"ui/pages/DashboardPage.tsx",
			"ui/pages/AgentsPage.tsx",
			"ui/pages/AgentDetailPage.tsx",
			"ui/pages/EventsPage.tsx",
			"ui/pages/IncidentsPage.tsx",
		]) {
			expect(files.map((file) => file.replaceAll("\\", "/"))).toContain(page);
		}
		expect(files.length).toBeGreaterThan(60);
	});

	it("imports no test, fixture, mock or demo module", () => {
		expect(files.filter((file) => FAKE_PATH.test(file))).toEqual([]);
	});

	it("imports no fake-data or request-mocking package", () => {
		expect([...graph.packages].filter((name) => FAKE_PACKAGES.test(name))).toEqual([]);
	});

	it("contains no fake-data generator or demo-mode switch", () => {
		const hits: string[] = [];
		// Code only: generated JSON catalogs (e.g. rule titles) quote these words as data.
		for (const file of graph.files.filter((name) => /\.tsx?$/.test(name))) {
			const text = readFileSync(file, "utf8");
			for (const [pattern, label] of FAKE_CONTENT) {
				if (pattern.test(text)) hits.push(`${relative(SRC, file)}: ${label}`);
			}
		}
		expect(hits).toEqual([]);
	});

	it("keeps the legacy /demo route a redirect to sign-in, not a demo dashboard", () => {
		const main = readFileSync(ENTRY, "utf8");
		expect(main).toMatch(
			/\{\s*path:\s*"demo",\s*loader:\s*\(\)\s*=>\s*redirect\("\/login\?returnTo=%2Fonboarding"\)\s*\}/,
		);
	});
});
