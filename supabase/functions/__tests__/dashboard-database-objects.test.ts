/**
 * AIDR-019: dashboard browser code must only read tables/views and call RPCs
 * that a migration in supabase/migrations actually creates. The original
 * finding named `referrals` and `public.users`, which no migration creates;
 * this guard fails if any such dead query reappears.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DASHBOARD_SRC = join(ROOT, "packages", "dashboard", "src");
const MIGRATIONS = join(ROOT, "supabase", "migrations");

function dashboardSources(dir: string): string[] {
	const found: string[] = [];
	for (const entry of readdirSync(dir)) {
		if (entry === "__tests__" || entry === "node_modules" || entry === "dist") continue;
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) found.push(...dashboardSources(full));
		else if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry) && !entry.endsWith(".d.ts")) found.push(full);
	}
	return found;
}

function escape(name: string): string {
	return name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

type Reference = { kind: "from" | "rpc"; name: string; location: string };

function collectReferences(): Reference[] {
	const references: Reference[] = [];
	for (const file of dashboardSources(DASHBOARD_SRC)) {
		const source = readFileSync(file, "utf8");
		for (const match of source.matchAll(/\.(from|rpc)\(\s*["'`]([A-Za-z0-9_.]+)["'`]/g)) {
			const line = source.slice(0, match.index).split("\n").length;
			references.push({
				kind: match[1] as "from" | "rpc",
				name: match[2].replace(/^public\./, "").toLowerCase(),
				location: `${relative(ROOT, file)}:${line}`,
			});
		}
	}
	return references;
}

describe("dashboard database object coverage (AIDR-019)", () => {
	const migrationSql = readdirSync(MIGRATIONS)
		.filter((file) => file.endsWith(".sql"))
		.map((file) => readFileSync(join(MIGRATIONS, file), "utf8"))
		.join("\n")
		.toLowerCase();

	function created(reference: Reference): boolean {
		const name = escape(reference.name);
		const pattern = reference.kind === "rpc"
			? new RegExp(`create\\s+(or\\s+replace\\s+)?function\\s+(public\\.)?"?${name}"?\\s*\\(`)
			: new RegExp(`create\\s+(or\\s+replace\\s+)?(table|view|materialized\\s+view)\\s+(if\\s+not\\s+exists\\s+)?(public\\.)?"?${name}"?[\\s(]`);
		return pattern.test(migrationSql);
	}

	it("finds the dashboard query surface", () => {
		expect(collectReferences().length).toBeGreaterThan(10);
	});

	it("every .from()/.rpc() target in dashboard source is created by a migration", () => {
		const missing = collectReferences()
			.filter((reference) => !created(reference))
			.map((reference) => `${reference.kind}:${reference.name} (${reference.location})`);
		expect(missing).toEqual([]);
	});

	it("does not query the objects AIDR-019 originally named", () => {
		const names = collectReferences().map((reference) => reference.name);
		expect(names).not.toContain("referrals");
		expect(names).not.toContain("users");
	});

	it("rejects a reference to an object no migration creates", () => {
		expect(created({ kind: "from", name: "referrals", location: "fixture" })).toBe(false);
		expect(created({ kind: "rpc", name: "claim_referral_credits", location: "fixture" })).toBe(false);
		expect(created({ kind: "from", name: "approval_requests", location: "fixture" })).toBe(true);
	});
});
