/**
 * `aidr canary deploy|list|remove|status` against an isolated home and project.
 */

import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	type CanaryCommandDeps,
	canaryDeployCommand,
	canaryListCommand,
	canaryRemoveCommand,
	canaryStatusCommand,
} from "../commands/canary.js";

let root: string;
let home: string;
let project: string;
let deps: CanaryCommandDeps;
let out: string[];
let err: string[];

function lastJson<T>(): T {
	return JSON.parse(out.at(-1) as string) as T;
}

beforeEach(() => {
	root = mkdtempSync(join(tmpdir(), "aidr-canary-cli-"));
	home = join(root, "home");
	project = join(root, "project");
	mkdirSync(home, { recursive: true });
	mkdirSync(project, { recursive: true });
	vi.stubEnv("HOME", home);
	out = [];
	err = [];
	const configPath = join(root, "config.json");
	writeFileSync(configPath, JSON.stringify({ mode: "local" }));
	deps = {
		homeDir: home,
		cwd: project,
		registryPath: join(home, ".singularity-aidr", "canary", "registry.json"),
		configPath,
		out: (line) => out.push(line),
		err: (line) => err.push(line),
	};
	process.exitCode = undefined;
});

afterEach(() => {
	vi.unstubAllEnvs();
	process.exitCode = undefined;
	rmSync(root, { recursive: true, force: true });
});

describe("aidr canary", () => {
	it("deploys the requested kinds and never overwrites an existing file", async () => {
		writeFileSync(join(project, ".env.backup"), "OWN=1\n");
		await canaryDeployCommand({ kinds: "env,db-url", json: true }, deps);
		const result = lastJson<{ deployed: Array<{ kind: string; path: string }> }>();
		expect(result.deployed.map((entry) => entry.path).sort()).toEqual(
			[join(project, ".env.database.bak"), join(project, ".env.production.bak")].sort(),
		);
		expect(readFileSync(join(project, ".env.backup"), "utf8")).toBe("OWN=1\n");
		expect(process.exitCode).toBeUndefined();
	});

	it("rejects unknown kinds without writing anything", async () => {
		await canaryDeployCommand({ kinds: "aws,kubeconfig" }, deps);
		expect(err.join("\n")).toMatch(/Unknown canary kind "kubeconfig"/);
		expect(process.exitCode).toBe(1);
		expect(existsSync(deps.registryPath as string)).toBe(false);
	});

	it("lists decoys with their state and never prints digests", async () => {
		await canaryDeployCommand({ path: project }, deps);
		out = [];
		await canaryListCommand({ json: true }, deps);
		const listed = lastJson<{ canaries: Array<Record<string, unknown>> }>().canaries;
		expect(listed).toHaveLength(6);
		for (const entry of listed) {
			expect(Object.keys(entry).sort()).toEqual(["created_at", "id", "kind", "path", "state"]);
			expect(entry.state).toBe("intact");
		}
	});

	it("reports status, including modified decoys and recorded triggers", async () => {
		await canaryDeployCommand({ kinds: "env" }, deps);
		const envPath = join(project, ".env.backup");
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
		writeFileSync(
			join(home, ".singularity-aidr", "audit.jsonl"),
			`${JSON.stringify({ type: "runtime_verdict", timestamp: "2026-09-25T10:00:00.000Z", category: "canary_triggered", verdict: "deny" })}\n`,
		);
		out = [];
		await canaryStatusCommand({ json: true }, deps);
		expect(lastJson<Record<string, unknown>>()).toMatchObject({
			registry: "ok",
			counts: { intact: 1, missing: 0, modified: 0 },
			triggers: { count: 1, last: "2026-09-25T10:00:00.000Z", available: true },
		});
		expect(process.exitCode).toBeUndefined();

		writeFileSync(envPath, "changed\n");
		out = [];
		await canaryStatusCommand({}, deps);
		expect(out.join("\n")).toMatch(/1 modified/);
		expect(process.exitCode).toBe(1);
	});

	it("removes one decoy or all of them and cleans up", async () => {
		await canaryDeployCommand({ json: true }, deps);
		const deployed = lastJson<{ deployed: Array<{ id: string; path: string }> }>().deployed;
		const first = deployed[0] as { id: string; path: string };
		const rest = deployed.slice(1);

		await canaryRemoveCommand(first.id, {}, deps);
		expect(existsSync(first.path)).toBe(false);
		expect(out.at(-1)).toContain("decoy file deleted");

		await canaryRemoveCommand(undefined, { all: true, json: true }, deps);
		expect(lastJson<{ removed: unknown[] }>().removed).toHaveLength(rest.length);
		for (const entry of rest) expect(existsSync(entry.path)).toBe(false);
		expect(existsSync(join(home, ".aws"))).toBe(false);

		out = [];
		await canaryListCommand({}, deps);
		expect(out.join("\n")).toMatch(/No canary credentials are deployed/);
	});

	it("requires exactly one of an id or --all", async () => {
		await canaryRemoveCommand(undefined, {}, deps);
		expect(err.at(-1)).toMatch(/exactly one canary id or --all/);
		expect(process.exitCode).toBe(1);
	});
});
