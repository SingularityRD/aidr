import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { build } from "esbuild";
import { gatewayBundleOptions, readRuleSets } from "../../scripts/bundle-options.mjs";

/**
 * The gateway's embedded rule set carries the top-level threat rule files only;
 * toxic-flow capability patterns (threats/flow/capabilities.yaml) reach the
 * bundle through the core's embedded copy, which the core suite drift-tests
 * against the YAML. This test proves the bundled gateway classifies with that
 * data: a database dump read followed by a send tool completes an exfil chain.
 */

const packageRoot = resolve(import.meta.dirname, "../..");
const repoRoot = resolve(packageRoot, "../..");

test("the bundled gateway applies the shipped toxic-flow capability patterns", async () => {
	const root = await mkdtemp(join(tmpdir(), "aidr-mcp-flow-bundle-"));
	try {
		const entry = join(root, "entry.mjs");
		await writeFile(
			entry,
			`import { createToolCallDetector } from ${JSON.stringify(join(packageRoot, "src/detection.mjs"))};
const evaluate = createToolCallDetector({ stateDir: process.argv[2], detection: {} });
const server = { id: "files", tenantId: "t" };
const client = { id: "agent", tenantId: "t" };
const call = (toolName, args) => evaluate({ server, client, toolName, args })
	.then((verdict) => verdict.category, (error) => \`\${error.code}:\${error.category ?? ""}:\${error.threatId ?? ""}\`);
console.log(JSON.stringify([
	await call("read_file", { path: "/srv/exports/customer-dump.sql" }),
	await call("publish_report", { title: "weekly summary" }),
]));
`,
		);
		const outfile = join(root, "bundle.mjs");
		await build({
			...gatewayBundleOptions({ ruleSets: await readRuleSets() }),
			entryPoints: [entry],
			outfile,
			logLevel: "silent",
		});
		// The bundle embeds the capability YAML verbatim (through the core).
		const yaml = await readFile(join(repoRoot, "threats", "flow", "capabilities.yaml"), "utf8");
		const bundled = await readFile(outfile, "utf8");
		assert.ok(bundled.includes("EMBEDDED_FLOW_CAPABILITIES_YAML"));
		assert.ok(yaml.includes("database_dump"));

		const home = join(root, "home");
		await mkdir(home);
		const run = spawnSync(process.execPath, [outfile, join(root, "state")], {
			env: { ...process.env, HOME: home, USERPROFILE: home },
			encoding: "utf8",
			timeout: 60_000,
		});
		assert.equal(run.status, 0, run.stderr);
		const [first, second] = JSON.parse(run.stdout.trim());
		assert.notEqual(first.split(":")[0], "arguments_blocked");
		assert.equal(second, "approval_required:toxic_flow:AIDR-FLOW-002");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
