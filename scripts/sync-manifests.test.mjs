import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { nextChartVersion, SYNCS, syncChartText, syncManifests } from "./sync-manifests.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CHART = "deploy/helm/aidr/Chart.yaml";

function fixtureRoot(t) {
	const dir = mkdtempSync(path.join(tmpdir(), "aidr-sync-manifests-"));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	for (const relative of new Set(SYNCS.flatMap(({ source, target }) => [source, target]))) {
		mkdirSync(path.dirname(path.join(dir, relative)), { recursive: true });
		cpSync(path.join(root, relative), path.join(dir, relative));
	}
	return dir;
}

function bump(dir, relative, version) {
	const file = path.join(dir, relative);
	const json = JSON.parse(readFileSync(file, "utf8"));
	json.version = version;
	writeFileSync(file, `${JSON.stringify(json, null, "\t")}\n`);
}

test("the repository's version-bearing manifests match their package versions", () => {
	const result = spawnSync(process.execPath, [path.join(root, "scripts/sync-manifests.mjs"), "--check"], { cwd: root, encoding: "utf8" });
	assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
	const chart = readFileSync(path.join(root, CHART), "utf8");
	const dashboard = JSON.parse(readFileSync(path.join(root, "packages/dashboard/package.json"), "utf8")).version;
	assert.match(chart, new RegExp(`^appVersion: "${dashboard.replaceAll(".", "\\.")}"$`, "mu"));
});

test("a Changesets major bump moves the Helm appVersion and the chart version together (OPS-3)", (t) => {
	const dir = fixtureRoot(t);
	const before = readFileSync(path.join(dir, CHART), "utf8");
	const chartVersion = /^version: (\S+)$/mu.exec(before)[1];
	for (const pkg of ["packages/dashboard/package.json", "packages/claude-code/package.json", "packages/openclaw/package.json"]) bump(dir, pkg, "1.0.0");

	const lines = [];
	const check = syncManifests({ root: dir, check: true, log: (line) => lines.push(line) });
	assert.ok(check.drifted.includes(CHART), "the chart must be reported as drifted before the sync");
	assert.deepEqual(check.written, []);
	assert.equal(readFileSync(path.join(dir, CHART), "utf8"), before, "--check never writes");

	const written = syncManifests({ root: dir, log: () => {} });
	assert.ok(written.written.includes(CHART));
	const after = readFileSync(path.join(dir, CHART), "utf8");
	assert.match(after, /^appVersion: "1\.0\.0"$/mu);
	const [major, minor] = chartVersion.split(".").map(Number);
	assert.match(after, new RegExp(`^version: ${major}\\.${minor + 1}\\.0$`, "mu"));
	// Only the two version lines change; comments, description and keys survive.
	const changed = after.split("\n").filter((line, index) => line !== before.split("\n")[index]);
	assert.equal(changed.length, 2, changed.join("\n"));
	for (const manifest of [".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", "packages/openclaw/openclaw.plugin.json"]) {
		assert.equal(JSON.parse(readFileSync(path.join(dir, manifest), "utf8")).version, "1.0.0", manifest);
	}
	assert.ok(JSON.parse(readFileSync(path.join(dir, ".claude-plugin/marketplace.json"), "utf8")).plugins.every((plugin) => plugin.version === "1.0.0"));
	assert.deepEqual(syncManifests({ root: dir, check: true, log: () => {} }).drifted, [], "a second run is a no-op");
});

test("chart version policy: product patch -> chart patch, product minor/major -> chart minor", () => {
	assert.equal(nextChartVersion("0.1.0", "0.6.0", "0.6.1"), "0.1.1");
	assert.equal(nextChartVersion("0.1.3", "0.6.1", "0.7.0"), "0.2.0");
	assert.equal(nextChartVersion("0.1.0", "0.6.0", "1.0.0"), "0.2.0");
	assert.throws(() => nextChartVersion("0.1.0", "0.6.0", "1.0.0-rc.1"), /not a plain MAJOR\.MINOR\.PATCH/u);
});

test("syncChartText leaves an already-synced chart untouched and refuses a chart without appVersion", () => {
	const text = 'apiVersion: v2\nname: aidr\nversion: 0.1.0\nappVersion: "0.6.0"\n';
	assert.deepEqual(syncChartText(text, "0.6.0"), { text, changed: false, previous: "0.6.0" });
	assert.throws(() => syncChartText("apiVersion: v2\nversion: 0.1.0\n", "1.0.0"), /no top-level appVersion/u);
});

test("`pnpm run version` syncs manifests and `verify:manifests` checks them", () => {
	const scripts = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).scripts;
	assert.equal(scripts.version, "changeset version && node scripts/sync-manifests.mjs");
	assert.match(scripts["verify:manifests"], /node scripts\/sync-manifests\.mjs --check/u);
	assert.match(scripts["quality:static"], /pnpm verify:manifests/u);
});
