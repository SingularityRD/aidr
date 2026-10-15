import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { CATALOG, EXAMPLE_PATH, FILES, REFERENCE_PATH, catalogProblems, renderExample, renderReference } from "./generate-onprem-config-reference.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const generator = join(root, "scripts", "generate-onprem-config-reference.mjs");

function temporaryDirectory(t) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-onprem-config-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	return directory;
}

function envKeys(path) {
	return readFileSync(path, "utf8").split(/\r?\n/).filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line)).map((line) => line.slice(0, line.indexOf("=")));
}

/** A throwaway copy of every input the generator reads, so drift can be simulated safely. */
function generatorKit(t) {
	const kit = temporaryDirectory(t);
	for (const path of ["scripts/generate-onprem-config-reference.mjs", "scripts/deployment-prepare.mjs", "docker-compose.posture-scanner.yml", ".env.posture-scanner.example", REFERENCE_PATH, EXAMPLE_PATH]) {
		mkdirSync(dirname(join(kit, path)), { recursive: true });
		copyFileSync(join(root, path), join(kit, path));
	}
	return kit;
}

const run = (script, args = []) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8", timeout: 60_000 });

test("committed on-prem configuration reference and example are current", () => {
	assert.deepEqual(catalogProblems(), []);
	assert.equal(readFileSync(join(root, REFERENCE_PATH), "utf8"), renderReference());
	assert.equal(readFileSync(join(root, EXAMPLE_PATH), "utf8"), renderExample());
	const result = run(generator, ["--check"]);
	assert.equal(result.status, 0, result.stderr);
	assert.match(result.stdout, /is current \(\d+ variables\)/);
});

test("--check reports a stale reference and regeneration repairs it", (t) => {
	const kit = generatorKit(t);
	const script = join(kit, "scripts/generate-onprem-config-reference.mjs");
	writeFileSync(join(kit, REFERENCE_PATH), `${readFileSync(join(kit, REFERENCE_PATH), "utf8")}\nhand edit\n`);
	const stale = run(script, ["--check"]);
	assert.equal(stale.status, 1);
	assert.match(stale.stderr, /onprem-config-reference\.md is stale; run pnpm onprem:config-reference/);
	assert.equal(run(script).status, 0);
	assert.equal(run(script, ["--check"]).status, 0);
});

test("--check fails when posture scanner configuration or preparation drifts from the catalog", (t) => {
	const newScannerVariable = generatorKit(t);
	writeFileSync(join(newScannerVariable, ".env.posture-scanner.example"), `${readFileSync(join(newScannerVariable, ".env.posture-scanner.example"), "utf8")}POSTURE_SCANNER_UNDOCUMENTED_SETTING=1\nAIG_SOURCE_VERSION=v1\n`);
	const scannerResult = run(join(newScannerVariable, "scripts/generate-onprem-config-reference.mjs"), ["--check"]);
	assert.equal(scannerResult.status, 1);
	assert.match(scannerResult.stderr, /\.env\.posture-scanner\.example names POSTURE_SCANNER_UNDOCUMENTED_SETTING, which the reference does not document/);
	// Legacy names are tolerated only as Compose fallbacks, never in the operator example.
	assert.match(scannerResult.stderr, /\.env\.posture-scanner\.example names AIG_SOURCE_VERSION, which the reference does not document/);

	const missingFallback = generatorKit(t);
	const fallbackCompose = join(missingFallback, "docker-compose.posture-scanner.yml");
	writeFileSync(fallbackCompose, readFileSync(fallbackCompose, "utf8").replace("${POSTURE_SCANNER_AGENT_COUNT:-${AIG_AGENT_COUNT:-1}}", "${POSTURE_SCANNER_AGENT_COUNT:-1}"));
	const fallbackResult = run(join(missingFallback, "scripts/generate-onprem-config-reference.mjs"), ["--check"]);
	assert.equal(fallbackResult.status, 1);
	assert.match(fallbackResult.stderr, /POSTURE_SCANNER_AGENT_COUNT must fall back to AIG_AGENT_COUNT/);

	const composeVariable = generatorKit(t);
	writeFileSync(join(composeVariable, "docker-compose.posture-scanner.yml"), readFileSync(join(composeVariable, "docker-compose.posture-scanner.yml"), "utf8").replace("BRIDGE_LOG_LEVEL=${BRIDGE_LOG_LEVEL:-INFO}", "BRIDGE_LOG_LEVEL=${BRIDGE_VERBOSITY:-INFO}"));
	const composeResult = run(join(composeVariable, "scripts/generate-onprem-config-reference.mjs"), ["--check"]);
	assert.equal(composeResult.status, 1);
	assert.match(composeResult.stderr, /interpolates BRIDGE_VERBOSITY, which the reference does not document/);

	const removedVariable = generatorKit(t);
	writeFileSync(join(removedVariable, "scripts/deployment-prepare.mjs"), readFileSync(join(removedVariable, "scripts/deployment-prepare.mjs"), "utf8").replaceAll("AIDR_DRAIN_SIEM", "AIDR_SIEM_DRAIN"));
	const removedResult = run(join(removedVariable, "scripts/generate-onprem-config-reference.mjs"), ["--check"]);
	assert.equal(removedResult.status, 1);
	assert.match(removedResult.stderr, /\.env\.readiness AIDR_DRAIN_SIEM is catalogued but scripts\/deployment-prepare\.mjs no longer writes it/);
	// Refusing drift also means refusing to regenerate a misleading reference.
	assert.equal(run(join(removedVariable, "scripts/generate-onprem-config-reference.mjs")).status, 1);
});

test("the catalog lists exactly the variables a prepared installation writes", (t) => {
	const directory = temporaryDirectory(t);
	const output = join(directory, "cloud");
	const publicKey = join(directory, "artifact.pem");
	writeFileSync(publicKey, generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }));
	const result = spawnSync(process.execPath, [join(root, "scripts/deployment-prepare.mjs"),
		"--mode", "cloud", "--output", output,
		"--dashboard-url", "https://console.customer.example", "--supabase-url", "https://api.customer.example",
		"--device-start-upstream-url", "https://project.supabase.co/functions/v1/device-start",
		"--artifact-verification-public-key-file", publicKey,
		"--telemetry-queue-root", "/var/lib/aidr-telemetry",
		"--region", "self-hosted", "--tenant-region", "self-hosted", "--offline-policy", "keep_enforcing_local",
	], { encoding: "utf8", timeout: 60_000 });
	assert.equal(result.status, 0, result.stderr);
	for (const file of Object.keys(FILES)) {
		const expected = CATALOG.filter((entry) => entry.file === file && ["always", "cloud"].includes(entry.written)).map((entry) => entry.name).sort();
		assert.deepEqual(envKeys(join(output, file)).sort(), expected, `${file} differs from the catalog`);
	}
	const example = readFileSync(join(root, EXAMPLE_PATH), "utf8");
	for (const file of Object.keys(FILES)) {
		// The example never carries a generated secret value.
		for (const entry of CATALOG.filter((item) => item.file === file && item.source === "generated-secret")) {
			assert.match(example, new RegExp(`^${entry.name}=$`, "m"), `${entry.name} must stay blank in the example`);
		}
	}
});
