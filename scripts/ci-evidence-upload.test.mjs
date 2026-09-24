import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

function readWorkflow(name) {
	return readFileSync(new URL(`../.github/workflows/${name}`, import.meta.url), "utf8");
}

function step(workflow, name) {
	const marker = `      - name: ${name}`;
	const start = workflow.indexOf(marker);
	assert.notEqual(start, -1, `workflow step is missing: ${name}`);
	const nextBoundary = /\n {6}- name:|\n {2}[A-Za-z0-9_-]+:/.exec(workflow.slice(start + marker.length));
	const end = nextBoundary ? start + marker.length + nextBoundary.index : workflow.length;
	return workflow.slice(start, end);
}

function uploadPaths(workflow, name) {
	const lines = step(workflow, name).split(/\r?\n/);
	const pathIndex = lines.findIndex((line) => /^\s*path:/.test(line));
	assert.notEqual(pathIndex, -1, `${name} must use an explicit path allowlist`);
	const indent = lines[pathIndex].match(/^\s*/)[0].length;
	const pathValue = lines[pathIndex].slice(indent + "path:".length).trim();
	if (pathValue !== "|") return { upload: lines.join("\n"), paths: [pathValue] };
	const paths = [];
	for (const line of lines.slice(pathIndex + 1)) {
		if (!line.trim()) continue;
		const lineIndent = line.match(/^\s*/)[0].length;
		if (lineIndent <= indent) break;
		assert.equal(lineIndent, indent + 2, `${name} path entry must remain a single allowlisted value`);
		paths.push(line.trim());
	}
	return { upload: lines.join("\n"), paths };
}

function allArtifactUploads() {
	const files = readdirSync(new URL("../.github/workflows/", import.meta.url))
		.filter((name) => /\.ya?ml$/i.test(name))
		.sort();
	const uploads = [];
	for (const file of files) {
		const workflow = readWorkflow(file);
		const markers = [...workflow.matchAll(/^ {6}- name: (.+)$/gm)];
		for (const marker of markers) {
			const upload = step(workflow, marker[1]);
			if (!/^\s+uses: actions\/upload-artifact@/m.test(upload)) continue;
			uploads.push({ key: `${file}::${marker[1]}`, ...uploadPaths(workflow, marker[1]) });
		}
	}
	return uploads;
}

test("CI artifacts exclude raw release evidence and credentials-bearing E2E output", () => {
	const workflow = readWorkflow("ci.yml");
	const quality = uploadPaths(workflow, "Upload deterministic test evidence (pinned)");
	assert.deepEqual(quality.paths, ["coverage/"]);
	assert.match(quality.upload, /if: always\(\) && steps\.evidence_boundary\.outcome == 'success'/);
	assert.match(step(workflow, "Verify CI evidence upload boundary"), /id: evidence_boundary/);

	const connector = uploadPaths(workflow, "Upload connector evidence (pinned)");
	assert.deepEqual(connector.paths, [
		".e2e-artifacts/release/*.json",
		".e2e-artifacts/release/*.xml",
		".e2e-artifacts/release/*.log",
	]);
	assert.match(connector.upload, /if: always\(\) && steps\.evidence_boundary\.outcome == 'success'/);
	assert.match(step(workflow, "Verify connector evidence upload boundary"), /id: evidence_boundary/);

	assert.doesNotMatch(quality.upload + connector.upload, /\.release-evidence|\.e2e-artifacts\/negative-credentials|\.secrets|\.env/);
});

test("retained connector files come from the tested redacting release-E2E writer", () => {
	const runner = readFileSync(new URL("./run-e2e-release.mjs", import.meta.url), "utf8");
	const tests = readFileSync(new URL("./run-e2e-release.test.mjs", import.meta.url), "utf8");
	assert.match(runner, /function redactText\(/);
	assert.match(runner, /function redactValue\(/);
	assert.match(runner, /writeLog\(stdoutPath, result\.stdout, env\)/);
	assert.match(runner, /report = redactValue\(report, env\)/);
	assert.match(runner, /redactedLogs: true/);
	assert.match(tests, /suite logs redact DSNs and credential-bearing URLs/);
});

test("every workflow artifact upload has an explicit reviewed file selection", () => {
	const expected = new Map([
		["ci.yml::Upload deterministic test evidence (pinned)", ["coverage/"]],
		["ci.yml::Upload connector evidence (pinned)", [
			".e2e-artifacts/release/*.json",
			".e2e-artifacts/release/*.xml",
			".e2e-artifacts/release/*.log",
		]],
		["ci.yml::Upload Browser Guard zips (pinned)", [
			"packages/browser-guard/dist/*.zip",
			"packages/browser-guard/dist/SHA256SUMS",
		]],
		["docs-generation.yml::Upload generated documentation (pinned)", ["docs/api/", "docs/diagrams/"]],
		["error-to-insight.yml::Upload Insights Report", ["error-insights-report.md"]],
		["release-browser-guard.yml::Upload Browser Guard release bundle (pinned)", ["release-output-browser-guard/"]],
		["release-promote.yml::Persist anti-rollback state and verification receipt (pinned)", [
			"${{ runner.temp }}/aidr-promotion-state/anti-rollback-state.json",
			"${{ runner.temp }}/aidr-promotion-state/verification-receipt.json",
		]],
		["release-promote.yml::Archive promotion evidence (pinned)", ["release-output/"]],
		["release-rc.yml::Upload unsigned release inputs (pinned)", ["${{ runner.temp }}/prepared-release.tgz"]],
		["release-rc.yml::Upload signed package inputs (pinned)", ["${{ runner.temp }}/signed-package-inputs.tgz"]],
		["release-rc.yml::Upload exact unsigned outer bundle (pinned)", ["${{ runner.temp }}/exact-release-candidate.tgz"]],
		["release-rc.yml::Upload Windows native package receipt (pinned)", ["${{ runner.temp }}/claude-native-candidate.json"]],
		["release-rc.yml::Upload candidate-bound control-plane receipt (pinned)", [
			"${{ vars.AIDR_ACCEPTANCE_DEPLOYMENT_DIR }}/smoke-evidence-${{ needs.assemble-e2e.outputs.candidate_digest }}.json",
		]],
		["release-rc.yml::Upload immutable RC evidence (pinned)", ["release-output/"]],
	]);
	const actual = allArtifactUploads();
	assert.deepEqual(actual.map(({ key }) => key).sort(), [...expected.keys()].sort());
	for (const { key, paths } of actual) assert.deepEqual(paths, expected.get(key), `${key} changed its upload scope`);
});

test("release input archives reject .env* paths before crossing the artifact boundary", () => {
	const workflow = readWorkflow("release-rc.yml");
	for (const name of ["Archive unsigned release inputs", "Archive signed package inputs"]) {
		const archive = step(workflow, name);
		assert.match(archive, /find packages\/core\/dist[\s\S]*-name '\.env\*' -print -quit \| grep -q \./);
		assert.match(archive, /Release inputs contain a forbidden \.env\* path/);
		assert.match(archive, /\.release-evidence\/aidr-sbom\.cdx\.json(?:\.sha256)?/);
		assert.doesNotMatch(archive, /\.release-evidence\/\s/);
	}
});

test("broad release-output uploads follow exact signed-bundle verification", () => {
	const rc = readWorkflow("release-rc.yml");
	const signing = rc.indexOf("      - name: Canonically sign and independently verify exact bundle");
	const attestation = rc.indexOf("      - name: Attest the exact release bundle");
	const upload = rc.indexOf("      - name: Upload immutable RC evidence (pinned)");
	assert.ok(signing >= 0 && signing < attestation && attestation < upload);

	const promotion = readWorkflow("release-promote.yml");
	const identity = promotion.indexOf("      - name: Verify RC identity, manifest, SBOM and signatures");
	const archive = promotion.indexOf("      - name: Archive promotion evidence (pinned)");
	assert.ok(identity >= 0 && identity < archive);

	const signingLibrary = readFileSync(new URL("./release-signing-lib.mjs", import.meta.url), "utf8");
	const signingTests = readFileSync(new URL("./release-signing.test.mjs", import.meta.url), "utf8");
	assert.match(signingLibrary, /untracked file in release bundle/);
	assert.match(signingLibrary, /key material cannot be a release artifact/);
	assert.match(signingLibrary, /private key material found in release artifact/);
	assert.match(signingTests, /keeps private keys and trust policy outside the signed bundle/);
});
