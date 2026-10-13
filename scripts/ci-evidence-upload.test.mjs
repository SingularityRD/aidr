import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";
import { VSIX_PACKAGE_FILES } from "./lib/vsix-package-files.mjs";

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

function job(workflow, name) {
	const marker = `  ${name}:\n`;
	const start = workflow.indexOf(marker);
	assert.notEqual(start, -1, `workflow job is missing: ${name}`);
	const next = /\n {2}[A-Za-z0-9_-]+:/u.exec(workflow.slice(start + marker.length));
	return workflow.slice(start, next ? start + marker.length + next.index : undefined);
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

test("CI and RC require the owned SDK mTLS gate after the complete private profile gate", () => {
	for (const [file, gateName] of [
		["ci.yml", "Map-free private build, complete Node suite and installed signed MCP"],
		["release-rc.yml", "Private privacy full and installed signed MCP release gate"],
	]) {
		const workflow = readWorkflow(file);
		const full = step(workflow, gateName);
		const sdk = step(workflow, "Mandatory SDK ESM and CJS mTLS input and output gate");
		assert.match(full, /pnpm --filter @singularityrd\/aidr-privacy test:ci:platform/);
		const build = sdk.indexOf("pnpm --filter @singularityrd/aidr-privacy build:release");
		const check = sdk.indexOf("node --test packages/sdk/src/__tests__/privacy-send-mtls.test.mjs");
		assert.ok(build >= 0 && check > build, `${file}: the SDK gate needs fresh private bytes`);
		assert.ok(workflow.indexOf(full) < workflow.indexOf(sdk));
		assert.doesNotMatch(sdk, /continue-on-error:|\n\s+if:/);
	}
});

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

test("Windows fleet lifecycle gates use native Windows runners and remain required for release signing", () => {
	const ci = readWorkflow("ci.yml");
	const rc = readWorkflow("release-rc.yml");
	for (const [workflow, name] of [[ci, "quality-gate"], [rc, "build-rc"]]) {
		const linux = job(workflow, name);
		assert.match(linux, /runs-on: ubuntu-22\.04/u);
		assert.match(linux, /pnpm verify:fleet:unix/u);
		assert.doesNotMatch(linux, /verify:fleet:windows|verify-windows-fleet\.mjs/u);
		assert.match(linux, /node --test scripts\/saml-outage-recovery\.test\.mjs scripts\/saml-outage-recovery-postgres\.test\.mjs/u);
		assert.match(linux, /node --test scripts\/discovery-cloud-postgres\.test\.mjs/u);
	}
	const windows = job(ci, "fleet-windows");
	assert.match(windows, /runs-on: windows-2022/u);
	assert.match(windows, /pnpm install --frozen-lockfile --ignore-scripts/u);
	assert.match(windows, /pnpm compile:aig/u);
	assert.match(windows, /pnpm --filter @singularityrd\/aidr-core run build:release/u);
	assert.match(windows, /pnpm --filter @singularityrd\/aidr-claude-code run build:release/u);
	assert.match(windows, /node --test scripts\/windows-response-action\.test\.mjs scripts\/windows-response-worker-install\.test\.mjs/u);
	assert.ok(windows.indexOf("Claude release build failed") < windows.indexOf("node scripts/verify-windows-fleet.mjs"));
	assert.doesNotMatch(windows, /continue-on-error:|(?:^|\n)\s+if:/u);

	const native = job(rc, "acceptance-windows-native");
	assert.match(native, /runs-on: windows-2022/u);
	assert.match(native, /node --test scripts\/windows-response-action\.test\.mjs scripts\/windows-response-worker-install\.test\.mjs/u);
	assert.match(native, /name: aidr-signed-packages-/u);
	assert.match(native, /& tar -xzf \$archive -C \$env:GITHUB_WORKSPACE packages\/claude-code\/dist/u);
	assert.ok(native.indexOf("Signed Claude fleet input extraction failed") < native.indexOf("& node scripts/verify-windows-fleet.mjs"));
	assert.match(native, /if \(\$LASTEXITCODE -ne 0\) \{ throw "Windows fleet lifecycle verification failed" \}/u);
	assert.ok(native.indexOf("Windows fleet lifecycle verification failed") < native.indexOf("Upload Windows native package receipt"));
	assert.doesNotMatch(native, /continue-on-error:/u);
	assert.match(job(rc, "final-sign-publish"), /needs: \[build-rc, assemble-e2e, acceptance-e2e, acceptance-windows-native\]/u);
});

test("VSIX packaging keeps runtime rules inside the manifest-covered dist tree", () => {
	assert.ok(VSIX_PACKAGE_FILES.includes("dist/resources/**"));
	assert.ok(!VSIX_PACKAGE_FILES.includes("resources/**"));
	for (const file of ["../.github/scripts/package-vsix.mjs", "../packages/extension/scripts/package-vscode-vsix.mjs"]) {
		const packager = readFileSync(new URL(file, import.meta.url), "utf8");
		assert.match(packager, /cp\(join\(extensionRoot, "dist"\), join\(stageDir, "dist"\)/u);
		assert.doesNotMatch(packager, /cp\(join\(extensionRoot, "resources"\)/u);
	}
});

test("CI and RC block on full-migration OIDC administration and offboarding regressions", () => {
	const scripts = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).scripts;
	assert.match(scripts["verify:offboarding"], /scripts\/oidc-scim-offboarding-postgres\.test\.mjs/u);
	for (const [file, name] of [
		["ci.yml", "Blocking reputation, offboarding and retention PostgreSQL gates"],
		["release-rc.yml", "Blocking offboarding and retention PostgreSQL gates"],
	]) {
		const gate = step(readWorkflow(file), name);
		const image = gate.indexOf("docker pull supabase/postgres:17.11.0.004");
		const administration = gate.indexOf("node --test scripts/oidc-administration-postgres.test.mjs");
		const offboarding = gate.indexOf("pnpm verify:offboarding");
		assert.ok(image >= 0 && image < administration && administration < offboarding, `${file} must provision and require both OIDC suites`);
		assert.doesNotMatch(gate, /continue-on-error:|(?:^|\n)\s+if:/u);
	}
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
		// CycloneDX SBOM of the vendored scanner tree (generated by Trivy, no secrets).
		["ci.yml::Upload vendored posture scanner SBOM (pinned)", ["posture-scanner-sbom/"]],
		["docs-generation.yml::Upload generated documentation (pinned)", ["docs/api/", "docs/diagrams/"]],
		// Image digest manifest, scan summaries and per-image SBOMs (no credentials).
		["release-images.yml::Upload release image evidence (pinned)", ["release-images/"]],
		["error-to-insight.yml::Upload Insights Report", ["error-insights-report.md"]],
		["release-browser-guard.yml::Upload Browser Guard release bundle (pinned)", ["release-output-browser-guard/"]],
		["release-promote.yml::Persist anti-rollback state and verification receipt (pinned)", [
			"${{ runner.temp }}/aidr-promotion-state/anti-rollback-state.json",
			"${{ runner.temp }}/aidr-promotion-state/verification-receipt.json",
			"${{ runner.temp }}/aidr-promotion-state/production-go-ledger.json",
		]],
		["release-promote.yml::Archive promotion evidence (pinned)", ["release-output/"]],
		["release-rc.yml::Upload unsigned release inputs (pinned)", ["${{ runner.temp }}/prepared-release.tgz"]],
		["release-rc.yml::Upload signed Windows inputs (pinned)", ["${{ runner.temp }}/windows-authenticode.tgz"]],
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

test("prebuilt signing inventory is bound to the independent unsigned build job digest", () => {
	const workflow = readWorkflow("release-rc.yml");
	const archive = step(workflow, "Archive unsigned release inputs");
	assert.match(archive, /id: prepared_inputs/u);
	assert.match(archive, /GITHUB_OUTPUT, 'sbom_sha256='[\s\S]*createHash\('sha256'\)[\s\S]*readFileSync\('\.release-evidence\/aidr-sbom\.cdx\.json'\)/u);
	assert.match(workflow, /sbom_sha256: \$\{\{ steps\.prepared_inputs\.outputs\.sbom_sha256 \}\}/u);
	const signing = workflow.slice(workflow.indexOf("  package-signing:"), workflow.indexOf("  assemble-e2e:"));
	assert.match(signing, /AIDR_EXPECTED_PREBUILT_SBOM_SHA256: \$\{\{ needs\.build-rc\.outputs\.sbom_sha256 \}\}/u);
	assert.doesNotMatch(signing, /pnpm install|Setup pnpm/u);
	assert.match(workflow, /VSCE_VERSION: 4\.0\.0/u);
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
