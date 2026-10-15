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
	assert.match(job(rc, "final-sign-publish"), /needs: \[build-rc, assemble-e2e, acceptance-e2e, acceptance-windows-native, installers-linux, installers-windows, installers-sea-sign\]/u);
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
		// Signed intel packs and their offline folder (public signatures, no keys).
		["intel-pack-release.yml::Upload the release and offline folder (pinned)", ["${{ runner.temp }}/release/"]],
		["release-browser-guard.yml::Upload Browser Guard release bundle (pinned)", ["release-output-browser-guard/"]],
		// Store draft receipts: store, version, package sha256 and upload state; never a credential.
		["release-browser-guard.yml::Upload store draft receipts (pinned)", ["store-receipts/"]],
		["release-browser-guard.yml::Upload the update feed (pinned)", ["update-feed/"]],
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
		// Signed desktop installers, their SHA256SUMS (+ .asc) and the SEA manifest they wrap.
		["release-rc.yml::Upload unsigned Linux installers (pinned)", ["${{ runner.temp }}/installers-linux-unsigned.tgz"]],
		["release-rc.yml::Upload unsigned Linux SEA bundle (pinned)", ["${{ runner.temp }}/aidr-sea-linux-unsigned.tgz"]],
		["release-rc.yml::Upload unsigned Windows SEA bundle (pinned)", ["${{ runner.temp }}/aidr-sea-windows-unsigned.tgz"]],
		["release-rc.yml::Upload signed SEA bundles (pinned)", [
			"${{ runner.temp }}/aidr-sea-linux-signed.tgz",
			"${{ runner.temp }}/aidr-sea-windows-signed.tgz",
		]],
		["release-rc.yml::Upload Linux installers (pinned)", ["${{ runner.temp }}/installers-linux/"]],
		["release-rc.yml::Upload Windows installer (pinned)", ["${{ runner.temp }}/installers-windows/"]],
		// Per-customer installers: the verified packet (never a secret), then the signed
		// packages under SingularityAIDR-<CUSTOMER>-<version>-<arch>.<ext>.
		["customer-installer.yml::Hand the verified packet to the build jobs (pinned)", ["${{ runner.temp }}/packet/customer-packet.json"]],
		["customer-installer.yml::Upload unsigned customer Linux packages (pinned)", ["${{ runner.temp }}/installers-linux/"]],
		["customer-installer.yml::Upload the customer .deb (pinned)", [
			"${{ runner.temp }}/installers-linux/${{ needs.prepare.outputs.stem }}.deb",
			"${{ runner.temp }}/installers-linux/${{ needs.prepare.outputs.stem }}.deb.asc",
			"${{ runner.temp }}/installers-linux/linux-package-signing-key.asc",
		]],
		["customer-installer.yml::Upload the customer .rpm (pinned)", [
			"${{ runner.temp }}/installers-linux/${{ needs.prepare.outputs.stem }}.rpm",
			"${{ runner.temp }}/installers-linux/linux-package-signing-key.asc",
		]],
		["customer-installer.yml::Upload the customer .tar.gz (pinned)", [
			"${{ runner.temp }}/installers-linux/${{ needs.prepare.outputs.stem }}.tar.gz",
			"${{ runner.temp }}/installers-linux/${{ needs.prepare.outputs.stem }}.tar.gz.asc",
			"${{ runner.temp }}/installers-linux/${{ needs.prepare.outputs.stem }}-linux.SHA256SUMS",
			"${{ runner.temp }}/installers-linux/${{ needs.prepare.outputs.stem }}-linux.SHA256SUMS.asc",
			"${{ runner.temp }}/installers-linux/linux-package-signing-key.asc",
		]],
		["customer-installer.yml::Upload the customer .msi (pinned)", [
			"${{ runner.temp }}/installers-windows/${{ needs.prepare.outputs.stem }}.msi",
			"${{ runner.temp }}/installers-windows/${{ needs.prepare.outputs.stem }}-windows.SHA256SUMS",
		]],
		["customer-installer.yml::Upload the customer .exe (pinned)", [
			"${{ runner.temp }}/installers-windows/${{ needs.prepare.outputs.stem }}.exe",
			"${{ runner.temp }}/installers-windows/${{ needs.prepare.outputs.stem }}-windows.SHA256SUMS",
		]],
		// The signed air-gap transfer bundle: image tarballs + Ed25519-signed manifest (tar),
		// its cosign bundle, the vendor public key and SHA256SUMS. The signing key is deleted
		// by the step's trap and the throwaway stack's credentials never reach this directory.
		["release-images.yml::Upload the signed air-gap bundle (pinned)", ["${{ runner.temp }}/airgap-release/"]],
		// Windows real-host records and the VS Code JUnit report (mock model: no credential exists).
		["windows-real-host-e2e.yml::Upload the Windows evidence record (pinned)", ["docs/evidence/real-host/windows/"]],
		["windows-real-host-e2e.yml::Upload the VS Code evidence (pinned)", ["docs/evidence/real-host/windows/"]],
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

test("desktop installer jobs build the release-flavour bundle from the verified commit, sign it in a key-only job and reach the draft RC only checked", () => {
	const rc = readWorkflow("release-rc.yml");
	// SEA bundle builds: RC code, no secret of any kind beyond the public key.
	const seaBuilds = [job(rc, "installers-linux-sea"), job(rc, "installers-windows-build")];
	for (const build of seaBuilds) {
		assert.match(build, /needs: build-rc\n/u);
		assert.match(build, /ref: \$\{\{ needs\.build-rc\.outputs\.sha \}\}/u);
		assert.match(build, /pnpm install --frozen-lockfile --ignore-scripts/u);
		assert.match(build, /build:release/u);
		assert.match(build, /node packages\/claude-code\/scripts\/build-sea\.mjs --prebuilt --flavor release --out/u);
		assert.match(build, /archive_sha256=/u);
		assert.doesNotMatch(build, /PRIVATE_KEY|PFX|PASSPHRASE|secrets\./u, "SEA build jobs hold no secret");
	}
	// The release-key signing step sits between the bundle builds and packaging.
	const sign = job(rc, "installers-sea-sign");
	assert.match(sign, /needs: \[build-rc, assemble-e2e, installers-linux-sea, installers-windows-build\]/u);
	assert.doesNotMatch(sign, /pnpm|npm install|npx /u, "the signing job installs no dependencies");
	assert.match(sign, /secrets\.AIDR_SIGNING_PRIVATE_KEY_PEM/u);
	assert.match(sign, /no unsigned SEA bundle is packaged/u);
	assert.ok(sign.indexOf("sha256sum --check --strict") < sign.indexOf('printf \'%s\\n\' "${SIGNING_PRIVATE_KEY}"'), "archive hashes are checked before the key is written");
	assert.match(sign, /Candidate identity changed across runner boundary/u);
	assert.match(sign, /is not the recorded candidate artifact/u);
	assert.match(sign, /build-sea\.mjs --add-extensions[\s\S]*build-sea\.mjs --sign "\$\{sea\}" --key/u);
	assert.match(sign, /The release key does not match its pinned fingerprint/u);
	assert.match(sign, /rm -f "\$\{private_path\}"\n\s+# The Linux bundle runs here[\s\S]*--verify "\$\{RUNNER_TEMP\}\/aidr-sea-linux" --public-key/u);
	// Packaging and the GPG / Authenticode jobs never hold the release private key.
	const builds = [job(rc, "installers-linux-build")];
	const signers = [job(rc, "installers-linux"), job(rc, "installers-windows")];
	for (const installer of [...builds, ...signers]) {
		assert.doesNotMatch(installer, /secrets\.AIDR_SIGNING_PRIVATE_KEY_PEM/u, "installer jobs never hold the release private key");
	}
	for (const signer of signers) {
		assert.doesNotMatch(signer, /pnpm|npm install|npx /u, "signing jobs install no dependencies");
	}
	for (const installer of [...seaBuilds, sign, ...builds, ...signers]) {
		assert.doesNotMatch(installer, /continue-on-error:|-Unsigned\b|--signing unsigned/u);
	}
	const [linuxBuild] = builds;
	const [linux, windows] = signers;
	assert.match(linuxBuild, /needs: \[build-rc, installers-sea-sign\]/u);
	assert.match(linuxBuild, /EXPECTED_SEA_SHA256: \$\{\{ needs\.installers-sea-sign\.outputs\.linux_sha256 \}\}/u);
	assert.match(linuxBuild, /build-sea\.mjs --verify "\$\{RUNNER_TEMP\}\/aidr-sea" --public-key/u);
	assert.match(linuxBuild, /node --test deploy\/installers\/installers\.test\.mjs/u);
	assert.match(linuxBuild, /--formats deb,rpm,tar/u);
	assert.match(linuxBuild, /The release trust public key and its fingerprint are required to build installers/u);
	assert.match(seaBuilds[1], /runs-on: windows-2022/u);
	assert.match(linux, /needs: \[build-rc, installers-linux-build\]/u);
	assert.match(linux, /EXPECTED_ARCHIVE_SHA256: \$\{\{ needs\.installers-linux-build\.outputs\.archive_sha256 \}\}/u);
	assert.match(linux, /no unsigned package is published/u);
	assert.ok(linux.indexOf("sha256sum --check --strict") < linux.indexOf("gpg --batch --import"), "archive hash is checked before the key is imported");
	assert.ok(linux.indexOf("--addsign") < linux.indexOf("> SHA256SUMS"), "checksums follow rpm signing");
	assert.match(linux, /rpmkeys --dbpath "\$\{rpmdb\}" --checksig/u);
	assert.match(linux, /gpg --batch --verify/u);
	assert.match(windows, /needs: \[build-rc, installers-sea-sign\]/u);
	assert.match(windows, /EXPECTED_ARCHIVE_SHA256: \$\{\{ needs\.installers-sea-sign\.outputs\.windows_sha256 \}\}/u);
	assert.match(windows, /runs-on: windows-2022/u);
	assert.match(windows, /The release trust public key and its fingerprint are required to build installers/u);
	assert.match(windows, /no unsigned MSI is published/u);
	assert.ok(windows.indexOf("Signed SEA archive hash mismatch") < windows.indexOf("Import-PfxCertificate"));
	assert.match(windows, /build-msi\.ps1 [^\n]*-SignThumbprint \$thumbprint/u);
	assert.match(windows, /finally \{[\s\S]*Remove-Item -LiteralPath \$certificatePath -DeleteKey -Force/u);
	assert.match(windows, /Exactly one signed MSI is expected/u);

	const publish = job(rc, "final-sign-publish");
	const recheck = publish.indexOf("Recheck installer checksums across runner boundary");
	const attest = publish.indexOf("Attest the desktop installers (pinned)");
	const release = publish.indexOf("Publish draft prerelease evidence (pinned)");
	assert.ok(recheck > 0 && recheck < attest && attest < release);
	assert.match(publish, /An unsigned installer reached the release job/u);
	assert.match(publish, /\$\{\{ runner\.temp \}\}\/installers\/windows\/\*/u);
	assert.doesNotMatch(readWorkflow("release-promote.yml"), /installers-(?:linux|windows)/u);
});
