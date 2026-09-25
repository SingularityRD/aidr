import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { assertNoPrivateSigningMaterial } from "./build-workspace.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workflow = readFileSync(path.join(root, ".github", "workflows", "release-rc.yml"), "utf8");
const packageManifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));

test("root package scripts cannot bypass protected publication", () => {
	const directPublishScripts = Object.entries(packageManifest.scripts ?? {}).filter(([, command]) =>
		/\b(?:changeset\s+publish|pnpm\s+publish|npm\s+publish)\b/.test(command),
	);
	assert.deepEqual(directPublishScripts, []);
	assert.equal(packageManifest.scripts?.release, undefined);
});

function job(name, nextName) {
	const start = workflow.indexOf(`  ${name}:`);
	assert.notEqual(start, -1, `missing job ${name}`);
	const end = nextName ? workflow.indexOf(`  ${nextName}:`, start + 1) : workflow.length;
	assert.notEqual(end, -1, `missing next job ${nextName}`);
	return workflow.slice(start, end);
}

function step(source, name) {
	const marker = `      - name: ${name}`;
	const start = source.indexOf(marker);
	assert.notEqual(start, -1, `missing step ${name}`);
	const next = source.indexOf("\n      - name: ", start + marker.length);
	return source.slice(start, next === -1 ? source.length : next);
}

test("private release keys exist only in fresh signing jobs", () => {
	const build = job("build-rc", "package-signing");
	const signing = job("package-signing", "assemble-e2e");
	const assembly = job("assemble-e2e", "acceptance-e2e");
	const acceptance = job("acceptance-e2e", "final-sign-publish");
	const publishing = job("final-sign-publish");

	assert.doesNotMatch(build, /(?:AIDR|AIG).*PRIVATE_KEY|SIGNING_PRIVATE_KEY/);
	assert.doesNotMatch(assembly, /(?:AIDR|AIG).*PRIVATE_KEY|SIGNING_PRIVATE_KEY/);
	assert.doesNotMatch(acceptance, /(?:AIDR|AIG).*PRIVATE_KEY|SIGNING_PRIVATE_KEY/);
	assert.match(signing, /permissions:\s*\n\s+contents: read/);
	assert.match(assembly, /permissions:\s*\n\s+contents: read/);
	assert.match(acceptance, /permissions:\s*\n\s+contents: read/);
	assert.match(publishing, /contents: write[\s\S]*attestations: write[\s\S]*id-token: write/);
	assert.doesNotMatch(workflow, /AIDR_SIGNING_PRIVATE_KEY_PEM_PATH=.*GITHUB_ENV|GITHUB_ENV.*AIDR_SIGNING_PRIVATE_KEY_PEM_PATH/);
});

test("signing steps clean keys and never run dependency or network tooling", () => {
	const signing = job("package-signing", "assemble-e2e");
	const publishing = job("final-sign-publish");
	for (const [name, body] of [
		["AIG", step(signing, "Sign and verify pinned AIG data only")],
		["package", step(signing, "Sign package manifests only")],
		["release", step(publishing, "Canonically sign and independently verify exact bundle")],
	]) {
		assert.match(body, /trap cleanup EXIT/, `${name}: missing cleanup trap`);
		assert.match(body, /unset /, `${name}: raw secret environment is not cleared`);
		assert.match(body, /rm -f "\$\{private_path\}"/, `${name}: private key is not deleted before verification`);
		assert.doesNotMatch(body, /\b(?:pnpm|npm|npx|corepack|pip|curl|wget|docker)\b/, `${name}: dependency/network tool crosses signing boundary`);
	}
});

test("outer bundle uses one canonical signing claim after exact-candidate E2E", () => {
	const assembly = job("assemble-e2e", "acceptance-e2e");
	const acceptance = job("acceptance-e2e", "final-sign-publish");
	const publishing = job("final-sign-publish");
	assert.match(workflow, /node scripts\/release-sign\.mjs/);
	assert.match(workflow, /node scripts\/release-verify\.mjs/);
	assert.doesNotMatch(workflow, /sign-artifact-manifest\.mjs --dir release-output/);
	assert.match(assembly, /Reverify signed packages across runner boundary[\s\S]*node scripts\/verify-release-evidence\.mjs/);
	assert.ok(assembly.indexOf("Reverify signed packages across runner boundary") < assembly.indexOf("Clean-consumer package install gate"));
	assert.ok(assembly.indexOf("Clean-consumer package install gate") < assembly.indexOf("Bind candidate identity and digest"));
	assert.match(assembly, /verify-package-install\.mjs --require-signed --tarball-dir release-output/);
	assert.match(assembly, /sha256sum release-output\/release-metadata\.json release-output\/release-inventory\.json/);
	assert.match(acceptance, /AIDR_RUNNER_ENVIRONMENT[\s\S]*self-hosted/);
	assert.match(acceptance, /AIDR_E2E_CANDIDATE_BOUND_AT/);
	assert.match(acceptance, /AIDR_OPENCLAW_HOST_EVIDENCE_PUBLIC_KEY_PEM/);
	assert.match(acceptance, /AIDR_OPENCLAW_HOST_EVIDENCE_SIGNATURE/);
	assert.match(acceptance, /AIDR_E2E_CURSOR_VSIX_PATH=\$\{GITHUB_WORKSPACE\}\/\$\{cursor_vsix_path\}/);
	assert.match(acceptance, /AIDR_E2E_VSCODE_VSIX_PATH=\$\{GITHUB_WORKSPACE\}\/\$\{vscode_vsix_path\}/);
	assert.match(acceptance, /aidr-cursor\.vsix[\s\S]*aidr-vscode\.vsix[\s\S]*exact-candidate inventory/);
	assert.ok(workflow.indexOf("Bind candidate identity and digest") < workflow.indexOf("Real-host connector E2E gate"));
	assert.ok(workflow.indexOf("Real-host connector E2E gate") < workflow.indexOf("Canonically sign and independently verify exact bundle"));
	assert.match(publishing, /release_tag: process\.env\.EXPECTED_TAG/);
	assert.match(publishing, /sha256sum release-output\/release-metadata\.json release-output\/release-inventory\.json/);
	assert.match(workflow, /echo "AIDR_GIT_SHA=\$\{tag_sha\}"/);
	assert.ok((workflow.match(/AIDR_GIT_SHA:/g) ?? []).length >= 4, "resolved tag SHA must cross every release job boundary");
	assert.match(workflow, /AIDR_BUILD_FLAVOR: commercial/);
	assert.doesNotMatch(workflow, /604800/);
	assert.match(workflow, /AIDR_RELEASE_SIGNER_POLICY_JSON/);
});

test("unsigned RC quality gate enforces root and all-source core coverage", () => {
	const build = job("build-rc", "package-signing");
	const qualityGate = step(build, "Full deterministic quality gate");
	assert.match(qualityGate, /pnpm test:coverage && pnpm test:coverage:core/);
});

test("changeset status and the RC workflow preserve the monoversion package set", () => {
	const packageLoop = workflow.match(/for package_json in ([^;]+); do/u)?.[1];
	assert.ok(packageLoop, "release RC workflow must enumerate package manifests");
	const packagePaths = packageLoop.trim().split(/\s+/u);
	const packages = packagePaths.map((packagePath) => JSON.parse(readFileSync(path.join(root, packagePath), "utf8")));
	const packageNames = packages.map((pkg) => pkg.name);
	assert.equal(new Set(packages.map((pkg) => pkg.version)).size, 1, "RC package manifests must start at one stable version");
	const outputName = `.changeset-status-${process.pid}-${Date.now()}.json`;
	const output = path.join(root, outputName);
	try {
		const status = spawnSync(process.execPath, [path.join(root, "node_modules", "@changesets", "cli", "bin.js"), "status", "--output", outputName], {
			cwd: root,
			encoding: "utf8",
		});
		assert.equal(status.status, 0, status.stderr);
		const changesetStatus = JSON.parse(readFileSync(output, "utf8"));
		const releases = changesetStatus.releases;
		if (releases.length === 0) return;
		assert.deepEqual(releases.map((release) => release.name).sort(), packageNames.sort());
		assert.equal(new Set(releases.map((release) => release.newVersion)).size, 1, "RC package manifests must advance to one stable version");
		assert.notEqual(releases[0].newVersion, packages[0].version);
		const sdkRelease = releases.find((release) => release.name === "@singularityrd/aidr-sdk");
		assert.ok(sdkRelease);
		const current = packages[0].version.split(".").map(Number);
		const next = sdkRelease.newVersion.split(".").map(Number);
		assert.equal(current.length, 3);
		assert.equal(next.length, 3);
		const expectedType = next[0] > current[0] ? "major" : next[1] > current[1] ? "minor" : "patch";
		assert.equal(sdkRelease.type, expectedType);
		const summary = changesetStatus.changesets.map((changeset) => changeset.summary).join("\n");
		assert.match(summary, /createGenericMiddleware/);
		assert.match(summary, /Node\.js 22\.12/);
	} finally {
		rmSync(output, { force: true });
	}
});

test("workspace build rejects every supported private signing variable", () => {
	for (const name of [
		"AIDR_SIGNING_PRIVATE_KEY_PEM_PATH",
		"AIDR_SIGNING_PRIVATE_KEY_PEM",
		"AIDR_RELEASE_SIGNING_PRIVATE_KEY_PATH",
		"AIG_DATA_SIGNING_PRIVATE_KEY_PEM",
		"AIG_PRIVATE_KEY_PEM",
		"AIG_SIGNING_PRIVATE_KEY",
		"AIG_SIGNING_PRIVATE_KEY_PATH",
		"SIGNING_PRIVATE_KEY",
	]) {
		assert.throws(() => assertNoPrivateSigningMaterial({ [name]: "secret" }), new RegExp(name));
	}
	assert.doesNotThrow(() => assertNoPrivateSigningMaterial({}));
});

test("SBOM and artifact preparation fail before spawning with a private key", () => {
	for (const [script, expected, status] of [
		["scripts/generate-sbom.mjs", /SBOM generation refuses private signing material/, 2],
		["scripts/release-artifact-manifests.mjs", /Artifact preparation refuses private signing material/, 1],
	]) {
		const result = spawnSync(process.execPath, [script], {
			cwd: root,
			encoding: "utf8",
			env: { ...process.env, AIDR_SIGNING_PRIVATE_KEY_PEM_PATH: "must-not-cross-boundary.pem" },
		});
		assert.equal(result.status, status, `${script}: ${result.stderr}`);
		assert.match(result.stderr, expected);
	}
	const preparationSource = readFileSync(path.join(root, "scripts", "release-artifact-manifests.mjs"), "utf8");
	assert.doesNotMatch(preparationSource, /sign-artifact-manifest\.mjs/);
});
