import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

import { findReleaseStateRun } from "./find-release-state-run.mjs";
import { planNpmPublication, sha512Integrity } from "./plan-npm-release-publication.mjs";
import { verifyProvenance, verifySbom } from "./verify-release-promotion.mjs";
import { assertReleaseRun, assertRunAttestation, verifyReleaseRun } from "./verify-release-run.mjs";
import { assertTrustedGitHubApiUrl } from "./lib/trusted-github-api-url.mjs";

const sha = "a".repeat(40);
const expected = {
	repository: "singularityrd/aidr",
	workflowPath: ".github/workflows/release-rc.yml",
	sha,
	tag: "v1.2.3-rc.0",
	runId: "123",
};
const tempDirectories = [];

afterEach(async () => {
	await Promise.all(tempDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

test("release run gate requires the RC workflow, success, repository and push commit", () => {
	const run = {
		status: "completed",
		conclusion: "success",
		path: ".github/workflows/release-rc.yml",
		repository: { full_name: expected.repository },
		event: "push",
		head_sha: sha,
		head_branch: expected.tag,
	};
	assert.doesNotThrow(() => assertReleaseRun(run, expected));
	assert.throws(() => assertReleaseRun({ ...run, conclusion: "failure" }, expected), /completed successfully/);
	assert.throws(() => assertReleaseRun({ ...run, path: ".github/workflows/ci.yml" }, expected), /workflow mismatch/);
	assert.throws(() => assertReleaseRun({ ...run, head_sha: "b".repeat(40) }, expected), /commit mismatch/);
});

test("signed evidence binds a manual RC run to the requested tag and commit", () => {
	const evidence = { predicate: { invocation: { parameters: { ci_run_id: expected.runId, git_sha: sha } } } };
	const metadata = { release_tag: expected.tag, git_sha: sha };
	assert.doesNotThrow(() => assertRunAttestation(evidence, metadata, expected));
	assert.throws(
		() => assertRunAttestation({ predicate: { invocation: { parameters: { ci_run_id: "999", git_sha: sha } } } }, metadata, expected),
		/run ID/,
	);
});

test("anti-rollback restore keeps the latest verified state when later publication fails", async () => {
	const fetchImpl = async (url) => {
		if (url.pathname.endsWith("/actions/artifacts")) {
			return Response.json({
				artifacts: [
					{ name: "aidr-promotion-anti-rollback-state", expired: false, created_at: "2026-09-23T00:00:00Z", workflow_run: { id: 78 } },
					{ name: "aidr-promotion-anti-rollback-state", expired: false, created_at: "2026-09-22T00:00:00Z", workflow_run: { id: 77 } },
				],
			});
		}
		return Response.json({
			id: Number(url.pathname.split("/").at(-1)),
			status: "completed",
			conclusion: url.pathname.endsWith("/77") ? "success" : "failure",
			event: "workflow_dispatch",
			path: ".github/workflows/release-promote.yml",
			head_branch: "master",
			repository: { full_name: expected.repository, default_branch: "master" },
		});
	};
	assert.equal(
		await findReleaseStateRun(
			{
				artifactName: "aidr-promotion-anti-rollback-state",
				repository: expected.repository,
			apiUrl: "https://github.test/api/v3",
			serverUrl: "https://github.test",
				workflowPath: ".github/workflows/release-promote.yml",
				defaultBranch: "master",
				token: "test",
			},
			fetchImpl,
		),
		"78",
	);
});

test("release token can only be sent to the trusted GitHub API origin", async () => {
	assert.equal(assertTrustedGitHubApiUrl("https://api.github.com", "https://github.com").origin, "https://api.github.com");
	assert.equal(assertTrustedGitHubApiUrl("https://github.enterprise.test/api/v3", "https://github.enterprise.test").origin, "https://github.enterprise.test");
	for (const apiUrl of [
		"http://api.github.com",
		"https://api.github.com.attacker.example",
		"https://token@api.github.com",
		"https://api.github.com/?redirect=attacker",
	]) {
		assert.throws(() => assertTrustedGitHubApiUrl(apiUrl, "https://github.com"), /HTTPS|origin/);
	}

	let fetched = false;
	await assert.rejects(
		verifyReleaseRun(
			{
				apiUrl: "https://attacker.example",
				serverUrl: "https://github.com",
				token: "must-not-leak",
				repository: expected.repository,
				runId: expected.runId,
				bundle: "unused",
				workflowPath: expected.workflowPath,
			},
			async () => {
				fetched = true;
				return Response.json({});
			},
		),
		/GitHub API origin does not match/,
	);
	assert.equal(fetched, false);
});

test("promotion semantic gate validates CycloneDX and provenance bindings", async () => {
	const directory = await mkdtemp(path.join(os.tmpdir(), "aidr-promotion-test-"));
	tempDirectories.push(directory);
	const lockfile = path.join(directory, "pnpm-lock.yaml");
	const sbomPath = path.join(directory, "aidr-sbom.cdx.json");
	const lockBytes = "lockfileVersion: '9.0'\n";
	const sbom = {
		bomFormat: "CycloneDX",
		specVersion: "1.5",
		metadata: { component: { type: "application", "bom-ref": "urn:aidr:workspace", name: "AIDR" } },
		components: [{ type: "library", name: "example", "bom-ref": "pkg:npm/example@1.0.0", licenses: [{ license: { id: "MIT" } }], hashes: [{ alg: "SHA-256", content: "b".repeat(64) }] }],
		dependencies: [{ ref: "urn:aidr:workspace", dependsOn: ["pkg:npm/example@1.0.0"] }, { ref: "pkg:npm/example@1.0.0", dependsOn: [] }],
	};
	const sbomRaw = `${JSON.stringify(sbom)}\n`;
	const manifestRaw = '{"artifact_id":"core/dist"}\n';
	const manifestDirectory = path.join(directory, "archive-root", "package", "dist");
	await mkdir(manifestDirectory, { recursive: true });
	await writeFile(path.join(manifestDirectory, "aidr-artifact.manifest.json"), manifestRaw);
	const archiveName = "singularityrd-aidr-core-1.2.3.tgz";
	const archive = spawnSync("tar", ["-czf", path.join(directory, archiveName), "-C", path.join(directory, "archive-root"), "package"]);
	assert.equal(archive.status, 0, archive.stderr?.toString());
	await writeFile(path.join(directory, "release-inventory.json"), JSON.stringify({ artifacts: [{ staged_path: archiveName }] }));
	await writeFile(lockfile, lockBytes);
	await writeFile(sbomPath, sbomRaw);
	await writeFile(`${sbomPath}.sha256`, `${digest(sbomRaw)}  aidr-sbom.cdx.json\n`);
	const provenancePath = path.join(directory, "aidr-provenance.intoto.json");
	const statement = {
		_type: "https://in-toto.io/Statement/v0.1",
		predicateType: "https://slsa.dev/provenance/v0.2",
		subject: [{ name: "core/dist", digest: { sha256: digest(manifestRaw) } }],
		predicate: {
			builder: { id: "urn:aidr:test" },
			buildType: "https://singularityrd.dev/aidr/release-artifact-manifests/v1",
			invocation: {
				parameters: { release_version: "1.2.3", git_sha: sha, ci_run_id: expected.runId },
				environment: { build_host: "github_actions" },
			},
			materials: [{ uri: "file:///workspace/pnpm-lock.yaml", digest: { sha256: digest(lockBytes) } }],
			byproducts: [{ uri: "file:///workspace/aidr-sbom.cdx.json", digest: { sha256: digest(sbomRaw) } }],
		},
	};
	await writeFile(
		provenancePath,
		JSON.stringify(statement),
	);
	await verifySbom(directory);
	await verifyProvenance(directory, lockfile, { expectedVersion: "1.2.3", expectedSha: sha, runId: expected.runId });
	statement.subject[0].digest.sha256 = "c".repeat(64);
	await writeFile(provenancePath, JSON.stringify(statement));
	await assert.rejects(
		verifyProvenance(directory, lockfile, { expectedVersion: "1.2.3", expectedSha: sha, runId: expected.runId }),
		/provenance subject digest does not match signed package manifest/,
	);
	sbom.components[0].licenses = [];
	await writeFile(sbomPath, JSON.stringify(sbom));
	await assert.rejects(verifySbom(directory), /license metadata/);
});

test("npm publication plan resumes a partial release only when published integrity matches", async () => {
	const directory = await mkdtemp(path.join(os.tmpdir(), "aidr-publication-plan-test-"));
	tempDirectories.push(directory);
	const publishedFile = path.join(directory, "published.tgz");
	const missingFile = path.join(directory, "missing.tgz");
	await writeFile(publishedFile, "signed published package");
	await writeFile(missingFile, "signed missing package");
	const publishedIntegrity = await sha512Integrity(publishedFile);
	const candidates = [
		{ name: "@singularityrd/published", file: publishedFile },
		{ name: "@singularityrd/missing", file: missingFile },
	];
	const missing = await planNpmPublication(candidates, {
		version: "1.2.3",
		registry: "https://npm.pkg.github.test",
		viewIntegrity: async (name) => (name === "@singularityrd/published" ? publishedIntegrity : null),
	});
	assert.deepEqual(missing, [candidates[1]]);
});

test("npm publication plan fails closed on a same-version registry mismatch", async () => {
	const directory = await mkdtemp(path.join(os.tmpdir(), "aidr-publication-mismatch-test-"));
	tempDirectories.push(directory);
	const file = path.join(directory, "candidate.tgz");
	await writeFile(file, "signed candidate package");
	await assert.rejects(
		planNpmPublication([{ name: "@singularityrd/aidr-core", file }], {
			version: "1.2.3",
			registry: "https://npm.pkg.github.test",
			viewIntegrity: async () => `sha512-${Buffer.alloc(64).toString("base64")}`,
		}),
		/Registry integrity mismatch/,
	);
});

test("promotion workflow keeps verifier trust, run attestation, durable state and pinned yank runtime", async () => {
	const workflow = await readFile(new URL("../.github/workflows/release-promote.yml", import.meta.url), "utf8");
	const versionWorkflow = await readFile(new URL("../.github/workflows/release-version.yml", import.meta.url), "utf8");
	assert.equal((workflow.match(/ref: \$\{\{ github\.workflow_sha \}\}/g) ?? []).length, 3);
	assert.equal((workflow.match(/\.trusted-release-verifier\/scripts\/verify-release-promotion\.mjs/g) ?? []).length, 3);
	assert.equal((workflow.match(/\.trusted-release-verifier\/scripts\/verify-release-run\.mjs/g) ?? []).length, 3);
	assert.doesNotMatch(workflow, /node scripts\/release-verify\.mjs/);
	assert.match(workflow, /--record/);
	assert.match(workflow, /name: aidr-promotion-anti-rollback-state/);
	assert.match(workflow, /\.trusted-release-verifier\/scripts\/plan-npm-release-publication\.mjs/);
	const publication = workflow.slice(workflow.indexOf("Publish verified npm packages"), workflow.indexOf("Promote the exact dashboard commit"));
	assert.ok(publication.indexOf("plan-npm-release-publication.mjs") < publication.indexOf("npm publish"));
	const dashboardPromotion = workflow.slice(workflow.indexOf("Promote the exact dashboard commit"), workflow.indexOf("Move npm dist-tags to latest"));
	assert.match(dashboardPromotion, /expected_version="\$\{version%-rc\.\*\}"/);
	assert.match(dashboardPromotion, /state\.version !== process\.env\.EXPECTED_VERSION/);
	assert.match(dashboardPromotion, /state\.git_sha !== process\.env\.EXPECTED_SHA/);
	assert.match(dashboardPromotion, /dashboard_archive_sha256/);
	assert.match(dashboardPromotion, /verify-deployed-dashboard\.mjs/);
	assert.ok(dashboardPromotion.indexOf("verify-deployed-dashboard.mjs") < dashboardPromotion.indexOf("test:route-smoke"));
	assert.doesNotMatch(dashboardPromotion, /grep -F/);
	const rollback = workflow.slice(workflow.indexOf("  rollback:"), workflow.indexOf("  yank:"));
	assert.match(rollback, /id: rollback_verify/);
	assert.match(rollback, /VERIFIED_SHA: \$\{\{ steps\.rollback_verify\.outputs\.verified_sha \}\}/);
	assert.match(rollback, /git_sha\\\":\\\"\$\{VERIFIED_SHA\}/);
	assert.match(rollback, /state\.git_sha !== process\.env\.EXPECTED_SHA/);
	assert.match(rollback, /dashboard_archive_sha256/);
	assert.match(rollback, /verify-deployed-dashboard\.mjs/);
	assert.ok(rollback.indexOf("state.git_sha !== process.env.EXPECTED_SHA") < rollback.indexOf("npm dist-tag add"));
	assert.ok(rollback.indexOf("verify-deployed-dashboard.mjs") < rollback.indexOf("npm dist-tag add"));
	assert.ok(rollback.indexOf("Dashboard rollback smoke failed") < rollback.indexOf("npm dist-tag add"));
	const yank = workflow.slice(workflow.indexOf("  yank:"));
	assert.ok(yank.indexOf("Setup Node.js (pinned)") < yank.indexOf("npm deprecate"));
	assert.match(workflow, /softprops\/action-gh-release@efb35369e0ad2afab669f228072c1b0d510eae64 # v3\.0\.3/);
	assert.match(versionWorkflow, /changesets\/action@d94a5c301145045a0960133674e003b265942a22 # v1\.8\.0/);
});

test("release promotion verifies pinned GitHub attestations against the exact protected tag commit", async () => {
	const rcWorkflow = await readFile(new URL("../.github/workflows/release-rc.yml", import.meta.url), "utf8");
	const promotionWorkflow = await readFile(new URL("../.github/workflows/release-promote.yml", import.meta.url), "utf8");
	const releaseAction = /uses: (softprops\/action-gh-release@[0-9a-f]{40}) # (v\d+\.\d+\.\d+)/u;
	const rcAction = rcWorkflow.match(releaseAction);
	const promotionAction = promotionWorkflow.match(releaseAction);
	assert.ok(rcAction, "RC workflow must pin a versioned GitHub release action");
	assert.ok(promotionAction, "promotion workflow must pin a versioned GitHub release action");
	assert.deepEqual(rcAction.slice(1), promotionAction.slice(1), "RC and promotion must use the same immutable release-action pin and label");
	assert.match(
		rcWorkflow,
		/\[\[ "\$\{GITHUB_REF\}" == "refs\/tags\/\$\{tag\}" && "\$\{GITHUB_SHA\}" == "\$\{tag_sha\}" \]\]/,
	);
	assert.equal((promotionWorkflow.match(/attestations: read/g) ?? []).length, 3);
	assert.equal((promotionWorkflow.match(/name: Install pinned GitHub CLI for attestation verification/g) ?? []).length, 3);
	assert.equal((promotionWorkflow.match(/name: Verify GitHub build attestations for every release file/g) ?? []).length, 3);
	assert.equal((promotionWorkflow.match(/gh attestation verify "\$\{file\}"/g) ?? []).length, 3);
	assert.match(promotionWorkflow, /GH_CLI_VERSION: "2\.101\.0"/);
	assert.match(promotionWorkflow, /GH_CLI_SHA256_LINUX_AMD64: 9bca2d1c16825f109907a23307628a2f0698fbf99662b73a5cf0b020293072b8/);
	assert.equal((promotionWorkflow.match(/--signer-workflow "\$\{GITHUB_REPOSITORY\}\/\.github\/workflows\/release-rc\.yml"/g) ?? []).length, 3);
	assert.equal((promotionWorkflow.match(/--predicate-type "https:\/\/slsa\.dev\/provenance\/v1"/g) ?? []).length, 3);
	assert.equal((promotionWorkflow.match(/--source-ref "refs\/tags\/\$\{RELEASE_TAG\}"/g) ?? []).length, 3);
	assert.equal((promotionWorkflow.match(/--source-digest "\$\{expected_sha\}"/g) ?? []).length, 3);
});

function digest(value) {
	return createHash("sha256").update(value).digest("hex");
}
