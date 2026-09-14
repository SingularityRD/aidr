import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "..");
const provenanceScript = path.join(repoRoot, "scripts", "generate-provenance.mjs");
const temporaryDirectories = [];

afterEach(async () => {
	await Promise.all(
		temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
	);
});

test("provenance names every released artifact digest and the lockfile material", async () => {
	const fixture = await createFixture();
	const generated = generate(fixture);
	assert.equal(generated.status, 0, generated.stderr);
	const summary = JSON.parse(generated.stdout.trim().split(/\r?\n/).at(-1));
	assert.equal(summary.status, "generated");
	assert.equal(summary.subjects, 2);

	const statement = JSON.parse(await readFile(fixture.output, "utf8"));
	assert.equal(statement._type, "https://in-toto.io/Statement/v0.1");
	assert.equal(statement.predicateType, "https://slsa.dev/provenance/v0.2");
	assert.ok(typeof statement.predicate.buildType === "string" && statement.predicate.buildType.length > 0);
	assert.ok(typeof statement.predicate.builder.id === "string" && statement.predicate.builder.id.length > 0);

	assert.deepEqual(
		statement.subject.map((entry) => entry.name),
		["cli/dist", "core/dist"],
	);
	for (const subject of statement.subject) {
		const manifestPath = fixture.manifests[subject.name];
		assert.equal(subject.digest.sha256, sha256(await readFile(manifestPath)));
	}

	assert.equal(statement.predicate.materials.length, 1);
	assert.equal(statement.predicate.materials[0].digest.sha256, sha256(await readFile(fixture.lockfile)));
	assert.equal(statement.predicate.byproducts.length, 1);
	assert.equal(statement.predicate.byproducts[0].digest.sha256, sha256(await readFile(fixture.sbom)));

	const verified = verify(fixture);
	assert.equal(verified.status, 0, verified.stderr);
	const verifiedSummary = JSON.parse(verified.stdout.trim().split(/\r?\n/).at(-1));
	assert.equal(verifiedSummary.status, "verified");
	assert.equal(verifiedSummary.subjects, 2);
	assert.equal(verifiedSummary.materials, 1);
	assert.equal(verifiedSummary.byproducts, 1);
});

test("rejects a provenance file whose subject digest does not match the bundle", async () => {
	const fixture = await createFixture();
	assert.equal(generate(fixture).status, 0);
	const statement = JSON.parse(await readFile(fixture.output, "utf8"));
	const original = statement.subject[0].digest.sha256;
	statement.subject[0].digest.sha256 = original === "a".repeat(64) ? "b".repeat(64) : "a".repeat(64);
	await writeFile(fixture.output, `${JSON.stringify(statement, null, 2)}\n`);

	const result = verify(fixture);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /artifact manifest digest mismatch/);
});

test("rejects a provenance file that omits a released artifact manifest", async () => {
	const fixture = await createFixture();
	assert.equal(generate(fixture).status, 0);
	const extra = path.join(fixture.root, "extra-dist");
	await mkdir(extra, { recursive: true });
	await writeFile(
		path.join(extra, "aidr-artifact.manifest.json"),
		`${JSON.stringify({ schema_version: 1, artifact_id: "extra/dist", artifact_version: "1.2.3", files: [] }, null, 2)}\n`,
	);

	const result = verify(fixture, ["--artifact-dir", extra]);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /is not named in the provenance/);
});

test("detects tampering with the lockfile material", async () => {
	const fixture = await createFixture();
	assert.equal(generate(fixture).status, 0);
	const lockfile = await readFile(fixture.lockfile, "utf8");
	await writeFile(fixture.lockfile, `${lockfile}# dependency added after provenance was recorded\n`);

	const result = verify(fixture);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /lockfile material digest mismatch/);
});

test("detects tampering with the SBOM byproduct", async () => {
	const fixture = await createFixture();
	assert.equal(generate(fixture).status, 0);
	const sbom = JSON.parse(await readFile(fixture.sbom, "utf8"));
	sbom.components = [{ type: "library", name: "injected-after-the-fact", version: "9.9.9" }];
	await writeFile(fixture.sbom, `${JSON.stringify(sbom, null, 2)}\n`);

	const result = verify(fixture);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /byproduct digest mismatch/);
});

async function createFixture() {
	const root = await mkdtemp(path.join(os.tmpdir(), "aidr-provenance-"));
	temporaryDirectories.push(root);
	const artifacts = [
		{ id: "core/dist", dir: path.join(root, "artifacts", "core") },
		{ id: "cli/dist", dir: path.join(root, "artifacts", "cli") },
	];
	const manifests = {};
	for (const artifact of artifacts) {
		await mkdir(artifact.dir, { recursive: true });
		const payload = Buffer.from(`// ${artifact.id}\n`);
		await writeFile(path.join(artifact.dir, "payload.js"), payload);
		manifests[artifact.id] = path.join(artifact.dir, "aidr-artifact.manifest.json");
		await writeFile(
			manifests[artifact.id],
			`${JSON.stringify(
				{
					schema_version: 1,
					artifact_id: artifact.id,
					artifact_version: "1.2.3",
					files: [{ path: "payload.js", sha256: sha256(payload) }],
				},
				null,
				2,
			)}\n`,
		);
	}
	const lockfile = path.join(root, "pnpm-lock.yaml");
	await writeFile(lockfile, "lockfileVersion: '9.0'\n");
	const sbom = path.join(root, "aidr-sbom.cdx.json");
	await writeFile(sbom, `${JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", version: 1 }, null, 2)}\n`);
	return {
		root,
		artifactDirs: artifacts.map((artifact) => artifact.dir),
		manifests,
		lockfile,
		sbom,
		output: path.join(root, "aidr-provenance.intoto.json"),
	};
}

function generate(fixture, extraArguments = []) {
	return run(provenanceScript, [
		...fixture.artifactDirs.flatMap((dir) => ["--artifact-dir", dir]),
		"--lockfile",
		fixture.lockfile,
		"--sbom",
		fixture.sbom,
		"--output",
		fixture.output,
		...extraArguments,
	]);
}

function verify(fixture, extraArguments = []) {
	return run(provenanceScript, [
		"--verify-provenance",
		"--provenance",
		fixture.output,
		"--lockfile",
		fixture.lockfile,
		"--sbom",
		fixture.sbom,
		...fixture.artifactDirs.flatMap((dir) => ["--artifact-dir", dir]),
		...extraArguments,
	]);
}

function run(script, arguments_) {
	return spawnSync(process.execPath, [script, ...arguments_], {
		cwd: repoRoot,
		encoding: "utf8",
		windowsHide: true,
	});
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}
