import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "..");
const airgapScript = path.join(repoRoot, "scripts", "build-airgap-images.mjs");
const missingDockerBin = "definitely-not-an-installed-docker-binary";
const temporaryDirectories = [];

afterEach(async () => {
	await Promise.all(
		temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
	);
});

test("an air-gapped bundle verifies without network access", async () => {
	const fixture = await createFixture();
	await writeBundle(fixture, ["example/a:1", "example/b:2"]);

	const result = run(["--verify", "--output", fixture.output, "--plan", fixture.plan, "--docker-bin", missingDockerBin]);
	assert.equal(result.status, 0, result.stderr);
	const summary = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
	assert.equal(summary.status, "verified");
	assert.equal(summary.images, 2);
	assert.equal(summary.plan_checked, true);
});

test("reads the required image set from a prepared compose file", async () => {
	const fixture = await createFixture();
	await writeBundle(fixture, ["example/a:1", "example/b:2"]);
	const compose = path.join(fixture.root, "compose.yml");
	await writeFile(
		compose,
		[
			"services:",
			"  db:",
			"    image: example/a:1",
			"  api:",
			'    image: "example/b:2"',
			"  dashboard:",
			"    build: ./dashboard",
			"",
		].join("\n"),
	);

	const verified = run(["--verify", "--output", fixture.output, "--compose", compose, "--docker-bin", missingDockerBin]);
	assert.equal(verified.status, 0, verified.stderr);

	const unresolved = path.join(fixture.root, "unresolved-compose.yml");
	await writeFile(unresolved, ["services:", "  db:", "    image: registry.example/${TAG}", ""].join("\n"));
	const refused = run(["--verify", "--output", fixture.output, "--compose", unresolved, "--docker-bin", missingDockerBin]);
	assert.equal(refused.status, 1);
	assert.match(refused.stderr, /image reference is not resolved/);
});

test("refuses an incomplete image set and a tampered tarball", async () => {
	const incomplete = await createFixture();
	await writeBundle(incomplete, ["example/a:1"]);
	const missing = run(["--verify", "--output", incomplete.output, "--plan", incomplete.plan]);
	assert.equal(missing.status, 1);
	assert.match(missing.stderr, /bundle is incomplete/);

	const tampered = await createFixture();
	await writeBundle(tampered, ["example/a:1", "example/b:2"]);
	// Same byte length as the fixture archive, so the digest comparison (not the
	// size check) is what has to catch the replacement.
	await writeFile(path.join(tampered.output, "tarballs", "example-a-1.tar"), "X".repeat(36));
	const tamperedResult = run(["--verify", "--output", tampered.output, "--plan", tampered.plan]);
	assert.equal(tamperedResult.status, 1);
	assert.match(tamperedResult.stderr, /image tarball digest mismatch/);

	const missingTarball = await createFixture();
	await writeBundle(missingTarball, ["example/a:1", "example/b:2"]);
	await rm(path.join(missingTarball.output, "tarballs", "example-b-2.tar"));
	const missingTarballResult = run(["--verify", "--output", missingTarball.output, "--plan", missingTarball.plan]);
	assert.equal(missingTarballResult.status, 1);
	assert.match(missingTarballResult.stderr, /image tarball is missing from the bundle/);
});

test("fails closed without writing a manifest when Docker is unavailable", async () => {
	const root = await mkdtemp(path.join(os.tmpdir(), "aidr-airgap-images-"));
	temporaryDirectories.push(root);
	const output = path.join(root, "bundle");

	const result = run(["--output", output, "--images", "example/a:1", "--docker-bin", missingDockerBin]);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /Docker daemon is unavailable/);
	assert.match(result.stderr, /no manifest was written/);
	await assert.rejects(stat(output), /ENOENT/);
});

async function createFixture() {
	const root = await mkdtemp(path.join(os.tmpdir(), "aidr-airgap-images-"));
	temporaryDirectories.push(root);
	const output = path.join(root, "bundle");
	await mkdir(path.join(output, "tarballs"), { recursive: true });
	const plan = path.join(root, "images.plan.json");
	await writeFile(
		plan,
		`${JSON.stringify(
			{
				schema_version: 1,
				platform: "linux/amd64",
				images: [{ ref: "example/a:1" }, { ref: "example/b:2" }],
			},
			null,
			2,
		)}\n`,
	);
	return { root, output, plan };
}

async function writeBundle(fixture, refs) {
	const images = [];
	for (const ref of refs) {
		const bytes = Buffer.from(`docker save archive for ${ref}\n`);
		const tarball = `tarballs/${ref.replace(/[^A-Za-z0-9._-]+/g, "-")}.tar`;
		await writeFile(path.join(fixture.output, tarball), bytes);
		images.push({ ref, tarball, sha256: sha256(bytes), size: bytes.byteLength, repo_digest: null, image_id: null });
	}
	await writeFile(
		path.join(fixture.output, "aidr-airgap-images.manifest.json"),
		`${JSON.stringify(
			{
				schema_version: 1,
				kind: "aidr-airgap-image-bundle",
				image_source: "docker save",
				platform: "linux/amd64",
				created_at: "2026-01-01T00:00:00.000Z",
				images,
			},
			null,
			2,
		)}\n`,
	);
}

function run(arguments_) {
	return spawnSync(process.execPath, [airgapScript, ...arguments_], {
		cwd: repoRoot,
		encoding: "utf8",
		windowsHide: true,
	});
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}
