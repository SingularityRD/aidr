import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
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
	await writeBundle(fixture, ["example/a:1", "example/b:2", "example/node:24"]);
	const compose = path.join(fixture.root, "compose.yml");
	await mkdir(path.join(fixture.root, "dashboard"));
	await writeFile(path.join(fixture.root, "dashboard", "Dockerfile"), "FROM example/node:24\nCMD [\"node\"]\n");
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

test("rejects a pinned image when the bundle has no matching digest", async () => {
	const fixture = await createFixture();
	await writeBundle(fixture, ["example/a:1", "example/b:2"]);
	const plan = JSON.parse(await readFile(fixture.plan, "utf8"));
	plan.images[0].digest = `sha256:${"a".repeat(64)}`;
	await writeFile(fixture.plan, JSON.stringify(plan));

	const result = run(["--verify", "--output", fixture.output, "--plan", fixture.plan]);
	assert.equal(result.status, 1);
	assert.match(result.stderr, /does not match the digest pinned in the plan/);
});

test("enforces the digest embedded in a prepared compose image reference", async () => {
	const fixture = await createFixture();
	const pinnedDigest = `sha256:${"a".repeat(64)}`;
	const ref = `example/gateway:1@${pinnedDigest}`;
	await writeBundle(fixture, [ref]);
	const compose = path.join(fixture.root, "compose.yml");
	await writeFile(compose, `services:\n  api:\n    image: ${ref}\n`);
	const manifestPath = path.join(fixture.output, "aidr-airgap-images.manifest.json");
	const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
	manifest.images[0].repo_digest = `example/gateway@sha256:${"b".repeat(64)}`;
	manifest.images[0].image_id = `sha256:${"c".repeat(64)}`;
	await writeFile(manifestPath, JSON.stringify(manifest));
	const refused = run(["--verify", "--output", fixture.output, "--compose", compose, "--docker-bin", missingDockerBin]);
	assert.equal(refused.status, 1, "wrong image identity was accepted under the pinned compose reference");
	assert.match(refused.stderr, /does not match the digest pinned in the plan/);

	// OCI index/repository digests differ from the image-config identity.
	manifest.images[0].repo_digest = `example/gateway@${pinnedDigest}`;
	await writeFile(manifestPath, JSON.stringify(manifest));
	const accepted = run(["--verify", "--output", fixture.output, "--compose", compose, "--docker-bin", missingDockerBin]);
	assert.equal(accepted.status, 0, accepted.stderr);
});

test("refuses malformed and conflicting digest-qualified image plans", async () => {
	const fixture = await createFixture();
	const pinnedDigest = `sha256:${"a".repeat(64)}`;
	for (const images of [
		[{ ref: "example/gateway:1@sha256:short" }],
		[{ ref: `example/gateway:1@${pinnedDigest}`, digest: `sha256:${"b".repeat(64)}` }],
		[{ ref: "example/gateway:1", digest: pinnedDigest }, { ref: "example/gateway:1", digest: `sha256:${"b".repeat(64)}` }],
	]) {
		await writeFile(fixture.plan, JSON.stringify({ images }));
		await writeBundle(fixture, [images[0].ref]);
		const refused = run(["--verify", "--output", fixture.output, "--plan", fixture.plan, "--docker-bin", missingDockerBin]);
		assert.equal(refused.status, 1);
		assert.match(refused.stderr, /must pin a sha256|conflicting pinned digests/);
	}
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

test("plans Dockerfile FROM base images for every compose build service", async () => {
	const fixture = await createFixture();
	const pinned = `example/python:3.12@sha256:${"b".repeat(64)}`;
	await mkdir(path.join(fixture.root, "app", "docker"), { recursive: true });
	await writeFile(
		path.join(fixture.root, "app", "docker", "Dockerfile.release"),
		[
			"# syntax=docker/dockerfile:1",
			"ARG NODE_TAG=22",
			"ARG RUNTIME=example/runtime:1",
			"FROM --platform=$BUILDPLATFORM example/node:${NODE_TAG} AS frontend",
			"RUN build \\",
			"  --flag",
			"FROM frontend AS tested",
			"FROM scratch AS empty",
			`FROM ${pinned}`,
			"COPY --from=tested /out /out",
			"FROM ${RUNTIME}",
			"",
		].join("\n"),
	);
	const compose = path.join(fixture.root, "compose.yml");
	await writeFile(
		compose,
		[
			"services:",
			"  app:",
			"    image: aidr-app:1.0.0",
			"    build:",
			"      context: ./app",
			"      dockerfile: docker/Dockerfile.release",
			"      args:",
			"        NODE_TAG: '24'",
			"  db:",
			"    image: example/a:1",
			"",
		].join("\n"),
	);
	const expected = ["aidr-app:1.0.0", "example/a:1", "example/node:24", pinned, "example/runtime:1"];

	await writeBundle(fixture, expected.filter((ref) => ref !== "example/node:24"));
	const incomplete = run(["--verify", "--output", fixture.output, "--compose", compose, "--docker-bin", missingDockerBin]);
	assert.equal(incomplete.status, 1);
	assert.match(incomplete.stderr, /bundle is incomplete: example\/node:24 is required by the plan/);

	const complete = await createFixture();
	await writeBundle(complete, expected, { [pinned]: `example/python@sha256:${"b".repeat(64)}` });
	const verified = run(["--verify", "--output", complete.output, "--compose", compose, "--docker-bin", missingDockerBin]);
	assert.equal(verified.status, 0, verified.stderr);
	assert.equal(JSON.parse(verified.stdout.trim()).images, expected.length);
});

test("refuses build services whose base image cannot be resolved offline", async () => {
	const fixture = await createFixture();
	await writeBundle(fixture, ["example/a:1"]);
	const cases = [
		["FROM example/node:${MISSING_TAG}\n", "build: ./app", /references build argument MISSING_TAG without a value/],
		["FROM example/node:24\n", "build: https://github.com/example/app.git", /remote or unresolved context/],
		[null, "build: ./app", /Dockerfile, which is missing; its base images cannot be planned/],
	];
	for (const [index, [dockerfile, build, expected]] of cases.entries()) {
		const directory = path.join(fixture.root, `case-${index}`);
		await mkdir(path.join(directory, "app"), { recursive: true });
		if (dockerfile) await writeFile(path.join(directory, "app", "Dockerfile"), dockerfile);
		const compose = path.join(directory, "compose.yml");
		await writeFile(compose, ["services:", "  app:", `    ${build}`, ""].join("\n"));
		const result = run(["--verify", "--output", fixture.output, "--compose", compose, "--docker-bin", missingDockerBin]);
		assert.equal(result.status, 1, `case ${index} unexpectedly verified`);
		assert.match(result.stderr, expected);
	}
});

test("bundles locally built images without pulling them and pulls their base images", { skip: process.platform === "win32" && "fake docker binary is a POSIX script" }, async () => {
	const fixture = await createFixture();
	const docker = await fakeDocker(fixture.root);
	const compose = path.join(fixture.root, "compose.yml");
	// The real reviewed build contexts: dashboard, AIG bridge and AIG worker.
	await writeFile(
		compose,
		[
			"services:",
			"  dashboard:",
			"    image: aidr-dashboard:0.0.0-test",
			`    build: ${JSON.stringify(path.join(repoRoot, "deploy", "dashboard"))}`,
			"  aig-bridge:",
			`    build: ${JSON.stringify(path.join(repoRoot, "services", "aig-bridge"))}`,
			"  aig-agent:",
			"    image: aidr-aig-agent:0.0.0-test",
			"    build:",
			`      context: ${JSON.stringify(path.join(repoRoot, "vendor", "ai-infra-guard"))}`,
			"      dockerfile: Dockerfile_Agent",
			"",
		].join("\n"),
	);
	const dashboardBase = readFileSync(path.join(repoRoot, "deploy", "dashboard", "Dockerfile"), "utf8").match(/^FROM (\S+)/m)[1];
	const agentBases = [...readFileSync(path.join(repoRoot, "vendor", "ai-infra-guard", "Dockerfile_Agent"), "utf8").matchAll(/^FROM (\S+)/gm)].map((match) => match[1]);

	const result = run(["--output", fixture.output, "--compose", compose, "--docker-bin", docker.bin], { FAKE_DOCKER_LOG: docker.log });
	assert.equal(result.status, 0, result.stderr);
	const calls = (await readFile(docker.log, "utf8")).trim().split("\n");
	const pulled = calls.filter((call) => call.startsWith("pull ")).map((call) => call.slice(5));
	assert.ok(pulled.includes(dashboardBase), "dashboard Dockerfile base image was not pulled");
	for (const base of agentBases) assert.ok(pulled.includes(base), `AIG worker base ${base} was not pulled`);
	assert.ok(pulled.some((ref) => ref.startsWith("python:3.12-slim@sha256:")), "digest-pinned bridge base image was not pulled");
	assert.equal(pulled.some((ref) => ref.startsWith("aidr-")), false, "a locally built image must never be pulled");

	const manifest = JSON.parse(await readFile(path.join(fixture.output, "aidr-airgap-images.manifest.json"), "utf8"));
	const byRef = new Map(manifest.images.map((image) => [image.ref, image]));
	assert.equal(byRef.get("aidr-dashboard:0.0.0-test").source, "local-build");
	assert.equal(byRef.get("aidr-aig-agent:0.0.0-test").source, "local-build");
	assert.equal(byRef.get(dashboardBase).role, "build-base");
	assert.equal(byRef.get(dashboardBase).source, "registry");

	const verified = run(["--verify", "--output", fixture.output, "--compose", compose, "--docker-bin", missingDockerBin]);
	assert.equal(verified.status, 0, verified.stderr);
});

test("a missing local build fails with the build instruction and writes no manifest", { skip: process.platform === "win32" && "fake docker binary is a POSIX script" }, async () => {
	const fixture = await createFixture();
	const docker = await fakeDocker(fixture.root);
	await mkdir(path.join(fixture.root, "app"));
	await writeFile(path.join(fixture.root, "app", "Dockerfile"), "FROM example/node:24\n");
	const compose = path.join(fixture.root, "compose.yml");
	await writeFile(compose, ["services:", "  app:", "    image: aidr-app:9.9.9", "    build: ./app", ""].join("\n"));
	const result = run(["--output", fixture.output, "--compose", compose, "--docker-bin", docker.bin], {
		FAKE_DOCKER_LOG: docker.log,
		FAKE_DOCKER_ABSENT: "aidr-app:9.9.9",
	});
	assert.equal(result.status, 1);
	assert.match(result.stderr, /aidr-app:9\.9\.9 is built locally and was not found; run `docker compose build`/);
	await assert.rejects(stat(path.join(fixture.output, "aidr-airgap-images.manifest.json")), /ENOENT/);
	assert.doesNotMatch(await readFile(docker.log, "utf8"), /^pull aidr-app/m);
});

async function fakeDocker(root) {
	const bin = path.join(root, "fake-docker.mjs");
	const log = path.join(root, "docker-calls.log");
	await writeFile(log, "");
	await writeFile(
		bin,
		`#!${process.execPath}
import { appendFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
const args = process.argv.slice(2);
const absent = (process.env.FAKE_DOCKER_ABSENT ?? "").split(",").filter(Boolean);
const ref = args.at(-1);
if (args[0] === "version") { console.log("29.0.0-fake"); process.exit(0); }
if (args[0] === "pull") { appendFileSync(process.env.FAKE_DOCKER_LOG, "pull " + ref + "\\n"); process.exit(0); }
if (args[0] === "image" && args[1] === "inspect") {
	if (absent.includes(ref)) { console.error("No such image: " + ref); process.exit(1); }
	const at = ref.indexOf("@");
	const repository = at === -1 ? null : ref.slice(0, at).replace(/:[^/]*$/, "");
	console.log(JSON.stringify({ Id: "sha256:" + createHash("sha256").update(ref).digest("hex"), RepoDigests: repository ? [repository + ref.slice(at)] : [], Os: "linux", Architecture: "amd64" }));
	process.exit(0);
}
if (args[0] === "save") { writeFileSync(args[2], "docker save archive for " + ref + "\\n"); appendFileSync(process.env.FAKE_DOCKER_LOG, "save " + ref + "\\n"); process.exit(0); }
console.error("unexpected docker call: " + args.join(" "));
process.exit(2);
`,
		{ mode: 0o755 },
	);
	return { bin, log };
}

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

async function writeBundle(fixture, refs, repoDigests = {}) {
	const images = [];
	for (const ref of refs) {
		const bytes = Buffer.from(`docker save archive for ${ref}\n`);
		const tarball = `tarballs/${ref.replace(/[^A-Za-z0-9._-]+/g, "-")}.tar`;
		await writeFile(path.join(fixture.output, tarball), bytes);
		images.push({ ref, tarball, sha256: sha256(bytes), size: bytes.byteLength, repo_digest: repoDigests[ref] ?? null, image_id: null });
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

function run(arguments_, env = {}) {
	return spawnSync(process.execPath, [airgapScript, ...arguments_], {
		cwd: repoRoot,
		encoding: "utf8",
		windowsHide: true,
		env: { ...process.env, ...env },
	});
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}
