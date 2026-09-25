import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { pinnedSourceTreeDigest, readPinnedDataFiles, readPinnedYamlFiles, readWorktreeDataFiles, readWorktreeYamlFiles, sanitizedAigChildEnv } from "./lib/aig-source-tree.mjs";
import { parseCvssScore } from "./compile-aig-data.mjs";

const root = new URL("..", import.meta.url);
const verifierPath = new URL("./verify-aig-source.mjs", import.meta.url);
const compilerPath = fileURLToPath(new URL("./compile-aig-data.mjs", import.meta.url));

test("CVSS parsing accepts only complete numeric scores or valid CVSS v3 vectors", () => {
	const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
	const scopeChangedNoInteraction = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N";
	const scopeChangedInteraction = scopeChangedNoInteraction.replace("UI:N", "UI:R");
	const interactionAndIntegrity = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H";
	assert.equal(parseCvssScore(" 8.8 "), 8.8);
	assert.equal(parseCvssScore("10"), 10);
	assert.equal(parseCvssScore(vector), 9.8);
	assert.equal(parseCvssScore(vector.replace("3.1", "3.0")), 9.8);
	assert.equal(parseCvssScore(`${vector}/E:F/RL:W/RC:C`), 9.8);
	assert.equal(parseCvssScore(scopeChangedNoInteraction), 7.2);
	assert.equal(parseCvssScore(scopeChangedNoInteraction.replace("3.1", "3.0")), 7.2);
	assert.equal(parseCvssScore(scopeChangedInteraction), 6.1);
	assert.equal(parseCvssScore(interactionAndIntegrity), 8.6);

	for (const invalid of [
		"score 8.8",
		"8.8 points",
		"10.1",
		`note ${vector}`,
		`AV:N ${vector}`,
		`${vector} trailing text`,
		`${vector} AV:N`,
		vector.replace("/AC:L", "/AC:L/AC:H"),
		vector.replace("/A:H", ""),
		vector.replace("/AC:L", "/AC:X"),
		`${vector}/E:F/E:H`,
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
	]) {
		assert.equal(parseCvssScore(invalid), null, `unexpected score for ${invalid}`);
	}
});

test("AIG Git child processes cannot inherit private-key variables", () => {
	const child = sanitizedAigChildEnv({
		PATH: "trusted-bin",
		AIG_SIGNING_PRIVATE_KEY: "raw-aig-key",
		AIG_SIGNING_PRIVATE_KEY_PATH: "/tmp/aig.pem",
		AIDR_SIGNING_PRIVATE_KEY_PEM_PATH: "/tmp/artifact.pem",
		aidr_entitlement_signing_private_key_pkcs8_b64: "raw-entitlement-key",
		AIG_SIGNING_PUBLIC_KEY_PATH: "/tmp/aig-public.pem",
		AIG_SIGNING_KEY_ID: "aig-production-1",
	});
	assert.deepEqual(child, {
		PATH: "trusted-bin",
		AIG_SIGNING_PUBLIC_KEY_PATH: "/tmp/aig-public.pem",
		AIG_SIGNING_KEY_ID: "aig-production-1",
	});
});

test("compiler rejects missing or placeholder signing key IDs before compiling outputs", () => {
	for (const keyId of [undefined, "   ", " UnSpEcIfIeD "]) {
		const env = Object.fromEntries(
			Object.entries(process.env).filter(([name]) => ![
				"AIG_SIGNING_PRIVATE_KEY",
				"AIG_SIGNING_PRIVATE_KEY_PATH",
				"AIG_SIGNING_KEY_ID",
			].includes(name.toUpperCase())),
		);
		env.AIG_SIGNING_PRIVATE_KEY = "invalid-test-key";
		if (keyId !== undefined) env.AIG_SIGNING_KEY_ID = keyId;

		const result = spawnSync(process.execPath, [compilerPath], {
			cwd: root,
			env,
			encoding: "utf8",
		});
		const output = `${result.stdout}\n${result.stderr}`;
		assert.notEqual(result.status, 0);
		assert.match(output, /AIG_SIGNING_KEY_ID must identify the configured signing key/);
		assert.doesNotMatch(output, /Compiling (?:CVE|fingerprint|MCP)/);
	}
});

test("compiler rejects a non-RSA signing key", () => {
	const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const env = {
		...process.env,
		AIG_SIGNING_PRIVATE_KEY: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		AIG_SIGNING_KEY_ID: "ec-must-not-pass",
	};
	delete env.AIG_SIGNING_PRIVATE_KEY_PATH;

	const result = spawnSync(process.execPath, [compilerPath], { cwd: root, env, encoding: "utf8" });
	assert.notEqual(result.status, 0);
	assert.match(`${result.stdout}\n${result.stderr}`, /AIG signing private key must be RSA/);
});

test("release verifier rejects an EC key mislabeled as RSA-SHA256", async (t) => {
	const generatedDir = await mkdtemp(join(tmpdir(), "aidr-aig-generated-"));
	t.after(() => rm(generatedDir, { recursive: true, force: true }));
	const sourceDir = fileURLToPath(new URL("../packages/core/src/generated/", import.meta.url));
	for (const name of ["aig-cve-index.json", "aig-fingerprints.json", "aig-mcp-categories.json"]) {
		await copyFile(join(sourceDir, name), join(generatedDir, name));
	}
	const manifest = JSON.parse(await readFile(join(sourceDir, "aig-data-manifest.json"), "utf8"));
	delete manifest.signature;
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const signer = createSign("RSA-SHA256");
	signer.update(JSON.stringify(manifest));
	signer.end();
	manifest.signature = {
		algorithm: "RSA-SHA256",
		key_id: "ec-must-not-pass",
		value: signer.sign(privateKey, "base64"),
	};
	await writeFile(join(generatedDir, "aig-data-manifest.json"), JSON.stringify(manifest));
	const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
	const fingerprint = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
	const result = spawnSync(process.execPath, [fileURLToPath(verifierPath)], {
		cwd: root,
		encoding: "utf8",
		env: {
			...process.env,
			AIG_GENERATED_DIR: generatedDir,
			AIG_RELEASE: "true",
			AIG_SIGNING_PUBLIC_KEY: publicKeyPem,
			AIG_TRUSTED_SIGNING_KEY_ID: "ec-must-not-pass",
			AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256: fingerprint,
		},
	});
	assert.notEqual(result.status, 0);
	assert.match(`${result.stdout}\n${result.stderr}`, /AIG public verification key must be RSA/);
});

test("verifier rejects an invalid optional release sequence", async (t) => {
	const generatedDir = await mkdtemp(join(tmpdir(), "aidr-aig-sequence-"));
	t.after(() => rm(generatedDir, { recursive: true, force: true }));
	const sourceDir = fileURLToPath(new URL("../packages/core/src/generated/", import.meta.url));
	for (const name of ["aig-cve-index.json", "aig-fingerprints.json", "aig-mcp-categories.json"]) {
		await copyFile(join(sourceDir, name), join(generatedDir, name));
	}
	const manifest = JSON.parse(await readFile(join(sourceDir, "aig-data-manifest.json"), "utf8"));
	manifest.release_sequence = 0;
	manifest.signature = null;
	await writeFile(join(generatedDir, "aig-data-manifest.json"), JSON.stringify(manifest));
	const result = spawnSync(process.execPath, [fileURLToPath(verifierPath)], {
		cwd: root,
		encoding: "utf8",
		env: { ...process.env, AIG_GENERATED_DIR: generatedDir, AIG_RELEASE: "false", AIG_REQUIRE_SIGNED: "false" },
	});
	assert.notEqual(result.status, 0);
	assert.match(`${result.stdout}\n${result.stderr}`, /manifest release_sequence must be a safe integer greater than or equal to 1/);
});

test("verifier rejects a different valid bundle without a registry sequence bump", async (t) => {
	const generatedDir = await mkdtemp(join(tmpdir(), "aidr-aig-unregistered-"));
	t.after(() => rm(generatedDir, { recursive: true, force: true }));
	const sourceDir = fileURLToPath(new URL("../packages/core/src/generated/", import.meta.url));
	const artifactNames = ["aig-cve-index.json", "aig-fingerprints.json", "aig-mcp-categories.json"];
	for (const name of artifactNames) await copyFile(join(sourceDir, name), join(generatedDir, name));
	const changedName = "aig-mcp-categories.json";
	const changed = Buffer.concat([await readFile(join(generatedDir, changedName)), Buffer.from(" ")]);
	await writeFile(join(generatedDir, changedName), changed);
	const manifest = JSON.parse(await readFile(join(sourceDir, "aig-data-manifest.json"), "utf8"));
	manifest.artifacts[changedName] = {
		sha256: createHash("sha256").update(changed).digest("hex"),
		bytes: changed.length,
	};
	manifest.bundle_id = createHash("sha256")
		.update(JSON.stringify(Object.fromEntries(artifactNames.map((name) => [name, manifest.artifacts[name]]))))
		.digest("hex");
	manifest.signature = null;
	await writeFile(join(generatedDir, "aig-data-manifest.json"), JSON.stringify(manifest));
	const result = spawnSync(process.execPath, [fileURLToPath(verifierPath)], {
		cwd: root,
		encoding: "utf8",
		env: { ...process.env, AIG_GENERATED_DIR: generatedDir, AIG_RELEASE: "false", AIG_REQUIRE_SIGNED: "false" },
	});
	assert.notEqual(result.status, 0);
	assert.match(`${result.stdout}\n${result.stderr}`, /manifest does not match the committed AIG release sequence registry/);
});

test("vendored source tree matches the registered AIG commit tree", async () => {
	const registry = JSON.parse(await readFile(new URL("../config/aig-release-sequence.json", import.meta.url), "utf8"));
	const expectedTree = registry.releases.at(-1).source_tree_oid;
	const tree = execFileSync(
		"git",
		["ls-tree", "HEAD", "vendor/ai-infra-guard"],
		{ cwd: root, encoding: "utf8" },
	).trim();
	const match = tree.match(/^040000 tree ([0-9a-f]{40})\tvendor\/ai-infra-guard$/);
	assert.ok(match, "vendor/ai-infra-guard must be a committed directory");
	assert.equal(match[1], expectedTree);
});

test("Compose and its safe env example report the pinned AIG release tag", async () => {
	const registry = JSON.parse(await readFile(new URL("../config/aig-release-sequence.json", import.meta.url), "utf8"));
	const source = registry.releases.at(-1);
	const tag = source.source_tag;
	const manifest = JSON.parse(await readFile(new URL("../packages/core/src/generated/aig-data-manifest.json", import.meta.url), "utf8"));
	assert.equal(source.source_commit, manifest.source.commit);
	assert.equal(source.source_tree_oid, manifest.source.git_tree_oid);
	const env = await readFile(new URL("../.env.posture-scanner.example", import.meta.url), "utf8");
	const compose = await readFile(new URL("../docker-compose.posture-scanner.yml", import.meta.url), "utf8");
	assert.match(env, new RegExp(`^POSTURE_SCANNER_SOURCE_VERSION=${tag.replaceAll(".", "\\.")}$`, "m"));
	for (const key of ["POSTURE_SCANNER_AGENT_SHARED_SECRET", "BRIDGE_API_KEY"]) {
		assert.match(env, new RegExp(`^${key}=$`, "m"), `${key} must remain blank in the committed example`);
	}
	const pinned = `\\$\\{POSTURE_SCANNER_SOURCE_VERSION:-\\$\\{AIG_SOURCE_VERSION:-${tag.replaceAll(".", "\\.")}\\}\\}`;
	assert.match(compose, new RegExp(`AIG_AGENT_VERSION=${pinned}`));
	assert.match(compose, new RegExp(`AIG_SOURCE_VERSION=${pinned}`));
});

test("the generated manifest is bound to every pinned Unicode Git blob", async () => {
	const aigRoot = fileURLToPath(new URL("../vendor/ai-infra-guard/", import.meta.url));
	const files = readPinnedYamlFiles({ aigRoot, cwd: root });
	assert.equal(files.filter((file) => file.path.startsWith("data/vuln/") || file.path.startsWith("data/vuln_en/")).length, 4028);
	assert.equal(files.filter((file) => file.path.startsWith("data/fingerprints/")).length, 146);
	assert.ok(files.some((file) => /[^\x00-\x7f]/.test(file.path)), "the fixture must cover Git's quoted Unicode-path edge case");
	const manifest = JSON.parse(await readFile(new URL("../packages/core/src/generated/aig-data-manifest.json", import.meta.url), "utf8"));
	const registry = JSON.parse(await readFile(new URL("../config/aig-release-sequence.json", import.meta.url), "utf8"));
	const currentRelease = registry.releases.at(-1);
	assert.equal(manifest.release_sequence, currentRelease.release_sequence);
	assert.equal(manifest.source.commit, currentRelease.source_commit);
	assert.equal(manifest.bundle_id, currentRelease.bundle_id);
	assert.equal(manifest.source.tree_sha256, pinnedSourceTreeDigest(files));
	const runtimeFiles = readPinnedDataFiles({ aigRoot, cwd: root });
	assert.equal(manifest.runtime.schema, "aig-runtime-data/v1");
	assert.equal(manifest.runtime.root, "data");
	assert.equal(manifest.runtime.files, runtimeFiles.length);
	assert.equal(manifest.runtime.bytes, runtimeFiles.reduce((total, file) => total + file.contents.length, 0));
	assert.equal(manifest.runtime.tree_sha256, pinnedSourceTreeDigest(runtimeFiles));
});

test("the source-tree digest changes when either a pinned path or blob changes", () => {
	const original = [
		{ path: "data/vuln/a/one.yaml", contents: Buffer.from("id: one\n") },
		{ path: "data/vuln_en/b/two.yaml", contents: Buffer.from("id: two\n") },
	];
	const digest = pinnedSourceTreeDigest(original);
	assert.notEqual(
		pinnedSourceTreeDigest([{ ...original[0], contents: Buffer.from("id: tampered\n") }, original[1]]),
		digest,
	);
	assert.notEqual(
		pinnedSourceTreeDigest([{ ...original[0], path: "data/vuln/a/renamed.yaml" }, original[1]]),
		digest,
	);
});

test("worktree sync input is byte-exact, sorted and limited to AIG YAML roots", async (t) => {
	const aigRoot = await mkdtemp(join(tmpdir(), "aidr-aig-worktree-"));
	t.after(() => rm(aigRoot, { recursive: true, force: true }));
	await mkdir(join(aigRoot, "data", "vuln", "z"), { recursive: true });
	await mkdir(join(aigRoot, "data", "vuln_en", "a"), { recursive: true });
	await mkdir(join(aigRoot, "data", "fingerprints"), { recursive: true });
	await writeFile(join(aigRoot, "data", "vuln", "z", "two.yaml"), "id: two\r\n");
	await writeFile(join(aigRoot, "data", "vuln_en", "a", "one.yaml"), "id: one\n");
	await writeFile(join(aigRoot, "data", "fingerprints", "fingerprint.yaml"), "info:\n  name: fixture\n");
	await writeFile(join(aigRoot, "data", "vuln", "z", "ignored.txt"), "not yaml\n");

	const files = readWorktreeYamlFiles({ aigRoot });
	assert.deepEqual(files.map((file) => file.path), [
		"data/fingerprints/fingerprint.yaml",
		"data/vuln/z/two.yaml",
		"data/vuln_en/a/one.yaml",
	]);
	assert.equal(files[1].contents.toString("utf8"), "id: two\r\n");
	const runtimeFiles = readWorktreeDataFiles({ aigRoot });
	assert.deepEqual(runtimeFiles.map((file) => file.path), [
		"data/fingerprints/fingerprint.yaml",
		"data/vuln/z/ignored.txt",
		"data/vuln/z/two.yaml",
		"data/vuln_en/a/one.yaml",
	]);
});
