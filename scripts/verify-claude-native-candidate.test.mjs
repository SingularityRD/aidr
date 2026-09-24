import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { instrumentAmsiBackend, nativeHookPreloadSource } from "./verify-claude-native-candidate.mjs";

const script = fileURLToPath(new URL("./verify-claude-native-candidate.mjs", import.meta.url));
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

test("native backend diagnostic instruments only the exact packaged hook init boundary", () => {
	assert.throws(() => instrumentAmsiBackend("no AMSI boundary"), /unambiguous AMSI init boundary/u);
	assert.throws(() => instrumentAmsiBackend("await amsiClient.init(); await amsiClient.init();"), /unambiguous AMSI init boundary/u);
	const stage = mkdtempSync(join(tmpdir(), "aidr-native-hook-diagnostic-"));
	try {
		const hook = join(stage, "hook.cjs");
		const preload = join(stage, "preload.cjs");
		const backend = join(stage, "backend.txt");
		const spawns = join(stage, "spawns.txt");
		writeFileSync(hook, "const amsiClient = { backendKind: 'native-koffi', async init() {} }; async function main() { await amsiClient.init(); } main();\n");
		writeFileSync(preload, nativeHookPreloadSource(hook, spawns));
		const result = spawnSync(process.execPath, ["--require", preload, hook], {
			encoding: "utf8", timeout: 10_000, env: { ...process.env, AIDR_BACKEND_AUDIT: backend },
		});
		assert.equal(result.status, 0, result.stderr);
		assert.equal(readFileSync(backend, "utf8"), "native-koffi");
		assert.equal(existsSync(spawns), false);
		assert.match(readFileSync(hook, "utf8"), /await amsiClient\.init\(\);/u, "signed hook bytes stay untouched");
	} finally { rmSync(stage, { recursive: true, force: true }); }
});

test("Claude native candidate gate refuses an archive that differs from its inventory", { skip: process.platform !== "win32" }, () => {
	const candidate = mkdtempSync(join(tmpdir(), "aidr-claude-native-test-"));
	try {
		const name = "aidr-claude-plugin-0.6.0.tar.gz";
		const bytes = Buffer.from("not the declared archive");
		const declared = "0".repeat(64);
		const keyPath = join(candidate, "public.pem");
		const { publicKey } = generateKeyPairSync("ed25519");
		writeFileSync(keyPath, publicKey.export({ type: "spki", format: "pem" }));
		writeFileSync(join(candidate, name), bytes);
		const metadata = JSON.stringify({
			schema_version: 1, worktree_dirty: false, git_sha: "a".repeat(40), release_version: "0.6.0",
			artifacts: [{ path: name, size: bytes.length, sha256: declared }],
		});
		const inventory = JSON.stringify({
			schema_version: 1,
			artifacts: [{ staged_path: name, source_path: `release-output/${name}`, sha256: declared }],
		});
		writeFileSync(join(candidate, "release-metadata.json"), metadata);
		writeFileSync(join(candidate, "release-inventory.json"), inventory);
		const digest = sha256(`${sha256(metadata)}  release-output/release-metadata.json\n${sha256(inventory)}  release-output/release-inventory.json\n`);
		const result = spawnSync(process.execPath, [script, "--candidate", candidate, "--expected-candidate-digest", digest, "--public-key", keyPath], { encoding: "utf8", timeout: 10_000 });
		assert.equal(result.status, 1);
		assert.match(result.stderr, /archive digest differs from the candidate/u);
		assert.doesNotMatch(result.stdout, /"status":"PASS"/u);
		const wrongBinding = spawnSync(process.execPath, [script, "--candidate", candidate, "--expected-candidate-digest", "b".repeat(64), "--public-key", keyPath], { encoding: "utf8", timeout: 10_000 });
		assert.equal(wrongBinding.status, 1);
		assert.match(wrongBinding.stderr, /protected workflow binding/u);
	} finally {
		rmSync(candidate, { recursive: true, force: true });
	}
});
