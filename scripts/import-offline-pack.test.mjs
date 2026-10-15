import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { canonicalJson } from "./license-verify.mjs";

const importScript = fileURLToPath(new URL("./import-offline-pack.mjs", import.meta.url));
const signScript = fileURLToPath(new URL("./sign-intel-pack-manifest.mjs", import.meta.url));
const coreLoader = new URL("../packages/core/dist/intel/loader.js", import.meta.url);
const TENANT = "11111111-1111-4111-8111-111111111111";

// DEV test publisher key: generated per run, never persisted outside the temp dir.
const publisher = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function workdir(t) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-offline-pack-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	return directory;
}

/**
 * Build a signed pack the way the vendor does: write manifest + files, then sign
 * the exact manifest bytes with the real sign-intel-pack-manifest.mjs.
 */
function buildPack(root, { version = "1.1.0", keyId = "aidr-intel-dev-1", privateKey = publisher.privateKey, files, manifestOverrides = {}, name = `pack-${version}` } = {}) {
	const directory = join(root, name);
	mkdirSync(join(directory, "lists"), { recursive: true });
	const entries = files ?? [{ path: "lists/url-deny.txt", kind: "url_denylist", content: "# offline test list\nhttps://exfil.offline-pack.test/upload\n" }];
	for (const entry of entries) writeFileSync(join(directory, ...entry.path.split("/")), entry.content);
	const manifest = {
		pack_id: "aidr-offline-intel",
		version,
		issued_at: "2026-09-20T00:00:00Z",
		expires_at: "2099-01-01T00:00:00Z",
		key_id: keyId,
		files: entries.map((entry) => ({ kind: entry.kind, path: entry.path, sha256: entry.sha256 ?? sha256(entry.content) })),
		...manifestOverrides,
	};
	writeFileSync(join(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	const keyPath = join(root, `${name}-signing.pem`);
	writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
	const signed = spawnSync(process.execPath, [signScript, "--manifest", join(directory, "manifest.json"), "--private-key", keyPath], { encoding: "utf8" });
	assert.equal(signed.status, 0, signed.stderr);
	rmSync(keyPath);
	return directory;
}

function trustedKeys(root) {
	const path = join(root, "trusted-keys.json");
	writeFileSync(path, JSON.stringify({ "aidr-intel-dev-1": publisher.publicKey.export({ type: "spki", format: "pem" }).toString() }));
	return path;
}

function runImport(args, env = {}) {
	const result = spawnSync(process.execPath, [importScript, ...args], { encoding: "utf8", env: { ...process.env, ...env } });
	return { ...result, json: result.status === 0 ? JSON.parse(result.stdout.trim().split("\n").at(-1)) : null };
}

test("a signed offline pack installs locally and the endpoint loader accepts it", async (t) => {
	const root = workdir(t);
	const pack = buildPack(root);
	const keys = trustedKeys(root);
	const packsDir = join(root, "intel", "packs");
	const result = runImport(["--pack", pack, "--trusted-keys", keys, "--target", "local", "--packs-dir", packsDir]);
	assert.equal(result.status, 0, result.stderr);
	assert.equal(result.json.outcome, "installed");
	assert.equal(result.json.pack_id, "aidr-offline-intel");
	assert.equal(result.json.version, "1.1.0");
	assert.deepEqual(JSON.parse(readFileSync(join(packsDir, "aidr-offline-intel", "active.json"), "utf8")), { version: "1.1.0" });
	assert.ok(!existsSync(join(packsDir, "aidr-offline-intel", ".staging")), "no staging residue");

	// The same bytes pass the endpoint's own loader, which re-verifies signature and hashes.
	const { loadMergedIntelFromDisk } = await import(coreLoader.href);
	const merged = await loadMergedIntelFromDisk({ packsDir, trustedKeysPath: keys, intelDir: join(root, "intel") });
	assert.equal(merged.availability, "available");
	assert.ok(merged.urlDenyHosts.has("exfil.offline-pack.test"));

	const again = runImport(["--pack", pack, "--trusted-keys", keys, "--target", "local", "--packs-dir", packsDir]);
	assert.equal(again.status, 0, again.stderr);
	assert.equal(again.json.outcome, "already_installed", "re-importing identical bytes is idempotent");
});

test("tampered, unsigned, untrusted, unsafe and expired packs are refused before anything is written", (t) => {
	const root = workdir(t);
	const keys = trustedKeys(root);
	const packsDir = join(root, "packs");
	const cases = [];

	const tamperedFile = buildPack(root, { name: "tampered-file" });
	writeFileSync(join(tamperedFile, "lists", "url-deny.txt"), "https://allowed-by-attacker.test\n");
	cases.push([tamperedFile, /SHA-256 mismatch/]);

	const tamperedManifest = buildPack(root, { name: "tampered-manifest" });
	const manifestPath = join(tamperedManifest, "manifest.json");
	writeFileSync(manifestPath, readFileSync(manifestPath, "utf8").replace("2099-01-01", "2199-01-01"));
	cases.push([tamperedManifest, /signature does not verify/]);

	cases.push([buildPack(root, { name: "wrong-key", privateKey: stranger.privateKey }), /signature does not verify/]);
	cases.push([buildPack(root, { name: "untrusted", keyId: "unknown-publisher", privateKey: stranger.privateKey }), /not in the trusted-keys file/]);
	cases.push([buildPack(root, { name: "expired", manifestOverrides: { expires_at: "2020-01-01T00:00:00Z" } }), /expired at 2020/]);

	const traversal = buildPack(root, { name: "traversal", files: [{ path: "lists/url-deny.txt", kind: "url_denylist", content: "x\n" }], manifestOverrides: { files: [{ kind: "url_denylist", path: "../../escape.txt", sha256: sha256("x\n") }] } });
	cases.push([traversal, /unsafe path/]);

	const unlisted = buildPack(root, { name: "unlisted" });
	writeFileSync(join(unlisted, "lists", "smuggled.txt"), "extra\n");
	cases.push([unlisted, /unlisted file/]);

	const unsigned = buildPack(root, { name: "unsigned" });
	rmSync(join(unsigned, "manifest.sig"));
	cases.push([unsigned, /manifest\.sig is missing/]);

	for (const [pack, expected] of cases) {
		const result = runImport(["--pack", pack, "--trusted-keys", keys, "--target", "local", "--packs-dir", packsDir]);
		assert.notEqual(result.status, 0, `${pack} must be refused`);
		assert.match(result.stderr, expected, pack);
		assert.equal(existsSync(join(packsDir, "aidr-offline-intel")), false, `${pack}: nothing installed`);
	}
	const emptyKeys = join(root, "empty-keys.json");
	writeFileSync(emptyKeys, "{}");
	const noKeys = runImport(["--pack", buildPack(root, { name: "no-keys" }), "--trusted-keys", emptyKeys, "--target", "local", "--packs-dir", packsDir]);
	assert.notEqual(noKeys.status, 0);
	assert.match(noKeys.stderr, /contains no public keys/);
});

test("rollback and version equivocation are refused; bundles round-trip for media transfer", (t) => {
	const root = workdir(t);
	const keys = trustedKeys(root);
	const packsDir = join(root, "packs");
	const newer = buildPack(root, { version: "2.0.0" });
	assert.equal(runImport(["--pack", newer, "--trusted-keys", keys, "--target", "local", "--packs-dir", packsDir]).status, 0);

	const older = runImport(["--pack", buildPack(root, { version: "1.9.0" }), "--trusted-keys", keys, "--target", "local", "--packs-dir", packsDir]);
	assert.notEqual(older.status, 0);
	assert.match(older.stderr, /older than installed 2\.0\.0; rollback refused/);

	const equivocation = buildPack(root, { version: "2.0.0", name: "equivocation", files: [{ path: "lists/url-deny.txt", kind: "url_denylist", content: "https://other.test\n" }] });
	const refused = runImport(["--pack", equivocation, "--trusted-keys", keys, "--target", "local", "--packs-dir", packsDir]);
	assert.notEqual(refused.status, 0);
	assert.match(refused.stderr, /version equivocation refused/);

	const bundlePath = join(root, "aidr-offline-intel-2.1.0.aidrpack.json");
	const exported = runImport(["--pack", buildPack(root, { version: "2.1.0" }), "--trusted-keys", keys, "--export-bundle", bundlePath]);
	assert.equal(exported.status, 0, exported.stderr);
	assert.equal(JSON.parse(readFileSync(bundlePath, "utf8")).format, "aidr-intel-pack-bundle-v1");
	const fromBundle = runImport(["--pack", bundlePath, "--trusted-keys", keys, "--target", "local", "--packs-dir", packsDir]);
	assert.equal(fromBundle.status, 0, fromBundle.stderr);
	assert.equal(fromBundle.json.version, "2.1.0");
	assert.equal(readFileSync(join(packsDir, "aidr-offline-intel", "2.1.0", "lists", "url-deny.txt"), "utf8"), "# offline test list\nhttps://exfil.offline-pack.test/upload\n");

	const tamperedBundle = JSON.parse(readFileSync(bundlePath, "utf8"));
	tamperedBundle.files[0].content_b64 = Buffer.from("https://attacker.test\n").toString("base64");
	const tamperedPath = join(root, "tampered.aidrpack.json");
	writeFileSync(tamperedPath, JSON.stringify(tamperedBundle));
	const tampered = runImport(["--pack", tamperedPath, "--trusted-keys", keys, "--target", "local", "--packs-dir", join(root, "other-packs")]);
	assert.notEqual(tampered.status, 0);
	assert.match(tampered.stderr, /SHA-256 mismatch/);
});

async function storageServer(t, state) {
	const server = createServer(async (request, response) => {
		const url = new URL(request.url, "http://127.0.0.1");
		const chunks = [];
		for await (const chunk of request) chunks.push(chunk);
		const body = Buffer.concat(chunks);
		state.calls.push({ method: request.method, path: url.pathname, search: url.search, auth: request.headers.authorization, upsert: request.headers["x-upsert"] });
		const reply = (status, value) => {
			response.writeHead(status, { "content-type": "application/json" });
			response.end(value === undefined ? "" : typeof value === "string" ? value : JSON.stringify(value));
		};
		if (url.pathname.startsWith("/storage/v1/object/aidr-packs/") && request.method === "POST") {
			const key = url.pathname.slice("/storage/v1/object/aidr-packs/".length);
			if (state.objects.has(key)) return reply(409, { error: "Duplicate" });
			state.objects.set(key, body);
			return reply(200, { Key: `aidr-packs/${key}` });
		}
		if (url.pathname.startsWith("/storage/v1/object/authenticated/aidr-packs/")) {
			const object = state.objects.get(url.pathname.slice("/storage/v1/object/authenticated/aidr-packs/".length));
			if (!object) return reply(404, { error: "not_found" });
			response.writeHead(200, { "content-type": "application/json" });
			return response.end(object);
		}
		if (url.pathname === "/rest/v1/pack_versions" && request.method === "GET") {
			const packId = url.searchParams.get("pack_id").replace("eq.", "");
			return reply(200, state.rows.filter((row) => row.pack_id === packId));
		}
		if (url.pathname === "/rest/v1/pack_versions" && request.method === "POST") {
			if (state.failRegistration) return reply(503, { error: "unavailable" });
			state.rows.push(JSON.parse(body.toString("utf8")));
			return reply(201);
		}
		return reply(404, {});
	});
	await new Promise((done) => server.listen(0, "127.0.0.1", done));
	t.after(() => new Promise((done) => server.close(done)));
	return server.address().port;
}

function deployment(root, port) {
	const directory = join(root, "deployment");
	mkdirSync(directory);
	writeFileSync(join(directory, "deployment.json"), JSON.stringify({ mode: "self-hosted", supabase_url: `http://127.0.0.1:${port}`, development: true }));
	writeFileSync(join(directory, ".env"), "SERVICE_ROLE_KEY=test-service-role\nANON_KEY=test-anon\n", { mode: 0o600 });
	return directory;
}

/** Async child run: the in-process fake deployment must keep serving while the CLI runs. */
function runAsync(args) {
	return new Promise((done) => {
		const child = spawn(process.execPath, [importScript, ...args], { stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		child.stdout.setEncoding("utf8").on("data", (chunk) => {
			stdout += chunk;
		});
		child.stderr.setEncoding("utf8").on("data", (chunk) => {
			stderr += chunk;
		});
		child.on("close", (status) => done({ status, stdout, stderr }));
	});
}

test("storage target uploads the verified bundle to the private bucket and registers it, resumably", async (t) => {
	const root = workdir(t);
	const keys = trustedKeys(root);
	const state = { calls: [], objects: new Map(), rows: [], failRegistration: true };
	const port = await storageServer(t, state);
	const deploymentDir = deployment(root, port);
	const pack = buildPack(root, { version: "3.0.0" });
	const args = ["--pack", pack, "--trusted-keys", keys, "--target", "storage", "--deployment", deploymentDir, "--tenant-id", TENANT];

	const interrupted = await runAsync([...args]);
	assert.notEqual(interrupted.status, 0);
	assert.match(interrupted.stderr, /registration failed .*re-run the same import/);
	const storagePath = `${TENANT}/aidr-offline-intel/3.0.0.aidrpack.json`;
	assert.ok(state.objects.has(storagePath), "the private object landed below the tenant prefix");

	state.failRegistration = false;
	const resumed = await runAsync([...args]);
	assert.equal(resumed.status, 0, resumed.stderr);
	const summary = JSON.parse(resumed.stdout.trim());
	assert.equal(summary.outcome, "registered");
	assert.equal(summary.storage_path, storagePath);
	assert.equal(state.rows.length, 1);
	const [row] = state.rows;
	assert.equal(row.tenant_id, TENANT);
	assert.equal(row.key_id, "aidr-intel-dev-1");
	assert.equal(row.manifest_sig_b64, readFileSync(join(pack, "manifest.sig"), "utf8").trim());
	assert.equal(row.manifest_json.pack_id, "aidr-offline-intel");
	assert.ok(state.calls.every((call) => call.auth === "Bearer test-service-role"));
	assert.ok(state.calls.filter((call) => call.method === "POST" && call.path.startsWith("/storage/")).every((call) => call.upsert === "false"), "uploads never overwrite");

	// The stored object is itself an importable, verifiable bundle.
	const bundlePath = join(root, "downloaded.aidrpack.json");
	writeFileSync(bundlePath, state.objects.get(storagePath));
	const local = await runAsync(["--pack", bundlePath, "--trusted-keys", keys, "--target", "local", "--packs-dir", join(root, "endpoint-packs")]);
	assert.equal(local.status, 0, local.stderr);

	const repeat = await runAsync([...args]);
	assert.equal(repeat.status, 0, repeat.stderr);
	assert.equal(JSON.parse(repeat.stdout.trim()).outcome, "already_registered");

	const older = await runAsync([...args.map((value) => (value === pack ? buildPack(root, { version: "2.5.0" }) : value))]);
	assert.notEqual(older.status, 0);
	assert.match(older.stderr, /rollback refused/);

	const bad = buildPack(root, { version: "3.1.0", name: "storage-tampered" });
	writeFileSync(join(bad, "lists", "url-deny.txt"), "tampered\n");
	const before = state.calls.length;
	const refused = await runAsync([...args.map((value) => (value === pack ? bad : value))]);
	assert.notEqual(refused.status, 0);
	assert.equal(state.calls.length, before, "a pack that fails verification never reaches the deployment");
});


// ─── license-bound updates (--license) ───────────────────────────────────

const licenseSigner = generateKeyPairSync("ed25519");

/** A DEV aidr-license-v1 for customer_id "example-co", signed per run, plus its registry. */
function licenseFiles(root, { expiresAt = "2026-12-01T00:00:00Z", graceDays = 14 } = {}) {
	const payload = {
		license_id: "LIC-OFFLINE-1",
		customer: "Example Customer AG",
		customer_id: "example-co",
		plan_id: "enterprise",
		seats: 10,
		features: ["premium_intel"],
		deployment: "airgap",
		issued_at: "2026-09-01T00:00:00Z",
		not_before: "2026-09-01T00:00:00Z",
		expires_at: expiresAt,
		grace_days: graceDays,
	};
	const message = Buffer.from(`aidr-license-v1\n${canonicalJson(payload)}`, "utf8");
	const license = { format: "aidr-license-v1", key_id: "aidr-license-dev-1", payload, sig: sign(null, message, licenseSigner.privateKey).toString("base64") };
	const registry = {
		format: "aidr-license-public-keys-v1",
		schema_version: 1,
		keys: [{ key_id: "aidr-license-dev-1", algorithm: "ed25519", public_key_pem: licenseSigner.publicKey.export({ type: "spki", format: "pem" }).toString(), not_before: "2026-01-01T00:00:00Z", not_after: null, status: "active" }],
	};
	const licensePath = join(root, "license.json");
	const registryPath = join(root, "license-public-keys.json");
	writeFileSync(licensePath, JSON.stringify(license));
	writeFileSync(registryPath, JSON.stringify(registry));
	return { licensePath, registryPath, license };
}

test("--license gates new packs on the signed license term and the pack audience", (t) => {
	const root = workdir(t);
	const keys = trustedKeys(root);
	const env = { HOME: join(root, "home") };
	const { licensePath, registryPath } = licenseFiles(root);
	const packsDir = join(root, "packs");
	const local = (pack, extra = []) => runImport(["--pack", pack, "--trusted-keys", keys, "--target", "local", "--packs-dir", packsDir, ...extra], env);
	const licensed = ["--license", licensePath, "--license-public-keys", registryPath];

	// Addressed to this customer and issued inside expires_at + grace_days: installed.
	const ours = buildPack(root, { version: "1.0.0", name: "ours", manifestOverrides: { audience: { customer_ids: ["other-co", "example-co"] } } });
	const noLicense = local(ours);
	assert.notEqual(noLicense.status, 0);
	assert.match(noLicense.stderr, /pack_audience_requires_license/);
	assert.ok(!existsSync(join(packsDir, "aidr-offline-intel")), "a refused pack writes nothing");
	const accepted = local(ours, licensed);
	assert.equal(accepted.status, 0, accepted.stderr);
	assert.equal(accepted.json.outcome, "installed");
	assert.equal(accepted.json.license.customer_id, "example-co");
	assert.equal(accepted.json.license.updates_until, "2026-12-15T00:00:00.000Z");

	// Someone else's pack, and a pack signed after the term ended, are refused.
	const theirs = buildPack(root, { version: "1.1.0", name: "theirs", manifestOverrides: { audience: { customer_ids: ["other-co"] } } });
	assert.match(local(theirs, licensed).stderr, /pack_audience_mismatch/);
	const late = buildPack(root, { version: "1.2.0", name: "late", manifestOverrides: { issued_at: "2026-12-15T00:00:01Z" } });
	const lateResult = local(late, licensed);
	assert.notEqual(lateResult.status, 0);
	assert.match(lateResult.stderr, /license_term_ended/);
	assert.deepEqual(JSON.parse(readFileSync(join(packsDir, "aidr-offline-intel", "active.json"), "utf8")), { version: "1.0.0" }, "the installed pack stays active");

	// A pack issued at the very end of grace is still accepted.
	const lastDay = buildPack(root, { version: "1.3.0", name: "last-day", manifestOverrides: { issued_at: "2026-12-15T00:00:00Z" } });
	assert.equal(local(lastDay, licensed).status, 0);

	// A tampered license or a missing trust root is refused (fail closed).
	const tampered = join(root, "tampered-license.json");
	const document = JSON.parse(readFileSync(licensePath, "utf8"));
	writeFileSync(tampered, JSON.stringify({ ...document, payload: { ...document.payload, expires_at: "2030-01-01T00:00:00Z" } }));
	const forged = local(buildPack(root, { version: "1.4.0", name: "forged" }), ["--license", tampered, "--license-public-keys", registryPath]);
	assert.notEqual(forged.status, 0);
	assert.match(forged.stderr, /is not valid: .*does not verify/);
	const unconfigured = local(buildPack(root, { version: "1.4.0", name: "unconfigured" }), ["--license", licensePath]);
	assert.notEqual(unconfigured.status, 0);
	assert.match(unconfigured.stderr, /no license public keys are configured/);
});

test("the local target applies the endpoint's installed license without --license", (t) => {
	const root = workdir(t);
	const keys = trustedKeys(root);
	const home = join(root, "home");
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
	const { license, registryPath } = licenseFiles(root, { expiresAt: "2026-10-01T00:00:00Z", graceDays: 0 });
	writeFileSync(join(home, ".singularity-aidr", "license.json"), JSON.stringify(license));
	const late = buildPack(root, { version: "2.0.0", name: "late", manifestOverrides: { issued_at: "2026-10-02T00:00:00Z" } });
	const result = runImport(["--pack", late, "--trusted-keys", keys, "--target", "local", "--packs-dir", join(root, "packs"), "--license-public-keys", registryPath], { HOME: home });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /license_term_ended/);
});

test("the storage target is gated by --license before the deployment is contacted", (t) => {
	const root = workdir(t);
	const keys = trustedKeys(root);
	const { licensePath, registryPath } = licenseFiles(root);
	const pack = buildPack(root, { version: "3.0.0", manifestOverrides: { audience: { customer_ids: ["other-co"] } } });
	const base = ["--pack", pack, "--trusted-keys", keys, "--target", "storage", "--deployment", join(root, "no-deployment")];
	const unlicensed = runImport(base, { HOME: join(root, "home") });
	assert.match(unlicensed.stderr, /pack_audience_requires_license/);
	const mismatched = runImport([...base, "--license", licensePath, "--license-public-keys", registryPath], { HOME: join(root, "home") });
	assert.match(mismatched.stderr, /pack_audience_mismatch/);
});
