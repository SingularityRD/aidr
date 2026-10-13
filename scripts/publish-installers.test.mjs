import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

import {
	buildInstallerRelease,
	parseSha256Sums,
	publicKeyB64FromPrivatePem,
	stageInstallerRelease,
	uploadInstallerRelease,
	verifyEnvelope,
} from "./publish-installers.mjs";
import {
	createReleaseManifest,
	loadReleaseBundle,
	RELEASE_MANIFEST_NAME,
	RELEASE_SIGNATURE_NAME,
	signReleaseManifest,
} from "./release-signing-lib.mjs";

const temporary = [];
afterEach(async () => {
	await Promise.all(temporary.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

function keyPair() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return {
		privateKey,
		privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		publicKey,
		publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
		fingerprint: `sha256:${digest(publicKey.export({ type: "spki", format: "der" }))}`,
	};
}

const INSTALLERS = {
	"installers/windows-x64/AIDR-Setup-1.4.0-x64.msi": "windows installer bytes\n",
	"installers/linux-x64/aidr-install-1.4.0-linux-x64.sh": "#!/bin/sh\necho linux installer\n",
	"installers/linux-arm64/aidr-install-1.4.0-linux-arm64.sh": "#!/bin/sh\necho linux arm installer\n",
};

/** A promoted release bundle signed exactly as scripts/release-sign.mjs does. */
async function signedBundle({ sums, extraArtifacts = {}, sequence = 7, mutate } = {}) {
	const root = await mkdtemp(path.join(os.tmpdir(), "aidr-publish-installers-"));
	temporary.push(root);
	const bundleDir = path.join(root, "release-output");
	const artifacts = { "agent.tgz": "connector package\n", ...INSTALLERS, ...extraArtifacts };
	const sumsText =
		sums ??
		Object.entries(INSTALLERS)
			.map(([name, body]) => `${digest(Buffer.from(body))}  ${path.posix.basename(name)}\n`)
			.join("");
	artifacts.SHA256SUMS = sumsText;
	const entries = [];
	for (const [name, body] of Object.entries(artifacts).sort(([a], [b]) => (a < b ? -1 : 1))) {
		const target = path.join(bundleDir, ...name.split("/"));
		await mkdir(path.dirname(target), { recursive: true });
		const bytes = Buffer.from(body);
		await writeFile(target, bytes);
		entries.push({ path: name, size: bytes.byteLength, sha256: digest(bytes) });
	}
	await writeFile(
		path.join(bundleDir, "release-metadata.json"),
		`${JSON.stringify({ schema_version: 1, release_tag: "v1.4.0", release_version: "1.4.0", git_sha: "a".repeat(40), source_date_epoch: 1_789_167_600, worktree_dirty: false, artifacts: entries }, null, 2)}\n`,
	);
	await writeFile(
		path.join(bundleDir, "release-inventory.json"),
		`${JSON.stringify({ schema_version: 1, artifacts: entries.map((entry) => ({ source_path: `release-output/${entry.path}`, staged_path: entry.path, kind: "release-artifact", sha256: entry.sha256 })) }, null, 2)}\n`,
	);
	const releaseKey = keyPair();
	const bundle = await loadReleaseBundle(bundleDir);
	const manifest = createReleaseManifest(bundle, {
		productId: "singularity-aidr",
		channel: "stable",
		keyId: "release-key-1",
		releaseSequence: sequence,
		issuedAt: new Date(Date.now() - 1000).toISOString(),
		expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
		fingerprint: releaseKey.fingerprint,
	});
	const manifestRaw = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
	await writeFile(path.join(bundleDir, RELEASE_MANIFEST_NAME), manifestRaw);
	await writeFile(
		path.join(bundleDir, RELEASE_SIGNATURE_NAME),
		`${JSON.stringify(signReleaseManifest(manifestRaw, releaseKey.privateKey, "release-key-1"), null, 2)}\n`,
	);
	const policy = path.join(root, "signer-policy.json");
	const signer = {
		key_id: "release-key-1",
		public_key_pem: releaseKey.publicKeyPem,
		fingerprint_sha256: releaseKey.fingerprint,
		valid_from: new Date(Date.now() - 86_400_000).toISOString(),
		valid_until: new Date(Date.now() + 86_400_000).toISOString(),
	};
	await writeFile(
		policy,
		JSON.stringify({ schema_version: 1, policy_id: "promotion-policy", product_id: "singularity-aidr", allowed_channels: ["stable"], minimum_release_sequence: 1, maximum_signature_lifetime_seconds: 7200, trusted_signers: [signer], revoked_key_ids: [], revoked_fingerprints: [] }),
	);
	const catalogKey = keyPair();
	const signingKey = path.join(root, "catalog-key.pem");
	await writeFile(signingKey, catalogKey.privateKeyPem, { mode: 0o600 });
	if (mutate) await mutate(bundleDir);
	return { root, bundle: bundleDir, policy, signingKey, catalogKey };
}

test("verifies the signed release and builds a signed per-version catalog and latest pointer", async () => {
	const fixture = await signedBundle();
	const release = await buildInstallerRelease({
		bundle: fixture.bundle,
		policy: fixture.policy,
		signingKey: fixture.signingKey,
		keyId: "installer-catalog-1",
		releaseNotesUrl: "https://docs.example.com/aidr/releases/1.4.0",
		minOs: ["windows-x64=Windows 11"],
	});
	assert.equal(release.version, "1.4.0");
	assert.equal(release.signed, true);
	const paths = release.objects.map((object) => object.path);
	assert.deepEqual(paths, [
		"1.4.0/windows-x64/AIDR-Setup-1.4.0-x64.msi",
		"1.4.0/linux-x64/aidr-install-1.4.0-linux-x64.sh",
		"1.4.0/linux-arm64/aidr-install-1.4.0-linux-arm64.sh",
		"1.4.0/SHA256SUMS",
		"1.4.0/release/aidr-release.manifest.json",
		"1.4.0/release/aidr-release.manifest.sig",
		"1.4.0/manifest.json",
		"1.4.0/manifest.json.sig",
		"latest.json",
		"latest.json.sig",
	]);
	const byPath = new Map(release.objects.map((object) => [object.path, object]));
	const catalogRaw = byPath.get("1.4.0/manifest.json").bytes;
	const catalog = JSON.parse(catalogRaw.toString("utf8"));
	assert.equal(catalog.type, "aidr-installer-catalog");
	assert.equal(catalog.release_notes_url, "https://docs.example.com/aidr/releases/1.4.0");
	assert.equal(catalog.release.release_sequence, 7);
	assert.equal(catalog.files[0].minimum_os, "Windows 11");
	assert.equal(catalog.files[1].minimum_os, "glibc 2.28 (e.g. Ubuntu 20.04, RHEL 8)");
	assert.deepEqual(
		catalog.files.map((file) => [file.platform, file.format, file.sha256]),
		Object.entries(INSTALLERS).map(([name, body]) => [name.split("/")[1], path.extname(name).slice(1), digest(Buffer.from(body))]),
	);
	assert.equal(
		catalog.release.manifest_sha256,
		digest(await readFile(path.join(fixture.bundle, RELEASE_MANIFEST_NAME))),
	);

	// Both signatures verify with the catalog public key the Edge Function holds.
	const publicKey = createPublicKey({ key: Buffer.from(publicKeyB64FromPrivatePem(fixture.catalogKey.privateKeyPem), "base64"), format: "der", type: "spki" });
	const catalogSig = JSON.parse(byPath.get("1.4.0/manifest.json.sig").bytes.toString("utf8"));
	assert.equal(catalogSig.key_id, "installer-catalog-1");
	assert.ok(verifyEnvelope(catalogRaw, catalogSig, publicKey));
	const latestRaw = byPath.get("latest.json").bytes;
	assert.ok(verifyEnvelope(latestRaw, JSON.parse(byPath.get("latest.json.sig").bytes.toString("utf8")), publicKey));
	const latest = JSON.parse(latestRaw.toString("utf8"));
	assert.equal(latest.manifest_sha256, digest(catalogRaw));
	assert.equal(latest.manifest_path, "1.4.0/manifest.json");
	// A tampered catalog no longer verifies.
	assert.equal(verifyEnvelope(Buffer.concat([catalogRaw, Buffer.from(" ")]), catalogSig, publicKey), false);

	assert.equal(
		byPath.get("1.4.0/SHA256SUMS").bytes.toString("utf8"),
		catalog.files.map((file) => `${file.sha256}  ${file.platform}/${file.file}\n`).join(""),
	);
});

test("dry-run without a signing key stages an unsigned plan and writes no signatures", async () => {
	const fixture = await signedBundle();
	const release = await buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, dryRun: true });
	assert.equal(release.signed, false);
	assert.ok(!release.objects.some((object) => object.path.endsWith(".sig") && !object.path.includes("/release/")));
	const out = path.join(fixture.root, "staged");
	await stageInstallerRelease(release, out);
	assert.deepEqual((await readdir(out)).sort(), ["1.4.0", "latest.json"]);
	await assert.rejects(uploadInstallerRelease(release, { SUPABASE_URL: "https://x.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "k" }, () => {
		throw new Error("network must not be reached");
	}), /unsigned/);
});

test("a publish without the catalog signing key fails before anything else", async () => {
	const fixture = await signedBundle();
	await assert.rejects(buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy }), /signing key is required/);
	await assert.rejects(
		buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, signingKey: fixture.signingKey }),
		/key id is missing/,
	);
});

test("refuses an installer whose bytes changed after the release was signed", async () => {
	const fixture = await signedBundle({
		mutate: (bundle) => writeFile(path.join(bundle, "installers", "windows-x64", "AIDR-Setup-1.4.0-x64.msi"), "swapped\n"),
	});
	await assert.rejects(
		buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, dryRun: true }),
		/digest mismatch|size mismatch/,
	);
});

test("refuses a release signed by a key the policy does not trust", async () => {
	const fixture = await signedBundle();
	const policy = JSON.parse(await readFile(fixture.policy, "utf8"));
	const other = keyPair();
	policy.trusted_signers[0].public_key_pem = other.publicKeyPem;
	policy.trusted_signers[0].fingerprint_sha256 = other.fingerprint;
	await writeFile(fixture.policy, JSON.stringify(policy));
	await assert.rejects(
		buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, dryRun: true }),
		/fingerprint does not match|does not verify/,
	);
});

test("SHA256SUMS must list every installer with the signed digest", async () => {
	const wrong = await signedBundle({
		sums: Object.entries(INSTALLERS)
			.map(([name], index) => `${index === 0 ? "f".repeat(64) : digest(Buffer.from(INSTALLERS[name]))}  ${path.posix.basename(name)}\n`)
			.join(""),
	});
	await assert.rejects(
		buildInstallerRelease({ bundle: wrong.bundle, policy: wrong.policy, dryRun: true }),
		/does not match the signed release manifest/,
	);
	const missing = await signedBundle({ sums: `${digest(Buffer.from("x"))}  something-else.zip\n` });
	await assert.rejects(
		buildInstallerRelease({ bundle: missing.bundle, policy: missing.policy, dryRun: true }),
		/SHA256SUMS has no entry/,
	);
	assert.throws(() => parseSha256Sums("not a checksum line\n"), /malformed/);
});

test("an explicit --installer must name a signed artifact", async () => {
	const fixture = await signedBundle();
	await assert.rejects(
		buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, dryRun: true, installers: ["windows-x64=installers/windows-x64/unsigned.msi"] }),
		/not an artifact of the signed release manifest/,
	);
	await assert.rejects(
		buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, dryRun: true, installers: ["solaris-sparc=agent.tgz"] }),
		/unknown platform/,
	);
	// Benign twin: a signed non-conventional path is accepted when named explicitly.
	const release = await buildInstallerRelease({
		bundle: fixture.bundle,
		policy: fixture.policy,
		dryRun: true,
		installers: ["linux-arm64=installers/linux-arm64/aidr-install-1.4.0-linux-arm64.sh"],
	});
	assert.deepEqual(release.catalog.files.map((file) => file.platform), ["linux-arm64"]);
});

function fakeStorage({ existing = {}, failPath } = {}) {
	const objects = new Map(Object.entries(existing).map(([key, value]) => [key, Buffer.from(value)]));
	const calls = [];
	const fetchImpl = async (url, init) => {
		const parsed = new URL(url);
		assert.equal(init.headers.Authorization, "Bearer service-role");
		const match = /^\/storage\/v1\/object\/(authenticated\/)?aidr-installers\/(.+)$/.exec(parsed.pathname);
		assert.ok(match, parsed.pathname);
		const key = match[2].split("/").map(decodeURIComponent).join("/");
		calls.push({ method: init.method, key, upsert: init.headers["x-upsert"] });
		if (init.method === "GET") {
			return objects.has(key) ? new Response(objects.get(key)) : new Response('{"error":"not_found"}', { status: 404 });
		}
		if (key === failPath) return new Response("boom", { status: 500 });
		if (objects.has(key) && init.headers["x-upsert"] !== "true") {
			return new Response('{"statusCode":"409","error":"Duplicate"}', { status: 400 });
		}
		objects.set(key, Buffer.from(init.body));
		return new Response("{}", { status: 200 });
	};
	return { objects, calls, fetchImpl };
}

const ENV = { SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "service-role" };

test("uploads immutable versioned objects first and moves latest.json last", async () => {
	const fixture = await signedBundle();
	const release = await buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, signingKey: fixture.signingKey, keyId: "installer-catalog-1" });
	const storage = fakeStorage();
	const result = await uploadInstallerRelease(release, ENV, storage.fetchImpl);
	assert.equal(result.bucket, "aidr-installers");
	const puts = storage.calls.filter((call) => call.method === "POST");
	assert.deepEqual(puts.map((call) => call.key), release.objects.map((object) => object.path));
	assert.ok(puts.filter((call) => !call.key.startsWith("latest.json")).every((call) => call.upsert === "false"));
	assert.deepEqual(puts.slice(-2).map((call) => [call.key, call.upsert]), [["latest.json", "true"], ["latest.json.sig", "true"]]);

	// Re-running the same publication is idempotent: identical objects are left alone.
	const again = await uploadInstallerRelease(release, ENV, storage.fetchImpl);
	assert.ok(again.results.filter((entry) => !entry.path.startsWith("latest")).every((entry) => entry.result === "unchanged"));
});

test("never replaces a published object with different bytes", async () => {
	const fixture = await signedBundle();
	const release = await buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, signingKey: fixture.signingKey, keyId: "installer-catalog-1" });
	const storage = fakeStorage({ existing: { "1.4.0/windows-x64/AIDR-Setup-1.4.0-x64.msi": "older different bytes" } });
	await assert.rejects(uploadInstallerRelease(release, ENV, storage.fetchImpl), /immutable/);
	assert.ok(!storage.objects.has("latest.json"), "latest.json must not move after a failed upload");
});

test("refuses to move latest.json back to a lower release sequence", async () => {
	const fixture = await signedBundle({ sequence: 7 });
	const release = await buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, signingKey: fixture.signingKey, keyId: "installer-catalog-1" });
	const storage = fakeStorage({ existing: { "latest.json": JSON.stringify({ version: "1.5.0", release_sequence: 9 }) } });
	await assert.rejects(uploadInstallerRelease(release, ENV, storage.fetchImpl), /refusing to move it back/);
	assert.equal(storage.calls.filter((call) => call.method === "POST").length, 0);
	await uploadInstallerRelease(release, ENV, storage.fetchImpl, { allowDowngrade: true });
	assert.equal(JSON.parse(storage.objects.get("latest.json").toString()).version, "1.4.0");
});

test("upload configuration fails closed", async () => {
	const fixture = await signedBundle();
	const release = await buildInstallerRelease({ bundle: fixture.bundle, policy: fixture.policy, signingKey: fixture.signingKey, keyId: "installer-catalog-1" });
	const never = () => {
		throw new Error("network must not be reached");
	};
	await assert.rejects(uploadInstallerRelease(release, {}, never), /SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY/);
	await assert.rejects(
		uploadInstallerRelease(release, { ...ENV, SUPABASE_URL: "http://supabase.internal" }, never),
		/must be https/,
	);
	await assert.rejects(
		uploadInstallerRelease(release, { ...ENV, AIDR_INSTALLERS_BUCKET: "../other" }, never),
		/not a valid bucket name/,
	);
	const storage = fakeStorage({ failPath: "1.4.0/SHA256SUMS" });
	await assert.rejects(uploadInstallerRelease(release, ENV, storage.fetchImpl), /HTTP 500/);
	assert.ok(!storage.objects.has("latest.json"));
});

test("the CLI dry-run verifies, stages and reports without touching the network", async () => {
	const fixture = await signedBundle();
	const out = path.join(fixture.root, "cli-out");
	const script = path.join(import.meta.dirname, "publish-installers.mjs");
	const env = { PATH: process.env.PATH ?? "", SUPABASE_URL: "", SUPABASE_SERVICE_ROLE_KEY: "" };
	const run = (args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8", env });
	const dry = run(["--bundle", fixture.bundle, "--policy", fixture.policy, "--signing-key", fixture.signingKey, "--key-id", "installer-catalog-1", "--dry-run", "--out", out]);
	assert.equal(dry.status, 0, dry.stderr);
	const report = JSON.parse(dry.stdout);
	assert.equal(report.status, "dry-run");
	assert.equal(report.signed, true);
	assert.equal(report.files.length, 3);
	assert.ok((await readdir(path.join(out, "1.4.0"))).includes("manifest.json.sig"));
	const publish = run(["--bundle", fixture.bundle, "--policy", fixture.policy]);
	assert.equal(publish.status, 1);
	assert.match(publish.stderr, /signing key is required/);
	const unknown = run(["--bundle", fixture.bundle, "--bogus"]);
	assert.equal(unknown.status, 1);
	assert.match(unknown.stderr, /unknown option/);
});
