// Tests for scripts/onprem-offline-bundle.mjs (node --test). Docker is replaced
// by a fake `docker` executable; intel packs are signed with the real
// sign-intel-pack-manifest.mjs and verified by the built core verifier.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { buildBundle, importBundle, MANIFEST_NAME, SIGNATURE_NAME, SUMS_NAME, verifyBundle } from "./onprem-offline-bundle.mjs";
import { signReleaseManifest } from "./release-signing-lib.mjs";

const script = fileURLToPath(new URL("./onprem-offline-bundle.mjs", import.meta.url));
const signScript = fileURLToPath(new URL("./sign-intel-pack-manifest.mjs", import.meta.url));
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const operator = generateKeyPairSync("ed25519");
const stranger = generateKeyPairSync("ed25519");
const intelPublisher = generateKeyPairSync("ed25519");
const catalogKey = generateKeyPairSync("ed25519");
const pem = (key, type) => key.export({ type, format: "pem" }).toString();

function workdir(t) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-offline-bundle-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	return directory;
}

function fixtures(root) {
	const secrets = join(root, "secrets");
	mkdirSync(secrets);
	const signingKey = join(secrets, "operator.pem");
	writeFileSync(signingKey, pem(operator.privateKey, "pkcs8"), { mode: 0o600 });
	const publicKey = join(secrets, "operator.pub.pem");
	writeFileSync(publicKey, pem(operator.publicKey, "spki"));
	const strangerKey = join(secrets, "stranger.pub.pem");
	writeFileSync(strangerKey, pem(stranger.publicKey, "spki"));
	const catalogPublicKey = catalogKey.publicKey.export({ type: "spki", format: "der" }).toString("base64");

	// Image bundle in the build-airgap-images.mjs layout.
	const images = join(root, "airgap-images");
	mkdirSync(join(images, "tarballs"), { recursive: true });
	const tarball = Buffer.from("fake docker save output\n");
	writeFileSync(join(images, "tarballs", "aidr-dashboard-0.6.1.tar"), tarball);
	writeFileSync(join(images, "aidr-airgap-images.manifest.json"), JSON.stringify({
		schema_version: 1, kind: "aidr-airgap-image-bundle", image_source: "docker save", platform: "linux/amd64", created_at: "2026-10-13T00:00:00Z",
		images: [{ ref: "aidr-dashboard:0.6.1", tarball: "tarballs/aidr-dashboard-0.6.1.tar", sha256: sha256(tarball), size: tarball.length, image_id: `sha256:${"a".repeat(64)}`, repo_digest: null, source: "local-build", role: "service" }],
	}, null, 2));

	// Signed intel pack (vendor layout).
	const pack = join(root, "intel-pack");
	mkdirSync(join(pack, "lists"), { recursive: true });
	const list = "# offline bundle test\nhttps://exfil.offline-bundle.test/upload\n";
	writeFileSync(join(pack, "lists", "url-deny.txt"), list);
	writeFileSync(join(pack, "manifest.json"), `${JSON.stringify({ pack_id: "aidr-offline-intel", version: "2.0.0", issued_at: "2026-10-01T00:00:00Z", expires_at: "2099-01-01T00:00:00Z", key_id: "aidr-intel-dev-1", files: [{ kind: "url_denylist", path: "lists/url-deny.txt", sha256: sha256(list) }] }, null, 2)}\n`);
	const packKey = join(secrets, "intel.pem");
	writeFileSync(packKey, pem(intelPublisher.privateKey, "pkcs8"), { mode: 0o600 });
	const signed = spawnSync(process.execPath, [signScript, "--manifest", join(pack, "manifest.json"), "--private-key", packKey], { encoding: "utf8" });
	assert.equal(signed.status, 0, signed.stderr);
	const trustedKeys = join(secrets, "trusted-keys.json");
	writeFileSync(trustedKeys, JSON.stringify({ "aidr-intel-dev-1": pem(intelPublisher.publicKey, "spki") }));

	// Staged installer catalog in the publish-installers.mjs layout.
	const installers = join(root, "installers");
	const version = "0.6.1";
	const msi = Buffer.from("fake msi\n");
	const deb = Buffer.from("fake deb\n");
	mkdirSync(join(installers, version, "windows-x64"), { recursive: true });
	mkdirSync(join(installers, version, "linux-x64"), { recursive: true });
	mkdirSync(join(installers, version, "release"), { recursive: true });
	writeFileSync(join(installers, version, "windows-x64", "aidr-0.6.1-x64.msi"), msi);
	writeFileSync(join(installers, version, "linux-x64", "aidr_0.6.1_amd64.deb"), deb);
	writeFileSync(join(installers, version, "release", "aidr-release.manifest.json"), "{}\n");
	writeFileSync(join(installers, version, "release", "aidr-release.manifest.sig"), "{}\n");
	const files = [
		{ platform: "windows-x64", file: "aidr-0.6.1-x64.msi", path: `${version}/windows-x64/aidr-0.6.1-x64.msi`, size: msi.length, sha256: sha256(msi) },
		{ platform: "linux-x64", file: "aidr_0.6.1_amd64.deb", path: `${version}/linux-x64/aidr_0.6.1_amd64.deb`, size: deb.length, sha256: sha256(deb) },
	];
	writeFileSync(join(installers, version, "SHA256SUMS"), files.map((file) => `${file.sha256}  ${file.platform}/${file.file}\n`).join(""));
	const catalogRaw = Buffer.from(`${JSON.stringify({ schema_version: 1, type: "aidr-installer-catalog", version, release: { manifest_path: `${version}/release/aidr-release.manifest.json` }, files }, null, 2)}\n`);
	writeFileSync(join(installers, version, "manifest.json"), catalogRaw);
	writeFileSync(join(installers, version, "manifest.json.sig"), JSON.stringify(signReleaseManifest(catalogRaw, catalogKey.privateKey, "installer-catalog-1")));
	const latestRaw = Buffer.from(`${JSON.stringify({ schema_version: 1, type: "aidr-installer-latest", version, manifest_path: `${version}/manifest.json`, manifest_sha256: sha256(catalogRaw) }, null, 2)}\n`);
	writeFileSync(join(installers, "latest.json"), latestRaw);
	writeFileSync(join(installers, "latest.json.sig"), JSON.stringify(signReleaseManifest(latestRaw, catalogKey.privateKey, "installer-catalog-1")));

	// Browser Guard feed: a CRX3 package, a Mozilla-signed XPI and update manifests.
	const feed = join(root, "browser-guard-feed");
	mkdirSync(feed);
	const header = Buffer.from("signed-header-protobuf");
	const crx = Buffer.alloc(12);
	crx.write("Cr24", 0, "latin1");
	crx.writeUInt32LE(3, 4);
	crx.writeUInt32LE(header.length, 8);
	writeFileSync(join(feed, "aidr-browser-guard-1.2.0.crx"), Buffer.concat([crx, header, Buffer.from("PK\u0003\u0004zip")]));
	const xpi = Buffer.alloc(4);
	xpi.writeUInt32LE(0x04034b50, 0);
	writeFileSync(join(feed, "aidr-browser-guard-1.2.0.xpi"), Buffer.concat([xpi, Buffer.from("...META-INF/cose.sig...")]));
	writeFileSync(join(feed, "update.xml"), "<gupdate/>\n");

	return { secrets, signingKey, publicKey, strangerKey, catalogPublicKey, images, pack, trustedKeys, installers, feed };
}

function buildOptions(f, output, overrides = {}) {
	return {
		output, signingKey: f.signingKey, keyId: "operator-2026", images: f.images, intelPacks: [f.pack], intelTrustedKeys: f.trustedKeys,
		installers: f.installers, installerCatalogPublicKey: f.catalogPublicKey, browserGuardFeed: f.feed, ...overrides,
	};
}

const verifyOptions = (f, bundle, overrides = {}) => ({ bundle, publicKey: f.publicKey, intelTrustedKeys: f.trustedKeys, installerCatalogPublicKey: f.catalogPublicKey, ...overrides });

test("builds one signed bundle with a manifest and SHA256SUMS covering every component", async (t) => {
	const root = workdir(t);
	const f = fixtures(root);
	const output = join(root, "aidr-offline-0.6.1");
	const result = await buildBundle(buildOptions(f, output));
	assert.deepEqual(Object.keys(result.components).sort(), ["browser_guard", "images", "installers", "intel_packs"]);
	assert.deepEqual(readdirSync(output).sort(), [MANIFEST_NAME, SIGNATURE_NAME, SUMS_NAME, "browser-guard", "images", "installers", "intel-packs"].sort());
	const manifest = JSON.parse(readFileSync(join(output, MANIFEST_NAME), "utf8"));
	assert.equal(manifest.kind, "aidr-offline-bundle");
	assert.equal(manifest.components.images.count, 1);
	assert.equal(manifest.components.intel_packs[0].file, "intel-packs/aidr-offline-intel-2.0.0.json");
	assert.equal(manifest.components.installers.version, "0.6.1");
	assert.deepEqual(manifest.components.browser_guard.packages, ["aidr-browser-guard-1.2.0.crx", "aidr-browser-guard-1.2.0.xpi"]);
	const sums = readFileSync(join(output, SUMS_NAME), "utf8");
	for (const entry of manifest.files) assert.ok(sums.includes(`${entry.sha256}  ${entry.path}\n`), entry.path);
	assert.ok(sums.includes(`  ${MANIFEST_NAME}\n`) && sums.includes(`  ${SIGNATURE_NAME}\n`));
	assert.deepEqual(readdirSync(root).filter((name) => name.includes("staging")), [], "no staging residue");

	const verified = await verifyBundle(verifyOptions(f, output));
	verified.cleanup();
	assert.deepEqual(verified.checks.map(([name]) => name), ["images", "intel packs", "installers", "browser guard"]);
});

test("build fails closed on a missing key or signature and leaves nothing behind", async (t) => {
	const root = workdir(t);
	const f = fixtures(root);
	const attempt = async (name, overrides, pattern) => {
		const output = join(root, name);
		await assert.rejects(buildBundle(buildOptions(f, output, overrides)), pattern);
		assert.equal(existsSync(output), false, `${name}: no bundle written`);
	};
	await attempt("no-key", { signingKey: undefined }, /never written unsigned/);
	await attempt("no-intel-keys", { intelTrustedKeys: null }, /--intel-trusted-keys is required/);
	await attempt("no-catalog-key", { installerCatalogPublicKey: undefined }, /--installer-catalog-public-key is required/);
	await attempt("wrong-catalog-key", { installerCatalogPublicKey: f.strangerKey }, /signature does not verify/);
	await attempt("nothing", { images: undefined, intelPacks: [], installers: undefined, browserGuardFeed: undefined }, /nothing to bundle/);

	const otherTrust = join(f.secrets, "other-trust.json");
	writeFileSync(otherTrust, JSON.stringify({ "aidr-intel-dev-1": pem(stranger.publicKey, "spki") }));
	await attempt("untrusted-pack", { intelTrustedKeys: otherTrust }, /signature does not verify/);

	rmSync(join(f.installers, "0.6.1", "manifest.json.sig"));
	await attempt("unsigned-catalog", {}, /the catalog is unsigned/);
	writeFileSync(join(f.installers, "0.6.1", "manifest.json.sig"), "{}");

	writeFileSync(join(f.feed, "unsigned.xpi"), "PK\u0003\u0004 no signature");
	await attempt("unsigned-xpi", { installers: undefined }, /unsigned\.xpi carries no signature/);
	rmSync(join(f.feed, "unsigned.xpi"));

	mkdirSync(join(root, "exists"));
	await assert.rejects(buildBundle(buildOptions(f, join(root, "exists"))), /already exists/);
	assert.deepEqual(readdirSync(root).filter((name) => name.includes("staging")), []);
});

test("verify refuses a changed, extra or unsigned file and the wrong key", async (t) => {
	const root = workdir(t);
	const f = fixtures(root);
	const output = join(root, "bundle");
	await buildBundle(buildOptions(f, output, { intelPacks: [], intelTrustedKeys: null }));
	await assert.rejects(verifyBundle(verifyOptions(f, output, { publicKey: f.strangerKey })), /does not verify with --public-key/);
	await assert.rejects(verifyBundle(verifyOptions(f, output, { publicKey: undefined })), /--public-key is required/);
	await assert.rejects(verifyBundle(verifyOptions(f, output, { installerCatalogPublicKey: undefined })), /--installer-catalog-public-key is required/);

	writeFileSync(join(output, "extra.txt"), "x");
	await assert.rejects(verifyBundle(verifyOptions(f, output)), /SHA256SUMS does not match extra\.txt/);
	rmSync(join(output, "extra.txt"));

	const msi = join(output, "installers", "0.6.1", "windows-x64", "aidr-0.6.1-x64.msi");
	const original = readFileSync(msi);
	writeFileSync(msi, "tampered\n");
	await assert.rejects(verifyBundle(verifyOptions(f, output)), /SHA256SUMS does not match installers\/0\.6\.1\/windows-x64/);
	writeFileSync(msi, original);

	rmSync(join(output, SIGNATURE_NAME));
	await assert.rejects(verifyBundle(verifyOptions(f, output)), /the bundle is unsigned/);
});

test("import loads images, installs intel packs and copies installers and the feed only after every check", async (t) => {
	const root = workdir(t);
	const f = fixtures(root);
	const output = join(root, "bundle");
	await buildBundle(buildOptions(f, output, { tar: true }));
	assert.ok(existsSync(`${output}.tar`));

	const dockerLog = join(root, "docker.log");
	const docker = join(root, "fake-docker");
	writeFileSync(docker, `#!/bin/sh\necho "$@" >> '${dockerLog}'\n`);
	chmodSync(docker, 0o755);
	const lines = [];
	const packsDir = join(root, "intel", "packs");
	await importBundle({
		...verifyOptions(f, `${output}.tar`), lang: "en", loadImages: true, dockerBin: docker,
		intelTarget: "local", packsDir, installersOut: join(root, "portal"), browserGuardOut: join(root, "feed-out"),
	}, { out: (line) => lines.push(line) });
	assert.match(readFileSync(dockerLog, "utf8"), /^load -i .*aidr-dashboard-0\.6\.1\.tar$/m);
	assert.deepEqual(JSON.parse(readFileSync(join(packsDir, "aidr-offline-intel", "active.json"), "utf8")), { version: "2.0.0" });
	assert.ok(existsSync(join(root, "portal", "latest.json.sig")));
	assert.ok(existsSync(join(root, "feed-out", "aidr-browser-guard-1.2.0.crx")));
	assert.match(lines.at(-1), /verified and imported/);
	assert.deepEqual(readdirSync(root).filter((name) => name.startsWith(".aidr-offline-import-")), [], "extracted archive removed");

	// A tampered transfer is refused before anything is loaded.
	writeFileSync(join(output, "images", "tarballs", "aidr-dashboard-0.6.1.tar"), "swapped\n");
	writeFileSync(dockerLog, "");
	await assert.rejects(importBundle({ ...verifyOptions(f, output), loadImages: true, dockerBin: docker }, { out: () => {} }), /SHA256SUMS does not match images/);
	assert.equal(readFileSync(dockerLog, "utf8"), "");
});

test("the CLI refuses a transfer archive with links and reports in Turkish", (t) => {
	const root = workdir(t);
	const f = fixtures(root);
	const evil = join(root, "evil");
	mkdirSync(evil);
	writeFileSync(join(evil, "a.txt"), "a");
	symlinkSync("/etc/passwd", join(evil, "link"));
	const archived = spawnSync("tar", ["-cf", "evil.tar", "evil"], { cwd: root });
	assert.equal(archived.status, 0);
	const result = spawnSync(process.execPath, [script, "verify", "--bundle", join(root, "evil.tar"), "--public-key", f.publicKey, "--lang", "tr"], { encoding: "utf8" });
	assert.equal(result.status, 1);
	assert.match(result.stderr, /Reddedildi: çevrim dışı paket eksik ya da doğru imzalanmamış/);
	assert.match(result.stderr, /link or special file/);

	const unsignedBuild = spawnSync(process.execPath, [script, "build", "--output", join(root, "out"), "--images", f.images], { encoding: "utf8", env: { ...process.env, AIDR_LANG: "en" } });
	assert.equal(unsignedBuild.status, 1);
	assert.match(unsignedBuild.stderr, /Refused: the offline bundle was not written/);
	assert.match(unsignedBuild.stderr, /never written unsigned/);
});

test("verify/import --compose: the image set must be exactly what the stack prepared on this host needs", async (t) => {
	const root = workdir(t);
	const f = fixtures(root);
	const output = join(root, "vendor-bundle");
	// The vendor bundle: images only (release-images.yml, job airgap-bundle).
	await buildBundle({ output, signingKey: f.signingKey, keyId: "aidr-offline-1", images: f.images, intelPacks: [], tar: true });
	const compose = (services) => {
		const path = join(root, `compose-${Object.keys(services).join("-")}.yml`);
		writeFileSync(path, `services:\n${Object.entries(services).map(([name, image]) => `  ${name}:\n    image: ${image}\n`).join("")}`);
		return path;
	};
	const matching = compose({ dashboard: "aidr-dashboard:0.6.1" });
	const verified = await verifyBundle({ bundle: `${output}.tar`, publicKey: f.publicKey, planCompose: matching });
	verified.cleanup();
	assert.deepEqual(verified.checks, [["images", "1 image(s)"]]);
	// A stack that needs an image the transfer media does not carry is refused before any load.
	const missing = compose({ dashboard: "aidr-dashboard:0.6.1", db: "supabase/postgres:17.11.0.004" });
	await assert.rejects(verifyBundle({ bundle: `${output}.tar`, publicKey: f.publicKey, planCompose: missing }), /incomplete: supabase\/postgres:17\.11\.0\.004 is required/);
	const dockerLog = join(root, "docker.log");
	const docker = join(root, "fake-docker");
	writeFileSync(docker, `#!/bin/sh\necho "$@" >> '${dockerLog}'\n`);
	chmodSync(docker, 0o755);
	await assert.rejects(importBundle({ bundle: `${output}.tar`, publicKey: f.publicKey, planCompose: missing, loadImages: true, dockerBin: docker }, { out: () => {} }), /incomplete/);
	assert.equal(existsSync(dockerLog), false, "nothing was loaded");
	// The CLI maps --compose to the plan check for verify (it means "build from" only for build).
	const cli = spawnSync(process.execPath, [script, "verify", "--bundle", `${output}.tar`, "--public-key", f.publicKey, "--compose", missing, "--lang", "en"], { encoding: "utf8" });
	assert.equal(cli.status, 1);
	assert.match(cli.stderr, /is required by the plan but not present/);
	const ok = spawnSync(process.execPath, [script, "verify", "--bundle", `${output}.tar`, "--public-key", f.publicKey, "--compose", matching, "--lang", "en"], { encoding: "utf8" });
	assert.equal(ok.status, 0, ok.stderr);
});
