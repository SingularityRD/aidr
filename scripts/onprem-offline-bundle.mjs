#!/usr/bin/env node
/**
 * One signed transfer bundle for an air-gapped AIDR installation.
 *
 * On a connected staging host (same release as the disconnected host):
 *
 *   node scripts/onprem-offline-bundle.mjs build --output <new dir> \
 *     --signing-key <ed25519 private PEM> --key-id <id> \
 *     [--images <dir made by build-airgap-images.mjs> | --compose <prepared compose.yml> [--platform linux/amd64]] \
 *     [--intel-pack <pack dir | bundle.json>]... --intel-trusted-keys <trusted-keys.json> \
 *     [--installers <staged installer catalog dir> --installer-catalog-public-key <PEM file | base64 SPKI>] \
 *     [--browser-guard-feed <dir>] [--tar]
 *
 * On the disconnected host:
 *
 *   node scripts/onprem-offline-bundle.mjs verify --bundle <dir | .tar> --public-key <PEM> [component keys] \
 *     [--compose <compose.yml prepared on this host>]
 *   node scripts/onprem-offline-bundle.mjs import --bundle <dir | .tar> --public-key <PEM> [component keys] \
 *     [--compose <compose.yml prepared on this host>] [--load-images] \
 *     [--intel-target local [--packs-dir <dir>] | --intel-target storage --deployment /srv/aidr] \
 *     [--installers-out <new dir>] [--browser-guard-out <new dir>]
 *
 * With --compose on verify/import the image set must also be exactly what the
 * stack prepared on this host needs (scripts/build-airgap-images.mjs --verify
 * --compose). The vendor's signed image bundle (release-images.yml, job
 * airgap-bundle) is checked this way after `deployment-prepare.mjs` generated
 * this installation's credentials locally.
 *
 * Every component is verified with its own existing verifier before it enters
 * the bundle and again before anything is imported, and nothing is imported
 * unless every check passes:
 *
 *   images        scripts/build-airgap-images.mjs --verify (size + SHA-256 per tarball)
 *   intel packs   scripts/import-offline-pack.mjs verifyOfflinePack (Ed25519 signature,
 *                 trusted key, expiry, file digests); imported with that same script
 *   installers    the signed installer catalog of scripts/publish-installers.mjs
 *                 (latest.json and manifest.json Ed25519 envelopes, every file digest)
 *   Browser Guard every .crx must carry a CRX3 signed header and every .xpi a
 *                 Mozilla signature; the browser checks those signatures again on install
 *
 * The bundle manifest (component digests and every file's SHA-256) is signed
 * with the operator's Ed25519 key, and SHA256SUMS lists every file. A missing
 * signature, key or digest is a refusal, never a warning.
 *
 * Boundary: the image tarballs are covered by the bundle signature and their
 * digests. The vendor bundle is signed with the vendor offline-bundle key (pass
 * its public key, shipped in the signed customer kit, as --public-key) and,
 * separately, keyless with cosign (`cosign verify-blob --bundle`); a bundle a
 * customer assembles itself is signed with the operator's key instead.
 */
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { createBundle, loadTrustedKeys, readPackSource, verifyOfflinePack } from "./import-offline-pack.mjs";
import { selectLanguage } from "./lib/onprem-language.mjs";
import { systemTar, tarDirectory } from "./lib/tar-path.mjs";
import { verifyEnvelope } from "./publish-installers.mjs";
import { loadEd25519PrivateKey, signReleaseManifest } from "./release-signing-lib.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const MANIFEST_NAME = "aidr-offline-bundle.manifest.json";
export const SIGNATURE_NAME = `${MANIFEST_NAME}.sig`;
export const SUMS_NAME = "SHA256SUMS";
const BUNDLE_KIND = "aidr-offline-bundle";
const IMAGES_MANIFEST = "aidr-airgap-images.manifest.json";
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/;

const MESSAGES = {
	en: {
		built: (dir) => `Offline bundle written to ${dir}. Copy the whole directory (or the .tar) to the disconnected host and run the import command there.`,
		tarBuilt: (path) => `Transfer archive: ${path}`,
		verified: (count) => `Offline bundle verified: signature, SHA256SUMS and ${count} component check(s) passed. Nothing was imported.`,
		imported: "Offline bundle verified and imported.",
		refused: "Refused: the offline bundle is incomplete or not signed correctly. Nothing was imported.",
		buildRefused: "Refused: the offline bundle was not written.",
		component: (name, detail) => `  ${name}: ${detail}`,
		next: {
			images: (registry) => `Images loaded. If the stack pulls from an internal registry, tag and push them there (${registry}).`,
			intel: "Intel packs installed with scripts/import-offline-pack.mjs.",
			installers: (dir) => `Installers and their signed catalog copied to ${dir}; serve them through the download portal (docs/installation/download-portal.md).`,
			browserGuard: (dir) => `Browser Guard update files copied to ${dir}; publish them on the internal update address your browser policy points at.`,
		},
	},
	tr: {
		built: (dir) => `Çevrim dışı paket ${dir} konumuna yazıldı. Dizinin tamamını (veya .tar dosyasını) internete kapalı sunucuya kopyalayın ve içe aktarma komutunu orada çalıştırın.`,
		tarBuilt: (path) => `Aktarım arşivi: ${path}`,
		verified: (count) => `Çevrim dışı paket doğrulandı: imza, SHA256SUMS ve ${count} bileşen kontrolü geçti. Hiçbir şey içe aktarılmadı.`,
		imported: "Çevrim dışı paket doğrulandı ve içe aktarıldı.",
		refused: "Reddedildi: çevrim dışı paket eksik ya da doğru imzalanmamış. Hiçbir şey içe aktarılmadı.",
		buildRefused: "Reddedildi: çevrim dışı paket yazılmadı.",
		component: (name, detail) => `  ${name}: ${detail}`,
		next: {
			images: (registry) => `İmajlar yüklendi. Sistem imajları kurum içi bir kayıt defterinden çekiyorsa, onları oraya etiketleyip gönderin (${registry}).`,
			intel: "Tehdit bilgisi paketleri scripts/import-offline-pack.mjs ile kuruldu.",
			installers: (dir) => `Kurulum dosyaları ve imzalı katalogları ${dir} konumuna kopyalandı; indirme portalı üzerinden sunun (docs/installation/download-portal.md).`,
			browserGuard: (dir) => `Browser Guard güncelleme dosyaları ${dir} konumuna kopyalandı; tarayıcı politikanızın gösterdiği kurum içi güncelleme adresinde yayımlayın.`,
		},
	},
};

export class OfflineBundleError extends Error {
	constructor(message) {
		super(message);
		this.name = "OfflineBundleError";
	}
}

const fail = (message) => {
	throw new OfflineBundleError(message);
};
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function regularFile(path, label) {
	let info;
	try {
		info = lstatSync(path);
	} catch {
		fail(`${label} is missing: ${path}`);
	}
	if (!info.isFile() || info.isSymbolicLink()) fail(`${label} must be a regular file: ${path}`);
	return readFileSync(path);
}

function realDirectory(path, label) {
	let info;
	try {
		info = lstatSync(path);
	} catch {
		fail(`${label} is missing: ${path}`);
	}
	if (!info.isDirectory() || info.isSymbolicLink()) fail(`${label} must be a real directory: ${path}`);
	return resolve(path);
}

/** Every regular file under `root`, as sorted POSIX relative paths. Symlinks and special files are refused. */
function listFiles(root, prefix = "") {
	const out = [];
	for (const entry of readdirSync(join(root, prefix), { withFileTypes: true })) {
		const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
		if (!SAFE_SEGMENT.test(entry.name)) fail(`unsafe file name in bundle: ${rel}`);
		if (entry.isSymbolicLink()) fail(`bundle contains a symbolic link: ${rel}`);
		if (entry.isDirectory()) out.push(...listFiles(root, rel));
		else if (entry.isFile()) out.push(rel);
		else fail(`bundle contains a special file: ${rel}`);
	}
	return out.sort();
}

function loadPublicKey(value, label) {
	if (!value) fail(`${label} is required; nothing is accepted unsigned`);
	try {
		if (existsSync(value)) return createPublicKey(readFileSync(value, "utf8"));
		return createPublicKey({ key: Buffer.from(value, "base64"), format: "der", type: "spki" });
	} catch {
		fail(`${label} is not a valid public key`);
	}
}

// --- component verifiers ----------------------------------------------------------

/**
 * Size and SHA-256 of every tarball. With `compose` (the stack prepared on this
 * host), also plan completeness: every image that compose file runs or builds
 * from is in the bundle, and nothing else is.
 */
function verifyImages(dir, { airgapScript = join(here, "build-airgap-images.mjs"), compose = null } = {}) {
	regularFile(join(dir, IMAGES_MANIFEST), "image manifest");
	const plan = compose ? ["--compose", resolve(compose)] : [];
	const result = spawnSync(process.execPath, [airgapScript, "--verify", "--output", dir, ...plan], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
	if (result.status !== 0) fail(`image bundle verification failed: ${(result.stderr || result.stdout).trim().split("\n").at(-1)}`);
	const manifest = JSON.parse(readFileSync(join(dir, IMAGES_MANIFEST), "utf8"));
	return { count: manifest.images.length, platform: manifest.platform ?? null, refs: manifest.images.map((image) => image.ref), manifest_sha256: sha256(readFileSync(join(dir, IMAGES_MANIFEST))) };
}

async function verifyIntelBundle(path, trustedKeys, now) {
	const pack = readPackSource(path);
	const verified = await verifyOfflinePack(pack, { trustedKeys, now });
	return { pack, verified };
}

/** Verify a staged installer catalog (scripts/publish-installers.mjs layout) against the catalog public key. */
export function verifyInstallerCatalog(dir, publicKey) {
	const latestRaw = regularFile(join(dir, "latest.json"), "installer latest.json");
	const latestSig = regularFile(join(dir, "latest.json.sig"), "installer latest.json.sig (the catalog is unsigned)");
	if (!verifyEnvelope(latestRaw, JSON.parse(latestSig.toString("utf8")), publicKey)) fail("installer latest.json signature does not verify with the catalog public key");
	const latest = JSON.parse(latestRaw.toString("utf8"));
	if (latest.type !== "aidr-installer-latest" || typeof latest.manifest_path !== "string" || !/^[^/]+\/manifest\.json$/.test(latest.manifest_path)) fail("installer latest.json is not an AIDR installer pointer");
	const catalogRaw = regularFile(join(dir, ...latest.manifest_path.split("/")), "installer catalog manifest.json");
	const catalogSig = regularFile(join(dir, ...`${latest.manifest_path}.sig`.split("/")), "installer catalog manifest.json.sig (the catalog is unsigned)");
	if (!verifyEnvelope(catalogRaw, JSON.parse(catalogSig.toString("utf8")), publicKey)) fail("installer catalog signature does not verify with the catalog public key");
	if (sha256(catalogRaw) !== latest.manifest_sha256) fail("installer latest.json does not point at this catalog");
	const catalog = JSON.parse(catalogRaw.toString("utf8"));
	if (catalog.type !== "aidr-installer-catalog" || catalog.version !== latest.version || !Array.isArray(catalog.files) || catalog.files.length === 0) fail("installer catalog lists no installers");
	const expected = new Set(["latest.json", "latest.json.sig", latest.manifest_path, `${latest.manifest_path}.sig`, `${catalog.version}/SHA256SUMS`]);
	if (catalog.release?.manifest_path) expected.add(catalog.release.manifest_path);
	if (catalog.release?.manifest_path) expected.add(catalog.release.manifest_path.replace(/\.json$/, ".sig"));
	for (const file of catalog.files) {
		if (typeof file.path !== "string" || !file.path.startsWith(`${catalog.version}/`)) fail("installer catalog entry has an unexpected path");
		const bytes = regularFile(join(dir, ...file.path.split("/")), `installer ${file.path}`);
		if (sha256(bytes) !== file.sha256 || bytes.byteLength !== file.size) fail(`installer ${file.path} does not match the signed catalog`);
		expected.add(file.path);
	}
	const sums = regularFile(join(dir, catalog.version, "SHA256SUMS"), "installer SHA256SUMS").toString("utf8");
	for (const file of catalog.files) {
		if (!sums.includes(`${file.sha256}  ${file.platform}/${file.file}`)) fail(`installer SHA256SUMS has no entry for ${file.path}`);
	}
	const unexpected = listFiles(dir).filter((path) => !expected.has(path));
	if (unexpected.length) fail(`installer directory holds files the signed catalog does not name: ${unexpected.join(", ")}`);
	return { version: catalog.version, files: catalog.files.length, catalog_sha256: sha256(catalogRaw) };
}

function crxSigned(bytes) {
	// CRX3: "Cr24", version 3, header length, then a protobuf CrxFileHeader that
	// carries the signatures. Chromium verifies them against the extension id.
	return bytes.length > 12 && bytes.subarray(0, 4).toString("latin1") === "Cr24" && bytes.readUInt32LE(4) === 3 && bytes.readUInt32LE(8) > 0 && bytes.readUInt32LE(8) < bytes.length - 12;
}

function xpiSigned(bytes) {
	// A Mozilla-signed XPI is a ZIP with META-INF/cose.sig or META-INF/mozilla.rsa.
	if (bytes.length < 4 || bytes.readUInt32LE(0) !== 0x04034b50) return false;
	const text = bytes.toString("latin1");
	return text.includes("META-INF/cose.sig") || text.includes("META-INF/mozilla.rsa");
}

/** Every extension package in the feed must be signed; at least one must be present. */
export function verifyBrowserGuardFeed(dir) {
	const files = listFiles(dir);
	const packages = files.filter((path) => /\.(crx|xpi)$/i.test(path));
	if (packages.length === 0) fail("Browser Guard feed holds no .crx or .xpi package");
	for (const path of packages) {
		const bytes = readFileSync(join(dir, ...path.split("/")));
		const signed = path.toLowerCase().endsWith(".crx") ? crxSigned(bytes) : xpiSigned(bytes);
		if (!signed) fail(`Browser Guard package ${path} carries no signature`);
	}
	return { files: files.length, packages };
}

// --- build -------------------------------------------------------------------------

function writeSums(dir) {
	const files = listFiles(dir).filter((path) => path !== SUMS_NAME);
	const lines = files.map((path) => `${sha256(readFileSync(join(dir, ...path.split("/"))))}  ${path}\n`);
	writeFileSync(join(dir, SUMS_NAME), lines.join(""), { mode: 0o644, flag: "wx" });
}

export async function buildBundle(options) {
	if (!options.output) fail("--output <new directory> is required");
	const output = resolve(options.output);
	if (existsSync(output)) fail(`${output} already exists; the bundle is always written to a new directory`);
	if (!options.signingKey || !options.keyId) fail("--signing-key and --key-id are required; the bundle is never written unsigned");
	const now = options.now ?? Date.now();
	const parent = realpathSync(dirname(output));
	const staging = mkdtempSync(join(parent, `.${basename(output)}.staging-`));
	const components = {};
	try {
		// The signing key must live outside the bundle it signs.
		const signing = await loadEd25519PrivateKey(resolve(options.signingKey), staging);
		if (options.images || options.compose) {
			const imagesDir = join(staging, "images");
			if (options.compose) {
				const result = spawnSync(process.execPath, [options.airgapScript ?? join(here, "build-airgap-images.mjs"), "--compose", resolve(options.compose), "--output", imagesDir, ...(options.platform ? ["--platform", options.platform] : [])], { stdio: "inherit" });
				if (result.status !== 0) fail("building the image bundle failed (see the messages above)");
			} else {
				cpSync(realDirectory(resolve(options.images), "--images directory"), imagesDir, { recursive: true, verbatimSymlinks: true });
			}
			components.images = verifyImages(imagesDir, options);
		}
		if (options.intelPacks.length) {
			if (!options.intelTrustedKeys) fail("--intel-trusted-keys is required with --intel-pack; intel packs are only bundled after their signature verifies");
			const trustedKeys = loadTrustedKeys(options.intelTrustedKeys);
			mkdirSync(join(staging, "intel-packs"));
			components.intel_packs = [];
			for (const source of options.intelPacks) {
				const { pack, verified } = await verifyIntelBundle(source, trustedKeys, now);
				const name = `${verified.manifest.pack_id}-${verified.manifest.version}.json`;
				if (!SAFE_SEGMENT.test(name)) fail(`intel pack name ${name} is not portable`);
				if (existsSync(join(staging, "intel-packs", name))) fail(`intel pack ${name} is listed twice`);
				writeFileSync(join(staging, "intel-packs", name), createBundle(pack, verified.manifest), { flag: "wx" });
				components.intel_packs.push({ file: `intel-packs/${name}`, pack_id: verified.manifest.pack_id, version: verified.manifest.version, key_id: verified.manifest.key_id, manifest_sha256: verified.manifestSha256 });
			}
		}
		if (options.installers) {
			const publicKey = loadPublicKey(options.installerCatalogPublicKey, "--installer-catalog-public-key");
			const source = realDirectory(resolve(options.installers), "--installers directory");
			verifyInstallerCatalog(source, publicKey);
			cpSync(source, join(staging, "installers"), { recursive: true, verbatimSymlinks: true });
			components.installers = verifyInstallerCatalog(join(staging, "installers"), publicKey);
		}
		if (options.browserGuardFeed) {
			const source = realDirectory(resolve(options.browserGuardFeed), "--browser-guard-feed directory");
			cpSync(source, join(staging, "browser-guard"), { recursive: true, verbatimSymlinks: true });
			components.browser_guard = verifyBrowserGuardFeed(join(staging, "browser-guard"));
		}
		if (Object.keys(components).length === 0) fail("nothing to bundle: pass --images/--compose, --intel-pack, --installers or --browser-guard-feed");
		const files = listFiles(staging).map((path) => {
			const bytes = readFileSync(join(staging, ...path.split("/")));
			return { path, sha256: sha256(bytes), size: bytes.byteLength };
		});
		const manifest = {
			schema_version: 1,
			kind: BUNDLE_KIND,
			created_at: new Date(now).toISOString(),
			signer_key_id: options.keyId,
			signer_fingerprint: signing.fingerprint,
			components,
			files,
		};
		const manifestRaw = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
		writeFileSync(join(staging, MANIFEST_NAME), manifestRaw, { flag: "wx" });
		writeFileSync(join(staging, SIGNATURE_NAME), `${JSON.stringify(signReleaseManifest(manifestRaw, signing.privateKey, options.keyId), null, 2)}\n`, { flag: "wx" });
		writeSums(staging);
		renameSync(staging, output);
	} catch (error) {
		rmSync(staging, { recursive: true, force: true });
		throw error;
	}
	let archive = null;
	if (options.tar) {
		archive = `${output}.tar`;
		if (existsSync(archive)) fail(`${archive} already exists`);
		const result = spawnSync(systemTar(), ["-cf", basename(archive), "-C", tarDirectory(dirname(output)), basename(output)], { cwd: dirname(output), stdio: "inherit" });
		if (result.status !== 0) fail("writing the transfer archive failed");
	}
	return { output, archive, components };
}

// --- verify / import ---------------------------------------------------------------

/** Extract a transfer archive into a new private directory after checking every member is a plain file or directory with a safe path. */
function extractArchive(archive) {
	const tar = systemTar();
	const listing = spawnSync(tar, ["-tvf", basename(archive)], { cwd: dirname(archive), encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
	const names = spawnSync(tar, ["-tf", basename(archive)], { cwd: dirname(archive), encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
	if (listing.status !== 0 || names.status !== 0) fail("transfer archive cannot be read");
	for (const line of listing.stdout.split("\n").filter(Boolean)) {
		if (!["-", "d"].includes(line[0])) fail("transfer archive contains a link or special file");
	}
	const members = names.stdout.split("\n").filter(Boolean);
	const roots = new Set();
	for (const name of members) {
		const clean = name.replace(/\/$/, "");
		if (!clean || clean.startsWith("/") || clean.split("/").some((part) => part === ".." || part === "." || !SAFE_SEGMENT.test(part))) fail(`transfer archive member has an unsafe path: ${name}`);
		roots.add(clean.split("/")[0]);
	}
	if (roots.size !== 1) fail("transfer archive must hold exactly one bundle directory");
	const destination = mkdtempSync(join(dirname(archive), ".aidr-offline-import-"));
	const extract = spawnSync(tar, ["-xf", basename(archive), "-C", tarDirectory(destination), "--no-same-owner", "--no-same-permissions"], { cwd: dirname(archive), stdio: "inherit" });
	if (extract.status !== 0) {
		rmSync(destination, { recursive: true, force: true });
		fail("transfer archive could not be extracted");
	}
	return { dir: join(destination, [...roots][0]), cleanup: () => rmSync(destination, { recursive: true, force: true }) };
}

export async function verifyBundle(options) {
	if (!options.bundle) fail("--bundle <directory or .tar> is required");
	const publicKey = loadPublicKey(options.publicKey, "--public-key");
	let source = resolve(options.bundle);
	let cleanup = () => {};
	if (source.endsWith(".tar")) ({ dir: source, cleanup } = extractArchive(source));
	try {
		realDirectory(source, "bundle");
		const manifestRaw = regularFile(join(source, MANIFEST_NAME), "bundle manifest");
		const signature = regularFile(join(source, SIGNATURE_NAME), "bundle signature (the bundle is unsigned)");
		let envelope;
		try {
			envelope = JSON.parse(signature.toString("utf8"));
		} catch {
			fail("bundle signature is not a signature envelope");
		}
		if (!verifyEnvelope(manifestRaw, envelope, publicKey)) fail("bundle signature does not verify with --public-key; the bundle was changed or signed by another key");
		const manifest = JSON.parse(manifestRaw.toString("utf8"));
		if (manifest.schema_version !== 1 || manifest.kind !== BUNDLE_KIND || !Array.isArray(manifest.files)) fail("bundle manifest is not an AIDR offline bundle");
		const sums = new Map();
		for (const line of regularFile(join(source, SUMS_NAME), "SHA256SUMS").toString("utf8").split("\n").filter(Boolean)) {
			const match = /^([a-f0-9]{64}) {2}(.+)$/.exec(line);
			if (!match || sums.has(match[2])) fail("SHA256SUMS is malformed");
			sums.set(match[2], match[1]);
		}
		const present = listFiles(source).filter((path) => path !== SUMS_NAME);
		const listedInManifest = new Set(manifest.files.map((entry) => entry.path));
		for (const path of present) {
			const digest = sha256(readFileSync(join(source, ...path.split("/"))));
			if (sums.get(path) !== digest) fail(`SHA256SUMS does not match ${path}`);
			if (![MANIFEST_NAME, SIGNATURE_NAME].includes(path)) {
				const entry = manifest.files.find((item) => item.path === path);
				if (!entry || entry.sha256 !== digest) fail(`${path} is not in the signed manifest or was changed`);
			}
		}
		if (sums.size !== present.length) fail("SHA256SUMS names files that are missing");
		for (const path of listedInManifest) if (!present.includes(path)) fail(`signed manifest names a missing file: ${path}`);

		const checks = [];
		const components = manifest.components ?? {};
		if (components.images) {
			const images = verifyImages(join(source, "images"), { ...options, compose: options.planCompose });
			if (images.manifest_sha256 !== components.images.manifest_sha256) fail("image manifest differs from the signed bundle manifest");
			checks.push(["images", `${images.count} image(s)`]);
		}
		const intel = [];
		if (components.intel_packs?.length) {
			if (!options.intelTrustedKeys) fail("--intel-trusted-keys is required: the bundle carries intel packs and they are verified before import");
			const trustedKeys = loadTrustedKeys(options.intelTrustedKeys);
			for (const entry of components.intel_packs) {
				const { verified } = await verifyIntelBundle(join(source, ...entry.file.split("/")), trustedKeys, options.now ?? Date.now());
				if (verified.manifestSha256 !== entry.manifest_sha256) fail(`intel pack ${entry.file} differs from the signed bundle manifest`);
				intel.push(join(source, ...entry.file.split("/")));
			}
			checks.push(["intel packs", `${intel.length} signed pack(s)`]);
		}
		if (components.installers) {
			const catalog = verifyInstallerCatalog(join(source, "installers"), loadPublicKey(options.installerCatalogPublicKey, "--installer-catalog-public-key"));
			if (catalog.catalog_sha256 !== components.installers.catalog_sha256) fail("installer catalog differs from the signed bundle manifest");
			checks.push(["installers", `${catalog.version}, ${catalog.files} file(s)`]);
		}
		if (components.browser_guard) {
			const feed = verifyBrowserGuardFeed(join(source, "browser-guard"));
			checks.push(["browser guard", `${feed.packages.length} signed package(s)`]);
		}
		return { source, manifest, checks, intel, cleanup };
	} catch (error) {
		cleanup();
		throw error;
	}
}

function copyNew(source, destination, label) {
	const target = resolve(destination);
	if (existsSync(target)) fail(`${label} ${target} already exists; choose a new directory`);
	cpSync(source, target, { recursive: true, verbatimSymlinks: true });
	return target;
}

export async function importBundle(options, { out = console.log } = {}) {
	const t = MESSAGES[options.lang ?? "en"];
	const verified = await verifyBundle(options);
	try {
		const { source, manifest, intel } = verified;
		if (options.loadImages && manifest.components.images) {
			const images = JSON.parse(readFileSync(join(source, "images", IMAGES_MANIFEST), "utf8"));
			const docker = options.dockerBin ?? process.env.AIDR_DOCKER_BIN ?? "docker";
			for (const image of images.images) {
				const result = spawnSync(docker, ["load", "-i", join(source, "images", ...image.tarball.split("/"))], { stdio: "inherit" });
				if (result.status !== 0) fail(`docker load failed for ${image.ref}`);
			}
			out(t.next.images(images.images.map((image) => image.ref).join(", ")));
		}
		if (options.intelTarget && intel.length) {
			for (const pack of intel) {
				const args = [options.importPackScript ?? join(here, "import-offline-pack.mjs"), "--pack", pack, "--trusted-keys", options.intelTrustedKeys, "--target", options.intelTarget];
				if (options.intelTarget === "local" && options.packsDir) args.push("--packs-dir", options.packsDir);
				if (options.intelTarget === "storage") args.push("--deployment", options.deployment ?? fail("--intel-target storage requires --deployment"));
				const result = spawnSync(process.execPath, args, { stdio: "inherit" });
				if (result.status !== 0) fail(`intel pack import failed for ${basename(pack)}`);
			}
			out(t.next.intel);
		}
		if (options.installersOut && manifest.components.installers) out(t.next.installers(copyNew(join(source, "installers"), options.installersOut, "--installers-out")));
		if (options.browserGuardOut && manifest.components.browser_guard) out(t.next.browserGuard(copyNew(join(source, "browser-guard"), options.browserGuardOut, "--browser-guard-out")));
		out(t.imported);
	} finally {
		verified.cleanup();
	}
}

// --- CLI ---------------------------------------------------------------------------

function parseOptions(argv) {
	const { values, positionals } = parseArgs({
		args: argv,
		allowPositionals: true,
		options: {
			output: { type: "string" },
			"signing-key": { type: "string" },
			"key-id": { type: "string" },
			images: { type: "string" },
			compose: { type: "string" },
			platform: { type: "string" },
			"intel-pack": { type: "string", multiple: true, default: [] },
			"intel-trusted-keys": { type: "string" },
			installers: { type: "string" },
			"installer-catalog-public-key": { type: "string" },
			"browser-guard-feed": { type: "string" },
			tar: { type: "boolean", default: false },
			bundle: { type: "string" },
			"public-key": { type: "string" },
			"load-images": { type: "boolean", default: false },
			"intel-target": { type: "string" },
			"packs-dir": { type: "string" },
			deployment: { type: "string" },
			"installers-out": { type: "string" },
			"browser-guard-out": { type: "string" },
			lang: { type: "string" },
		},
	});
	if (values.images && values.compose) fail("use either --images or --compose");
	if (values["intel-target"] && !["local", "storage"].includes(values["intel-target"])) fail("--intel-target must be local or storage");
	return {
		action: positionals[0],
		output: values.output,
		signingKey: values["signing-key"],
		keyId: values["key-id"],
		images: values.images,
		compose: positionals[0] === "build" ? values.compose : undefined,
		planCompose: positionals[0] === "build" ? undefined : values.compose,
		platform: values.platform,
		intelPacks: values["intel-pack"].map((path) => resolve(path)),
		intelTrustedKeys: values["intel-trusted-keys"] ? resolve(values["intel-trusted-keys"]) : null,
		installers: values.installers,
		installerCatalogPublicKey: values["installer-catalog-public-key"],
		browserGuardFeed: values["browser-guard-feed"],
		tar: values.tar,
		bundle: values.bundle,
		publicKey: values["public-key"],
		loadImages: values["load-images"],
		intelTarget: values["intel-target"],
		packsDir: values["packs-dir"],
		deployment: values.deployment,
		installersOut: values["installers-out"],
		browserGuardOut: values["browser-guard-out"],
		lang: selectLanguage(values.lang),
	};
}

async function main() {
	const lang = selectLanguage(process.argv.find((arg, index) => process.argv[index - 1] === "--lang"));
	const t = MESSAGES[lang];
	let action = null;
	try {
		const options = parseOptions(process.argv.slice(2));
		action = options.action;
		if (action === "build") {
			const result = await buildBundle(options);
			for (const [name, detail] of Object.entries(result.components)) console.log(t.component(name, Array.isArray(detail) ? `${detail.length} pack(s)` : JSON.stringify(detail.count ?? detail.version ?? detail.files)));
			console.log(t.built(result.output));
			if (result.archive) console.log(t.tarBuilt(result.archive));
		} else if (action === "verify") {
			const result = await verifyBundle(options);
			result.cleanup();
			for (const [name, detail] of result.checks) console.log(t.component(name, detail));
			console.log(t.verified(result.checks.length));
		} else if (action === "import") {
			await importBundle(options);
		} else {
			fail("Use build, verify or import (see the header of scripts/onprem-offline-bundle.mjs)");
		}
	} catch (error) {
		console.error(action === "build" ? t.buildRefused : t.refused);
		console.error(`  ${error.message}`);
		process.exitCode = 1;
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) await main();

