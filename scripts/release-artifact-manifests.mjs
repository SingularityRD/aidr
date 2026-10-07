/**
 * Build the unsigned release-evidence set for all shipped AIDR artifacts.
 *
 * This preparation phase may execute the package manager while constructing
 * the SBOM, so private signing material is deliberately forbidden here.
 * Commercial/final mode emits complete manifests for a later isolated signing
 * job and still requires the stable RC/git/source/data/package/lock/SBOM
 * provenance tuple.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, mkdir, readdir, readFile, rm, writeFile, lstat } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { resolveGitTreeSha256 } from "./lib/release-evidence-digests.mjs";
import { assertReleaseSourceClean } from "./lib/release-source-clean.mjs";
import { assertCurrentPrebuiltSbom, assertPrebuiltSbomDigest } from "./lib/prebuilt-sbom-validation.mjs";
import { PRIVACY_PYTHON_SOURCES, readPythonSources } from "./lib/python-sbom-components.mjs";

const repoRoot = process.cwd();
const commercial = process.env.AIDR_RELEASE_MODE === "commercial" || process.env.AIDR_FINAL_RELEASE === "1";
const requireSbom = commercial || process.env.AIDR_REQUIRE_SBOM === "1";
const keyId = process.env.AIDR_SIGNING_KEY_ID;
const configuredFingerprint = process.env.AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT;
const watermarkId = process.env.AIDR_WATERMARK_ID;
assertNoPrivateSigningMaterial();
const targets = [
	{ pkg: "packages/core/package.json", dir: "packages/core/dist", artifactId: "core/dist" },
	{ pkg: "packages/claude-code/package.json", dir: "packages/claude-code/dist", artifactId: "claude-code/dist" },
	{ pkg: "packages/extension/package.json", dir: "packages/extension/dist", artifactId: "extension/dist" },
	{ pkg: "packages/openclaw/package.json", dir: "packages/openclaw/dist", artifactId: "openclaw/dist" },
	{ pkg: "packages/opencode/package.json", dir: "packages/opencode/dist", artifactId: "opencode/dist" },
	{ pkg: "packages/cli/package.json", dir: "packages/cli/dist", artifactId: "cli/dist" },
	{ pkg: "packages/sdk/package.json", dir: "packages/sdk/dist", artifactId: "sdk/dist" },
	{ pkg: "packages/dashboard/package.json", dir: "packages/dashboard/dist", artifactId: "dashboard/dist" },
	{ pkg: "packages/codex/package.json", dir: "packages/codex/dist", artifactId: "codex/dist" },
	{ pkg: "packages/mcp-gateway/package.json", dir: "packages/mcp-gateway/dist", artifactId: "mcp-gateway/dist" },
	{ pkg: "packages/privacy/package.json", dir: "packages/privacy/dist", artifactId: "privacy/dist" },
];

if (commercial) {
	if (!keyId) fail("Commercial release requires AIDR_SIGNING_KEY_ID.");
	if (!configuredFingerprint) fail("Commercial release requires AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT.");
	if (!watermarkId) fail("Commercial release requires AIDR_WATERMARK_ID.");
	if (!process.env.AIDR_RC_VERSION && !process.env.AIDR_RELEASE_VERSION) fail("Commercial release requires AIDR_RC_VERSION (or AIDR_RELEASE_VERSION).");
	if (!process.env.SOURCE_DATE_EPOCH) process.env.SOURCE_DATE_EPOCH = resolveGitTimestamp();
	assertReleaseSourceClean(repoRoot);
}
const keyFingerprint = configuredFingerprint ? normalizeFingerprint(configuredFingerprint) : undefined;
const gitSha = process.env.AIDR_GIT_SHA ?? process.env.AIDR_BUILD_ID ?? process.env.GITHUB_SHA ?? process.env.CI_COMMIT_SHA ?? resolveGitSha();
const sourceDigest = process.env.AIDR_SOURCE_DIGEST ?? resolveGitTreeSha256(repoRoot);
const dataDigest = process.env.AIDR_DATA_DIGEST ?? (await digestDataRoots());
const lockfileDigest = `sha256:${sha256(await readFile(path.join(repoRoot, "pnpm-lock.yaml")))}`;

for (const target of targets) {
	const pkgPath = path.join(repoRoot, target.pkg);
	const distDir = path.join(repoRoot, target.dir);
	if (!existsSync(pkgPath) || !existsSync(distDir)) fail(`Release artifact target is missing: ${target.dir}`);
}

const evidenceDir = path.join(repoRoot, ".release-evidence");
await mkdir(evidenceDir, { recursive: true });
const sbomPath = path.join(evidenceDir, "aidr-sbom.cdx.json");
const sbomChecksumPath = `${sbomPath}.sha256`;
const prebuiltSbom = process.env.AIDR_PREBUILT_SBOM_PATH?.trim();
let sbomOk;
if (prebuiltSbom) {
	await reuseSbomEvidence(prebuiltSbom, sbomPath, { sourceDigest, dataDigest });
	sbomOk = true;
} else {
	sbomOk = run(
		["scripts/generate-sbom.mjs", "--output", sbomPath],
		finalEnv({ AIDR_SOURCE_DIGEST: sourceDigest, AIDR_DATA_DIGEST: dataDigest }),
		{ allowFailure: !requireSbom },
	);
}
if (!sbomOk && !requireSbom) console.warn("WARN: SBOM unavailable in developer mode; no SBOM was copied.");
if (sbomOk) {
	for (const target of targets) {
		await copySbomEvidence(sbomPath, path.join(repoRoot, target.dir));
	}
}
const sbomDigest = sbomOk ? `sha256:${readSha256Sidecar(sbomChecksumPath)}` : undefined;

const packageDigests = [];
for (const target of targets) {
	const pkgPath = path.join(repoRoot, target.pkg);
	const distDir = path.join(repoRoot, target.dir);
	await rm(path.join(distDir, "aidr-artifact.manifest.sig"), { force: true });
	await rm(path.join(distDir, "aidr-artifact.manifest.json"), { force: true });
	const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
	const version = String(pkg.version ?? "0.0.0");
	const packageDigest = await digestPackage(pkgPath, distDir);
	packageDigests.push({ artifact_id: target.artifactId, digest: packageDigest });
	run(
		[
			"scripts/generate-artifact-manifest.mjs",
			"--dir",
			distDir,
			"--id",
			target.artifactId,
			"--version",
			version,
			"--rc-version",
			process.env.AIDR_RC_VERSION ?? process.env.AIDR_RELEASE_VERSION ?? version,
			...(commercial
				? ["--watermark-id", watermarkId, "--channel", "commercial"]
				: []),
		],
		finalEnv({ AIDR_PACKAGE_DIGEST: packageDigest, AIDR_SBOM_DIGEST: sbomDigest }),
	);
}

let verificationDirs = targets.map((target) => path.join(repoRoot, target.dir));
if (commercial || process.env.AIDR_INCLUDE_RELEASE_BUNDLE === "1") {
	const bundle = await prepareReleaseBundle(evidenceDir, packageDigests, {
		gitSha,
		sourceDigest,
		dataDigest,
		lockfileDigest,
		sbomDigest,
		keyFingerprint,
	});
	verificationDirs = [...verificationDirs, bundle];
}

if (commercial) console.log(`Prepared ${verificationDirs.length} unsigned commercial release manifest(s) for isolated signing.`);
else if (sbomOk) console.log(`Developer release evidence: SBOM copied to ${targets.length} artifact(s); signatures remain optional.`);

function finalEnv(extra = {}) {
	return {
		...process.env,
		...extra,
		...(commercial
			? {
					AIDR_FINAL_MANIFEST: "1",
					AIDR_DETERMINISTIC_MANIFEST: "1",
					AIDR_RC_VERSION: process.env.AIDR_RC_VERSION ?? process.env.AIDR_RELEASE_VERSION,
					AIDR_GIT_SHA: gitSha,
					AIDR_SOURCE_DIGEST: sourceDigest,
					AIDR_DATA_DIGEST: dataDigest,
					AIDR_LOCKFILE_DIGEST: lockfileDigest,
					AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT: keyFingerprint,
				}
				: {}),
	};
}

async function prepareReleaseBundle(dir, packageDigestsValue, provenance) {
	const attachmentsDir = path.join(dir, "attachments");
	await rm(attachmentsDir, { recursive: true, force: true });
	await rm(path.join(dir, "aidr-artifact.manifest.json"), { force: true });
	await rm(path.join(dir, "aidr-artifact.manifest.sig"), { force: true });
	await rm(path.join(dir, "release-inventory.json"), { force: true });
	await mkdir(attachmentsDir, { recursive: true });

	const candidates = await discoverRelatedArtifacts();
	const inventory = [];
	for (const candidate of candidates) {
		const relativeSource = path.relative(repoRoot, candidate).replace(/\\/g, "/");
		const kind = classifyArtifact(relativeSource);
		const destination = path.join(attachmentsDir, kind, relativeSource);
		await mkdir(path.dirname(destination), { recursive: true });
		await copyFile(candidate, destination);
		inventory.push({
			source_path: relativeSource,
			staged_path: path.relative(dir, destination).replace(/\\/g, "/"),
			kind,
			sha256: sha256(await readFile(candidate)),
		});
	}
	if (process.env.AIDR_IMAGE_DIGEST) {
		const imageRecord = { digest: process.env.AIDR_IMAGE_DIGEST, recorded_at_source_date_epoch: process.env.SOURCE_DATE_EPOCH };
		const imagePath = path.join(attachmentsDir, "images", "image-digests.json");
		await mkdir(path.dirname(imagePath), { recursive: true });
		await writeFile(imagePath, `${JSON.stringify(imageRecord, null, 2)}\n`, "utf8");
		inventory.push({ source_path: "env:AIDR_IMAGE_DIGEST", staged_path: "attachments/images/image-digests.json", kind: "image", sha256: sha256(Buffer.from(JSON.stringify(imageRecord, null, 2) + "\n")) });
	}
	inventory.sort((a, b) => compareStrings(a.staged_path, b.staged_path));
	await writeFile(path.join(dir, "release-inventory.json"), `${JSON.stringify({ schema_version: 1, artifacts: inventory }, null, 2)}\n`, "utf8");

	const aggregatePackageDigest = `sha256:${sha256(Buffer.from(JSON.stringify(packageDigestsValue.sort((a, b) => compareStrings(a.artifact_id, b.artifact_id)))))}`;
	const version = process.env.AIDR_RC_VERSION ?? process.env.AIDR_RELEASE_VERSION ?? "release";
	const env = finalEnv({ AIDR_PACKAGE_DIGEST: aggregatePackageDigest, AIDR_SBOM_DIGEST: provenance.sbomDigest });
	run(
		[
			"scripts/generate-artifact-manifest.mjs",
			"--dir",
			dir,
			"--id",
			"release/bundle",
			"--version",
			version,
			"--rc-version",
			version,
			"--watermark-id",
			watermarkId ?? "developer-bundle",
			"--channel",
			commercial ? "commercial" : "dev",
		],
		env,
	);
	return dir;
}

async function reuseSbomEvidence(source, destination, bindings) {
	const sourcePath = path.resolve(source);
	if (!existsSync(sourcePath)) fail(`Prebuilt SBOM is missing: ${sourcePath}`);
	const sourceBytes = await readFile(sourcePath);
	const trusted = assertPrebuiltSbomDigest(sourceBytes, process.env.AIDR_EXPECTED_PREBUILT_SBOM_SHA256, { required: requireSbom });
	if (!trusted) console.warn("WARN: Developer prebuilt SBOM has no trusted build-job digest; it is not accepted production evidence.");
	let payload;
	try {
		payload = JSON.parse(sourceBytes.toString("utf8"));
	} catch (error) {
		fail(`Prebuilt SBOM is invalid: ${error instanceof Error ? error.message : String(error)}`);
	}
	assertCurrentPrebuiltSbom(payload, {
		pnpmLockBytes: await readFile(path.join(repoRoot, "pnpm-lock.yaml")),
		pythonLockBytes: await readFile(path.join(repoRoot, "services/aig-bridge/requirements-runtime.lock")),
		pythonEvidenceJson: await readFile(path.join(repoRoot, "services/aig-bridge/pypi-runtime-licenses.json"), "utf8"),
		extraPythonSources: readPythonSources(repoRoot, PRIVACY_PYTHON_SOURCES),
		sourceDigest: bindings.sourceDigest,
		workspacePackages: (await Promise.all((await readdir(path.join(repoRoot, "packages"), { withFileTypes: true }))
			.filter((entry) => entry.isDirectory())
			.map(async (entry) => {
				const packagePath = path.join(repoRoot, "packages", entry.name, "package.json");
				return existsSync(packagePath) ? JSON.parse(await readFile(packagePath, "utf8")) : null;
			}))).filter(Boolean),
	});
	const properties = Array.isArray(payload.metadata?.properties) ? payload.metadata.properties : [];
	const rebound = properties.filter((entry) => entry?.name !== "aidr:source-digest" && entry?.name !== "aidr:data-digest");
	rebound.push({ name: "aidr:source-digest", value: bindings.sourceDigest });
	rebound.push({ name: "aidr:data-digest", value: bindings.dataDigest });
	payload.metadata = { ...payload.metadata, properties: rebound };
	delete payload.serialNumber;
	payload.serialNumber = `urn:uuid:${toUuid(sha256(Buffer.from(JSON.stringify(payload))))}`;
	const output = `${JSON.stringify(payload, null, 2)}\n`;
	await writeFile(destination, output, "utf8");
	await writeFile(`${destination}.sha256`, `${sha256(Buffer.from(output))}  aidr-sbom.cdx.json\n`, "utf8");
}

async function copySbomEvidence(sourcePath, destinationDir) {
	const bytes = await readFile(sourcePath);
	const digest = sha256(bytes);
	await copyFile(sourcePath, path.join(destinationDir, "aidr-sbom.cdx.json"));
	await writeFile(path.join(destinationDir, "aidr-sbom.cdx.json.sha256"), `${digest}  aidr-sbom.cdx.json\n`, "utf8");
}

async function discoverRelatedArtifacts() {
	const paths = new Set();
	const explicit = process.env.AIDR_EXTRA_ARTIFACT_PATHS?.split(path.delimiter).filter(Boolean) ?? [];
	for (const item of explicit) paths.add(path.resolve(repoRoot, item));
	for (const plugin of [".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"]) {
		if (existsSync(path.join(repoRoot, plugin))) paths.add(path.join(repoRoot, plugin));
	}
	for (const packageDir of ["packages/claude-code", "packages/openclaw", "packages/opencode", "packages/extension"]) {
		const root = path.join(repoRoot, packageDir);
		if (!existsSync(root)) continue;
		for (const file of await listFiles(root, { extensions: [".tgz", ".tar.gz", ".tar", ".zip", ".vsix", ".plugin.json", ".plugin.yaml", ".plugin.yml"] })) paths.add(file);
	}
	const functionsRoot = path.join(repoRoot, "supabase", "functions");
	if (existsSync(functionsRoot)) {
		for (const file of await listFiles(functionsRoot, { extensions: [".ts", ".js", ".json"] })) paths.add(file);
	}
	const result = [];
	for (const candidate of [...paths].sort(compareStrings)) {
		const info = await lstat(candidate);
		if (info.isSymbolicLink()) fail(`Related artifact is a symlink: ${candidate}`);
		if (!info.isFile()) fail(`Related artifact is not a file: ${candidate}`);
		if (candidate.includes(`${path.sep}node_modules${path.sep}`) || candidate.includes(`${path.sep}.git${path.sep}`)) continue;
		if (candidate.startsWith(`${path.resolve(repoRoot, ".release-evidence")}${path.sep}`)) continue;
		if (!isWithinRepo(candidate)) fail(`Related artifact must be inside the repository: ${candidate}`);
		result.push(candidate);
	}
	return result;
}

async function listFiles(root, options = {}) {
	const out = [];
	const stack = [root];
	while (stack.length) {
		const current = stack.pop();
		for (const entry of await readdir(current, { withFileTypes: true })) {
			const full = path.join(current, entry.name);
			const info = await lstat(full);
			if (info.isSymbolicLink()) fail(`Symlink is not allowed: ${full}`);
			if (info.isDirectory()) {
				if (!["node_modules", ".git", "dist", "coverage"].includes(entry.name)) stack.push(full);
			} else if (info.isFile() && (!options.extensions || options.extensions.some((ext) => full.endsWith(ext)))) out.push(full);
		}
	}
	return out;
}

async function digestPackage(packageJsonPath, distDir) {
	const files = await listFiles(distDir);
	const tuples = [{ path: "package.json", sha256: sha256(await readFile(packageJsonPath)) }];
	for (const file of files) {
		const rel = path.relative(distDir, file).replace(/\\/g, "/");
		if (rel === "aidr-artifact.manifest.json" || rel === "aidr-artifact.manifest.sig") continue;
		tuples.push({ path: `dist/${rel}`, sha256: sha256(await readFile(file)) });
	}
	tuples.sort((a, b) => compareStrings(a.path, b.path));
	return `sha256:${sha256(Buffer.from(JSON.stringify(tuples)))}`;
}

async function digestDataRoots() {
	const roots = ["packages/core/src/generated", "threats", "allowlists"]
		.map((item) => path.join(repoRoot, item))
		.filter((item) => existsSync(item));
	const tuples = [];
	for (const root of roots) {
		for (const file of await listFiles(root)) tuples.push({ path: path.relative(repoRoot, file).replace(/\\/g, "/"), sha256: sha256(await readFile(file)) });
	}
	if (commercial && tuples.length === 0) fail("Commercial release has no source data roots to digest.");
	tuples.sort((a, b) => compareStrings(a.path, b.path));
	return `sha256:${sha256(Buffer.from(JSON.stringify(tuples)))}`;
}

function normalizeFingerprint(value) {
	const normalized = String(value).toLowerCase().replace(/^sha256:/, "");
	if (!/^[0-9a-f]{64}$/.test(normalized)) fail("AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT must be SHA-256 hex.");
	return `sha256:${normalized}`;
}

function readSha256Sidecar(filePath) {
	const [value] = readFileSync(filePath, "utf8").trim().split(/\s+/, 1);
	if (!/^[0-9a-f]{64}$/i.test(value ?? "")) fail(`Invalid SBOM checksum sidecar: ${filePath}`);
	return value.toLowerCase();
}

function classifyArtifact(relativePath) {
	if (/\.vsix$/i.test(relativePath)) return "vsix";
	if (/\.(?:tgz|tar\.gz|tar|zip)$/i.test(relativePath)) return "tarballs";
	if (/plugin\.(?:json|yaml|yml)$/i.test(relativePath) || relativePath.includes(".claude-plugin/")) return "plugins";
	if (relativePath.startsWith("supabase/functions/")) return "functions";
	return "other";
}

function run(argv, env = process.env, options = {}) {
	const result = spawnSync(process.execPath, argv, { cwd: repoRoot, env, stdio: "inherit" });
	if (result.error || result.status !== 0) {
		if (options.allowFailure) return false;
		process.exit(result.status ?? 1);
	}
	return true;
}

function resolveGitSha() {
	const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" });
	if (result.status !== 0) fail("Unable to derive git SHA.");
	return String(result.stdout).trim();
}

function resolveGitTimestamp() {
	const result = spawnSync("git", ["show", "-s", "--format=%ct", "HEAD"], { cwd: repoRoot, encoding: "utf8" });
	const value = Number(String(result.stdout ?? "").trim());
	if (result.status !== 0 || !Number.isInteger(value) || value < 0) fail("Unable to derive SOURCE_DATE_EPOCH from git.");
	return String(value);
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function toUuid(hex) {
	const chars = hex.slice(0, 32).split("");
	chars[12] = "5";
	chars[16] = ((Number.parseInt(chars[16], 16) & 0x3) | 0x8).toString(16);
	return `${chars.slice(0, 8).join("")}-${chars.slice(8, 12).join("")}-${chars.slice(12, 16).join("")}-${chars.slice(16, 20).join("")}-${chars.slice(20, 32).join("")}`;
}

function assertNoPrivateSigningMaterial() {
	const names = [
		"AIDR_SIGNING_PRIVATE_KEY_PEM_PATH",
		"AIDR_SIGNING_PRIVATE_KEY_PEM",
		"AIDR_RELEASE_SIGNING_PRIVATE_KEY_PATH",
		"AIG_DATA_SIGNING_PRIVATE_KEY_PEM",
		"AIG_PRIVATE_KEY_PEM",
		"AIG_SIGNING_PRIVATE_KEY",
		"AIG_SIGNING_PRIVATE_KEY_PATH",
		"SIGNING_PRIVATE_KEY",
	].filter((name) => process.env[name]);
	if (names.length > 0) fail(`Artifact preparation refuses private signing material: ${names.join(", ")}`);
}

function compareStrings(a, b) {
	return a < b ? -1 : a > b ? 1 : 0;
}

function isWithinRepo(candidate) {
	const root = path.resolve(repoRoot);
	const resolved = path.resolve(candidate);
	return resolved === root || resolved.startsWith(`${root}${path.sep}`);
}

function fail(message) {
	console.error(`ERROR: ${message}`);
	process.exit(1);
}
