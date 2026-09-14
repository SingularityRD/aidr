#!/usr/bin/env node
/**
 * Generate and verify a local in-toto/SLSA-style provenance statement for the
 * release artifacts described by `scripts/release-artifact-manifests.mjs`.
 *
 * The statement binds, by digest:
 *   - `subject`    every `aidr-artifact.manifest.json` produced for a released
 *                  artifact (named by its `artifact_id`);
 *   - `materials`  the `pnpm-lock.yaml` dependency lock used for the build;
 *   - `byproducts` the CycloneDX SBOM copied beside the artifacts.
 *
 * Boundary: this is an unsigned, locally constructed predicate. It proves that
 * the recorded digests still match the files on disk, so a changed manifest,
 * lockfile, or SBOM is detected. It is *not* a signed attestation, does not
 * carry a publisher identity, is not registered in a transparency log, and does
 * not replace publisher key custody or registry publication (DEP-05), which
 * remain external. `--verify-provenance` is deliberately usable offline and
 * never contacts a network or Docker daemon.
 *
 * Usage:
 *   node scripts/generate-provenance.mjs [--artifact-dir <dir>]... [--lockfile <file>]
 *     [--sbom <file>] [--output <file>] [--builder-id <id>]
 *   node scripts/generate-provenance.mjs --verify-provenance [--provenance <file>]
 *     [--artifact-dir <dir>]... [--lockfile <file>] [--sbom <file>]
 *
 * `--artifact-dir` may be repeated. Without it the built `dist` directory of
 * each released package is used; directories that do not exist are skipped
 * unless the directory was requested explicitly.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1";
const PREDICATE_TYPE = "https://slsa.dev/provenance/v0.2";
const BUILD_TYPE = "https://singularityrd.dev/aidr/release-artifact-manifests/v1";
const MANIFEST_NAME = "aidr-artifact.manifest.json";
const DEFAULT_OUTPUT = ".release-evidence/aidr-provenance.intoto.json";
const DEFAULT_LOCKFILE = "pnpm-lock.yaml";
const DEFAULT_SBOM = ".release-evidence/aidr-sbom.cdx.json";
const DEFAULT_BUILDER_ID = "urn:aidr:release-provenance-builder:v1";
const DEFAULT_ARTIFACT_DIRS = [
	"packages/core/dist",
	"packages/claude-code/dist",
	"packages/extension/dist",
	"packages/openclaw/dist",
	"packages/opencode/dist",
	"packages/cli/dist",
	"packages/sdk/dist",
	"packages/dashboard/dist",
	"packages/codex/dist",
	"packages/mcp-gateway/dist",
];

const repoRoot = path.resolve(process.cwd());
const options = parseArguments(process.argv.slice(2));

if (options.verifyProvenance) await verifyProvenance();
else await generateProvenance();

async function generateProvenance() {
	const artifactDirs = resolveArtifactDirs();
	const subjects = [];
	for (const entry of artifactDirs) {
		const manifestPath = path.join(entry.dir, MANIFEST_NAME);
		if (!existsSync(manifestPath)) {
			if (entry.explicit) fail(`artifact manifest is missing: ${manifestPath}`);
			continue;
		}
		const manifest = readManifest(manifestPath);
		subjects.push({
			name: manifest.artifact_id,
			digest: { sha256: sha256(readFileSync(manifestPath)) },
		});
	}
	if (subjects.length === 0) {
		fail(`no ${MANIFEST_NAME} files were found; build the release artifacts before generating provenance`);
	}
	assertUniqueSubjectNames(subjects);
	subjects.sort((a, b) => compareStrings(a.name, b.name));

	const lockfilePath = resolveInput(options.lockfile ?? DEFAULT_LOCKFILE);
	if (!existsSync(lockfilePath)) fail(`lockfile is missing: ${lockfilePath}`);
	const materials = [
		{ uri: fileUri(lockfilePath), digest: { sha256: sha256(readFileSync(lockfilePath)) } },
	];

	const byproducts = [];
	const sbomPath = resolveInput(options.sbom ?? DEFAULT_SBOM);
	if (existsSync(sbomPath)) {
		byproducts.push({ uri: fileUri(sbomPath), digest: { sha256: sha256(readFileSync(sbomPath)) } });
	} else if (options.sbom) {
		fail(`SBOM is missing: ${sbomPath}`);
	} else {
		console.warn(`WARN: no SBOM at ${sbomPath}; the provenance statement carries no byproduct digest.`);
	}

	const statement = {
		_type: STATEMENT_TYPE,
		subject: subjects,
		predicateType: PREDICATE_TYPE,
		predicate: {
			builder: { id: options.builderId ?? process.env.AIDR_BUILDER_ID ?? DEFAULT_BUILDER_ID },
			buildType: BUILD_TYPE,
			invocation: {
				parameters: {
					artifact_dirs: artifactDirs.map((entry) => relativeDisplay(entry.dir)),
					lockfile: relativeDisplay(lockfilePath),
					sbom: byproducts.length > 0 ? relativeDisplay(sbomPath) : null,
					release_version: process.env.AIDR_RELEASE_VERSION ?? process.env.AIDR_RC_VERSION ?? null,
					git_sha: process.env.AIDR_BUILD_ID ?? process.env.GITHUB_SHA ?? null,
					ci_run_id: process.env.GITHUB_RUN_ID ?? null,
				},
				environment: { build_host: process.env.GITHUB_ACTIONS ? "github_actions" : "local" },
			},
			metadata: {
				buildStartedOn: buildTimestamp(),
				buildFinishedOn: buildTimestamp(),
				completeness: { parameters: true, environment: false, materials: true },
				reproducible: false,
			},
			materials,
			byproducts,
		},
	};

	const outputPath = resolveInput(options.output ?? DEFAULT_OUTPUT);
	await mkdir(path.dirname(outputPath), { recursive: true });
	await writeFile(outputPath, `${JSON.stringify(statement, null, 2)}\n`, "utf8");
	console.log(
		JSON.stringify({
			status: "generated",
			output: relativeDisplay(outputPath),
			subjects: subjects.length,
			materials: materials.length,
			byproducts: byproducts.length,
		}),
	);
}

async function verifyProvenance() {
	const provenancePath = resolveInput(options.provenance ?? options.output ?? DEFAULT_OUTPUT);
	if (!existsSync(provenancePath)) fail(`provenance file is missing: ${provenancePath}`);
	if (!statSync(provenancePath).isFile()) fail(`provenance must be a regular file: ${provenancePath}`);
	let statement;
	try {
		statement = JSON.parse(readFileSync(provenancePath, "utf8"));
	} catch (error) {
		fail(`provenance is not valid JSON: ${formatError(error)}`);
	}
	if (!statement || typeof statement !== "object" || Array.isArray(statement)) fail("provenance must be a JSON object");
	if (statement._type !== STATEMENT_TYPE) fail(`unexpected provenance statement type: ${String(statement._type)}`);
	if (statement.predicateType !== PREDICATE_TYPE) fail(`unexpected provenance predicate type: ${String(statement.predicateType)}`);
	const predicate = statement.predicate;
	if (!predicate || typeof predicate !== "object" || Array.isArray(predicate)) fail("provenance predicate is missing");
	if (typeof predicate.builder?.id !== "string" || predicate.builder.id === "") fail("provenance builder id is missing");

	const declared = new Map();
	for (const subject of asArray(statement.subject, "provenance subject")) {
		if (!subject || typeof subject.name !== "string" || subject.name === "") fail("provenance subject entry is missing a name");
		if (declared.has(subject.name)) fail(`provenance names the same subject twice: ${subject.name}`);
		declared.set(subject.name, assertHexDigest(subject.digest?.sha256, `subject ${subject.name}`));
	}
	if (declared.size === 0) fail("provenance declares no subjects");

	const discovered = new Map();
	for (const entry of resolveArtifactDirs()) {
		const manifestPath = path.join(entry.dir, MANIFEST_NAME);
		if (!existsSync(manifestPath)) {
			if (entry.explicit) fail(`artifact manifest is missing: ${manifestPath}`);
			continue;
		}
		const manifest = readManifest(manifestPath);
		if (discovered.has(manifest.artifact_id)) fail(`duplicate artifact manifest for ${manifest.artifact_id}`);
		discovered.set(manifest.artifact_id, sha256(readFileSync(manifestPath)));
	}
	if (discovered.size === 0) fail(`no ${MANIFEST_NAME} files were found to verify against`);

	for (const [name, digest] of declared) {
		const actual = discovered.get(name);
		if (!actual) fail(`provenance subject ${name} has no matching artifact manifest in the verified directories`);
		if (actual !== digest) {
			fail(`artifact manifest digest mismatch for ${name}: provenance declares sha256:${digest} but the bundle has sha256:${actual}`);
		}
	}
	for (const name of discovered.keys()) {
		if (!declared.has(name)) fail(`artifact manifest ${name} is not named in the provenance`);
	}

	const materials = asArray(predicate.materials, "provenance materials");
	if (materials.length === 0) fail("provenance declares no build materials");
	const lockfilePath = resolveInput(options.lockfile ?? DEFAULT_LOCKFILE);
	if (!existsSync(lockfilePath)) fail(`lockfile is missing: ${lockfilePath}`);
	const lockfileBasename = path.basename(lockfilePath);
	const lockMaterial = materials.find((entry) => uriBasename(entry?.uri) === lockfileBasename);
	if (!lockMaterial) fail(`provenance does not declare the lockfile material ${lockfileBasename}`);
	const declaredLockDigest = assertHexDigest(lockMaterial.digest?.sha256, "lockfile material");
	const actualLockDigest = sha256(readFileSync(lockfilePath));
	if (declaredLockDigest !== actualLockDigest) {
		fail(`lockfile material digest mismatch: provenance declares sha256:${declaredLockDigest} but the lockfile has sha256:${actualLockDigest}`);
	}

	const byproducts = asArray(predicate.byproducts ?? [], "provenance byproducts");
	for (const byproduct of byproducts) {
		const declaredDigest = assertHexDigest(byproduct?.digest?.sha256, `byproduct ${byproduct?.uri ?? "?"}`);
		const candidate = resolveInput(options.sbom ?? DEFAULT_SBOM);
		const candidateBasename = path.basename(candidate);
		const uriName = uriBasename(byproduct?.uri);
		if (uriName !== candidateBasename) {
			fail(`provenance declares byproduct ${String(byproduct?.uri)} but the verifier was given ${candidateBasename}`);
		}
		if (!existsSync(candidate)) fail(`provenance declares byproduct ${uriName} but it is not present at ${candidate}`);
		const actualDigest = sha256(readFileSync(candidate));
		if (actualDigest !== declaredDigest) {
			fail(`byproduct digest mismatch for ${uriName}: provenance declares sha256:${declaredDigest} but the file has sha256:${actualDigest}`);
		}
	}

	console.log(
		JSON.stringify({
			status: "verified",
			provenance: relativeDisplay(provenancePath),
			subjects: declared.size,
			materials: materials.length,
			byproducts: byproducts.length,
		}),
	);
}

function resolveArtifactDirs() {
	const requested = options.artifactDirs.length > 0 ? options.artifactDirs : DEFAULT_ARTIFACT_DIRS;
	const explicit = options.artifactDirs.length > 0;
	const seen = new Set();
	const resolved = [];
	for (const value of requested) {
		const dir = resolveInput(value);
		if (seen.has(dir)) continue;
		seen.add(dir);
		if (!existsSync(dir)) {
			if (explicit) fail(`artifact directory does not exist: ${dir}`);
			continue;
		}
		if (!statSync(dir).isDirectory()) fail(`artifact directory is not a directory: ${dir}`);
		resolved.push({ dir, explicit });
	}
	return resolved;
}

function readManifest(manifestPath) {
	let manifest;
	try {
		manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
	} catch (error) {
		fail(`unable to read artifact manifest ${manifestPath}: ${formatError(error)}`);
	}
	if (!manifest || typeof manifest !== "object" || typeof manifest.artifact_id !== "string" || manifest.artifact_id === "") {
		fail(`artifact manifest is missing artifact_id: ${manifestPath}`);
	}
	return manifest;
}

function assertUniqueSubjectNames(subjects) {
	const names = new Set();
	for (const subject of subjects) {
		if (names.has(subject.name)) fail(`duplicate artifact_id in artifact manifests: ${subject.name}`);
		names.add(subject.name);
	}
}

function assertHexDigest(value, label) {
	if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
		fail(`${label} must carry a lowercase sha256:<64 hex> digest`);
	}
	return value;
}

function asArray(value, label) {
	if (!Array.isArray(value)) fail(`${label} must be an array`);
	return value;
}

function resolveInput(value) {
	return path.resolve(repoRoot, value);
}

function relativeDisplay(absolutePath) {
	const relative = path.relative(repoRoot, absolutePath);
	if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) return toPosix(absolutePath);
	return toPosix(relative);
}

function fileUri(absolutePath) {
	return `file:${relativeDisplay(absolutePath)}`;
}

function uriBasename(uri) {
	if (typeof uri !== "string") return "";
	const withoutScheme = uri.replace(/^file:/, "").split(/[?#]/, 1)[0];
	return withoutScheme.split("/").pop() ?? "";
}

function buildTimestamp() {
	const raw = process.env.SOURCE_DATE_EPOCH;
	if (raw !== undefined && raw !== "") {
		const seconds = Number(raw);
		if (Number.isFinite(seconds) && seconds >= 0) return new Date(seconds * 1000).toISOString();
	}
	return new Date().toISOString();
}

function toPosix(value) {
	return value.replace(/\\/g, "/");
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function compareStrings(a, b) {
	return a < b ? -1 : a > b ? 1 : 0;
}

function parseArguments(argv) {
	const parsed = {
		artifactDirs: [],
		lockfile: undefined,
		sbom: undefined,
		output: undefined,
		provenance: undefined,
		builderId: undefined,
		verifyProvenance: false,
	};
	for (let index = 0; index < argv.length; index += 1) {
		const flag = argv[index];
		if (flag === "--verify-provenance") {
			parsed.verifyProvenance = true;
			continue;
		}
		if (!["--artifact-dir", "--lockfile", "--sbom", "--output", "--provenance", "--builder-id"].includes(flag)) {
			fail(`unknown argument: ${flag ?? ""}`);
		}
		const value = argv[index + 1];
		if (!value || value.startsWith("--")) fail(`missing value for ${flag}`);
		index += 1;
		if (flag === "--artifact-dir") parsed.artifactDirs.push(value);
		else if (flag === "--lockfile") parsed.lockfile = value;
		else if (flag === "--sbom") parsed.sbom = value;
		else if (flag === "--output") parsed.output = value;
		else if (flag === "--provenance") parsed.provenance = value;
		else if (flag === "--builder-id") parsed.builderId = value;
	}
	return parsed;
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}

function fail(message) {
	console.error(`ERROR: ${message}`);
	process.exit(1);
}
