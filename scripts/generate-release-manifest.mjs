#!/usr/bin/env node
/**
 * Generate the download-center release manifest (docs/contracts/release-manifest.md)
 * from a directory of release artifacts.
 *
 * Every artifact's sha256 and size are computed from the bytes on disk, so the
 * manifest can only describe files that exist in the release directory. The
 * output is validated with the same rules the dashboard server applies before
 * serving /release-manifest.json.
 *
 * Usage:
 *   node scripts/generate-release-manifest.mjs --dir <artifact-dir> --version <semver>
 *     --base-url https://downloads.example.com/aidr/<version>/
 *     [--published-at <RFC 3339>] [--out <file>]
 *     [--artifact <id>=<relative-file>[@platform,platform]]...
 *
 * Files are matched to artifact ids by their release file names (see
 * DEFAULT_PATTERNS). --artifact maps a file explicitly and overrides the
 * patterns for that file. A sibling "<file>.sig" becomes the artifact's
 * detached-signature URL. Files that match nothing are reported on stderr and
 * left out. publishedAt defaults to SOURCE_DATE_EPOCH when set, else now.
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
	assertHttpsUrl,
	RELEASE_ARTIFACT_IDS,
	validateReleaseManifest,
} from "../deploy/dashboard/release-manifest.mjs";

/** Release file names produced by scripts/build-release-candidate.mjs and the extension/browser builds. */
const DEFAULT_PATTERNS = Object.freeze([
	{ id: "claude-code", pattern: /^aidr-claude-plugin(?:-[^/]*)?\.tar\.gz$/ },
	{ id: "cursor", pattern: /^aidr-cursor(?:-[^/]*)?\.vsix$/ },
	{ id: "vscode", pattern: /^aidr-vscode(?:-[^/]*)?\.vsix$/ },
	{ id: "openclaw", pattern: /^singularityrd-aidr-openclaw-[^/]+\.tgz$/ },
	{ id: "opencode", pattern: /^singularityrd-aidr-opencode-[^/]+\.tgz$/ },
	{ id: "codex", pattern: /^singularityrd-aidr-codex-[^/]+\.tgz$/ },
	{ id: "cli", pattern: /^(?:singularityrd-aidr-cli-[^/]+\.tgz|aidr-cli-[^/]+)$/ },
	{ id: "browser-guard-chrome", pattern: /^aidr-browser-guard-chrome(?:-[^/]*)?\.zip$/ },
	{ id: "browser-guard-firefox", pattern: /^aidr-browser-guard-firefox(?:-[^/]*)?\.(?:xpi|zip)$/ },
	{ id: "mcp-gateway", pattern: /^(?:singularityrd-aidr-mcp-gateway-[^/]+\.tgz|aidr-mcp-gateway(?:-[^/]*)?\.tar\.gz)$/ },
]);

const SIDE_FILE_RE = /\.(?:sig|sha256)$/;
const SEMVER_IN_NAME_RE = /\d+\.\d+\.\d+/;
const PLATFORM_IN_NAME_RE = /(?:^|[-_.])(linux|darwin|macos|win32|windows)[-_](x64|arm64)(?=$|[-_.])/;
const PLATFORM_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;

function fail(message) {
	throw new Error(`generate-release-manifest: ${message}`);
}

function parseArgs(argv) {
	const values = { artifact: [] };
	for (let index = 0; index < argv.length; index++) {
		const flag = argv[index];
		const value = argv[index + 1];
		if (!["--dir", "--version", "--base-url", "--published-at", "--out", "--artifact"].includes(flag)) {
			fail(`unknown argument ${flag}`);
		}
		if (value === undefined || value.startsWith("--")) fail(`${flag} requires a value`);
		index++;
		if (flag === "--artifact") values.artifact.push(value);
		else values[flag.slice(2)] = value;
	}
	return values;
}

function parseArtifactOverride(spec) {
	const match = /^([a-z-]+)=([^@]+)(?:@([a-z0-9_,-]+))?$/.exec(spec);
	if (!match) fail(`--artifact must look like <id>=<relative-file>[@platform,platform], got ${spec}`);
	const [, id, file, platformList] = match;
	if (!RELEASE_ARTIFACT_IDS.includes(id)) fail(`--artifact uses unsupported id ${id}`);
	const platforms = platformList ? platformList.split(",") : null;
	if (platforms && !platforms.every((platform) => PLATFORM_RE.test(platform))) {
		fail(`--artifact ${spec} has an invalid platform`);
	}
	return { id, file: path.posix.normalize(file.replaceAll("\\", "/")), platforms };
}

async function listFiles(root, relative = "") {
	const entries = await readdir(path.join(root, relative), { withFileTypes: true });
	const files = [];
	for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
		const entryRelative = relative ? `${relative}/${entry.name}` : entry.name;
		const info = await lstat(path.join(root, entryRelative));
		if (info.isSymbolicLink()) fail(`refusing symlink ${entryRelative}; release artifacts must be regular files`);
		if (info.isDirectory()) files.push(...(await listFiles(root, entryRelative)));
		else if (info.isFile()) files.push({ relative: entryRelative, size: info.size });
	}
	return files;
}

function sha256File(file) {
	return new Promise((resolve, reject) => {
		const hash = createHash("sha256");
		createReadStream(file)
			.on("data", (chunk) => hash.update(chunk))
			.on("error", reject)
			.on("end", () => resolve(hash.digest("hex")));
	});
}

export function inferPlatforms(id, fileName) {
	if (id === "browser-guard-chrome") return ["chrome", "edge"];
	if (id === "browser-guard-firefox") return ["firefox"];
	const match = PLATFORM_IN_NAME_RE.exec(fileName.toLowerCase());
	if (!match) return ["any"];
	const os = { macos: "darwin", windows: "win32" }[match[1]] ?? match[1];
	return [`${os}-${match[2]}`];
}

function publicUrl(baseUrl, relative) {
	return new URL(relative.split("/").map(encodeURIComponent).join("/"), baseUrl).href;
}

function resolvePublishedAt(explicit, env) {
	if (explicit) return explicit;
	if (env.SOURCE_DATE_EPOCH) {
		const seconds = Number(env.SOURCE_DATE_EPOCH);
		if (!Number.isSafeInteger(seconds) || seconds < 0) fail("SOURCE_DATE_EPOCH must be a non-negative integer");
		return new Date(seconds * 1000).toISOString();
	}
	return new Date().toISOString();
}

/**
 * Build and validate a manifest. Returns { manifest, skipped } where skipped
 * lists the relative paths that matched no artifact id.
 */
export async function generateReleaseManifest({ dir, version, baseUrl, publishedAt, artifacts = [], env = process.env }) {
	if (!dir) fail("--dir is required");
	if (!version) fail("--version is required");
	if (!baseUrl) fail("--base-url is required");
	try {
		assertHttpsUrl(baseUrl, "--base-url");
	} catch (error) {
		fail(error instanceof Error ? error.message : String(error));
	}
	const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
	const root = path.resolve(dir);
	const files = await listFiles(root);
	const present = new Map(files.map((file) => [file.relative, file]));
	const overrides = new Map();
	for (const override of artifacts.map(parseArtifactOverride)) {
		if (!present.has(override.file)) fail(`--artifact file ${override.file} does not exist in ${dir}`);
		if (overrides.has(override.file)) fail(`--artifact maps ${override.file} more than once`);
		overrides.set(override.file, override);
	}

	const entries = [];
	const skipped = [];
	for (const file of files) {
		const fileName = path.posix.basename(file.relative);
		const override = overrides.get(file.relative);
		if (!override && SIDE_FILE_RE.test(fileName)) continue;
		const id = override?.id ?? DEFAULT_PATTERNS.find(({ pattern }) => pattern.test(fileName))?.id;
		if (!id) {
			skipped.push(file.relative);
			continue;
		}
		if (SEMVER_IN_NAME_RE.test(fileName) && !fileName.includes(version)) {
			fail(`${file.relative} names a different version than --version ${version}`);
		}
		if (file.size < 1) fail(`${file.relative} is empty`);
		const signatureFile = present.get(`${file.relative}.sig`);
		entries.push({
			id,
			version,
			url: publicUrl(base, file.relative),
			sha256: await sha256File(path.join(root, file.relative)),
			...(signatureFile && signatureFile.size > 0 ? { signature: publicUrl(base, signatureFile.relative) } : {}),
			size: file.size,
			platforms: override?.platforms ?? inferPlatforms(id, fileName),
		});
	}
	if (entries.length === 0) fail(`no release artifacts recognized in ${dir}`);
	entries.sort(
		(left, right) =>
			RELEASE_ARTIFACT_IDS.indexOf(left.id) - RELEASE_ARTIFACT_IDS.indexOf(right.id) ||
			left.url.localeCompare(right.url),
	);
	const manifest = validateReleaseManifest({
		version,
		publishedAt: resolvePublishedAt(publishedAt, env),
		artifacts: entries,
	});
	return { manifest, skipped };
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	const { manifest, skipped } = await generateReleaseManifest({
		dir: args.dir,
		version: args.version,
		baseUrl: args["base-url"],
		publishedAt: args["published-at"],
		artifacts: args.artifact,
	});
	for (const relative of skipped) process.stderr.write(`skipped (no artifact id matched): ${relative}\n`);
	const json = `${JSON.stringify(manifest, null, "\t")}\n`;
	if (args.out) {
		await writeFile(args.out, json, { mode: 0o644 });
		process.stderr.write(`wrote ${manifest.artifacts.length} artifact(s) to ${args.out}\n`);
	} else {
		process.stdout.write(json);
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
	main().catch((error) => {
		process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
		process.exitCode = 1;
	});
}
