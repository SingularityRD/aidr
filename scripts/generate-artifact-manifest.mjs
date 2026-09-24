/**
 * Generate a deterministic, tamper-evident manifest for a release artifact.
 *
 * The manifest hashes every shipped byte. It intentionally rejects symlinks,
 * source maps, obvious secret material, and host-path leaks instead of
 * silently omitting them. Commercial release wrappers add the provenance
 * block (RC/git/source/data/package/SBOM digests) before signing.
 *
 * Usage:
 *   node scripts/generate-artifact-manifest.mjs --dir <dir> --id <id> --version <version>
 *     [--rc-version <version>] [--git-sha <sha>] [--source-digest <digest>]
 *     [--data-digest <digest>] [--image-digest <digest>] [--package-digest <digest>]
 *     [--lockfile-digest <digest>] [--sbom-digest <digest>]
 *     [--key-id <id>] [--key-fingerprint <sha256:fingerprint>]
 *
 * The final release wrapper sets AIDR_FINAL_MANIFEST=1. Developer package
 * builds may still create unsigned manifests without commercial provenance.
 */

import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { lstat, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const SECRET_PATH_RE = /(^|\/)(?:\.env(?:\.|$)|[^/]+\.(?:pem|key|p12|pfx|jks|keystore|crt|csr|secret|token))$/i;
const SECRET_CONTENT_PATTERNS = [
	/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
	/\bAKIA[0-9A-Z]{16}\b/,
	/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/,
	/\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
	/\bxox[baprs]-[A-Za-z0-9-]{20,}\b/,
	/\bsk-[A-Za-z0-9_-]{20,}\b/,
];
// These values are the public examples used by our DLP tests and generated
// declaration docs. They are only ignored when they occur inside a source
// comment; the same values in executable strings remain blocked.
const DOCUMENTATION_SECRET_VALUES = new Set(["AKIAIOSFODNN7EXAMPLE"]);
const LEAK_PATTERNS = [
	/[A-Za-z]:\\Users\\[^\s"']+/,
	/(?:^|[\s"'`])\/(?:Users|home|root)\/[^\s"'`]+/,
	/(?:^|[\s"'`])(?:[A-Za-z]:[\\/]|\/)[^\s"'`]*node_modules[\\/]\.pnpm[\\/][^\s"'`]+/i,
];

const args = parseArgs(process.argv.slice(2));
const dir = path.resolve(args["--dir"] ?? ".");
const pkg = tryReadLocalPackageJson();
const artifactId = args["--id"] ?? args["--artifact-id"] ?? pkg?.name;
const artifactVersion = args["--version"] ?? pkg?.version;
const keyId = args["--key-id"] ?? process.env.AIDR_SIGNING_KEY_ID;
const keyFingerprint = args["--key-fingerprint"] ?? process.env.AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT;
const watermarkId = args["--watermark-id"] ?? process.env.AIDR_WATERMARK_ID;
const issuedTo = args["--issued-to"] ?? process.env.AIDR_WATERMARK_ISSUED_TO;
const channel = args["--channel"] ?? process.env.AIDR_WATERMARK_CHANNEL;
const rcVersion = args["--rc-version"] ?? process.env.AIDR_RC_VERSION ?? process.env.AIDR_RELEASE_VERSION;
const buildId =
	args["--build-id"] ??
	process.env.AIDR_BUILD_ID ??
	process.env.GITHUB_RUN_ID ??
	process.env.CI_PIPELINE_ID;
const gitSha = args["--git-sha"] ?? process.env.AIDR_GIT_SHA ?? process.env.GITHUB_SHA ?? process.env.CI_COMMIT_SHA;
const ciProvider =
	args["--ci-provider"] ??
	(process.env.GITHUB_ACTIONS ? "github_actions" : process.env.CI ? "ci" : undefined);
const ciRunId = args["--ci-run-id"] ?? process.env.GITHUB_RUN_ID ?? process.env.CI_JOB_ID;
const nonceB64 = args["--nonce-b64"] ?? process.env.AIDR_WATERMARK_NONCE_B64;
const deterministic = process.env.AIDR_DETERMINISTIC_MANIFEST === "1";
const finalManifest = process.env.AIDR_FINAL_MANIFEST === "1";

if (!artifactId || !artifactVersion) {
	console.error("Missing required args: --id <artifactId> --version <version>");
	process.exit(2);
}

const files = artifactId === "claude-code/package" ? await listEndpointPackageFiles(dir) : await listFilesRecursive(dir);
const included = files
	.map((abs) => path.relative(dir, abs).replace(/\\/g, "/"))
	.filter((rel) => rel !== "aidr-artifact.manifest.json" && rel !== "aidr-artifact.manifest.sig");
included.sort(compareStrings);

const entries = [];
for (const rel of included) {
	const abs = path.join(dir, rel);
	const bytes = await readFile(abs);
	validateFile(rel, bytes);
	entries.push({ path: rel, sha256: createHash("sha256").update(bytes).digest("hex") });
}

const provenance = {
	schema_version: 1,
	rc_version: rcVersion ?? artifactVersion,
	...(gitSha ? { git_sha: gitSha } : {}),
	...(resolveDigest(args["--source-digest"], process.env.AIDR_SOURCE_DIGEST, "source")
		? { source_digest: resolveDigest(args["--source-digest"], process.env.AIDR_SOURCE_DIGEST, "source") }
		: {}),
	...(resolveDigest(args["--data-digest"], process.env.AIDR_DATA_DIGEST, "data")
		? { data_digest: resolveDigest(args["--data-digest"], process.env.AIDR_DATA_DIGEST, "data") }
		: {}),
	...(resolveDigest(args["--image-digest"], process.env.AIDR_IMAGE_DIGEST, "image")
		? { image_digest: resolveDigest(args["--image-digest"], process.env.AIDR_IMAGE_DIGEST, "image") }
		: {}),
	...(resolveDigest(args["--package-digest"], process.env.AIDR_PACKAGE_DIGEST, "package")
		? { package_digest: resolveDigest(args["--package-digest"], process.env.AIDR_PACKAGE_DIGEST, "package") }
		: {}),
	...(resolveDigest(args["--lockfile-digest"], process.env.AIDR_LOCKFILE_DIGEST, "lockfile")
		? { lockfile_digest: resolveDigest(args["--lockfile-digest"], process.env.AIDR_LOCKFILE_DIGEST, "lockfile") }
		: {}),
	...(resolveDigest(args["--sbom-digest"], process.env.AIDR_SBOM_DIGEST, "sbom")
		? { sbom_digest: resolveDigest(args["--sbom-digest"], process.env.AIDR_SBOM_DIGEST, "sbom") }
		: {}),
};

if (finalManifest) validateFinalProvenance(provenance);

const createdAt = resolveCreatedAt();
const deterministicNonce =
	nonceB64 ??
	(deterministic
		? createHash("sha256")
				.update(`${artifactId}\0${artifactVersion}\0${gitSha ?? ""}\0${provenance.source_digest ?? ""}`)
				.digest()
				.subarray(0, 16)
				.toString("base64")
		: randomBytes(16).toString("base64"));

const manifest = {
	schema_version: 1,
	artifact_id: artifactId,
	artifact_version: artifactVersion,
	created_at: createdAt,
	...(keyId ? { key_id: keyId } : {}),
	...(keyFingerprint ? { key_fingerprint: normalizeFingerprint(keyFingerprint) } : {}),
	files: entries,
	provenance,
	...(watermarkId
		? {
				lineage: {
					watermark_id: watermarkId,
					...(issuedTo ? { issued_to: issuedTo } : {}),
					...(channel ? { channel } : {}),
					nonce_b64: deterministicNonce,
					...(buildId ? { build_id: buildId } : {}),
					...(gitSha ? { git_sha: gitSha } : {}),
					...(ciProvider ? { ci_provider: ciProvider } : {}),
					...(ciRunId ? { ci_run_id: ciRunId } : {}),
				},
			}
		: {}),
};

await writeFile(path.join(dir, "aidr-artifact.manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
console.log(`Wrote ${path.join(dir, "aidr-artifact.manifest.json")}`);

async function listFilesRecursive(root) {
	const rootStat = await lstat(root);
	if (!rootStat.isDirectory()) throw new Error(`Artifact root is not a directory: ${root}`);
	const out = [];
	const stack = [root];
	while (stack.length) {
		const current = stack.pop();
		const entriesInDir = await readdir(current, { withFileTypes: true });
		entriesInDir.sort((a, b) => compareStrings(a.name, b.name));
		for (const entry of entriesInDir) {
			const full = path.join(current, entry.name);
			const info = await lstat(full);
			if (info.isSymbolicLink()) throw new Error(`Symlink is not allowed in release artifact: ${full}`);
			if (info.isDirectory()) stack.push(full);
			else if (info.isFile()) out.push(full);
			else throw new Error(`Unsupported filesystem entry in release artifact: ${full}`);
		}
	}
	return out;
}

async function listEndpointPackageFiles(root) {
	const packageJson = path.join(root, "package.json");
	const packageInfo = await lstat(packageJson);
	if (!packageInfo.isFile() || packageInfo.isSymbolicLink()) throw new Error("Claude endpoint package requires a regular package.json");
	const files = [packageJson];
	for (const name of ["dist", "resources"]) files.push(...(await listFilesRecursive(path.join(root, name))));
	return files;
}

function validateFile(rel, bytes) {
	if (/\.map$/i.test(rel)) throw new Error(`Source map is not allowed in release artifact: ${rel}`);
	if (SECRET_PATH_RE.test(rel)) throw new Error(`Secret-looking file is not allowed in release artifact: ${rel}`);
	if (bytes.includes(0)) return;
	const text = bytes.toString("utf8");
	const codeLike = isCodeLike(rel);
	const maskedSource = codeLike ? maskCodeComments(text) : { text, ranges: [] };
	const codeText = maskedSource.text;
	for (const pattern of SECRET_CONTENT_PATTERNS) {
		if (pattern.test(codeText)) throw new Error(`Secret-like content is not allowed in release artifact: ${rel}`);
		if (!codeLike) continue;
		for (const match of findMatches(text, pattern)) {
			const index = match.index ?? -1;
			const masked = index >= 0 ? codeText.slice(index, index + match[0].length) : "";
			const maskRange = maskedSource.ranges.find(
				(range) => index >= range.start && index + match[0].length <= range.end,
			);
			const allowedCommentExample = maskRange?.kind === "comment" && DOCUMENTATION_SECRET_VALUES.has(match[0]);
			const allowedRegexLiteral = maskRange?.kind === "regex";
			if (!masked || !/^\s*$/.test(masked) || (!allowedCommentExample && !allowedRegexLiteral)) {
				throw new Error(`Secret-like content is not allowed in release artifact: ${rel}`);
			}
		}
	}
	for (const pattern of LEAK_PATTERNS) {
		if (pattern.test(codeText)) throw new Error(`Host-path leak is not allowed in release artifact: ${rel}`);
	}
}

function isCodeLike(rel) {
	return /\.(?:[cm]?js|[cm]?ts|tsx|jsx)$/i.test(rel) || /\.d\.[cm]?ts$/i.test(rel);
}

/**
 * Replace comments and regular-expression literals with whitespace while
 * preserving source offsets. Keeping string/template literal contents intact
 * means a real token in executable code is still rejected, while generated
 * JSDoc examples and detector regex definitions do not become release
 * blockers. This is intentionally a small lexer rather than a broad regex so
 * URLs and quoted values are never mistaken for comments.
 */
function maskCodeComments(text) {
	let output = "";
	let state = "code";
	const ranges = [];
	let maskStart = -1;
	let maskKind;
	const beginMask = (index, kind) => {
		maskStart = index;
		maskKind = kind;
	};
	const endMask = (end) => {
		if (maskStart >= 0) ranges.push({ start: maskStart, end, kind: maskKind });
		maskStart = -1;
		maskKind = undefined;
	};
	for (let index = 0; index < text.length; index++) {
		const current = text[index];
		const next = text[index + 1];
		if (state === "code") {
			if (current === "/" && next === "/") {
				beginMask(index, "comment");
				output += "  ";
				index++;
				state = "line-comment";
				continue;
			}
			if (current === "/" && next === "*") {
				beginMask(index, "comment");
				output += "  ";
				index++;
				state = "block-comment";
				continue;
			}
			if (current === "/" && shouldStartRegex(text, index, output)) {
				const end = findRegexLiteralEnd(text, index + 1);
				if (end >= 0) {
					beginMask(index, "regex");
					output += maskSegment(text.slice(index, end + 1));
					endMask(end + 1);
					index = end;
					continue;
				}
			}
			if (current === "\"" || current === "'" || current === "`") {
				output += current;
				state = current === "\"" ? "double-quoted" : current === "'" ? "single-quoted" : "template";
				continue;
			}
			output += current;
			continue;
		}
		if (state === "line-comment") {
			if (current === "\r" || current === "\n") {
				endMask(index);
				output += current;
				state = "code";
			} else output += " ";
			continue;
		}
		if (state === "block-comment") {
			if (current === "*" && next === "/") {
				output += "  ";
				index++;
				endMask(index + 1);
				state = "code";
			} else output += current === "\r" || current === "\n" ? current : " ";
			continue;
		}
		output += current;
		if (current === "\\" && index + 1 < text.length) output += text[++index];
		else if ((state === "double-quoted" && current === "\"") || (state === "single-quoted" && current === "'") || (state === "template" && current === "`")) state = "code";
	}
	if (maskStart >= 0) endMask(text.length);
	return { text: output, ranges };
}

function maskSegment(segment) {
	return segment.replace(/[^\r\n]/g, " ");
}

function shouldStartRegex(text, index, output) {
	const previous = output.trimEnd().at(-1);
	if (!previous) return true;
	if ("=(:,;!?&|+-*%^~<>[{".includes(previous)) return true;
	const prefix = text.slice(0, index).trimEnd();
	return /(?:^|[^A-Za-z0-9_$])(?:return|throw|case|delete|void|typeof|instanceof|in|of|yield|await|new)$/.test(prefix);
}

function findRegexLiteralEnd(text, start) {
	let characterClass = false;
	for (let index = start; index < text.length; index++) {
		const current = text[index];
		if (current === "\\") {
			index++;
			continue;
		}
		if (current === "\r" || current === "\n") return -1;
		if (current === "[") characterClass = true;
		else if (current === "]") characterClass = false;
		else if (current === "/" && !characterClass) return index;
	}
	return -1;
}

function findMatches(text, pattern) {
	const globalPattern = new RegExp(pattern.source, `${pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`}`);
	return [...text.matchAll(globalPattern)];
}

function validateFinalProvenance(value) {
	const required = ["rc_version", "git_sha", "source_digest", "data_digest", "package_digest", "lockfile_digest", "sbom_digest"];
	for (const field of required) {
		if (!value[field]) throw new Error(`Commercial manifest provenance is missing ${field}`);
	}
	for (const field of ["source_digest", "data_digest", "package_digest", "lockfile_digest", "sbom_digest"]) {
		if (!/^sha256:[0-9a-f]{64}$/i.test(value[field])) {
			throw new Error(`Commercial manifest provenance ${field} must be sha256:<64 hex>`);
		}
	}
	if (!keyId) throw new Error("Commercial manifest requires AIDR_SIGNING_KEY_ID");
	if (!keyFingerprint) throw new Error("Commercial manifest requires AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT");
}

function resolveDigest(explicit, fromEnv, label) {
	const value = explicit ?? fromEnv;
	if (value === undefined || value === "") return undefined;
	if (!/^(?:sha256|sha1|sha512):[A-Za-z0-9+/=_-]+$/.test(value)) {
		throw new Error(`Invalid ${label} digest format; expected sha256:<hex> or another explicit algorithm`);
	}
	if (label === "image" && !/^sha256:[0-9a-f]{64}$/i.test(value)) throw new Error("Image digest must be immutable sha256:<64 hex>");
	return value;
}

function normalizeFingerprint(value) {
	const normalized = value.toLowerCase().replace(/^sha256:/, "");
	if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error("Signing key fingerprint must be SHA-256 hex");
	return `sha256:${normalized}`;
}

function resolveCreatedAt() {
	const sourceDateEpoch = process.env.SOURCE_DATE_EPOCH;
	if (deterministic && sourceDateEpoch) {
		const seconds = Number(sourceDateEpoch);
		if (Number.isFinite(seconds) && seconds >= 0) return new Date(seconds * 1000).toISOString();
		throw new Error(`Invalid SOURCE_DATE_EPOCH: ${sourceDateEpoch}`);
	}
	if (deterministic) throw new Error("AIDR_DETERMINISTIC_MANIFEST=1 requires SOURCE_DATE_EPOCH");
	return new Date().toISOString();
}

function parseArgs(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i++) {
		const flag = argv[i];
		if (!flag?.startsWith("--")) continue;
		const value = argv[i + 1];
		if (value && !value.startsWith("--")) {
			values[flag] = value;
			i++;
		} else values[flag] = "true";
	}
	return values;
}

function tryReadLocalPackageJson() {
	try {
		return JSON.parse(readFileSync("package.json", "utf8"));
	} catch {
		return null;
	}
}

function compareStrings(a, b) {
	return a < b ? -1 : a > b ? 1 : 0;
}
