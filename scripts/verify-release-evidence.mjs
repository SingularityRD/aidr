/**
 * Verify commercial release evidence emitted by release-artifact-manifests.
 *
 * This deliberately does not trust a filename or a non-empty signature. It
 * verifies every manifest file hash, validates the SBOM shape, and verifies
 * each Ed25519 signature using the configured public key (or the public half
 * of the signing key in an isolated CI workspace).
 *
 * Usage:
 *   node scripts/verify-release-evidence.mjs --dirs packages/core/dist ...
 */

import { createPublicKey, createHash, verify as cryptoVerify } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
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
// Public examples used by generated declaration docs. These are exempt only
// when the verifier confirms they occur inside a source comment.
const DOCUMENTATION_SECRET_VALUES = new Set(["AKIAIOSFODNN7EXAMPLE"]);
const LEAK_PATTERNS = [
	/[A-Za-z]:\\Users\\[^\s"']+/,
	/(?:^|[\s"'`])\/(?:Users|home|root)\/[^\s"'`]+/,
	/(?:^|[\s"'`])(?:[A-Za-z]:[\\/]|\/)[^\s"'`]*node_modules[\\/]\.pnpm[\\/][^\s"'`]+/i,
];

const dirs = parseDirs(process.argv.slice(2));
const args = parseFlags(process.argv.slice(2));
const commercial = process.env.AIDR_RELEASE_MODE === "commercial" || process.env.AIDR_FINAL_RELEASE === "1";
const keyPath = args["--public-key"] ?? process.env.AIDR_SIGNING_PUBLIC_KEY_PEM_PATH;
const expectedFingerprint = args["--fingerprint"] ?? process.env.AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT;
const keyId = process.env.AIDR_SIGNING_KEY_ID;
const lockfilePath = args["--lockfile"];
const providedLockfileDigest = lockfilePath ? `sha256:${createHash("sha256").update(await readFile(path.resolve(lockfilePath))).digest("hex")}` : undefined;
const expectedProvenance = {
	rc_version: args["--rc-version"],
	git_sha: args["--git-sha"],
	source_digest: args["--source-digest"],
	data_digest: args["--data-digest"],
	image_digest: args["--image-digest"],
	package_digest: args["--package-digest"],
	sbom_digest: args["--sbom-digest"],
};

if (dirs.length === 0) {
	console.error("Usage: node scripts/verify-release-evidence.mjs --dirs <artifactDir> [...]");
	process.exit(2);
}
if (!keyPath) {
	console.error("AIDR_SIGNING_PUBLIC_KEY_PEM_PATH (or --public-key) is required for independent verification.");
	process.exit(2);
}
if (commercial && !expectedFingerprint) {
	console.error("AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT (or --fingerprint) is required in commercial mode.");
	process.exit(2);
}

let publicKey;
let actualFingerprint;
try {
	const keyPem = await readFile(path.resolve(keyPath), "utf8");
	if (/BEGIN .*PRIVATE KEY/.test(keyPem)) throw new Error("private key supplied; independent verification requires the public key");
	publicKey = createPublicKey(keyPem);
	if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("verification key must be Ed25519");
	actualFingerprint = `sha256:${createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex")}`;
	if (expectedFingerprint && normalizeFingerprint(expectedFingerprint) !== actualFingerprint) {
		throw new Error(`public-key fingerprint mismatch (expected ${expectedFingerprint}, actual ${actualFingerprint})`);
	}
} catch (error) {
	console.error(`Unable to load release verification key: ${formatError(error)}`);
	process.exit(1);
}

const failures = [];
for (const rawDir of dirs) {
	const dir = path.resolve(rawDir);
	const manifestPath = path.join(dir, "aidr-artifact.manifest.json");
	const signaturePath = path.join(dir, "aidr-artifact.manifest.sig");
	const sbomPath = path.join(dir, "aidr-sbom.cdx.json");
	const sbomChecksumPath = path.join(dir, "aidr-sbom.cdx.json.sha256");
	let manifestRaw;
	let manifest;
	try {
		manifestRaw = await readFile(manifestPath, "utf8");
		manifest = JSON.parse(manifestRaw);
	} catch (error) {
		failures.push(`${dir}: cannot read manifest (${formatError(error)})`);
		continue;
	}

	if (!manifest || manifest.schema_version !== 1 || typeof manifest.artifact_id !== "string") {
		failures.push(`${dir}: invalid artifact manifest schema`);
		continue;
	}
	const endpointPackage = manifest.artifact_id === "claude-code/package";
	if (endpointPackage) {
		try {
			const pkg = JSON.parse(await readFile(path.join(dir, "package.json"), "utf8"));
			if (pkg.name !== "@singularityrd/aidr-claude-code" || pkg.version !== manifest.artifact_version) {
				failures.push(`${dir}: endpoint package identity/version does not match package.json`);
			}
		} catch (error) {
			failures.push(`${dir}: cannot read endpoint package.json (${formatError(error)})`);
		}
	}
	if (!/^(?:@[a-z0-9][a-z0-9._-]{0,63}\/)?[a-z0-9][a-z0-9._/-]{0,127}$/i.test(manifest.artifact_id)) {
		failures.push(`${dir}: unsafe artifact_id ${manifest.artifact_id}`);
	}
	if (keyId && manifest.key_id !== keyId) failures.push(`${dir}: manifest key_id does not match AIDR_SIGNING_KEY_ID`);
	if (actualFingerprint && manifest.key_fingerprint !== actualFingerprint) {
		failures.push(`${dir}: manifest key_fingerprint does not match the supplied public key`);
	}
	if (!manifest.lineage?.watermark_id) failures.push(`${dir}: missing commercial lineage.watermark_id`);
	if (manifest.lineage?.channel !== "commercial") failures.push(`${dir}: lineage.channel is not commercial`);
	if (!endpointPackage) {
		validateProvenance(dir, manifest, failures);
		for (const [field, expected] of Object.entries(expectedProvenance)) {
			if (expected && manifest.provenance?.[field] !== expected) failures.push(`${dir}: provenance ${field} does not match the expected value`);
		}
		if (providedLockfileDigest && manifest.provenance?.lockfile_digest !== providedLockfileDigest) {
			failures.push(`${dir}: lockfile digest does not match --lockfile`);
		}
	}
	if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
		failures.push(`${dir}: manifest has no files`);
	} else {
		const paths = manifest.files.map((entry) => entry?.path).filter((value) => typeof value === "string");
		if (new Set(paths).size !== paths.length) failures.push(`${dir}: manifest contains duplicate file paths`);
		if (paths.includes("aidr-artifact.manifest.json") || paths.includes("aidr-artifact.manifest.sig")) failures.push(`${dir}: manifest self-reference is not allowed`);
		if (paths.join("\0") !== [...paths].sort(compareStrings).join("\0")) {
			failures.push(`${dir}: manifest file entries are not sorted`);
		}
		for (const entry of manifest.files) await verifyEntry(dir, entry, failures);
		await verifyExactFileSet(dir, manifest.files, failures, endpointPackage);
	}

	if (!endpointPackage && !manifest.files?.some((entry) => entry.path === "aidr-sbom.cdx.json")) {
		failures.push(`${dir}: manifest does not cover aidr-sbom.cdx.json`);
	}
	if (!endpointPackage && !manifest.files?.some((entry) => entry.path === "aidr-sbom.cdx.json.sha256")) {
		failures.push(`${dir}: manifest does not cover aidr-sbom.cdx.json.sha256`);
	}

	let sbomRaw;
	if (!endpointPackage) {
		try {
			sbomRaw = await readFile(sbomPath, "utf8");
			const sbom = JSON.parse(sbomRaw);
			if (sbom.bomFormat !== "CycloneDX" || sbom.specVersion !== "1.5" || !Array.isArray(sbom.components)) {
				failures.push(`${dir}: invalid CycloneDX SBOM shape`);
			} else if (sbom.components.length === 0) {
				failures.push(`${dir}: SBOM has no components`);
			} else {
				const refs = new Set();
				for (const component of sbom.components) {
					if (!component || typeof component["bom-ref"] !== "string" || refs.has(component["bom-ref"])) {
						failures.push(`${dir}: SBOM has an invalid or duplicate component reference`);
						continue;
					}
					refs.add(component["bom-ref"]);
					if (component.type === "library" && (!Array.isArray(component.licenses) || component.licenses.length === 0)) {
						failures.push(`${dir}: SBOM component ${component.name ?? component["bom-ref"]} has no license metadata`);
					}
					if (component.type === "library" && (!Array.isArray(component.hashes) || component.hashes.length === 0)) {
						failures.push(`${dir}: SBOM component ${component.name ?? component["bom-ref"]} has no lock integrity hash`);
					}
				}
				for (const dependency of sbom.dependencies ?? []) {
					if (!refs.has(dependency.ref)) failures.push(`${dir}: SBOM dependency references unknown component ${dependency.ref}`);
					for (const child of dependency.dependsOn ?? []) if (!refs.has(child)) failures.push(`${dir}: SBOM dependency references unknown child ${child}`);
				}
			}
		} catch (error) {
			failures.push(`${dir}: cannot read SBOM (${formatError(error)})`);
		}
		try {
			const checksumRaw = (await readFile(sbomChecksumPath, "utf8")).trim();
			const [expected, filename] = checksumRaw.split(/\s+/, 2);
			if (!/^[0-9a-f]{64}$/i.test(expected ?? "") || filename !== "aidr-sbom.cdx.json") {
				failures.push(`${dir}: malformed SBOM checksum sidecar`);
			} else if (sbomRaw && createHash("sha256").update(sbomRaw, "utf8").digest("hex") !== expected.toLowerCase()) {
				failures.push(`${dir}: SBOM checksum sidecar mismatch`);
			}
		} catch (error) {
			failures.push(`${dir}: cannot read SBOM checksum sidecar (${formatError(error)})`);
		}
		if (manifest.provenance?.sbom_digest && sbomRaw) {
			const actualSbomDigest = `sha256:${createHash("sha256").update(sbomRaw, "utf8").digest("hex")}`;
			if (manifest.provenance.sbom_digest !== actualSbomDigest) failures.push(`${dir}: provenance sbom_digest mismatch`);
		}
	}
	if (manifest.artifact_id === "release/bundle") await verifyInventory(dir, failures);

	try {
		const signatureRaw = (await readFile(signaturePath, "utf8")).trim();
		const signature = Buffer.from(signatureRaw, "base64");
		if (signature.length !== 64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(signatureRaw)) {
			failures.push(`${dir}: malformed Ed25519 signature`);
		} else if (!cryptoVerify(null, Buffer.from(manifestRaw, "utf8"), publicKey, signature)) {
			failures.push(`${dir}: Ed25519 signature does not verify`);
		}
	} catch (error) {
		failures.push(`${dir}: cannot verify signature (${formatError(error)})`);
	}
}

async function verifyExactFileSet(dir, entries, failuresOut, endpointPackage = false) {
	const actual = [];
	const stack = endpointPackage ? [path.join(dir, "dist"), path.join(dir, "resources")] : [dir];
	if (endpointPackage) {
		const packageJson = path.join(dir, "package.json");
		const info = await lstat(packageJson);
		if (info.isSymbolicLink() || !info.isFile()) failuresOut.push(`${dir}: package.json is not a regular file`);
		else actual.push("package.json");
	}
	while (stack.length > 0) {
		const current = stack.pop();
		if (endpointPackage) {
			const rootInfo = await lstat(current);
			if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
				failuresOut.push(`${dir}: endpoint package input is not a regular directory: ${path.basename(current)}`);
				continue;
			}
		}
		for (const entry of await readdir(current, { withFileTypes: true })) {
			const full = path.join(current, entry.name);
			const info = await lstat(full);
			const relative = path.relative(dir, full).replace(/\\/g, "/");
			if (info.isSymbolicLink()) {
				failuresOut.push(`${dir}: symlink is not allowed: ${relative}`);
			} else if (info.isDirectory()) {
				stack.push(full);
			} else if (info.isFile()) {
				if (!["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig"].includes(relative)) actual.push(relative);
			} else {
				failuresOut.push(`${dir}: unsupported filesystem entry: ${relative}`);
			}
		}
	}
	const declared = entries
		.map((entry) => (typeof entry?.path === "string" ? entry.path.replace(/\\/g, "/") : undefined))
		.filter(Boolean);
	const declaredSet = new Set(declared);
	const actualSet = new Set(actual);
	for (const file of actual.sort(compareStrings)) {
		if (!declaredSet.has(file)) failuresOut.push(`${dir}: unexpected file is not covered by the signed manifest: ${file}`);
	}
	for (const file of declared.sort(compareStrings)) {
		if (!actualSet.has(file)) failuresOut.push(`${dir}: signed manifest names a file absent from the artifact: ${file}`);
	}
}

if (failures.length > 0) {
	console.error("Commercial release evidence verification failed:");
	for (const failure of failures) console.error(`  - ${failure}`);
	process.exit(1);
}

console.log(`Commercial release evidence verified for ${dirs.length} artifact(s).`);

async function verifyEntry(dir, entry, failuresOut) {
	if (!entry || typeof entry.path !== "string" || !/^[0-9a-f]{64}$/i.test(entry.sha256 ?? "")) {
		failuresOut.push(`${dir}: malformed manifest file entry`);
		return;
	}
	const normalized = entry.path.replace(/\\/g, "/");
	if (!normalized || normalized.startsWith("/") || normalized.includes(":") || normalized.split("/").includes("..")) {
		failuresOut.push(`${dir}: unsafe manifest path ${entry.path}`);
		return;
	}
	if (/\.map$/i.test(normalized)) failuresOut.push(`${dir}: source map is not allowed: ${entry.path}`);
	if (SECRET_PATH_RE.test(normalized)) failuresOut.push(`${dir}: secret-looking path is not allowed: ${entry.path}`);
	const fullPath = path.resolve(dir, normalized);
	if (!fullPath.startsWith(`${path.resolve(dir)}${path.sep}`)) {
		failuresOut.push(`${dir}: manifest path escapes artifact root ${entry.path}`);
		return;
	}
	try {
		const info = await lstat(fullPath);
		if (info.isSymbolicLink()) {
			failuresOut.push(`${dir}: symlink is not allowed: ${entry.path}`);
			return;
		}
		const bytes = await readFile(fullPath);
		if (!bytes.includes(0)) {
			const text = bytes.toString("utf8");
			const codeLike = isCodeLike(entry.path);
			const maskedSource = codeLike ? maskCodeComments(text) : { text, ranges: [] };
			if (hasSecretLikeContent(text, maskedSource, codeLike)) failuresOut.push(`${dir}: secret-like content in ${entry.path}`);
			if (LEAK_PATTERNS.some((pattern) => pattern.test(maskedSource.text))) failuresOut.push(`${dir}: host-path leak in ${entry.path}`);
		}
		const actual = createHash("sha256").update(bytes).digest("hex");
		if (actual.toLowerCase() !== entry.sha256.toLowerCase()) {
			failuresOut.push(`${dir}: hash mismatch for ${entry.path}`);
		}
	} catch {
		failuresOut.push(`${dir}: manifest file is missing ${entry.path}`);
	}
}

function hasSecretLikeContent(text, maskedSource, codeLike) {
	for (const pattern of SECRET_CONTENT_PATTERNS) {
		if (pattern.test(maskedSource.text)) return true;
		if (!codeLike) continue;
		for (const match of findMatches(text, pattern)) {
			const index = match.index ?? -1;
			const masked = index >= 0 ? maskedSource.text.slice(index, index + match[0].length) : "";
			const maskRange = maskedSource.ranges.find(
				(range) => index >= range.start && index + match[0].length <= range.end,
			);
			const allowedCommentExample = maskRange?.kind === "comment" && DOCUMENTATION_SECRET_VALUES.has(match[0]);
			const allowedRegexLiteral = maskRange?.kind === "regex";
			if (!masked || !/^\s*$/.test(masked) || (!allowedCommentExample && !allowedRegexLiteral)) return true;
		}
	}
	return false;
}

function isCodeLike(rel) {
	return /\.(?:[cm]?js|[cm]?ts|tsx|jsx)$/i.test(rel) || /\.d\.[cm]?ts$/i.test(rel);
}

/** Keep executable strings visible while masking comments and regex literals. */
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
	const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
	return [...text.matchAll(new RegExp(pattern.source, flags))];
}

function parseDirs(argv) {
	const index = argv.indexOf("--dirs");
	if (index < 0) return [];
	return argv.slice(index + 1).filter((value) => value && !value.startsWith("--"));
}

function parseFlags(argv) {
	const flags = {};
	for (let i = 0; i < argv.length; i++) {
		if (!argv[i]?.startsWith("--") || argv[i] === "--dirs") continue;
		if (argv[i + 1] && !argv[i + 1].startsWith("--")) flags[argv[i]] = argv[++i];
	}
	return flags;
}

function validateProvenance(dir, manifest, failuresOut) {
	const provenance = manifest.provenance;
	if (!provenance || provenance.schema_version !== 1) {
		failuresOut.push(`${dir}: missing provenance block`);
		return;
	}
	for (const field of ["rc_version", "git_sha", "source_digest", "data_digest", "package_digest", "lockfile_digest", "sbom_digest"]) {
		if (typeof provenance[field] !== "string" || provenance[field].length === 0) failuresOut.push(`${dir}: provenance missing ${field}`);
	}
	for (const field of ["source_digest", "data_digest", "package_digest", "lockfile_digest", "sbom_digest"]) {
		if (provenance[field] !== undefined && !/^sha256:[0-9a-f]{64}$/i.test(provenance[field])) {
			failuresOut.push(`${dir}: provenance ${field} must be sha256:<64 hex>`);
		}
	}
	if (provenance.image_digest !== undefined && !/^sha256:[0-9a-f]{64}$/i.test(provenance.image_digest)) {
		failuresOut.push(`${dir}: image_digest must be immutable sha256:<64 hex>`);
	}
}

async function verifyInventory(dir, failuresOut) {
	const inventoryPath = path.join(dir, "release-inventory.json");
	try {
		const inventory = JSON.parse(await readFile(inventoryPath, "utf8"));
		if (inventory.schema_version !== 1 || !Array.isArray(inventory.artifacts)) {
			failuresOut.push(`${dir}: invalid release inventory`);
			return;
		}
		for (const entry of inventory.artifacts) {
			if (!entry || typeof entry.staged_path !== "string" || !/^[0-9a-f]{64}$/i.test(entry.sha256 ?? "")) {
				failuresOut.push(`${dir}: malformed release inventory entry`);
				continue;
			}
			const full = path.resolve(dir, entry.staged_path);
			if (!full.startsWith(`${path.resolve(dir)}${path.sep}`)) {
				failuresOut.push(`${dir}: release inventory path escapes bundle: ${entry.staged_path}`);
				continue;
			}
			const actual = createHash("sha256").update(await readFile(full)).digest("hex");
			if (actual.toLowerCase() !== entry.sha256.toLowerCase()) failuresOut.push(`${dir}: release inventory hash mismatch: ${entry.staged_path}`);
		}
	} catch (error) {
		failuresOut.push(`${dir}: cannot verify release inventory (${formatError(error)})`);
	}
}

function normalizeFingerprint(value) {
	const normalized = String(value).toLowerCase().replace(/^sha256:/, "");
	if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error("fingerprint must be SHA-256 hex");
	return `sha256:${normalized}`;
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}

function compareStrings(a, b) {
	return a < b ? -1 : a > b ? 1 : 0;
}
