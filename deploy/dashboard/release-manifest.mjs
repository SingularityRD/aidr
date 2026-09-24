/**
 * Release manifest validation shared by the dashboard server (which serves
 * /release-manifest.json) and scripts/generate-release-manifest.mjs.
 *
 * The contract is docs/contracts/release-manifest.md and its JSON Schema is
 * packages/dashboard/src/onboarding/release-manifest.schema.json. The dashboard
 * re-validates in the browser (src/onboarding/release-manifest.ts), so a
 * manifest is checked at generation, at serving time and at display time.
 * Every check fails closed: an invalid manifest is never served or shown.
 */

export const RELEASE_ARTIFACT_IDS = Object.freeze([
	"claude-code",
	"cursor",
	"vscode",
	"openclaw",
	"opencode",
	"codex",
	"cli",
	"browser-guard-chrome",
	"browser-guard-firefox",
	"mcp-gateway",
]);

export const RELEASE_MANIFEST_MAX_BYTES = 1024 * 1024;
const MAX_ARTIFACTS = 200;
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const PLATFORM_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const ARTIFACT_KEYS = new Set(["id", "version", "url", "sha256", "signature", "size", "platforms"]);
const MANIFEST_KEYS = new Set(["version", "publishedAt", "artifacts"]);

function fail(message) {
	throw new Error(`release manifest: ${message}`);
}

function isRecord(value) {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rejectUnknownKeys(value, allowed, where) {
	for (const key of Object.keys(value)) {
		if (!allowed.has(key)) fail(`${where} has unsupported field "${key}"`);
	}
}

/** Returns the URL string when it is an absolute https: URL without credentials. */
export function assertHttpsUrl(value, where) {
	if (typeof value !== "string" || value.length === 0 || value.length > 2048 || /\s/.test(value)) {
		fail(`${where} must be an absolute https: URL`);
	}
	let parsed;
	try {
		parsed = new URL(value);
	} catch {
		fail(`${where} must be an absolute https: URL`);
	}
	if (parsed.protocol !== "https:") fail(`${where} must use https: (got ${parsed.protocol})`);
	if (parsed.username || parsed.password) fail(`${where} must not embed credentials`);
	if (!value.toLowerCase().startsWith("https://")) fail(`${where} must be an absolute https: URL`);
	return value;
}

function assertVersion(value, where) {
	if (typeof value !== "string" || value.length > 64 || !SEMVER_RE.test(value)) {
		fail(`${where} must be a semantic version`);
	}
	return value;
}

/**
 * Validate a parsed manifest object. Throws with a descriptive message on the
 * first violation; returns a normalized copy (no unknown keys) otherwise.
 */
export function validateReleaseManifest(value) {
	if (!isRecord(value)) fail("must be a JSON object");
	rejectUnknownKeys(value, MANIFEST_KEYS, "manifest");
	const version = assertVersion(value.version, "version");
	if (
		typeof value.publishedAt !== "string" ||
		!RFC3339_RE.test(value.publishedAt) ||
		!Number.isFinite(Date.parse(value.publishedAt))
	) {
		fail("publishedAt must be an RFC 3339 timestamp");
	}
	if (!Array.isArray(value.artifacts)) fail("artifacts must be an array");
	if (value.artifacts.length > MAX_ARTIFACTS) fail(`artifacts must not exceed ${MAX_ARTIFACTS} entries`);
	const seen = new Set();
	const artifacts = value.artifacts.map((artifact, index) => {
		const where = `artifacts[${index}]`;
		if (!isRecord(artifact)) fail(`${where} must be an object`);
		rejectUnknownKeys(artifact, ARTIFACT_KEYS, where);
		if (!RELEASE_ARTIFACT_IDS.includes(artifact.id)) fail(`${where}.id is not a supported artifact id`);
		const artifactVersion = assertVersion(artifact.version, `${where}.version`);
		const url = assertHttpsUrl(artifact.url, `${where}.url`);
		if (typeof artifact.sha256 !== "string" || !SHA256_RE.test(artifact.sha256)) {
			fail(`${where}.sha256 must be 64 lower-case hex characters`);
		}
		const signature =
			artifact.signature === undefined ? undefined : assertHttpsUrl(artifact.signature, `${where}.signature`);
		if (!Number.isSafeInteger(artifact.size) || artifact.size < 1) {
			fail(`${where}.size must be a positive integer byte count`);
		}
		if (
			!Array.isArray(artifact.platforms) ||
			artifact.platforms.length === 0 ||
			artifact.platforms.length > 16 ||
			!artifact.platforms.every((platform) => typeof platform === "string" && PLATFORM_RE.test(platform)) ||
			new Set(artifact.platforms).size !== artifact.platforms.length
		) {
			fail(`${where}.platforms must be 1-16 unique platform identifiers`);
		}
		for (const platform of artifact.platforms) {
			const key = `${artifact.id}\u0000${platform}`;
			if (seen.has(key)) fail(`${where} duplicates ${artifact.id} for platform ${platform}`);
			seen.add(key);
		}
		return {
			id: artifact.id,
			version: artifactVersion,
			url,
			sha256: artifact.sha256,
			...(signature === undefined ? {} : { signature }),
			size: artifact.size,
			platforms: [...artifact.platforms],
		};
	});
	return { version, publishedAt: value.publishedAt, artifacts };
}

/** Parse and validate manifest bytes (UTF-8 JSON), enforcing the size limit. */
export function parseReleaseManifestBytes(bytes) {
	if (bytes.byteLength > RELEASE_MANIFEST_MAX_BYTES) fail(`exceeds ${RELEASE_MANIFEST_MAX_BYTES} bytes`);
	let parsed;
	try {
		parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
	} catch {
		fail("is not valid JSON");
	}
	return validateReleaseManifest(parsed);
}
