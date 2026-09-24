/**
 * Browser-side release manifest loading and validation for the download center.
 *
 * Contract: docs/contracts/release-manifest.md and ./release-manifest.schema.json.
 * The dashboard server validates the manifest before serving it; this module
 * re-validates in the browser because the manifest may also come from an
 * external URL (VITE_AIDR_RELEASE_MANIFEST_URL). Everything fails closed: a
 * manifest with an http: download link, a missing digest or any unknown field
 * is rejected as a whole, never partially rendered.
 */

export const RELEASE_ARTIFACT_IDS = [
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
] as const;

export type ReleaseArtifactId = (typeof RELEASE_ARTIFACT_IDS)[number];

export type ReleaseArtifact = {
	id: ReleaseArtifactId;
	version: string;
	url: string;
	sha256: string;
	signature?: string;
	size: number;
	platforms: string[];
};

export type ReleaseManifest = {
	version: string;
	publishedAt: string;
	artifacts: ReleaseArtifact[];
};

export class ReleaseManifestError extends Error {
	constructor(message: string) {
		super(`Release manifest rejected: ${message}`);
		this.name = "ReleaseManifestError";
	}
}

export const RELEASE_MANIFEST_MAX_BYTES = 1024 * 1024;
const MAX_ARTIFACTS = 200;
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const PLATFORM_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const MANIFEST_KEYS = new Set(["version", "publishedAt", "artifacts"]);
const ARTIFACT_KEYS = new Set(["id", "version", "url", "sha256", "signature", "size", "platforms"]);

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isArtifactId(value: unknown): value is ReleaseArtifactId {
	return typeof value === "string" && (RELEASE_ARTIFACT_IDS as readonly string[]).includes(value);
}

function rejectUnknownKeys(value: Record<string, unknown>, allowed: Set<string>, where: string) {
	for (const key of Object.keys(value)) {
		if (!allowed.has(key))
			throw new ReleaseManifestError(`${where} has unsupported field "${key}"`);
	}
}

function httpsUrl(value: unknown, where: string): string {
	if (typeof value !== "string" || value.length === 0 || value.length > 2048 || /\s/.test(value)) {
		throw new ReleaseManifestError(`${where} must be an absolute https: URL`);
	}
	let parsed: URL;
	try {
		parsed = new URL(value);
	} catch {
		throw new ReleaseManifestError(`${where} must be an absolute https: URL`);
	}
	if (parsed.protocol !== "https:" || !value.toLowerCase().startsWith("https://")) {
		throw new ReleaseManifestError(`${where} must use https:`);
	}
	if (parsed.username || parsed.password) {
		throw new ReleaseManifestError(`${where} must not embed credentials`);
	}
	return parsed.href;
}

function semver(value: unknown, where: string): string {
	if (typeof value !== "string" || value.length > 64 || !SEMVER_RE.test(value)) {
		throw new ReleaseManifestError(`${where} must be a semantic version`);
	}
	return value;
}

function sha256Digest(value: unknown, where: string): string {
	if (typeof value !== "string" || !SHA256_RE.test(value)) {
		throw new ReleaseManifestError(`${where} must be 64 lower-case hex characters`);
	}
	return value;
}

function byteSize(value: unknown, where: string): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
		throw new ReleaseManifestError(`${where} must be a positive integer byte count`);
	}
	return value;
}

function platformList(value: unknown, where: string): string[] {
	if (
		!Array.isArray(value) ||
		value.length === 0 ||
		value.length > 16 ||
		!value.every(
			(platform: unknown) => typeof platform === "string" && PLATFORM_RE.test(platform),
		) ||
		new Set(value).size !== value.length
	) {
		throw new ReleaseManifestError(`${where} must be 1-16 unique platform identifiers`);
	}
	return [...(value as string[])];
}

function parseArtifact(raw: unknown, where: string): ReleaseArtifact {
	if (!isRecord(raw)) throw new ReleaseManifestError(`${where} is not an object`);
	rejectUnknownKeys(raw, ARTIFACT_KEYS, where);
	if (!isArtifactId(raw.id))
		throw new ReleaseManifestError(`${where}.id is not a supported artifact`);
	const version = semver(raw.version, `${where}.version`);
	const url = httpsUrl(raw.url, `${where}.url`);
	const sha256 = sha256Digest(raw.sha256, `${where}.sha256`);
	const signature =
		raw.signature === undefined ? undefined : httpsUrl(raw.signature, `${where}.signature`);
	return {
		id: raw.id,
		version,
		url,
		sha256,
		...(signature === undefined ? {} : { signature }),
		size: byteSize(raw.size, `${where}.size`),
		platforms: platformList(raw.platforms, `${where}.platforms`),
	};
}

/** Validate an already-parsed manifest. Throws ReleaseManifestError on the first violation. */
export function parseReleaseManifest(value: unknown): ReleaseManifest {
	if (!isRecord(value)) throw new ReleaseManifestError("the document is not a JSON object");
	rejectUnknownKeys(value, MANIFEST_KEYS, "manifest");
	const version = semver(value.version, "version");
	if (
		typeof value.publishedAt !== "string" ||
		!RFC3339_RE.test(value.publishedAt) ||
		!Number.isFinite(Date.parse(value.publishedAt))
	) {
		throw new ReleaseManifestError("publishedAt must be an RFC 3339 timestamp");
	}
	if (!Array.isArray(value.artifacts) || value.artifacts.length > MAX_ARTIFACTS) {
		throw new ReleaseManifestError(
			`artifacts must be an array of at most ${MAX_ARTIFACTS} entries`,
		);
	}
	const seen = new Set<string>();
	const artifacts = value.artifacts.map((raw: unknown, index: number) => {
		const artifact = parseArtifact(raw, `artifacts[${index}]`);
		for (const platform of artifact.platforms) {
			const key = `${artifact.id}\u0000${platform}`;
			if (seen.has(key)) {
				throw new ReleaseManifestError(
					`artifacts[${index}] duplicates ${artifact.id} for platform ${platform}`,
				);
			}
			seen.add(key);
		}
		return artifact;
	});
	return { version, publishedAt: value.publishedAt, artifacts };
}

export type ReleaseManifestSource =
	| { configured: false }
	| { configured: true; url: string }
	| { configured: true; error: string };

/**
 * Resolve where the manifest is fetched from. The Node deployment publishes it
 * through runtime config (a same-origin /release-manifest.json or an external
 * HTTPS URL); static hosting falls back to the build-time
 * VITE_AIDR_RELEASE_MANIFEST_URL. Only https: or a same-origin path is
 * accepted; an http: URL is a configuration error, not a fallback.
 */
export function resolveReleaseManifestSource(
	runtimeUrl: string | null | undefined = typeof window !== "undefined"
		? window.__AIDR_CONFIG__?.releaseManifestUrl
		: undefined,
	buildUrl: string | undefined = import.meta.env.VITE_AIDR_RELEASE_MANIFEST_URL as
		| string
		| undefined,
	origin: string = window.location.origin,
): ReleaseManifestSource {
	const candidate = (runtimeUrl ?? buildUrl ?? "").trim();
	if (!candidate) return { configured: false };
	const invalid = {
		configured: true as const,
		error:
			"The release manifest URL is not an HTTPS or same-origin address, so downloads are withheld.",
	};
	if (candidate.startsWith("//") || candidate.includes("\\")) return invalid;
	if (!candidate.startsWith("/") && !candidate.toLowerCase().startsWith("https://")) return invalid;
	let parsed: URL;
	try {
		parsed = new URL(candidate, origin);
	} catch {
		return invalid;
	}
	if (parsed.username || parsed.password) return invalid;
	const sameOriginPath = candidate.startsWith("/") && parsed.origin === origin;
	if (!sameOriginPath && parsed.protocol !== "https:") return invalid;
	return { configured: true, url: parsed.href };
}

/** Fetch and validate the manifest. Throws ReleaseManifestError or a network error. */
export async function fetchReleaseManifest(
	url: string,
	fetchImpl: typeof fetch = fetch,
	signal?: AbortSignal,
): Promise<ReleaseManifest> {
	const response = await fetchImpl(url, {
		method: "GET",
		credentials: "omit",
		cache: "no-cache",
		redirect: "error",
		headers: { Accept: "application/json" },
		signal,
	});
	if (!response.ok) {
		throw new ReleaseManifestError(`the manifest endpoint answered HTTP ${response.status}`);
	}
	const text = await response.text();
	if (new TextEncoder().encode(text).byteLength > RELEASE_MANIFEST_MAX_BYTES) {
		throw new ReleaseManifestError("the manifest is larger than 1 MiB");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new ReleaseManifestError("the manifest is not valid JSON");
	}
	return parseReleaseManifest(parsed);
}

/** A shell-safe file name for the downloaded artifact, derived from its URL. */
export function artifactFileName(artifact: Pick<ReleaseArtifact, "url" | "id">): string {
	let segment = "";
	try {
		segment = decodeURIComponent(new URL(artifact.url).pathname.split("/").pop() ?? "");
	} catch {
		segment = "";
	}
	return /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/.test(segment)
		? segment
		: `aidr-${artifact.id}.download`;
}

export type VerifyCommand = { label: string; command: string };

/** Commands that compare a downloaded file against the manifest digest. */
export function verifyCommands(
	artifact: Pick<ReleaseArtifact, "url" | "id" | "sha256">,
): VerifyCommand[] {
	const file = artifactFileName(artifact);
	return [
		{ label: "Linux", command: `echo "${artifact.sha256}  ${file}" | sha256sum --check` },
		{ label: "macOS", command: `echo "${artifact.sha256}  ${file}" | shasum -a 256 --check` },
		{
			label: "Windows PowerShell",
			command: `if ((Get-FileHash -Algorithm SHA256 ".\\${file}").Hash.ToLower() -ne "${artifact.sha256}") { throw "SHA-256 mismatch" } else { "OK" }`,
		},
	];
}

export function formatBytes(size: number): string {
	if (size < 1024) return `${size} B`;
	const units = ["KiB", "MiB", "GiB", "TiB"];
	let value = size / 1024;
	let unit = 0;
	while (value >= 1024 && unit < units.length - 1) {
		value /= 1024;
		unit++;
	}
	return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
}
