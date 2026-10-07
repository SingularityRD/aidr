// Latest published AIDR release, for the public version-check endpoint.
//
// Two operator-provisioned sources, in order of authority:
//
// 1. A signed release manifest: the exact bytes of `aidr-release.manifest.json`
//    produced by `scripts/release-sign.mjs` (base64 in
//    AIDR_RELEASE_MANIFEST_B64), its detached signature document
//    (`aidr-release.manifest.sig`, JSON in AIDR_RELEASE_MANIFEST_SIG) and the
//    publisher's Ed25519 public key (SPKI DER or raw 32 bytes, base64 in
//    AIDR_RELEASE_SIGNING_PUBLIC_KEY_B64). The signature is verified over the
//    exact manifest bytes; an expired, foreign-product or wrongly signed
//    manifest is refused — never downgraded to the configured fallback.
// 2. A configured version string (AIDR_LATEST_RELEASE_VERSION) for deployments
//    that do not distribute a signed manifest to the control plane.
//
// With neither, there is no answer: the endpoint reports the version as
// unavailable instead of inventing one.

export const RELEASE_MANIFEST_ENV = "AIDR_RELEASE_MANIFEST_B64";
export const RELEASE_SIGNATURE_ENV = "AIDR_RELEASE_MANIFEST_SIG";
export const RELEASE_PUBLIC_KEY_ENV = "AIDR_RELEASE_SIGNING_PUBLIC_KEY_B64";
export const LATEST_VERSION_ENV = "AIDR_LATEST_RELEASE_VERSION";
export const RELEASE_PRODUCT_ID = "singularity-aidr";

const SEMVER = /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:-[0-9A-Za-z.-]{1,64})?$/;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const ED25519_SPKI_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

export type LatestRelease =
	| {
			ok: true;
			version: string;
			source: "signed_release_manifest" | "configured";
			channel?: string;
			releaseTag?: string;
			keyId?: string;
	  }
	| { ok: false; reason: "release_manifest_incomplete" | "release_manifest_invalid" | "latest_version_unconfigured" };

/** A plain semver release string (optionally `v`-prefixed and pre-release suffixed), or null. */
export function normalizeReleaseVersion(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const trimmed = value.trim();
	return SEMVER.test(trimmed) ? trimmed.replace(/^v/, "") : null;
}

/** True when `latest` is a strictly newer major.minor.patch than `current`. */
export function isNewerRelease(current: string, latest: string): boolean {
	const parse = (value: string) => (SEMVER.exec(value)?.slice(1, 4) ?? []).map(Number);
	const a = parse(current);
	const b = parse(latest);
	if (a.length !== 3 || b.length !== 3) return false;
	for (let i = 0; i < 3; i++) {
		if (b[i]! > a[i]!) return true;
		if (b[i]! < a[i]!) return false;
	}
	// Same core version: the final release outranks any of its pre-releases.
	return current.includes("-") && !latest.includes("-");
}

function fromBase64(value: string): Uint8Array | null {
	const normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) return null;
	try {
		const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
		return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
	} catch {
		return null;
	}
}

function spkiFor(publicKey: Uint8Array): Uint8Array | null {
	if (publicKey.length === 32) {
		const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + 32);
		spki.set(ED25519_SPKI_PREFIX);
		spki.set(publicKey, ED25519_SPKI_PREFIX.length);
		return spki;
	}
	if (publicKey.length !== ED25519_SPKI_PREFIX.length + 32) return null;
	return ED25519_SPKI_PREFIX.every((byte, index) => publicKey[index] === byte) ? publicKey : null;
}

function record(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

async function verifyEd25519(spki: Uint8Array, signature: Uint8Array, message: Uint8Array): Promise<boolean> {
	try {
		const key = await crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
		return await crypto.subtle.verify("Ed25519", key, signature, message);
	} catch {
		return false;
	}
}

/**
 * Verify the signed release manifest and return the release it names, or null
 * when any part of it fails (bad encoding, signature, key id, product, expiry).
 */
export async function verifySignedReleaseManifest(
	manifestB64: string,
	signatureJson: string,
	publicKeyB64: string,
	nowMs: number,
): Promise<Extract<LatestRelease, { ok: true }> | null> {
	const manifestBytes = fromBase64(manifestB64);
	const publicKey = fromBase64(publicKeyB64);
	const spki = publicKey ? spkiFor(publicKey) : null;
	if (!manifestBytes || manifestBytes.length === 0 || manifestBytes.length > MAX_MANIFEST_BYTES || !spki) return null;
	let signatureDoc: Record<string, unknown> | null;
	let manifest: Record<string, unknown> | null;
	try {
		signatureDoc = record(JSON.parse(signatureJson));
		manifest = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes)));
	} catch {
		return null;
	}
	if (!signatureDoc || !manifest) return null;
	if (signatureDoc.schema_version !== 1 || signatureDoc.algorithm !== "Ed25519") return null;
	const keyId = signatureDoc.key_id;
	const signature = typeof signatureDoc.signature_b64 === "string" ? fromBase64(signatureDoc.signature_b64) : null;
	if (typeof keyId !== "string" || !signature || signature.length !== 64) return null;
	if (!(await verifyEd25519(spki, signature, manifestBytes))) return null;

	// Only now is the manifest content trusted.
	const signer = record(manifest.signer);
	const expiresAt = typeof manifest.expires_at === "string" ? Date.parse(manifest.expires_at) : Number.NaN;
	const version = normalizeReleaseVersion(manifest.release_version);
	if (
		manifest.schema_version !== 1 ||
		manifest.type !== "aidr-release" ||
		manifest.product_id !== RELEASE_PRODUCT_ID ||
		signer?.key_id !== keyId ||
		!Number.isFinite(expiresAt) ||
		expiresAt <= nowMs ||
		!version
	) {
		return null;
	}
	return {
		ok: true,
		version,
		source: "signed_release_manifest",
		channel: typeof manifest.channel === "string" ? manifest.channel : undefined,
		releaseTag: typeof manifest.release_tag === "string" ? manifest.release_tag : undefined,
		keyId,
	};
}

/** Resolve the latest release from the configured sources (see the header). */
export async function resolveLatestRelease(
	env: (name: string) => string | undefined | null,
	nowMs: number = Date.now(),
): Promise<LatestRelease> {
	const read = (name: string) => {
		const value = env(name);
		return typeof value === "string" ? value.trim() : "";
	};
	const manifest = read(RELEASE_MANIFEST_ENV);
	const signature = read(RELEASE_SIGNATURE_ENV);
	const publicKey = read(RELEASE_PUBLIC_KEY_ENV);
	const provided = [manifest, signature, publicKey].filter(Boolean).length;
	if (provided > 0 && provided < 3) return { ok: false, reason: "release_manifest_incomplete" };
	if (provided === 3) {
		const verified = await verifySignedReleaseManifest(manifest, signature, publicKey, nowMs);
		return verified ?? { ok: false, reason: "release_manifest_invalid" };
	}
	const configured = normalizeReleaseVersion(read(LATEST_VERSION_ENV));
	return configured ? { ok: true, version: configured, source: "configured" } : { ok: false, reason: "latest_version_unconfigured" };
}
