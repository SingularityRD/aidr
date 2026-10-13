import { createHash, createPublicKey } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { type Config, isCommercialBuild } from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";

/**
 * The release public key: the Ed25519 key whose signatures prove that the
 * files of a release build are genuine. A release (commercial) hook refuses to
 * trust its own rules until the key is in `integrity.public_keys_pem` of
 * ~/.singularity-aidr/config.json, so `aidr setup` provisions it:
 *
 *   - from the key the signed desktop installer places next to the bundle
 *     (<prefix>/config/release-public.pem), automatically; or
 *   - from `aidr setup --release-key <file.pem>` for a manual install.
 *
 * Provisioning only ever adds the key to an empty trust list. A different key
 * an operator configured is kept unless `--force` is given: trusting a new
 * signer is a decision for the operator, not a side effect of setup.
 */

const MAX_KEY_BYTES = 16 * 1024;

export interface ReleaseKey {
	/** Normalised SPKI PEM. */
	pem: string;
	/** sha256 of the SPKI DER, lower-case hex (the form `--trust-key-fingerprint` and release-rc use). */
	fingerprint: string;
}

class ReleaseKeyError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ReleaseKeyError";
	}
}

/** Parse an Ed25519 SPKI public key in PEM form; anything else is refused with the reason. */
export function parseReleaseKey(text: string): ReleaseKey {
	if (/BEGIN [A-Z ]*PRIVATE KEY/u.test(text)) {
		throw new ReleaseKeyError("it holds a PRIVATE key; give the release PUBLIC key");
	}
	if (!/-----BEGIN PUBLIC KEY-----/u.test(text)) {
		throw new ReleaseKeyError("it is not a PEM public key (-----BEGIN PUBLIC KEY-----)");
	}
	let key: ReturnType<typeof createPublicKey>;
	try {
		key = createPublicKey(text);
	} catch {
		throw new ReleaseKeyError("it is not a readable PEM public key");
	}
	if (key.asymmetricKeyType !== "ed25519") {
		throw new ReleaseKeyError(`it is a ${key.asymmetricKeyType ?? "unknown"} key, not Ed25519`);
	}
	const der = key.export({ type: "spki", format: "der" });
	return {
		pem: key.export({ type: "spki", format: "pem" }).toString(),
		fingerprint: createHash("sha256").update(der).digest("hex"),
	};
}

/** Read and parse a release key file. Errors name the file. */
export function readReleaseKeyFile(path: string): ReleaseKey {
	let text: string;
	try {
		const bytes = readFileSync(path);
		if (bytes.length > MAX_KEY_BYTES) throw new ReleaseKeyError("it is too large to be a key");
		text = bytes.toString("utf8");
	} catch (error) {
		if (error instanceof ReleaseKeyError) throw new ReleaseKeyError(`${path}: ${error.message}`);
		throw new ReleaseKeyError(`${path} cannot be read`);
	}
	try {
		return parseReleaseKey(text);
	} catch (error) {
		throw new ReleaseKeyError(
			`${path} is not an Ed25519 release public key: ${(error as Error).message}`,
		);
	}
}

/** Where the desktop installers place the release key for a bundle at `<prefix>/bundle`. */
function installerReleaseKeyPath(bundleRoot: string): string {
	return join(dirname(bundleRoot), "config", "release-public.pem");
}

/** The installer's release key next to a standalone bundle, or null when the installer shipped none. */
export function installerReleaseKey(bundleRoot: string): { key: ReleaseKey; path: string } | null {
	const path = installerReleaseKeyPath(bundleRoot);
	return existsSync(path) ? { key: readReleaseKeyFile(path), path } : null;
}

/** Fingerprint of a configured key, or null for an entry that is not an Ed25519 public key. */
function fingerprintOf(pem: string): string | null {
	try {
		return parseReleaseKey(pem).fingerprint;
	} catch {
		return null;
	}
}

type ReleaseKeyOutcome =
	/** The trust list was empty; the key is now its only entry. */
	| "added"
	/** The key was already trusted; nothing changes. */
	| "present"
	/** Other keys are configured and --force was not given; they are kept unchanged. */
	| "kept_existing"
	/** --force: the configured keys were replaced by this one. */
	| "replaced";

export interface ReleaseKeyPlan {
	outcome: ReleaseKeyOutcome;
	/** The trust list to write (equal to the current one for present / kept_existing). */
	keys: string[];
	/** Fingerprints of the keys that were configured before. */
	existing: string[];
}

/** Decide how to merge `key` into the configured `integrity.public_keys_pem`. */
export function planReleaseKey(
	configured: readonly string[],
	key: ReleaseKey,
	force: boolean,
): ReleaseKeyPlan {
	const current = configured.filter((entry) => typeof entry === "string" && entry.trim() !== "");
	const existing = current.map((entry) => fingerprintOf(entry) ?? "unreadable");
	if (current.length === 0) return { outcome: "added", keys: [key.pem], existing };
	if (existing.includes(key.fingerprint))
		return { outcome: "present", keys: [...current], existing };
	if (force) return { outcome: "replaced", keys: [key.pem], existing };
	return { outcome: "kept_existing", keys: [...current], existing };
}

/** Read and write `integrity.public_keys_pem` of the local config (injectable for tests). */
export interface ReleaseKeyStore {
	read(): string[];
	write(keys: string[]): void;
}

/** Merge the release key into the configured trust list; writes only when the list changes. */
export function provisionReleaseKey(
	key: ReleaseKey,
	store: ReleaseKeyStore,
	{ force = false, dryRun = false }: { force?: boolean; dryRun?: boolean } = {},
): ReleaseKeyPlan {
	const plan = planReleaseKey(store.read(), key, force);
	if (!dryRun && (plan.outcome === "added" || plan.outcome === "replaced")) store.write(plan.keys);
	return plan;
}

// ── Reporting (aidr status / aidr doctor) ──────────────────────────────

/**
 * Whether this installation can verify its own release signature. `aidr status`
 * and `aidr doctor` share this so they never disagree.
 *
 * A release (commercial) build without `integrity.public_keys_pem` cannot check
 * the signature of its own connector bundles, and an unsigned bundle then fails
 * closed: every tool call is blocked. That is the state an administrator must see
 * in red, with the one command that fixes it. The checks themselves are not
 * changed here; this only reports them.
 */
type ReleaseKeyStatus =
	/** At least one key is configured and every configured key parses. */
	| "ok"
	/** Release build with no key: the installation cannot be verified. */
	| "missing"
	/** A configured key is not a usable public key. */
	| "invalid"
	/** Development build with integrity checks on but no key: digests only. */
	| "digests_only"
	/** Development build with integrity checks off. */
	| "off";

export interface ReleaseKeyState {
	status: ReleaseKeyStatus;
	/** Release build: the key is mandatory. */
	release_build: boolean;
	keys: number;
	invalid_keys: number;
}

/** The command that installs the key (implemented by `aidr setup`), with a localized placeholder. */
export function releaseKeyFix(): string {
	return ct("integrity.fixCommand");
}

function parses(pem: string): boolean {
	try {
		createPublicKey(pem);
		return true;
	} catch {
		return false;
	}
}

/** `config` must come from `loadConfig`, which applies the release-build overrides. */
export function releaseKeyState(
	config: Pick<Config, "integrity">,
	releaseBuild = isCommercialBuild(),
): ReleaseKeyState {
	const keys = (config.integrity.public_keys_pem ?? []).filter((pem) => pem.trim().length > 0);
	const invalid = keys.filter((pem) => !parses(pem)).length;
	const base = { release_build: releaseBuild, keys: keys.length, invalid_keys: invalid };
	if (invalid > 0) return { status: "invalid", ...base };
	if (keys.length > 0) return { status: "ok", ...base };
	if (releaseBuild) return { status: "missing", ...base };
	const checking = config.integrity.enabled && config.integrity.verify_on_start;
	return { status: checking ? "digests_only" : "off", ...base };
}

/** A missing or unusable key in a release build stops every call: that is a failure. */
export function releaseKeySeverity(state: ReleaseKeyState): "ok" | "warn" | "fail" {
	if (state.status === "missing") return "fail";
	if (state.status === "invalid") return state.release_build ? "fail" : "warn";
	return state.status === "digests_only" ? "warn" : "ok";
}

/** One line in the current locale. */
export function describeReleaseKey(state: ReleaseKeyState): string {
	switch (state.status) {
		case "ok":
			return ct("integrity.ok", { count: state.keys });
		case "missing":
			return ct("integrity.missing", { fix: releaseKeyFix() });
		case "invalid":
			return ct("integrity.invalid", {
				invalid: state.invalid_keys,
				total: state.keys,
				fix: releaseKeyFix(),
			});
		case "digests_only":
			return ct("integrity.digestsOnly");
		default:
			return ct("integrity.off");
	}
}
