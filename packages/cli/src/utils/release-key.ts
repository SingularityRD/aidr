import { createPublicKey } from "node:crypto";
import { type Config, isCommercialBuild } from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";

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
