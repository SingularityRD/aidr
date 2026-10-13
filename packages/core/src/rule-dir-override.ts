/**
 * `AIDR_THREATS_DIR` / `AIDR_ALLOWLISTS_DIR`: environment overrides of the rule
 * and allowlist directories a connector loads.
 *
 * An override replaces the whole bundled rule set, so anything that can set the
 * host environment (a settings `env` block, a shell start-up file, a launcher
 * wrapper) could otherwise swap in an empty or benign directory while AIDR kept
 * answering "allow". The policy here:
 *
 *   - Commercial (release) builds never honour the override: they load only the
 *     bundled, manifest-checked resources. The override is reported, not used.
 *   - Development builds honour it (rule development, packaging tests), and the
 *     directory goes through the same manifest check as the bundled one (it is
 *     the primary rule directory, see `loadThreatsFromDirsWithReport`).
 *   - Either way an override is never silent: {@link ruleDirOverrideNotice}
 *     gives the warning the connectors show on every verdict, at session start
 *     and in their health output.
 *
 * Setting either variable from a tool call is denied by CLT-SELF-007, and
 * writing it into agent settings or start-up files by CLT-SELF-004.
 */

import { isCommercialBuild } from "./build-flavor.js";
import { boundTerminalText } from "./terminal-text.js";

export type RuleDirKind = "threats" | "allowlists";

/** Environment variable that overrides each directory. */
export const RULE_DIR_ENV: Readonly<Record<RuleDirKind, string>> = {
	threats: "AIDR_THREATS_DIR",
	allowlists: "AIDR_ALLOWLISTS_DIR",
};

export interface RuleDirOverride {
	kind: RuleDirKind;
	envName: string;
	/** The directory the variable names, as set. */
	path: string;
	/** False in a commercial build: the bundled directory is used instead. */
	accepted: boolean;
}

export interface RuleDirOverrideOptions {
	env?: Readonly<Record<string, string | undefined>>;
	/** Defaults to {@link isCommercialBuild}. */
	commercial?: boolean;
}

/** The override set for `kind`, or null when the variable is unset or blank. */
export function ruleDirOverride(
	kind: RuleDirKind,
	options: RuleDirOverrideOptions = {},
): RuleDirOverride | null {
	const envName = RULE_DIR_ENV[kind];
	const path = (options.env ?? process.env)[envName]?.trim();
	if (!path) return null;
	const commercial = options.commercial ?? isCommercialBuild();
	return { kind, envName, path, accepted: !commercial };
}

/** Both overrides that are set, threats first. */
export function ruleDirOverrides(options: RuleDirOverrideOptions = {}): RuleDirOverride[] {
	return (["threats", "allowlists"] as const)
		.map((kind) => ruleDirOverride(kind, options))
		.filter((override): override is RuleDirOverride => override !== null);
}

const NOUN: Readonly<Record<RuleDirKind, string>> = {
	threats: "threat rules",
	allowlists: "allowlists",
};

/** One user-facing warning line per override, or null when none is set. */
export function ruleDirOverrideNotice(overrides: readonly RuleDirOverride[]): string | null {
	if (overrides.length === 0) return null;
	return overrides
		.map((override) => {
			const shown = boundTerminalText(override.path, 200).text;
			const noun = NOUN[override.kind];
			return override.accepted
				? `⚠️ Singularity AIDR is using ${noun} from ${override.envName}=${shown} instead of its bundled ${noun} (development build). Detection is only as good as that directory; unset ${override.envName} to use the bundled rules.`
				: `⚠️ Singularity AIDR ignored ${override.envName}=${shown}: this release build uses only its bundled, integrity-checked ${noun}. Something set this variable in the agent's environment (settings env block, shell start-up file or launcher); remove it.`;
		})
		.join("\n");
}
