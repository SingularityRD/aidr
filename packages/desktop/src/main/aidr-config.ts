import { ConfigSchema } from "@singularityrd/aidr-core";
import { type Config, getConfig, updateConfig } from "../../../cli/src/utils/config-manager.js";

/**
 * `logging.log_clean` in `~/.singularity-aidr/config.json`: whether allowed
 * verdicts are written to the audit log as well (off by default). Changed
 * through the CLI's config manager, which keeps the file's private ACL and
 * refuses a concurrent edit; the result is validated with the core schema
 * first, as `aidr setup` does.
 */
export function setLogClean(enabled: boolean): void {
	const current = getConfig() as (Config & { logging?: Record<string, unknown> }) | null;
	if (!current)
		throw new Error("The AIDR configuration does not exist yet; connect Claude Code first.");
	const update = { logging: { ...(current.logging ?? {}), log_clean: enabled } };
	if (!ConfigSchema.safeParse({ ...current, ...update }).success) {
		throw new Error("the resulting configuration is not valid");
	}
	updateConfig(update as Partial<Config>);
}
