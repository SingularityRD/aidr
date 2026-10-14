import {
	ControlPlaneClient,
	getInstallationId,
	isInvalidConfig,
	loadConfig,
	resolveManagedApiKey,
	resolvePath,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { buildHeartbeat, type HeartbeatConnector, type HeartbeatDeps } from "../utils/heartbeat.js";

export interface HeartbeatCommandOptions {
	json?: boolean;
	dryRun?: boolean;
	/** Scheduler mode: print nothing unless the report could not be sent. */
	quiet?: boolean;
}

/** Test seams; production callers pass nothing. */
export interface HeartbeatCommandDeps extends Partial<HeartbeatDeps> {
	send?: (payload: {
		iid: string;
		connectors: HeartbeatConnector[];
	}) => Promise<{ ok: boolean; error?: string }>;
	iid?: () => Promise<string | undefined>;
}

/**
 * `aidr heartbeat` — measure every agent host on this device and report the
 * state of each AIDR hook to the control plane (C10). Local mode measures and
 * prints only: there is no control plane to tell.
 */
export default async function heartbeatCommand(
	options: HeartbeatCommandOptions = {},
	deps: HeartbeatCommandDeps = {},
): Promise<void> {
	const home = deps.home ?? resolvePath("~");
	const connectors = buildHeartbeat({ ...deps, home });
	const say = (line: string) => {
		if (!options.quiet) console.log(line);
	};
	if (options.json) {
		console.log(JSON.stringify({ connectors }, null, 2));
	} else if (!options.quiet) {
		if (connectors.length === 0) say(ct("heartbeat.none"));
		for (const entry of connectors) {
			say(
				ct("heartbeat.line", {
					connector: entry.connector,
					state: entry.state,
					enforcement: entry.enforcement,
				}),
			);
		}
	}
	const config = await loadConfig();
	if (isInvalidConfig(config) || config.mode !== "managed") {
		say(ct("heartbeat.localMode"));
		return;
	}
	if (connectors.length === 0 || options.dryRun) {
		if (options.dryRun) say(ct("heartbeat.dryRun"));
		return;
	}
	const iid = await (deps.iid ?? (() => getInstallationId(resolvePath("~/.singularity-aidr"))))();
	const send =
		deps.send ??
		(async (payload: { iid: string; connectors: HeartbeatConnector[] }) => {
			const apiKey = await resolveManagedApiKey(config);
			if (!apiKey) return { ok: false, error: "not_enrolled" };
			return new ControlPlaneClient(config.control_plane, apiKey).sendConnectorHeartbeat(
				payload as unknown as {
					iid: string;
					connectors: Array<Record<string, string | number | boolean>>;
				},
			);
		});
	if (!iid) {
		console.error(ct("heartbeat.failed", { error: "installation_id_unavailable" }));
		process.exitCode = 1;
		return;
	}
	const outcome = await send({ iid, connectors });
	if (outcome.ok) {
		say(ct("heartbeat.sent", { count: connectors.length }));
		return;
	}
	console.error(ct("heartbeat.failed", { error: outcome.error ?? "unknown" }));
	process.exitCode = 1;
}
