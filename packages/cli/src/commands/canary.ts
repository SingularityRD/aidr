/**
 * `aidr canary deploy|list|remove|status`: operator management of canary
 * credentials (honeytokens). The decoys are new files with random, never-valid
 * credential values; the registry keeps only their paths and SHA-256 digests.
 * Agents cannot run these commands (threat rule CLT-CANARY-001) or read the
 * registry (CLT-SELF-008).
 */

import {
	CANARY_KINDS,
	CANARY_PLACEMENTS,
	type CanaryKind,
	type CanaryStatusEntry,
	canaryStatus,
	deployCanaries,
	escapeTerminalText,
	isCanaryKind,
	isInvalidConfig,
	loadConfig,
	removeCanaries,
} from "@singularityrd/aidr-core";
import { auditLogFiles, readAuditEntries } from "./audit.js";

/** Test seams; production callers pass nothing. */
export interface CanaryCommandDeps {
	registryPath?: string;
	homeDir?: string;
	cwd?: string;
	configPath?: string;
	out?: (line: string) => void;
	err?: (line: string) => void;
}

interface JsonOption {
	json?: boolean;
}

export interface CanaryDeployOptions extends JsonOption {
	path?: string;
	kinds?: string;
}

export interface CanaryRemoveOptions extends JsonOption {
	all?: boolean;
}

function writers(deps: CanaryCommandDeps) {
	return {
		out: deps.out ?? ((line: string) => console.log(line)),
		err: deps.err ?? ((line: string) => console.error(line)),
	};
}

function fail(deps: CanaryCommandDeps, message: string): void {
	writers(deps).err(message);
	process.exitCode = 1;
}

function parseKinds(value: string | undefined): CanaryKind[] | string {
	if (value === undefined) return [...CANARY_KINDS];
	const kinds = value
		.split(",")
		.map((kind) => kind.trim().toLowerCase())
		.filter((kind) => kind.length > 0);
	const unknown = kinds.filter((kind) => !isCanaryKind(kind));
	if (kinds.length === 0 || unknown.length > 0) {
		return `Unknown canary kind "${escapeTerminalText(unknown.join(", ") || value)}". Use a comma-separated list of: ${CANARY_KINDS.join(", ")}.`;
	}
	return kinds as CanaryKind[];
}

/** What a registry record may show: never a token value (the registry has none) nor its digest. */
function publicEntry(entry: CanaryStatusEntry) {
	return {
		id: entry.id,
		kind: entry.kind,
		path: entry.path,
		created_at: entry.created_at,
		state: entry.state,
	};
}

export async function canaryDeployCommand(
	options: CanaryDeployOptions,
	deps: CanaryCommandDeps = {},
): Promise<void> {
	const { out } = writers(deps);
	const kinds = parseKinds(options.kinds);
	if (typeof kinds === "string") {
		fail(deps, kinds);
		return;
	}
	let result: ReturnType<typeof deployCanaries>;
	try {
		result = deployCanaries({
			kinds,
			projectDir: options.path ?? deps.cwd,
			homeDir: deps.homeDir,
			registryPath: deps.registryPath,
		});
	} catch (error) {
		fail(deps, `Canary deploy failed: ${escapeTerminalText((error as Error).message)}`);
		return;
	}
	if (options.json) {
		out(
			JSON.stringify({
				deployed: result.deployed.map((record) => ({
					id: record.id,
					kind: record.kind,
					path: record.path,
					created_at: record.created_at,
				})),
				skipped: result.skipped,
			}),
		);
	} else {
		for (const record of result.deployed) {
			out(`deployed  ${record.id}  ${record.kind.padEnd(10)}  ${escapeTerminalText(record.path)}`);
		}
		for (const skip of result.skipped) {
			out(`skipped   ${skip.kind.padEnd(10)}  ${escapeTerminalText(skip.reason)}`);
		}
		if (result.deployed.some((record) => CANARY_PLACEMENTS[record.kind].scope === "project")) {
			out(
				"Project decoys are new files in your working tree: keep them out of version control (for example with a .gitignore entry) so they are never committed.",
			);
		}
	}
	if (result.deployed.length === 0) process.exitCode = 1;
}

export async function canaryListCommand(
	options: JsonOption,
	deps: CanaryCommandDeps = {},
): Promise<void> {
	const { out } = writers(deps);
	const status = canaryStatus(deps.registryPath);
	if (status.registry === "invalid") {
		fail(deps, `The canary registry is unusable (${status.reason}).`);
		return;
	}
	if (options.json) {
		out(JSON.stringify({ canaries: status.canaries.map(publicEntry) }));
		return;
	}
	if (status.canaries.length === 0) {
		out("No canary credentials are deployed. Run `aidr canary deploy` to plant them.");
		return;
	}
	for (const entry of status.canaries) {
		out(
			`${entry.id}  ${entry.kind.padEnd(10)}  ${entry.state.padEnd(11)}  ${escapeTerminalText(entry.path)}`,
		);
	}
}

export async function canaryRemoveCommand(
	id: string | undefined,
	options: CanaryRemoveOptions,
	deps: CanaryCommandDeps = {},
): Promise<void> {
	const { out } = writers(deps);
	if (Boolean(id) === Boolean(options.all)) {
		fail(deps, "Pass exactly one canary id or --all.");
		return;
	}
	let result: ReturnType<typeof removeCanaries>;
	try {
		result = removeCanaries({
			ids: id ? [id] : undefined,
			all: options.all === true,
			registryPath: deps.registryPath,
		});
	} catch (error) {
		fail(deps, `Canary remove failed: ${escapeTerminalText((error as Error).message)}`);
		return;
	}
	if (options.json) {
		out(JSON.stringify(result));
	} else {
		for (const removed of result.removed) {
			const note =
				removed.file === "deleted"
					? "decoy file deleted"
					: removed.file === "missing"
						? "decoy file was already gone"
						: `decoy file ${removed.file === "modified" ? "was changed" : "is no longer a regular file"}; left in place, delete it yourself if it is not yours`;
			out(`removed  ${removed.id}  ${escapeTerminalText(removed.path)}  (${note})`);
		}
		if (result.removed.length === 0 && result.unknownIds.length === 0) {
			out("No canary credentials are deployed.");
		}
	}
	if (result.unknownIds.length > 0) {
		fail(deps, `Unknown canary id: ${escapeTerminalText(result.unknownIds.join(", "))}`);
	}
}

interface TriggerSummary {
	count: number;
	last: string | null;
	available: boolean;
}

async function recentTriggers(deps: CanaryCommandDeps): Promise<TriggerSummary> {
	try {
		const config = await loadConfig(deps.configPath);
		if (isInvalidConfig(config)) return { count: 0, last: null, available: false };
		const { entries } = await readAuditEntries(auditLogFiles(config.logging));
		const triggers = entries.filter((entry) => entry.category === "canary_triggered");
		const last = triggers.at(-1)?.timestamp;
		return {
			count: triggers.length,
			last: typeof last === "string" ? last : null,
			available: true,
		};
	} catch {
		return { count: 0, last: null, available: false };
	}
}

export async function canaryStatusCommand(
	options: JsonOption,
	deps: CanaryCommandDeps = {},
): Promise<void> {
	const { out } = writers(deps);
	const status = canaryStatus(deps.registryPath);
	const triggers = await recentTriggers(deps);
	const counts = { intact: 0, missing: 0, modified: 0, not_regular: 0 };
	for (const entry of status.canaries) counts[entry.state] += 1;
	const healthy =
		status.registry !== "invalid" &&
		counts.missing === 0 &&
		counts.modified === 0 &&
		counts.not_regular === 0;
	if (options.json) {
		out(
			JSON.stringify({
				registry: status.registry,
				...(status.reason ? { reason: status.reason } : {}),
				canaries: status.canaries.map(publicEntry),
				counts,
				triggers,
			}),
		);
	} else {
		if (status.registry === "invalid") {
			out(
				`Registry: UNUSABLE (${status.reason}); canary detection is NOT running until it is repaired.`,
			);
		} else if (status.registry === "absent" || status.canaries.length === 0) {
			out("Registry: no canary credentials deployed.");
		} else {
			out(
				`Registry: ${status.canaries.length} canary credential(s): ${counts.intact} intact, ${counts.missing} missing, ${counts.modified} modified, ${counts.not_regular} not a regular file.`,
			);
		}
		out(
			triggers.available
				? `Triggers in the local audit log: ${triggers.count}${triggers.last ? ` (latest ${triggers.last})` : ""}.`
				: "Triggers: the local audit log could not be read.",
		);
		for (const entry of status.canaries.filter((canary) => canary.state !== "intact")) {
			out(`  ${entry.id}  ${entry.kind}  ${entry.state}  ${escapeTerminalText(entry.path)}`);
		}
	}
	if (!healthy) process.exitCode = 1;
}
