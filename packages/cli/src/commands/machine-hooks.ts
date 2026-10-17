import { isCommercialBuild } from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import {
	installMachineHooks,
	type MachineHookDeps,
	type MachineHookResult,
	machineHookStatus,
	removeMachineHooks,
	type ScheduleDeps,
	scheduleHeartbeat,
} from "../utils/machine-hooks.js";
import { installerReleaseKey } from "../utils/release-key.js";
import {
	type StandaloneBundleCheck,
	standaloneBundleRoot,
	verifyStandaloneBundle,
} from "../utils/standalone.js";

export interface MachineHooksOptions {
	lockOtherHooks?: boolean;
	dryRun?: boolean;
	json?: boolean;
	/** Also install / remove the hourly `aidr heartbeat` for every user. */
	heartbeat?: boolean;
	/** Bundle root override (tests, staged images); defaults to the running bundle. */
	bundleRoot?: string;
}

/** Test seams; production callers pass nothing. */
export interface MachineHooksDeps extends MachineHookDeps, ScheduleDeps {
	isAdministrator?: () => boolean;
	/** Bundle verification (tests); default {@link verifyMachineBundle}. */
	verifyBundle?: (root: string) => StandaloneBundleCheck;
}

/**
 * Check the bundle the hosts will run before any system-wide hook points at
 * it: every file against the bundle manifest, and the manifest signatures
 * against the release key the installer placed next to the bundle
 * (`<prefix>/config/release-public.pem`). A release (commercial) build must be
 * signed. An unreadable key file trusts nothing, so a signed bundle then fails.
 */
export function verifyMachineBundle(
	root: string,
	commercial: boolean = isCommercialBuild(),
): StandaloneBundleCheck {
	let trustKeys: string[] = [];
	try {
		const installed = installerReleaseKey(root);
		if (installed) trustKeys = [installed.key.pem];
	} catch {
		trustKeys = [];
	}
	return verifyStandaloneBundle(root, { trustKeys, requireSignature: commercial });
}

function isAdministrator(deps: MachineHooksDeps): boolean {
	if (deps.isAdministrator) return deps.isAdministrator();
	// Windows has no cheap check; the write itself reports EPERM.
	if ((deps.platform ?? process.platform) === "win32") return true;
	return typeof process.getuid === "function" && process.getuid() === 0;
}

function print(results: MachineHookResult[], json: boolean | undefined): void {
	if (json) {
		console.log(JSON.stringify({ results }, null, 2));
		return;
	}
	for (const entry of results) console.log(`  ${entry.host}: ${entry.action} — ${entry.detail}`);
}

function finish(results: MachineHookResult[]): void {
	if (results.some((entry) => entry.action === "failed")) process.exitCode = 1;
}

function bundleRootOr(options: MachineHooksOptions): string | null {
	return options.bundleRoot ?? standaloneBundleRoot();
}

/** `aidr machine-hooks install` — run by the per-machine installers as administrator. */
export async function machineHooksInstallCommand(
	options: MachineHooksOptions = {},
	deps: MachineHooksDeps = {},
): Promise<void> {
	const root = bundleRootOr(options);
	if (!root) {
		console.error(ct("machineHooks.noBundle"));
		process.exitCode = 2;
		return;
	}
	if (!options.dryRun && !isAdministrator(deps)) {
		console.error(ct("machineHooks.needsAdmin"));
		process.exitCode = 2;
		return;
	}
	const check = (deps.verifyBundle ?? verifyMachineBundle)(root);
	if (!check.ok) {
		console.error(
			ct("machineHooks.bundleRefused", { root, problems: check.problems.slice(0, 3).join("; ") }),
		);
		process.exitCode = 1;
		return;
	}
	const results = installMachineHooks(
		{ bundleRoot: root, lockOtherHooks: options.lockOtherHooks, dryRun: options.dryRun },
		deps,
	);
	if (options.heartbeat)
		results.push(scheduleHeartbeat({ bundleRoot: root, dryRun: options.dryRun }, deps));
	if (!options.json) console.log(ct("machineHooks.installTitle"));
	print(results, options.json);
	if (!options.json) {
		console.log(ct("machineHooks.precedenceNote"));
		console.log(ct("machineHooks.editorsNote"));
	}
	finish(results);
}

/** `aidr machine-hooks remove` — run by the per-machine uninstallers. */
export async function machineHooksRemoveCommand(
	options: MachineHooksOptions = {},
	deps: MachineHooksDeps = {},
): Promise<void> {
	if (!options.dryRun && !isAdministrator(deps)) {
		console.error(ct("machineHooks.needsAdmin"));
		process.exitCode = 2;
		return;
	}
	const results = removeMachineHooks({ dryRun: options.dryRun }, deps);
	if (options.heartbeat) {
		results.push(
			scheduleHeartbeat(
				{ bundleRoot: bundleRootOr(options) ?? "", remove: true, dryRun: options.dryRun },
				deps,
			),
		);
	}
	print(results, options.json);
	finish(results);
}

/** `aidr machine-hooks status` — measured, no administrator rights needed. */
export async function machineHooksStatusCommand(
	options: MachineHooksOptions = {},
	deps: MachineHookDeps = {},
): Promise<void> {
	const states = machineHookStatus(deps);
	if (options.json) {
		console.log(JSON.stringify({ hosts: states }, null, 2));
		return;
	}
	for (const state of states) {
		const tamper =
			state.tamperResistant === null
				? ct("machineHooks.tamperUnknown")
				: state.tamperResistant
					? ct("machineHooks.tamperYes")
					: ct("machineHooks.tamperNo");
		console.log(
			state.registered
				? ct("machineHooks.statusRegistered", {
						host: state.host,
						path: state.path,
						locked: state.otherHooksLocked
							? ct("machineHooks.lockedYes")
							: ct("machineHooks.lockedNo"),
						tamper,
					})
				: ct("machineHooks.statusAbsent", { host: state.host, path: state.path }),
		);
		for (const problem of state.problems) console.log(`    ${problem}`);
	}
}
