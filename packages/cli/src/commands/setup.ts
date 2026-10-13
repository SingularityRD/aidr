import { resolvePath, VERSION } from "@singularityrd/aidr-core";
import { type CliMessageKey, ct } from "../i18n/index.js";
import { createConfig } from "../utils/config-manager.js";
import {
	type ConnectorInstallOptions,
	HOST_IDS,
	type HostCommandRunner,
	type HostId,
	type HostInstallResult,
	installConnectors,
} from "../utils/connector-install.js";
import { detectEnvironment } from "../utils/detect-env.js";
import { installHooks, recordHooksInstalled } from "../utils/install-hooks.js";
import {
	confirmOperatorAction,
	type OperatorCommandDeps,
	OperatorConfirmationError,
} from "../utils/operator-confirm.js";
import { writeSetupLedger } from "../utils/setup-ledger.js";
import { standaloneBundleRoot } from "../utils/standalone.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";

interface SetupOptions {
	force?: boolean;
	secretStore?: string;
	yes?: boolean;
	/** Show what would be installed; change nothing. */
	dryRun?: boolean;
	/** `--no-install`: configure only and print the manual connector steps. */
	install?: boolean;
	/** Comma-separated host ids (`--host codex,opencode`); default: every detected host. */
	host?: string;
	claudePluginDir?: string;
	cursorVsix?: string;
	vscodeVsix?: string;
}

interface SetupDeps extends OperatorCommandDeps {
	/** Home whose hosts are detected and configured (tests). */
	home?: string;
	/** Host CLI runner (tests). */
	run?: HostCommandRunner;
	/** Standalone bundle root (tests); defaults to the SEA this process runs from. */
	standaloneRoot?: string | null;
}

const ACTION_TEXT: Record<HostInstallResult["action"], CliMessageKey> = {
	already_installed: "setup.action.alreadyInstalled",
	installed: "setup.action.installed",
	updated: "setup.action.updated",
	would_install: "setup.action.wouldInstall",
	would_update: "setup.action.wouldUpdate",
	manual: "setup.action.manual",
	failed: "setup.action.failed",
	skipped_not_detected: "setup.action.notDetected",
};

/** Parse `--host a,b`; unknown ids are an error, never silently ignored. */
export function parseHosts(value: string | undefined): HostId[] | undefined {
	if (value === undefined) return undefined;
	const aliases: Record<string, HostId> = { claude: "claude-code", code: "vscode" };
	const hosts = value
		.split(",")
		.map((entry) => entry.trim().toLowerCase())
		.filter(Boolean)
		.map((entry) => aliases[entry] ?? entry);
	const unknown = hosts.filter((entry) => !(HOST_IDS as readonly string[]).includes(entry));
	if (unknown.length > 0 || hosts.length === 0) {
		throw new Error(
			`Unknown host ${unknown.join(", ") || "(none)"}. Valid hosts: ${HOST_IDS.join(", ")}.`,
		);
	}
	return [...new Set(hosts)] as HostId[];
}

function printHostResults(results: HostInstallResult[]): void {
	console.log(ct("setup.connectors"));
	for (const entry of results) {
		console.log(`  ${entry.label.padEnd(12)} ${ct(ACTION_TEXT[entry.action])} — ${entry.detail}`);
		for (const change of entry.changes) console.log(`               ${change}`);
	}
}

/** Run an operator confirmation; on refusal report it, set a failing exit code and return false. */
async function confirmed(
	prompt: string[],
	word: string,
	options: SetupOptions,
	deps: OperatorCommandDeps,
): Promise<boolean> {
	try {
		await confirmOperatorAction({
			prompt: prompt.join("\n"),
			word,
			yes: options.yes,
			env: deps.env,
			streams: deps.streams,
		});
		return true;
	} catch (error) {
		console.error(
			`${error instanceof OperatorConfirmationError ? error.message : String(error)} ${ct("setup.nothingChanged")}`,
		);
		process.exitCode = 1;
		return false;
	}
}

function confirmForce(options: SetupOptions, deps: OperatorCommandDeps): Promise<boolean> {
	// --force replaces the existing configuration and credential and resets
	// the recorded hook state, so it is an operator-only action confirmed like
	// `aidr allowlist add`. A plain `aidr setup` reuses the config unchanged.
	return confirmed(
		[
			"Singularity AIDR — forced re-setup",
			"The existing local configuration and CLI credential will be replaced.",
		],
		"replace",
		options,
		deps,
	);
}

/**
 * A plugin directory or VSIX is code the host will run. Installing one is an
 * operator action: without this, an agent could run `aidr setup
 * --claude-plugin-dir <its own directory>` to load arbitrary code into its host.
 * Host-registry installs with a fixed package spec need no confirmation.
 */
async function confirmArtifacts(
	options: SetupOptions,
	deps: OperatorCommandDeps,
): Promise<boolean> {
	const artifacts = [
		options.claudePluginDir && `  Claude Code plugin directory: ${options.claudePluginDir}`,
		options.cursorVsix && `  Cursor extension: ${options.cursorVsix}`,
		options.vscodeVsix && `  VS Code extension: ${options.vscodeVsix}`,
	].filter((line): line is string => typeof line === "string");
	if (artifacts.length === 0) return true;
	return confirmed(
		[
			"Singularity AIDR — install connector artifacts",
			...artifacts,
			"Install only artifacts you verified against the signed release bundle.",
		],
		"install",
		options,
		deps,
	);
}

async function setupCommand(options: SetupOptions = {}, deps: SetupDeps = {}): Promise<void> {
	console.log(`\n🛡️  ${ct("setup.title")}${options.dryRun ? ct("setup.titleDryRun") : ""}\n`);

	if (options.force && !options.dryRun && !(await confirmForce(options, deps))) return;
	if (!options.dryRun && !(await confirmArtifacts(options, deps))) return;

	try {
		const hosts = parseHosts(options.host);
		const home = deps.home ?? resolvePath("~");
		const hostEnv = deps.env ?? process.env;

		console.error(ct("setup.detecting"));
		// Home-based only, the same measurement `aidr status` prints (PRD-14).
		const env = await detectEnvironment(home, hostEnv);
		const detected = env.detectedHosts ?? [];
		// Finding nothing to protect is not a success: no ✓ for it.
		console.error(
			detected.length > 0
				? `✓ ${ct("setup.hostsFound", { hosts: detected.join(", ") })}`
				: `! ${ct("setup.noHosts")}`,
		);

		if (options.dryRun) {
			console.error(ct("setup.skipConfig"));
		} else {
			console.error(ct("setup.creatingConfig"));
			// Local mode needs no credential, so no vault either; a managed config's
			// credential goes to the OS vault or the encrypted file store.
			const config = await createConfig(env, options.force || false, {
				secretStoreSelection: options.secretStore,
			});
			// The reused branch must stay distinct (config.outcome === "reused"):
			// a rerun reports that no changes were needed, never a fresh success.
			console.error(
				config.outcome === "reused"
					? `✓ ${ct("setup.configReused", { path: config.path })}`
					: `✓ ${ct("setup.configCreated", { path: config.path })}`,
			);
			if (config.warning) console.warn(`⚠ ${config.warning}`);
			if (config.outcome === "reused") {
				console.log(`\n${ct("setup.rerunNoChanges")}`);
				console.log(`  ${ct("setup.rerunConfig", { path: config.path })}`);
			}
		}

		console.error(ct("setup.loadingRules"));
		const ruleCount = await loadBundledThreatCount();
		if (ruleCount <= 0) {
			console.error(ct("setup.noRules"));
			process.exit(1);
		}
		const detection = await verifyDetection();
		if (!detection.ok) {
			console.error(ct("setup.selfTestFailed", { reason: detection.reason }));
			process.exit(1);
		}
		// One line: the count is what loaded, the self-test proves it matches.
		console.error(`✓ ${ct("setup.detectionOk", { rules: ruleCount })}`);

		if (options.install === false) {
			// Guidance only: the previous behaviour, for operators who install by hand.
			const guidance = await installHooks(env);
			console.log(`\n${ct("setup.noInstallDone")}\n`);
			console.log(ct("setup.nextSteps"));
			console.log(`  1. ${ct("setup.noInstallStep1")}`);
			console.log(`  2. ${ct("setup.noInstallStep2")}`);
			console.log("");
			for (const line of guidance.followUp) console.log(line);
			return;
		}

		console.error(options.dryRun ? ct("setup.planning") : ct("setup.installing"));
		const installOptions: ConnectorInstallOptions = {
			hosts,
			dryRun: options.dryRun,
			claudePluginDir: options.claudePluginDir,
			cursorVsix: options.cursorVsix,
			vscodeVsix: options.vscodeVsix,
		};
		const standaloneRoot =
			deps.standaloneRoot === undefined ? standaloneBundleRoot() : deps.standaloneRoot;
		const results = installConnectors(
			{
				home,
				env: hostEnv,
				run: deps.run,
				version: VERSION,
				...(standaloneRoot ? { standaloneRoot } : {}),
			},
			installOptions,
		);
		const active = results.filter((entry) => entry.state === "installed");
		if (!options.dryRun) {
			try {
				recordHooksInstalled(active.length > 0);
			} catch {
				// The measured connector state below is what the user sees either way.
			}
			// A rerun that registers nothing new keeps the previous restart hint.
			const registered = results
				.filter((entry) => entry.action === "installed" || entry.action === "updated")
				.map((entry) => entry.host);
			try {
				if (registered.length > 0) writeSetupLedger(home, registered);
			} catch {
				// Only the restart hint in `aidr status` depends on it.
			}
		}

		console.log("");
		printHostResults(results);
		const failed = results.filter((entry) => entry.action === "failed");
		const pending = results.filter((entry) => entry.followUp.length > 0);
		// A host that was found (or asked for) but has no working connector after
		// this run: its tool calls are not inspected, so setup did not succeed.
		const unprotected = results.filter(
			(entry) => entry.action !== "skipped_not_detected" && entry.state !== "installed",
		);
		console.log("");
		if (options.dryRun) {
			console.log(ct("setup.dryRunDone"));
		} else if (active.length > 0 && failed.length === 0 && unprotected.length === 0) {
			console.log(ct("setup.complete"));
			console.log(
				`  ${ct("setup.registeredFor", { hosts: active.map((entry) => entry.label).join(", ") })}`,
			);
		} else {
			// Protection is NOT yet active for every agent: say so, never ✅.
			console.log(ct("setup.incomplete"));
			console.log(`  ${ct("setup.incompleteDetail")}`);
			if (unprotected.length > 0) {
				console.log(
					`  ${ct("setup.unprotected", { hosts: unprotected.map((entry) => entry.label).join(", ") })}`,
				);
			}
		}
		if (pending.length > 0) {
			console.log("");
			console.log(ct("setup.nextSteps"));
			for (const entry of pending) for (const line of entry.followUp) console.log(line);
		}
		console.log("");
		console.log(options.dryRun ? ct("setup.dryRunNext") : ct("setup.verifyNext"));
		console.log("");
		if (!options.dryRun && (failed.length > 0 || unprotected.length > 0 || active.length === 0)) {
			process.exitCode = 1;
		}
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : String(error);
		console.error(`Setup failed: ${message}`);
		process.exit(1);
	}
}

export default setupCommand;
