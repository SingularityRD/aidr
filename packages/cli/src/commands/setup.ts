import { resolvePath, VERSION } from "@singularityrd/aidr-core";
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
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";

export interface SetupOptions {
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

export interface SetupDeps extends OperatorCommandDeps {
	/** Home whose hosts are detected and configured (tests). */
	home?: string;
	/** Host CLI runner (tests). */
	run?: HostCommandRunner;
}

const ACTION_TEXT: Record<HostInstallResult["action"], string> = {
	already_installed: "already installed",
	installed: "installed",
	updated: "updated",
	would_install: "would install",
	would_update: "would update",
	manual: "manual step needed",
	failed: "FAILED",
	skipped_not_detected: "not detected",
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
	console.log("Connectors:");
	for (const entry of results) {
		console.log(`  ${entry.label.padEnd(12)} ${ACTION_TEXT[entry.action]} — ${entry.detail}`);
		for (const change of entry.changes) console.log(`               ${change}`);
	}
}

async function confirmForce(options: SetupOptions, deps: OperatorCommandDeps): Promise<boolean> {
	// --force replaces the existing configuration and credential and resets
	// the recorded hook state, so it is an operator-only action confirmed like
	// `aidr allowlist add`. A plain `aidr setup` reuses the config unchanged.
	try {
		await confirmOperatorAction({
			prompt: [
				"Singularity AIDR — forced re-setup",
				"The existing local configuration and CLI credential will be replaced.",
			].join("\n"),
			word: "replace",
			yes: options.yes,
			env: deps.env,
			streams: deps.streams,
		});
		return true;
	} catch (error) {
		console.error(
			`${error instanceof OperatorConfirmationError ? error.message : String(error)} Nothing was changed.`,
		);
		process.exitCode = 1;
		return false;
	}
}

async function setupCommand(options: SetupOptions = {}, deps: SetupDeps = {}): Promise<void> {
	console.log(`\n🛡️  AIDR Setup${options.dryRun ? " (dry run — nothing will be changed)" : ""}\n`);

	if (options.force && !options.dryRun && !(await confirmForce(options, deps))) return;

	try {
		const hosts = parseHosts(options.host);
		const home = deps.home ?? resolvePath("~");
		const hostEnv = deps.env ?? process.env;

		console.error("Detecting environment...");
		// Home-based only, the same measurement `aidr status` prints (PRD-14).
		const env = await detectEnvironment(home, hostEnv);
		console.error(
			env.detectedHosts && env.detectedHosts.length > 0
				? `✓ Agent hosts found: ${env.detectedHosts.join(", ")}`
				: "✓ No supported agent host found in this home directory",
		);

		if (options.dryRun) {
			console.error("Skipping config creation (dry run).");
		} else {
			console.error("Creating config...");
			// Local mode needs no credential, so no vault either; a managed config's
			// credential goes to the OS vault or the encrypted file store.
			const config = await createConfig(env, options.force || false, {
				secretStoreSelection: options.secretStore,
			});
			console.error(
				config.outcome === "reused"
					? `✓ Config already present: ${config.path}`
					: `✓ Config: ${config.path}`,
			);
			if (config.warning) console.warn(`⚠ ${config.warning}`);
			if (config.outcome === "reused") {
				console.log("\n✅ Setup verified — no changes were needed to the configuration.");
				console.log(`  Existing config reused: ${config.path}`);
			}
		}

		console.error("Loading threat database...");
		const ruleCount = await loadBundledThreatCount();
		if (ruleCount <= 0) {
			console.error(
				"No threat rules could be loaded. Detection would not be active - refusing to report success.",
			);
			process.exit(1);
		}
		console.error(`✓ ${ruleCount} rules active`);

		console.error("Testing protection...");
		const detection = await verifyDetection();
		if (!detection.ok) {
			console.error(`Detection self-test failed: ${detection.reason}`);
			process.exit(1);
		}
		console.error(`✓ Detection verified (${detection.detail})`);

		if (options.install === false) {
			// Guidance only: the previous behaviour, for operators who install by hand.
			const guidance = await installHooks(env);
			console.log("\n✅ Setup complete (connector install skipped: --no-install).\n");
			console.log("Next steps:");
			console.log("  1. Install the connector below — until you do, tool calls are NOT inspected");
			console.log("  2. View status:  aidr status");
			console.log("");
			for (const line of guidance.followUp) console.log(line);
			return;
		}

		console.error(options.dryRun ? "Planning connector installs..." : "Installing connectors...");
		const installOptions: ConnectorInstallOptions = {
			hosts,
			dryRun: options.dryRun,
			claudePluginDir: options.claudePluginDir,
			cursorVsix: options.cursorVsix,
			vscodeVsix: options.vscodeVsix,
		};
		const results = installConnectors(
			{ home, env: hostEnv, run: deps.run, version: VERSION },
			installOptions,
		);
		const active = results.filter((entry) => entry.state === "installed");
		if (!options.dryRun) {
			try {
				recordHooksInstalled(active.length > 0);
			} catch {
				// The measured connector state below is what the user sees either way.
			}
		}

		console.log("");
		printHostResults(results);
		const failed = results.filter((entry) => entry.action === "failed");
		const pending = results.filter((entry) => entry.followUp.length > 0);
		console.log("");
		if (options.dryRun) {
			console.log("Dry run: no file was written and no host command was run.");
		} else if (active.length > 0 && failed.length === 0) {
			console.log("✅ Setup complete!");
			console.log(
				`  Registered for: ${active.map((entry) => entry.label).join(", ")} (host execution not yet verified).`,
			);
		} else {
			console.log("⚠ Setup finished, but Protection is NOT yet active for every agent:");
			console.log("  tool calls of a host without a registered connector are NOT inspected.");
		}
		if (pending.length > 0) {
			console.log("");
			console.log("Next steps:");
			for (const entry of pending) for (const line of entry.followUp) console.log(line);
		}
		console.log("");
		console.log("Verify with: aidr status   (then run a host-side deny canary)");
		console.log("");
		if (failed.length > 0) process.exitCode = 1;
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : String(error);
		console.error(`Setup failed: ${message}`);
		process.exit(1);
	}
}

export default setupCommand;
