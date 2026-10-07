import { createConfig } from "../utils/config-manager.js";
import { detectEnvironment } from "../utils/detect-env.js";
import { installHooks } from "../utils/install-hooks.js";
import {
	confirmOperatorAction,
	type OperatorCommandDeps,
	OperatorConfirmationError,
} from "../utils/operator-confirm.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";

async function setupCommand(
	options: { force?: boolean; secretStore?: string; yes?: boolean },
	deps: OperatorCommandDeps = {},
): Promise<void> {
	console.log("\n🛡️  AIDR Setup\n");

	if (options.force) {
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
		} catch (error) {
			console.error(
				`${error instanceof OperatorConfirmationError ? error.message : String(error)} Nothing was changed.`,
			);
			process.exitCode = 1;
			return;
		}
	}

	try {
		console.error("Detecting environment...");
		const env = await detectEnvironment();
		console.error(`✓ ${env.agent} detected`);

		console.error("Creating config...");
		// The credential store is resolved before anything is written: with no
		// vault available and no explicit fallback this throws, and setup fails
		// closed instead of leaving a plaintext credential behind.
		const config = await createConfig(env, options.force || false, {
			secretStoreSelection: options.secretStore,
		});
		console.error(
			config.outcome === "reused"
				? `✓ Config already present: ${config.path}`
				: `✓ Config: ${config.path}`,
		);
		if (config.warning) console.warn(`⚠ ${config.warning}`);

		console.error("Preparing connector setup guidance...");
		const hookResult = await installHooks(env);
		console.error(`✓ ${hookResult.summary}`);

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

		// Report what actually happened this run. A rerun that reused the existing
		// config previously printed the same "Setup complete!" as a first install,
		// so the user could not tell a no-op from a real setup (AIDR-007).
		if (config.outcome === "reused") {
			console.log("\n✅ Setup verified — no changes were needed.\n");
			console.log(`  Existing config reused: ${config.path}`);
		} else {
			console.log("\n✅ Setup complete!\n");
		}

		// The next steps must not contradict the warning that follows them. The
		// previous text said "Start using your AI agent normally" on the same
		// screen that said "Protection is NOT yet active for your agent" — an
		// unqualified all-clear printed by a security product.
		console.log("Next steps:");
		console.log("  1. Install the connector below — until you do, tool calls are NOT inspected");
		console.log("  2. View status:  aidr status");
		console.log("  3. Adjust policy: aidr config --list");
		console.log("");

		for (const line of hookResult.followUp) {
			console.log(line);
		}
		console.log("");
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : String(error);
		console.error(`Setup failed: ${message}`);
		process.exit(1);
	}
}

export default setupCommand;
