import chalk from "chalk";
import ora from "ora";
import { createConfig } from "../utils/config-manager.js";
import { detectEnvironment } from "../utils/detect-env.js";
import { installHooks } from "../utils/install-hooks.js";
import { loadBundledThreatCount, verifyDetection } from "../utils/test-protection.js";

async function setupCommand(options: { force?: boolean; secretStore?: string }): Promise<void> {
	console.log(chalk.blue("\n🛡️  AIDR Setup\n"));

	const spinner = ora();

	try {
		spinner.start("Detecting environment...");
		const env = await detectEnvironment();
		spinner.succeed(`${env.agent} detected`);

		spinner.start("Creating config...");
		// The credential store is resolved before anything is written: with no
		// vault available and no explicit fallback this throws, and setup fails
		// closed instead of leaving a plaintext credential behind.
		const config = await createConfig(env, options.force || false, {
			secretStoreSelection: options.secretStore,
		});
		spinner.succeed(
			config.outcome === "reused"
				? `Config already present: ${config.path}`
				: `Config: ${config.path}`,
		);
		if (config.warning) spinner.warn(config.warning);

		spinner.start("Installing hooks...");
		const hookResult = await installHooks(env);
		spinner.succeed(hookResult.summary);

		spinner.start("Loading threat database...");
		const ruleCount = await loadBundledThreatCount();
		if (ruleCount <= 0) {
			spinner.fail(
				"No threat rules could be loaded. Detection would not be active - refusing to report success.",
			);
			process.exit(1);
		}
		spinner.succeed(`${ruleCount} rules active`);

		spinner.start("Testing protection...");
		const detection = await verifyDetection();
		if (!detection.ok) {
			spinner.fail(`Detection self-test failed: ${detection.reason}`);
			process.exit(1);
		}
		spinner.succeed(`Detection verified (${detection.detail})`);

		// Report what actually happened this run. A rerun that reused the existing
		// config previously printed the same "Setup complete!" as a first install,
		// so the user could not tell a no-op from a real setup (AIDR-007).
		if (config.outcome === "reused") {
			console.log(chalk.green("\n✅ Setup verified — no changes were needed.\n"));
			console.log(chalk.gray(`  Existing config reused: ${config.path}`));
		} else {
			console.log(chalk.green("\n✅ Setup complete!\n"));
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
			console.log(chalk.gray(line));
		}
		console.log("");
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : String(error);
		spinner.fail(`Setup failed: ${message}`);
		process.exit(1);
	}
}

export default setupCommand;
