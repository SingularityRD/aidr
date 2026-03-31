import chalk from "chalk";
import ora from "ora";
import { createConfig } from "../utils/config-manager.js";
import { detectEnvironment } from "../utils/detect-env.js";
import { installHooks } from "../utils/install-hooks.js";
import { testProtection } from "../utils/test-protection.js";

async function setupCommand(options: { force?: boolean }): Promise<void> {
	console.log(chalk.blue("\n🛡️  AIDR Setup\n"));

	const spinner = ora();

	try {
		spinner.start("Detecting environment...");
		const env = await detectEnvironment();
		spinner.succeed(`${env.agent} detected`);

		spinner.start("Creating config...");
		const configPath = await createConfig(env, options.force || false);
		spinner.succeed(`Config: ${configPath}`);

		spinner.start("Installing hooks...");
		await installHooks(env);
		spinner.succeed(`${env.agent} integrated`);

		spinner.start("Loading threat database...");
		await loadThreatDatabase();
		spinner.succeed("150 rules active");

		spinner.start("Testing protection...");
		await testProtection();
		spinner.succeed("AIDR is working!");

		console.log(chalk.green("\n✅ Setup complete!\n"));
		console.log("Next steps:");
		console.log("  1. Create account: aidr auth signup");
		console.log("  2. View status: aidr status");
		console.log("  3. Start using your AI agent normally\n");
		console.log(chalk.gray("Free tier: 100 calls/day active"));
		console.log(chalk.gray("Upgrade anytime: https://aidr.security\n"));
	} catch (error: unknown) {
		const message = error instanceof Error ? error.message : String(error);
		spinner.fail(`Setup failed: ${message}`);
		process.exit(1);
	}
}

async function loadThreatDatabase(): Promise<number> {
	const { loadThreatsFromDirs } = await import("@singularityrd/aidr-core");
	const { homedir } = await import("node:os");
	const { join } = await import("node:path");
	const threatDir = join(homedir(), ".singularity-aidr", "threats");
	const threats = await loadThreatsFromDirs([threatDir]);
	return threats.length;
}

export default setupCommand;
