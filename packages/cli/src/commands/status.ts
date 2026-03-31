import chalk from "chalk";
import { getConfig } from "../utils/config-manager.js";

async function statusCommand(): Promise<void> {
	const config = getConfig();

	console.log(chalk.blue("\n🛡️  AIDR Status\n"));

	if (!config) {
		console.log(chalk.yellow("⚠️  AIDR not configured"));
		console.log("Run: aidr setup\n");
		return;
	}

	console.log(chalk.green("✅ AIDR is configured"));
	console.log(`   Agent: ${config.environment.agent}`);
	console.log(`   Node: ${config.environment.nodeVersion}`);
	console.log(`   Hooks: ${config.hooksInstalled ? "installed" : "not installed"}`);
	console.log(`   API Key: ${config.apiKey.slice(0, 4)}****${config.apiKey.slice(-4)}`);
	console.log(`   Created: ${new Date(config.createdAt).toLocaleDateString()}`);

	console.log(chalk.gray("\nRun 'aidr config --list' for detailed settings\n"));
}

export default statusCommand;
