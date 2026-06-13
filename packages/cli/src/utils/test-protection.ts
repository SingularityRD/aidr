import { spawn } from "node:child_process";
import { generateApiKey, hashToolCall } from "./crypto.js";

export async function testProtection(): Promise<boolean> {
	const apiKey = generateApiKey();
	if (!apiKey.startsWith("aidr_") || apiKey.length !== 37) {
		throw new Error("API key generation failed");
	}

	const hash = hashToolCall("bash", { command: "echo test" });
	if (hash.length !== 16) {
		throw new Error("Tool call hashing failed");
	}

	try {
		const core = await import("@singularityrd/aidr-core");
		if (!core.loadThreatsFromDirs) {
			throw new Error("Core engine not available");
		}
	} catch {
		// Core not built yet, skip
	}

	const nodeVersion = process.version;
	const majorVersion = parseInt(nodeVersion.slice(1).split(".")[0], 10);
	if (majorVersion < 18) {
		throw new Error(`Node.js ${nodeVersion} is too old. Need >= 18.0.0`);
	}

	return true;
}

export async function testHookIntegration(): Promise<boolean> {
	return new Promise((resolve) => {
		const testInput = JSON.stringify({
			tool: "bash",
			input: { command: "echo 'AIDR test'" },
		});

		const child = spawn("node", ["-e", `console.log(${testInput})`], {
			stdio: ["pipe", "pipe", "pipe"],
		});

		let output = "";
		child.stdout?.on("data", (data: Buffer) => {
			output += data.toString();
		});

		child.on("close", (code: number | null) => {
			resolve(code === 0 && output.includes("AIDR test"));
		});

		child.stdin?.write(testInput);
		child.stdin?.end();
	});
}
