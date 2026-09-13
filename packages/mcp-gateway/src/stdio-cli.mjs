#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createMcpGateway } from "./gateway.mjs";
import { runStdioBridge } from "./stdio.mjs";

const [configPath, tenantId, clientId, serverId, tokenEnv] = process.argv.slice(2);
if (!configPath || !tenantId || !clientId || !serverId || !tokenEnv || process.argv.length !== 7) {
	process.stderr.write(
		"usage: aidr-mcp-stdio <config.json> <tenantId> <clientId> <serverId> <tokenEnv>\n",
	);
	process.exitCode = 2;
} else {
	try {
		const config = JSON.parse(await readFile(configPath, "utf8"));
		await runStdioBridge({
			gateway: createMcpGateway(config),
			tenantId,
			clientId,
			serverId,
			tokenEnv,
			input: process.stdin,
			output: process.stdout,
		});
	} catch {
		process.stderr.write(
			"AIDR MCP stdio bridge stopped after a configuration, transport, or protocol failure\n",
		);
		process.exitCode = 1;
	}
}
