#!/usr/bin/env node
import { readGatewayConfig, reportFailure, stage } from "./diagnostics.mjs";
import { createMcpGateway } from "./gateway.mjs";
import { requireGatewayIntegrity } from "./integrity.mjs";
import { runStdioBridge } from "./stdio.mjs";

const [configPath, tenantId, clientId, serverId, tokenEnv] = process.argv.slice(2);
if (!configPath || !tenantId || !clientId || !serverId || !tokenEnv || process.argv.length !== 7) {
	process.stderr.write(
		"usage: aidr-mcp-stdio <config.json> <tenantId> <clientId> <serverId> <tokenEnv>\n",
	);
	process.exitCode = 2;
} else {
	try {
		await stage("integrity_verification_failed", () => requireGatewayIntegrity());
		const config = await readGatewayConfig(configPath);
		const gateway = await stage("config_invalid", () => createMcpGateway(config));
		await stage("bridge_stopped", () =>
			runStdioBridge({
				gateway,
				tenantId,
				clientId,
				serverId,
				tokenEnv,
				input: process.stdin,
				output: process.stdout,
			}),
		);
	} catch (error) {
		process.exitCode = reportFailure("AIDR MCP stdio bridge", error);
	}
}
