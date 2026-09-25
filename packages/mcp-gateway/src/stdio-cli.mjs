#!/usr/bin/env node
import { reportFailure, stage } from "./diagnostics.mjs";
import { openVerifiedGateway } from "./operator-startup.mjs";
import { runStdioBridge } from "./stdio.mjs";

const [configPath, tenantId, clientId, serverId, tokenEnv] = process.argv.slice(2);
if (!configPath || !tenantId || !clientId || !serverId || !tokenEnv || process.argv.length !== 7) {
	process.stderr.write(
		"usage: aidr-mcp-stdio <config.json> <tenantId> <clientId> <serverId> <tokenEnv>\n",
	);
	process.exitCode = 2;
} else {
	try {
		const gateway = await openVerifiedGateway(configPath);
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
