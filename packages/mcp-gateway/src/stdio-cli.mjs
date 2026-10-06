#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createMcpGateway } from "./gateway.mjs";
import { requireGatewayIntegrity } from "./integrity.mjs";
import { runStdioBridge } from "./stdio.mjs";
import { requireStandaloneProfile, standalonePayloadGuard } from "./standalone.mjs";

const [configPath, tenantId, clientId, serverId, tokenEnv, routingFlag] = process.argv.slice(2);
const requireRouting = routingFlag === "--require-routing";
if (
	!configPath ||
	!tenantId ||
	!clientId ||
	!serverId ||
	!tokenEnv ||
	(process.argv.length !== 7 && !(process.argv.length === 8 && requireRouting))
) {
	process.stderr.write(
		"usage: aidr-mcp-stdio <config.json> <tenantId> <clientId> <serverId> <tokenEnv> [--require-routing]\n",
	);
	process.exitCode = 2;
} else {
	try {
		await requireStandaloneProfile();
		await requireGatewayIntegrity();
		const config = JSON.parse(await readFile(configPath, "utf8"));
		if (requireRouting) config.routingRequired = true;
		await requireStandaloneProfile();
		await runStdioBridge({
			gateway: createMcpGateway(config, {
				assertInstalledPrivacySupported: requireStandaloneProfile,
				toolGuard: standalonePayloadGuard,
				outputGuard: standalonePayloadGuard,
				onEvent: (event) => process.stderr.write(`${JSON.stringify(event)}\n`),
			}),
			tenantId,
			clientId,
			serverId,
			tokenEnv,
			input: process.stdin,
			output: process.stdout,
			assertInstalledPrivacySupported: requireStandaloneProfile,
		});
	} catch {
		process.stderr.write(
			"AIDR MCP stdio bridge stopped after a configuration, transport, or protocol failure\n",
		);
		process.exitCode = 1;
	}
}
