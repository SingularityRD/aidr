#!/usr/bin/env node
import { reportFailure, stage } from "./diagnostics.mjs";
import { openVerifiedGateway } from "./operator-startup.mjs";
import { requireStandaloneProfile } from "./standalone.mjs";
import { runStdioBridge } from "./stdio.mjs";

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
		const gateway = await openVerifiedGateway(configPath, { standalone: true, requireRouting });
		await stage("bridge_stopped", () =>
			runStdioBridge({
				gateway,
				tenantId,
				clientId,
				serverId,
				tokenEnv,
				input: process.stdin,
				output: process.stdout,
				assertInstalledPrivacySupported: requireStandaloneProfile,
			}),
		);
	} catch (error) {
		process.exitCode = reportFailure("AIDR MCP stdio bridge", error);
	}
}
