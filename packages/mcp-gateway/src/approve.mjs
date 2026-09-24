#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createMcpGateway } from "./gateway.mjs";
import { requireGatewayIntegrity } from "./integrity.mjs";

const [configPath, tenantId, serverId, toolsetHash, bindingSha256, approvedBy, ...reasonParts] =
	process.argv.slice(2);
if (
	!configPath ||
	!tenantId ||
	!serverId ||
	!toolsetHash ||
	!bindingSha256 ||
	!approvedBy ||
	reasonParts.length === 0
) {
	process.stderr.write(
		"usage: aidr-mcp-approve <config.json> <tenantId> <serverId> <toolsetHash> <bindingSha256> <operatorId> <reason>\n",
	);
	process.exitCode = 2;
} else {
	try {
		await requireGatewayIntegrity();
		const config = JSON.parse(await readFile(configPath, "utf8"));
		const gateway = createMcpGateway(config);
		const result = await gateway.approve({
			tenantId,
			serverId,
			toolsetHash,
			bindingSha256,
			approvedBy,
			reason: reasonParts.join(" "),
		});
		if (!result.approved) throw new Error("approval rejected");
		process.stdout.write(`Approved MCP toolset ${result.toolsetHash}\n`);
	} catch {
		process.stderr.write("AIDR MCP toolset approval failed\n");
		process.exitCode = 1;
	}
}
