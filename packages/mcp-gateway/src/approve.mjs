#!/usr/bin/env node
import { readGatewayConfig, reportFailure, stage } from "./diagnostics.mjs";
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
		await stage("integrity_verification_failed", () => requireGatewayIntegrity());
		const config = await readGatewayConfig(configPath);
		const gateway = await stage("config_invalid", () => createMcpGateway(config));
		const result = await stage("approval_failed", async () => {
			const approval = await gateway.approve({
				tenantId,
				serverId,
				toolsetHash,
				bindingSha256,
				approvedBy,
				reason: reasonParts.join(" "),
			});
			if (!approval.approved) throw new Error("approval rejected");
			return approval;
		});
		process.stdout.write(`Approved MCP toolset ${result.toolsetHash}\n`);
	} catch (error) {
		process.exitCode = reportFailure("AIDR MCP toolset approval", error);
	}
}
