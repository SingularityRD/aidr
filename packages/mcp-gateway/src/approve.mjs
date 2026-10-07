#!/usr/bin/env node
import { reportFailure, stage } from "./diagnostics.mjs";
import { openVerifiedGateway } from "./operator-startup.mjs";

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
		const gateway = await openVerifiedGateway(configPath);
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
