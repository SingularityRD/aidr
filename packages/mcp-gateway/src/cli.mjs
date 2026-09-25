#!/usr/bin/env node
import { reportFailure, stage } from "./diagnostics.mjs";
import { openVerifiedGateway } from "./operator-startup.mjs";

const configPath = process.argv[2];
if (!configPath || process.argv.length !== 3) {
	process.stderr.write("usage: aidr-mcp-gateway <config.json>\n");
	process.exitCode = 2;
} else {
	try {
		const gateway = await openVerifiedGateway(configPath);
		const address = await stage("startup_failed", () => gateway.listen());
		process.stdout.write(`AIDR MCP gateway listening on 127.0.0.1:${address.port}\n`);
	} catch (error) {
		process.exitCode = reportFailure("AIDR MCP gateway", error);
	}
}
