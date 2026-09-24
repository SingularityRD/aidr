#!/usr/bin/env node
import { readGatewayConfig, reportFailure, stage } from "./diagnostics.mjs";
import { createMcpGateway } from "./gateway.mjs";
import { requireGatewayIntegrity } from "./integrity.mjs";

const configPath = process.argv[2];
if (!configPath || process.argv.length !== 3) {
	process.stderr.write("usage: aidr-mcp-gateway <config.json>\n");
	process.exitCode = 2;
} else {
	try {
		await stage("integrity_verification_failed", () => requireGatewayIntegrity());
		const config = await readGatewayConfig(configPath);
		const gateway = await stage("config_invalid", () => createMcpGateway(config));
		const address = await stage("startup_failed", () => gateway.listen());
		process.stdout.write(`AIDR MCP gateway listening on 127.0.0.1:${address.port}\n`);
	} catch (error) {
		process.exitCode = reportFailure("AIDR MCP gateway", error);
	}
}
