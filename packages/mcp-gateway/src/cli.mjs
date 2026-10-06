#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createMcpGateway } from "./gateway.mjs";
import { requireGatewayIntegrity } from "./integrity.mjs";

const configPath = process.argv[2];
const requireRouting = process.argv[3] === "--require-routing";
if (!configPath || (process.argv.length !== 3 && !(process.argv.length === 4 && requireRouting))) {
	process.stderr.write("usage: aidr-mcp-gateway <config.json> [--require-routing]\n");
	process.exitCode = 2;
} else {
	try {
		await requireGatewayIntegrity();
		const config = JSON.parse(await readFile(configPath, "utf8"));
		if (requireRouting) config.routingRequired = true;
		const gateway = createMcpGateway(config, {
			onEvent: (event) => process.stderr.write(`${JSON.stringify(event)}\n`),
		});
		const address = await gateway.listen();
		process.stdout.write(`AIDR MCP gateway listening on 127.0.0.1:${address.port}\n`);
	} catch {
		process.stderr.write("AIDR MCP gateway configuration or startup failed\n");
		process.exitCode = 1;
	}
}
