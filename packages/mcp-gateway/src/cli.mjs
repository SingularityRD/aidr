#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createMcpGateway } from "./gateway.mjs";

const configPath = process.argv[2];
if (!configPath || process.argv.length !== 3) {
	process.stderr.write("usage: aidr-mcp-gateway <config.json>\n");
	process.exitCode = 2;
} else {
	try {
		const config = JSON.parse(await readFile(configPath, "utf8"));
		const gateway = createMcpGateway(config);
		const address = await gateway.listen();
		process.stdout.write(`AIDR MCP gateway listening on 127.0.0.1:${address.port}\n`);
	} catch {
		process.stderr.write("AIDR MCP gateway configuration or startup failed\n");
		process.exitCode = 1;
	}
}
