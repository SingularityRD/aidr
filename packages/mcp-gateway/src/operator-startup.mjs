import { readGatewayConfig, stage } from "./diagnostics.mjs";
import { createMcpGateway } from "./gateway.mjs";
import { requireGatewayIntegrity } from "./integrity.mjs";

/**
 * The common start of every operator CLI: verify this gateway's own artifact
 * integrity first, then read and validate the configuration. Each step fails
 * with its stage code (see diagnostics.mjs).
 */
export async function openVerifiedGateway(configPath) {
	await stage("integrity_verification_failed", () => requireGatewayIntegrity());
	const config = await readGatewayConfig(configPath);
	return stage("config_invalid", () => createMcpGateway(config));
}
