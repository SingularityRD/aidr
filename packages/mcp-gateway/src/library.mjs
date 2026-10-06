import { requireGatewayIntegrity } from "./integrity.mjs";

// The installed library obeys the same operator-supplied artifact trust as the CLI.
await requireGatewayIntegrity();

export { createMcpGateway } from "./gateway.mjs";
