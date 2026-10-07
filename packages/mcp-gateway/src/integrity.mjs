import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyArtifactIntegrityAndLog } from "@singularityrd/aidr-core";

export async function requireGatewayIntegrity() {
	await verifyArtifactIntegrityAndLog({
		artifactDir: dirname(fileURLToPath(import.meta.url)),
		artifactId: "mcp-gateway/dist",
	});
}
