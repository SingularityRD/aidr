import { createHash, randomBytes } from "node:crypto";

/**
 * Generates a locally-scoped installation identifier/credential.
 *
 * Key material MUST come from a CSPRNG. The previous implementation derived this
 * value from `Math.random()`, whose internal state is recoverable from a small
 * number of observed outputs, making the generated credential predictable.
 */
export function generateApiKey(): string {
	return `aidr_${randomBytes(32).toString("base64url")}`;
}

export function hashToolCall(tool: string, input: Record<string, unknown>): string {
	return createHash("sha256")
		.update(`${tool}:${JSON.stringify(input)}`)
		.digest("hex")
		.slice(0, 16);
}
