import { createHash } from "node:crypto";

export function generateApiKey(): string {
	return `aidr_${createHash("sha256").update(Math.random().toString()).digest("hex").slice(0, 32)}`;
}

export function hashToolCall(tool: string, input: Record<string, unknown>): string {
	return createHash("sha256")
		.update(`${tool}:${JSON.stringify(input)}`)
		.digest("hex")
		.slice(0, 16);
}
