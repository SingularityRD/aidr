import { canonicalJson } from "./canonical-json.ts";

const POLICY_ACTION_KEYS = [
	"command_default", "file_default", "url_default", "package_default", "output_default",
	"mcp_default", "mcp_unknown", "mcp_risky",
] as const;
const POLICY_LIST_KEYS = [
	"mcp_allow_servers", "mcp_require_approval_servers", "mcp_deny_servers",
	"mcp_allow_tools", "mcp_require_approval_tools", "mcp_deny_tools",
] as const;

const MCP_ID = /^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$/;
const LEGACY_MCP_TOOL = /^[A-Za-z0-9][A-Za-z0-9_:/-]{0,255}\.[A-Za-z0-9][A-Za-z0-9_:/-]{0,255}$/;

function validMcpToolSelector(value: unknown): boolean {
	if (typeof value !== "string") return false;
	if (LEGACY_MCP_TOOL.test(value)) return true;
	if (value.length > 519 || !value.startsWith("[")) return false;
	try {
		const pair: unknown = JSON.parse(value);
		return Array.isArray(pair) && pair.length === 2 &&
			pair.every((part) => typeof part === "string" && MCP_ID.test(part)) &&
			JSON.stringify(pair) === value;
	} catch {
		return false;
	}
}

/** Reject typos and unsupported rules instead of acknowledging policy the runtime ignores. */
export function validateRuntimePolicy(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("policy_must_be_object");
	const entries = Object.entries(value);
	if (entries.length === 0) throw new Error("empty_policy");
	for (const [key, item] of entries) {
		if ((POLICY_ACTION_KEYS as readonly string[]).includes(key)) {
			if (!["allow", "ask", "deny"].includes(String(item)) || typeof item !== "string") throw new Error(`invalid_action:${key}`);
		} else if ((POLICY_LIST_KEYS as readonly string[]).includes(key)) {
			const valid = key.endsWith("_servers")
				? (value: unknown) => typeof value === "string" && MCP_ID.test(value)
				: validMcpToolSelector;
			if (!Array.isArray(item) || item.length > 200 || item.some((value) => !valid(value))) throw new Error(`invalid_list:${key}`);
		} else {
			throw new Error(`unsupported_policy_field:${key}`);
		}
	}
	return value as Record<string, unknown>;
}

export function membershipActive(row: { role?: string; expires_at?: string | null } | null, now = Date.now()): boolean {
	if (!row) return false;
	return !row.expires_at || (Number.isFinite(Date.parse(row.expires_at)) && Date.parse(row.expires_at) > now);
}

export async function sha256(value: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
	return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Digest input for `policy_sha256` and the other envelope-bound digests (./canonical-json.ts). */
export function canonicalPolicy(value: unknown): string {
	return canonicalJson(value);
}
