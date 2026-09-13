export const POLICY_ACTION_KEYS = [
	"command_default", "file_default", "url_default", "package_default", "output_default",
	"mcp_default", "mcp_unknown", "mcp_risky",
] as const;
export const POLICY_LIST_KEYS = [
	"mcp_allow_servers", "mcp_require_approval_servers", "mcp_deny_servers",
	"mcp_allow_tools", "mcp_require_approval_tools", "mcp_deny_tools",
] as const;

/** Reject typos and unsupported rules instead of acknowledging policy the runtime ignores. */
export function validateRuntimePolicy(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("policy_must_be_object");
	const entries = Object.entries(value);
	if (entries.length === 0) throw new Error("empty_policy");
	for (const [key, item] of entries) {
		if ((POLICY_ACTION_KEYS as readonly string[]).includes(key)) {
			if (!["allow", "ask", "deny"].includes(String(item)) || typeof item !== "string") throw new Error(`invalid_action:${key}`);
		} else if ((POLICY_LIST_KEYS as readonly string[]).includes(key)) {
			const pattern = key.endsWith("_servers") ? /^[a-z0-9][a-z0-9._-]{0,79}$/ : /^[a-z0-9][a-z0-9._-]{0,79}\.[a-z0-9][a-z0-9_.-]{0,159}$/;
			if (!Array.isArray(item) || item.length > 200 || item.some((v) => typeof v !== "string" || !pattern.test(v))) throw new Error(`invalid_list:${key}`);
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

export function canonicalPolicy(value: unknown): string {
	const normalized = (item: unknown): unknown => Array.isArray(item) ? item.map(normalized) : item && typeof item === "object" ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, val]) => [key, normalized(val)])) : item;
	return JSON.stringify(normalized(value));
}
