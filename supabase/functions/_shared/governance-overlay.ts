// Governance overlay delivered with the runtime policy (docs/ai-governance.md).
//
// The AI asset register can only tighten a tenant's published runtime policy:
// banned MCP servers become deny entries and restricted ones require approval,
// minus approved, unexpired exceptions for the calling member or agent. The
// overlay travels next to `runtime_policy` (never inside it) so the published
// revision, its digest and agent load receipts stay exactly as published.
// The signed runtime-policy envelope binds the same `governance_sha256` (see
// policy-signature.ts), so the overlay is covered by the policy signature.
// Connectors verify `governance_sha256` over the canonical overlay and add the
// lists on top of the published policy.

const MCP_ID = /^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$/;
const GOVERNANCE_OVERLAY_MAX_ENTRIES = 500;

export interface GovernanceOverlay {
	mcp_deny_servers: string[];
	mcp_require_approval_servers: string[];
}

function serverList(value: unknown): string[] {
	if (!Array.isArray(value) || value.length > GOVERNANCE_OVERLAY_MAX_ENTRIES ||
		!value.every((item) => typeof item === "string" && MCP_ID.test(item))) {
		throw new Error("invalid_governance_overlay");
	}
	return [...new Set(value as string[])];
}

/** Validate the overlay RPC result; anything malformed is refused, never trimmed. */
export function validateGovernanceOverlay(value: unknown): GovernanceOverlay {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_governance_overlay");
	const record = value as Record<string, unknown>;
	return {
		mcp_deny_servers: serverList(record.mcp_deny_servers),
		mcp_require_approval_servers: serverList(record.mcp_require_approval_servers),
	};
}

export function overlayIsEmpty(overlay: GovernanceOverlay): boolean {
	return overlay.mcp_deny_servers.length === 0 && overlay.mcp_require_approval_servers.length === 0;
}
