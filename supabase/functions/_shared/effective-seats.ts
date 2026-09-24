// PostgREST returns a table-valued RPC as an array. Treat any ambiguous or
// malformed result as unavailable instead of issuing a paid signed grant.
export function parseEffectiveSeats(data: unknown): {
	extraAgents: number;
	providerValidUntilMs: number | null;
} | null {
	if (!Array.isArray(data) || data.length !== 1) return null;
	const row = data[0];
	if (!row || typeof row !== "object" || Array.isArray(row)) return null;
	const extraAgents = (row as Record<string, unknown>).extra_agents;
	const term = (row as Record<string, unknown>).provider_valid_until;
	if (!Number.isSafeInteger(extraAgents) || (extraAgents as number) < 0) return null;
	if (term === null) return { extraAgents: extraAgents as number, providerValidUntilMs: null };
	if (typeof term !== "string") return null;
	const providerValidUntilMs = Date.parse(term);
	if (!Number.isFinite(providerValidUntilMs) || (extraAgents as number) === 0) return null;
	return { extraAgents: extraAgents as number, providerValidUntilMs };
}

export function capEntitlementTimes(
	expiresAt: string,
	graceUntil: string,
	providerValidUntilMs: number | null,
	nowMs = Date.now(),
): { expiresAt: string; graceUntil: string } | null {
	const expiresMs = Date.parse(expiresAt);
	const graceMs = Date.parse(graceUntil);
	if (!Number.isFinite(expiresMs) || !Number.isFinite(graceMs) || graceMs < expiresMs) return null;
	if (providerValidUntilMs === null) return { expiresAt, graceUntil };
	if (!Number.isFinite(providerValidUntilMs) || providerValidUntilMs <= nowMs) return null;
	return {
		expiresAt: new Date(Math.min(expiresMs, providerValidUntilMs)).toISOString(),
		graceUntil: new Date(Math.min(graceMs, providerValidUntilMs)).toISOString(),
	};
}

// The admission RPC is a tenant-scoped authorization result, not a billing
// projection. Reject malformed/mismatched kinds rather than minting a signed
// offline grant from an ambiguous response.
export function parseActiveAdmission(data: unknown, nowMs = Date.now()): {
	allowedAgents: number;
	validUntilMs: number | null;
} | null {
	if (!data || typeof data !== "object" || Array.isArray(data)) return null;
	const row = data as Record<string, unknown>;
	if (row.status !== "active" || !Number.isSafeInteger(row.allowed_agents) || Number(row.allowed_agents) < 1) return null;
	const kind = row.access_kind;
	const mode = row.mode;
	if (!((kind === "trial" && mode === "cloud")
		|| (kind === "licensed" && (mode === "cloud" || mode === "onprem"))
		|| (kind === "pilot" && mode === "pilot"))) return null;
	if (kind === "pilot") return row.expires_at === null
		? { allowedAgents: Number(row.allowed_agents), validUntilMs: null } : null;
	if (typeof row.expires_at !== "string") return null;
	const validUntilMs = Date.parse(row.expires_at);
	if (!Number.isFinite(validUntilMs) || validUntilMs <= nowMs) return null;
	return { allowedAgents: Number(row.allowed_agents), validUntilMs };
}
