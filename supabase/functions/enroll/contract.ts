export type ValidEnrollmentBody = {
	iid: string;
	agent_runtime: string | null;
	agent_runtime_version: string | null;
};

export function validateEnrollmentBody(value: unknown): ValidEnrollmentBody | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const body = value as Record<string, unknown>;
	if (typeof body.iid !== "string") return null;
	const iid = body.iid.trim();
	if (!iid || iid.length > 128 || /[\u0000-\u001f\u007f]/.test(iid)) return null;
	for (const field of ["agent_runtime", "agent_runtime_version"] as const) {
		const raw = body[field];
		if (raw !== undefined && raw !== null && (typeof raw !== "string" || raw.length > 128 || /[\u0000-\u001f\u007f]/.test(raw))) {
			return null;
		}
	}
	return {
		iid,
		agent_runtime: typeof body.agent_runtime === "string" ? body.agent_runtime : null,
		agent_runtime_version: typeof body.agent_runtime_version === "string" ? body.agent_runtime_version : null,
	};
}

export type EntitlementWindow = {
	issuedAt: string;
	expiresAt: string;
	graceUntil: string;
};

// A malformed or excessive operator value must not silently turn a signed
// entitlement into an already-expired or effectively unbounded grant.
export function entitlementWindow(
	issuedAt: Date,
	ttlHoursRaw: string,
	graceHoursRaw: string,
): EntitlementWindow | null {
	if (!/^(0|[1-9]\d{0,2})$/.test(ttlHoursRaw) || !/^(0|[1-9]\d{0,2})$/.test(graceHoursRaw)) return null;
	const ttl = Number(ttlHoursRaw);
	const grace = Number(graceHoursRaw);
	if (ttl < 1 || ttl > 720 || grace > 168 || !Number.isFinite(issuedAt.getTime())) return null;
	const issuedMs = issuedAt.getTime();
	const expiresMs = issuedMs + ttl * 3_600_000;
	return {
		issuedAt: issuedAt.toISOString(),
		expiresAt: new Date(expiresMs).toISOString(),
		graceUntil: new Date(expiresMs + grace * 3_600_000).toISOString(),
	};
}
