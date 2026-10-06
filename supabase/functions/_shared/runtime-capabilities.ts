import { parseActiveAdmission } from "./effective-seats.ts";

const CAPABILITIES = ["runtime_detectors", "behavioral_learning_v1"] as const;
const TENANT_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

/** Deployment/operator configuration only, never enrollment or browser input. */
export function tenantRuntimeCapabilities(
	tenantId: string,
	rawConfig: string | undefined,
	admissionData: unknown,
	nowMs = Date.now(),
): string[] {
	const admission = parseActiveAdmission(admissionData, nowMs);
	if (!admission || admission.validUntilMs === null
		|| (admissionData as Record<string, unknown>).access_kind !== "licensed"
		|| !rawConfig || rawConfig.length > 65_536) return [];
	try {
		const map: unknown = JSON.parse(rawConfig);
		if (!map || typeof map !== "object" || Array.isArray(map)) return [];
		const entries = Object.entries(map);
		if (entries.length > 256 || entries.some(([id, grants]) =>
			!TENANT_ID.test(id) || !Array.isArray(grants) || grants.length > CAPABILITIES.length
			|| grants.some((grant) => !CAPABILITIES.includes(grant))
			|| new Set(grants).size !== grants.length
			|| (grants.includes("behavioral_learning_v1") && !grants.includes("runtime_detectors"))
		)) return [];
		const grants = entries.find(([id]) => id === tenantId)?.[1];
		return Array.isArray(grants) ? CAPABILITIES.filter((capability) => grants.includes(capability)) : [];
	} catch {
		return [];
	}
}

export function buildPremiumModules(entRow: Record<string, unknown> | null, capabilities: string[] = []): string[] {
	const out: string[] = [];
	if (entRow?.premium_intel === true) out.push("premium_intel");
	if (entRow?.premium_correlation === true) out.push("premium_correlation");
	if (entRow?.premium_pkg_plugin === true) out.push("premium_pkg_plugin");
	return [...out, ...capabilities];
}
