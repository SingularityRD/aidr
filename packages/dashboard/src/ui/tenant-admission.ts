import { safeExternalUrl } from "./pages/public/external-url";

export type TenantAdmission = {
	mode: "unconfigured" | "cloud" | "onprem" | "pilot";
	status: string;
	access_kind: "trial" | "licensed" | "pilot" | null;
	allowed_agents: number;
	expires_at: string | null;
	trial_available: boolean;
};

export function readTenantAdmission(value: unknown): TenantAdmission | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const admission = value as Record<string, unknown>;
	if (
		!(["unconfigured", "cloud", "onprem", "pilot"] as unknown[]).includes(admission.mode) ||
		typeof admission.status !== "string" ||
		!(["trial", "licensed", "pilot", null] as unknown[]).includes(admission.access_kind) ||
		!Number.isInteger(admission.allowed_agents) ||
		(admission.allowed_agents as number) < 0 ||
		(admission.status === "active" && admission.allowed_agents === 0) ||
		(admission.expires_at !== null && typeof admission.expires_at !== "string") ||
		(typeof admission.expires_at === "string" &&
			!Number.isFinite(Date.parse(admission.expires_at))) ||
		typeof admission.trial_available !== "boolean"
	)
		return null;
	return admission as TenantAdmission;
}

type GaLegalDocument = { version: string; sha256: string; url: string };
export type GaLegal = {
	configured: boolean;
	terms: GaLegalDocument | null;
	privacy: GaLegalDocument | null;
};

function readLegalDocument(value: unknown): GaLegalDocument | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const document = value as Record<string, unknown>;
	if (
		typeof document.version !== "string" ||
		!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(document.version)
	)
		return null;
	if (typeof document.sha256 !== "string" || !/^[a-f0-9]{64}$/i.test(document.sha256)) return null;
	const url = safeExternalUrl(typeof document.url === "string" ? document.url : undefined);
	return url ? { version: document.version, sha256: document.sha256, url } : null;
}

export function readGaLegal(value: unknown): GaLegal | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const legal = value as Record<string, unknown>;
	if (legal.configured === false) return { configured: false, terms: null, privacy: null };
	if (legal.configured !== true) return null;
	const terms = readLegalDocument(legal.terms);
	const privacy = readLegalDocument(legal.privacy);
	return terms && privacy ? { configured: true, terms, privacy } : null;
}
