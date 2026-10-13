export type IntelFileKind =
	| "url_denylist"
	| "url_allowlist"
	| "domain_risk"
	| "package_name_denylist"
	| "package_hash_denylist"
	| "plugin_signature_denylist";

type DomainRiskAction = "allow" | "ask" | "deny";

type DomainRiskSeverity = "critical" | "high" | "medium" | "low";

export interface DomainRiskEntry {
	domain: string;
	action: DomainRiskAction;
	severity: DomainRiskSeverity;
	confidence?: number;
	reason?: string;
}

/** An installed pack past its signed expires_at: still enforcing, but needs an update. */
export interface StaleIntelPack {
	packId: string;
	version: string;
	expiresAt: string;
}

export interface IntelMerged {
	/** Coverage state for explicitly enabled signed packs; absence is legacy/unset. */
	availability?: "available" | "unavailable";
	detail?: string;
	/** Loaded packs past their expiry (non-enumerable; for status surfaces). */
	stalePacks?: StaleIntelPack[];
	urlDenyHosts: Set<string>;
	urlAllowHosts: Set<string>;
	domainRisk: Map<string, DomainRiskEntry>;
	packageNameDeny: Set<string>;
	packageHashDeny: Set<string>;
	pluginSignatureDeny: Set<string>;
}

export function emptyIntelMerged(): IntelMerged {
	return {
		urlDenyHosts: new Set(),
		urlAllowHosts: new Set(),
		domainRisk: new Map(),
		packageNameDeny: new Set(),
		packageHashDeny: new Set(),
		pluginSignatureDeny: new Set(),
	};
}
