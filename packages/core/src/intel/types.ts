export type IntelFileKind =
	| "url_denylist"
	| "url_allowlist"
	| "domain_risk"
	| "package_name_denylist"
	| "package_hash_denylist"
	| "plugin_signature_denylist";

export type DomainRiskAction = "allow" | "ask" | "deny";

export type DomainRiskSeverity = "critical" | "high" | "medium" | "low";

export interface DomainRiskEntry {
	domain: string;
	action: DomainRiskAction;
	severity: DomainRiskSeverity;
	confidence?: number;
	reason?: string;
}

export interface IntelMerged {
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
