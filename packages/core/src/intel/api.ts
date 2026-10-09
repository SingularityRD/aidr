import { isIP } from "node:net";

import type { DomainRiskEntry, IntelMerged } from "./types.js";

function normalizeDomain(s: string): string {
	return s.trim().toLowerCase().replace(/^\.+/, "").replace(/\.+$/, "");
}

function parseUrlHost(raw: string): { host: string; isIp: boolean } | null {
	try {
		const u = new URL(raw);
		const host = u.hostname.trim();
		if (!host) return null;
		return { host, isIp: isIP(host) !== 0 };
	} catch {
		return null;
	}
}

export function domainFromUrlOrHost(input: string): string | null {
	const trimmed = input.trim();
	if (!trimmed) return null;
	const parsed = parseUrlHost(trimmed);
	if (parsed) return normalizeDomain(parsed.host);
	// Allow raw hosts/domains in intel files.
	return normalizeDomain(trimmed);
}

export function lookupDomainRisk(merged: IntelMerged, host: string): DomainRiskEntry | null {
	const h = normalizeDomain(host);
	if (!h) return null;

	// Fast path exact.
	const exact = merged.domainRisk.get(h);
	if (exact) return exact;

	// Suffix match: find closest parent match.
	const parts = h.split(".");
	for (let i = 1; i < parts.length; i++) {
		const candidate = parts.slice(i).join(".");
		const hit = merged.domainRisk.get(candidate);
		if (hit) return hit;
	}
	return null;
}

export function matchPackageIntel(
	merged: IntelMerged,
	params: { name?: string; sha256?: string },
): { verdict: "ask" | "deny"; reason: string; confidence: number } | null {
	const name = typeof params.name === "string" ? params.name.trim() : "";
	if (name && merged.packageNameDeny.has(name)) {
		return { verdict: "deny", reason: "Intel package name denylist match", confidence: 1.0 };
	}

	const hash = typeof params.sha256 === "string" ? params.sha256.trim().toLowerCase() : "";
	if (hash && merged.packageHashDeny.has(hash)) {
		return { verdict: "deny", reason: "Intel package hash denylist match", confidence: 1.0 };
	}

	return null;
}

export function matchPluginIntel(
	merged: IntelMerged,
	params: { signature?: string },
): { verdict: "deny"; reason: string; confidence: number } | null {
	const sig = typeof params.signature === "string" ? params.signature.trim().toLowerCase() : "";
	if (sig && merged.pluginSignatureDeny.has(sig)) {
		return { verdict: "deny", reason: "Intel plugin signature denylist match", confidence: 1.0 };
	}
	return null;
}
