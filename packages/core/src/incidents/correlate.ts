import { compareEvidenceClock, type EvidenceClock } from "./evidence-receipt.js";
import type { Incident, IncidentEventRef, IncidentSeverity, NormalizedSignal } from "./types.js";

const SEVERITY_RANK: Record<IncidentSeverity, number> = {
	info: 0,
	warning: 1,
	high: 2,
	critical: 3,
};

function maxSeverity(a: IncidentSeverity, b: IncidentSeverity): IncidentSeverity {
	return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

function anyReason(s: NormalizedSignal, re: RegExp): boolean {
	const reasons = s.reasons ?? [];
	for (const r of reasons) {
		if (re.test(r)) return true;
	}
	return false;
}

function isSuspiciousDownloaderExecutor(artifact: string | undefined): boolean {
	if (!artifact) return false;
	return /(curl|wget|iwr|invoke-webrequest|powershell|pwsh|bash|sh)\b/i.test(artifact);
}

function isPluginDriftSignal(s: NormalizedSignal): boolean {
	if (s.signal_type !== "plugin_scan_finding") return false;
	const tid = (s.threat_id ?? "").toUpperCase();
	if (tid.includes("DRIFT")) return true;
	return anyReason(s, /\b(drift|baseline|integrity)\b/i);
}

function isPackageAnomalySignal(s: NormalizedSignal): boolean {
	if (s.signal_type !== "runtime_verdict") return false;
	if (s.source === "package_check") return true;
	if (s.package_name) return true;
	return anyReason(s, /\bPackage\b/i);
}

function isSelfDefenseBypassSignal(s: NormalizedSignal): boolean {
	if (s.signal_type !== "runtime_verdict") return false;
	const tid = (s.threat_id ?? "").toUpperCase();
	if (tid.startsWith("CLT-SELF-")) return true;
	return anyReason(s, /\b(disable|remove)\b.*\b(protection|hook|guardrail|allowlist|config)\b/i);
}

function summarizeSignal(s: NormalizedSignal): string {
	if (s.signal_type === "runtime_verdict") {
		const dec = s.decision ?? "unknown";
		return `${dec}${s.artifact ? `: ${String(s.artifact).slice(0, 80)}` : ""}`;
	}
	if (s.signal_type === "plugin_scan_finding") {
		return `${s.plugin_key ?? "plugin"}${s.artifact ? `: ${String(s.artifact).slice(0, 80)}` : ""}`;
	}
	if (s.signal_type === "explicit_incident") {
		return `${s.decision ?? "incident"}${s.reasons?.[0] ? `: ${s.reasons[0]}` : ""}`;
	}
	return s.signal_type;
}

function incidentKey(s: NormalizedSignal): string {
	// An agent id is the endpoint boundary: the same session name, plugin or
	// destination on two endpoints must never become one incident.
	const scope = `scope:${JSON.stringify([s.agent_iid ?? null, s.connector ?? null])}:`;
	if (s.session_id) return `${scope}sess:${JSON.stringify(s.session_id)}`;
	// Without an endpoint or session identity, a shared package/domain is not
	// enough evidence that two independent signals belong to one incident.
	if (!s.agent_iid) return `${scope}signal:${JSON.stringify(s.signal_id)}`;
	if (s.plugin_key) return `${scope}plugin:${JSON.stringify(s.plugin_key)}`;
	if (s.package_name) return `${scope}pkg:${JSON.stringify(s.package_name)}`;
	if (s.domain) return `${scope}dom:${JSON.stringify(s.domain)}`;
	if (s.file_path) return `${scope}path:${JSON.stringify(s.file_path)}`;
	return `${scope}signal:${JSON.stringify(s.signal_id)}`;
}

/** A signal that carries an evidence clock, whose counter is authoritative. */
type ClockedSignal = NormalizedSignal & { clock: EvidenceClock };

function hasEvidenceClock(signal: NormalizedSignal): signal is ClockedSignal {
	return signal.clock !== undefined;
}

/**
 * Order signals for the correlation pass.
 *
 * `compareEvidenceClock` decides the order wherever a signal carries a logical
 * clock, so a device that was offline and came back with a wall clock running
 * backwards still orders after everything it had already produced. Wall clock
 * remains the fallback: it is the only ordering a producer that emits no clock
 * offers, and it still decides which slot a clocked signal keeps when clocked
 * and clockless records are mixed.
 *
 * The reorder is applied as a permutation over the wall-clock order rather than
 * through one mixed comparator, because "both clocked -> compare clocks, else
 * compare wall clocks" is not transitive: a non-transitive comparator can leave
 * two clocked signals in host-time order, which is the defect this replaces.
 */
function orderSignals(signals: NormalizedSignal[]): NormalizedSignal[] {
	const byWallClock = [...signals].sort(
		(a, b) => a.timestamp_ms - b.timestamp_ms || a.signal_id.localeCompare(b.signal_id),
	);
	const clocked = byWallClock.filter(hasEvidenceClock);
	if (clocked.length < 2) return byWallClock;
	const byLogicalClock = [...clocked].sort((a, b) => {
		const byClock = compareEvidenceClock(a.clock, b.clock);
		return byClock !== 0 ? byClock : a.signal_id.localeCompare(b.signal_id);
	});
	let next = 0;
	return byWallClock.map((signal) => {
		if (!hasEvidenceClock(signal)) return signal;
		const replacement = byLogicalClock[next];
		next += 1;
		return replacement ?? signal;
	});
}

function toEventRef(s: NormalizedSignal): IncidentEventRef {
	return {
		signal_id: s.signal_id,
		timestamp_ms: s.timestamp_ms,
		signal_type: s.signal_type,
		severity: s.severity,
		summary: summarizeSignal(s),
		...(s.frameworks ? { frameworks: s.frameworks } : {}),
	};
}

export interface CorrelateOptions {
	// If signals with the same key are farther apart than this, open a new incident.
	max_gap_ms?: number;
	// Escalate severity when repeated denies occur in this window.
	deny_window_ms?: number;
	deny_escalation_threshold?: number;
}

const DEFAULTS: Required<CorrelateOptions> = {
	max_gap_ms: 10 * 60 * 1000,
	deny_window_ms: 5 * 60 * 1000,
	deny_escalation_threshold: 3,
};

export function correlateIncidents(
	signals: NormalizedSignal[],
	options: CorrelateOptions = {},
): Incident[] {
	const cfg = { ...DEFAULTS, ...options };
	const sorted = orderSignals(signals);
	const seenSignalIds = new Set<string>();

	const open = new Map<string, Incident>();
	const denyCounters = new Map<string, number[]>();
	const keyFlags = new Map<
		string,
		{
			hasAsk: boolean;
			hasOverride: boolean;
			hasEgress: boolean;
			hasPluginDrift: boolean;
			hasPackageAnomaly: boolean;
			hasSelfDefenseBypass: boolean;
		}
	>();
	const all: Incident[] = [];

	function bumpDeny(key: string, ts: number): number {
		const arr = denyCounters.get(key) ?? [];
		arr.push(ts);
		const cutoff = ts - cfg.deny_window_ms;
		const filtered = arr.filter((t) => t >= cutoff);
		denyCounters.set(key, filtered);
		return filtered.length;
	}

	for (const s of sorted) {
		// Replayed audit windows contain the same signal more than once. Counting
		// it again would fabricate both evidence and deny escalation.
		const replayKey = JSON.stringify([s.agent_iid ?? null, s.connector ?? null, s.signal_id]);
		if (seenSignalIds.has(replayKey)) continue;
		seenSignalIds.add(replayKey);
		const key = incidentKey(s);
		const existing = open.get(key);

		const isGapTooLarge = existing && s.timestamp_ms - existing.last_seen_ms > cfg.max_gap_ms;
		if (existing && isGapTooLarge) {
			open.delete(key);
			denyCounters.delete(key);
			keyFlags.delete(key);
		}

		const incident = open.get(key) ?? {
			incident_id: `inc_${key}_${s.timestamp_ms}`,
			opened_at_ms: s.timestamp_ms,
			last_seen_ms: s.timestamp_ms,
			severity: s.severity,
			status: "open" as const,
			session_id: s.session_id,
			agent_iid: s.agent_iid,
			connector: s.connector,
			plugin_key: s.plugin_key,
			package_name: s.package_name,
			domain: s.domain,
			file_path: s.file_path,
			events: [],
		};

		const flags = keyFlags.get(key) ?? {
			hasAsk: false,
			hasOverride: false,
			hasEgress: false,
			hasPluginDrift: false,
			hasPackageAnomaly: false,
			hasSelfDefenseBypass: false,
		};
		if (s.signal_type === "runtime_verdict") {
			if (s.decision === "ask") flags.hasAsk = true;
			if (s.decision === "allow" && s.user_override === true) flags.hasOverride = true;
		}
		if (s.domain) flags.hasEgress = true;
		if (isPluginDriftSignal(s)) flags.hasPluginDrift = true;
		if (isPackageAnomalySignal(s)) flags.hasPackageAnomaly = true;
		if (isSelfDefenseBypassSignal(s)) flags.hasSelfDefenseBypass = true;

		incident.last_seen_ms = Math.max(incident.last_seen_ms, s.timestamp_ms);
		incident.severity = maxSeverity(incident.severity, s.severity);
		incident.events.push(toEventRef(s));

		// Ask + override + egress escalation (prompt-injection / approval-abuse shape).
		if (flags.hasAsk && flags.hasOverride && flags.hasEgress) {
			incident.severity = maxSeverity(incident.severity, "high");
		}

		// Plugin drift + suspicious downloader/executor patterns -> critical.
		if (flags.hasPluginDrift && isSuspiciousDownloaderExecutor(s.artifact)) {
			incident.severity = maxSeverity(incident.severity, "critical");
		} else if (flags.hasPluginDrift) {
			incident.severity = maxSeverity(incident.severity, "high");
		}

		// Package anomaly -> high, deny -> critical.
		if (flags.hasPackageAnomaly) {
			incident.severity = maxSeverity(incident.severity, "high");
			if (s.decision === "deny") incident.severity = maxSeverity(incident.severity, "critical");
		}

		// Self-defense bypass attempts are always critical in the local incident model.
		if (flags.hasSelfDefenseBypass) {
			incident.severity = maxSeverity(incident.severity, "critical");
		}

		// Repeated deny escalation.
		if (s.decision === "deny") {
			const n = bumpDeny(key, s.timestamp_ms);
			if (n >= cfg.deny_escalation_threshold) {
				incident.severity = maxSeverity(incident.severity, "critical");
			}
		}

		open.set(key, incident);
		keyFlags.set(key, flags);
		if (!all.includes(incident)) all.push(incident);
	}

	// Return stable order: newest first.
	return all.sort((a, b) => b.last_seen_ms - a.last_seen_ms);
}
