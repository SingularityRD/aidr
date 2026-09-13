import { createHash } from "node:crypto";

import type { IncidentSeverity, NormalizedSignal, SignalType } from "./types.js";

function sha256Hex(input: string): string {
	return createHash("sha256").update(input).digest("hex");
}

function parseTimestampMs(value: unknown): number | null {
	if (typeof value === "number" && Number.isFinite(value)) return value;
	if (typeof value === "string") {
		const t = Date.parse(value);
		if (Number.isFinite(t)) return t;
	}
	return null;
}

function getString(o: Record<string, unknown>, key: string): string | undefined {
	const v = o[key];
	if (typeof v === "string" && v.trim()) return v;
	return undefined;
}

function severityFromRuntimePayload(payload: Record<string, unknown>): IncidentSeverity {
	const sev = String(payload.severity ?? "").toLowerCase();
	if (sev === "critical") return "critical";
	if (sev === "high") return "high";
	if (sev === "warning") return "warning";
	if (sev === "info") return "info";

	// Fallback based on decision.
	const decision = String(payload.verdict ?? "").toLowerCase();
	if (decision === "deny") return "critical";
	if (decision === "ask") return "warning";
	return "info";
}

function normalizeDomainFromUrl(raw: string): string | undefined {
	try {
		return new URL(raw).hostname.toLowerCase();
	} catch {
		return undefined;
	}
}

function looksLikePackageName(s: string): boolean {
	// npm-ish: @scope/name or name (very lightweight; avoids URLs/paths)
	if (s.includes("://")) return false;
	if (s.includes("\\") || s.includes("/")) return false;
	return /^(@[a-z0-9-_.]+\/)?[a-z0-9-_.]+$/i.test(s.trim());
}

function firstPackageLikeArtifact(artifacts: unknown[]): string | undefined {
	for (const a of artifacts) {
		if (typeof a !== "string") continue;
		const v = a.trim();
		if (!v) continue;
		if (looksLikePackageName(v)) return v;
	}
	return undefined;
}

function normalizeSignalId(type: SignalType, timestampMs: number, seed: string): string {
	return `sig_${type}_${timestampMs}_${sha256Hex(seed).slice(0, 12)}`;
}

export function normalizeAuditEntryToSignals(entry: unknown): NormalizedSignal[] {
	if (!entry || typeof entry !== "object") return [];
	const e = entry as Record<string, unknown>;
	const type = String(e.type ?? "unknown");

	// `incident_record` is an output of the correlator. Ignore to avoid feedback loops
	// when correlating from the same JSONL log we persist into.
	if (type === "incident_record") return [];

	const tsMs =
		parseTimestampMs(e.timestamp) ??
		parseTimestampMs(e.created_at) ??
		parseTimestampMs(e.time) ??
		Date.now();
	const agentIid = getString(e, "agent_iid");
	const connector = getString(e, "connector");

	// --- runtime_verdict ---
	if (type === "runtime_verdict") {
		const sessionId = getString(e, "session_id");
		const toolName = getString(e, "tool_name");
		const payloadVerdict = String(e.verdict ?? "");
		const userOverride = Boolean(e.user_override);
		const matchedThreatId = getString(e, "matched_threat_id");

		const artifactsRaw = Array.isArray(e.artifacts) ? (e.artifacts as unknown[]) : [];
		const artifact0 = typeof artifactsRaw[0] === "string" ? (artifactsRaw[0] as string) : undefined;
		const pkg = firstPackageLikeArtifact(artifactsRaw);

		const reasons = Array.isArray(e.reasons)
			? (e.reasons as unknown[]).filter((x) => typeof x === "string").map((x) => String(x))
			: undefined;

		const source = getString(e, "source");
		const decision =
			payloadVerdict === "deny" || payloadVerdict === "ask" || payloadVerdict === "allow"
				? (payloadVerdict as "allow" | "ask" | "deny")
				: undefined;

		const severity = severityFromRuntimePayload(e);
		const domain = artifact0 ? normalizeDomainFromUrl(artifact0) : undefined;

		const seed = JSON.stringify({
			sessionId,
			toolName,
			decision,
			artifact0,
			reasons,
			source,
			matchedThreatId,
		});
		return [
			{
				signal_id: normalizeSignalId("runtime_verdict", tsMs, seed),
				signal_type: "runtime_verdict",
				timestamp_ms: tsMs,
				session_id: sessionId,
				agent_iid: agentIid,
				connector,
				tool_name: toolName,
				decision,
				severity,
				user_override: userOverride,
				threat_id: matchedThreatId,
				artifact: artifact0,
				domain,
				package_name: pkg,
				reasons,
				source,
				raw: entry,
			},
		];
	}

	// --- plugin_scan ---
	if (type === "plugin_scan") {
		const pluginKey = getString(e, "plugin_key");
		const findings = Array.isArray(e.findings) ? (e.findings as unknown[]) : [];

		const signals: NormalizedSignal[] = [];
		for (const f of findings) {
			if (!f || typeof f !== "object") continue;
			const finding = f as Record<string, unknown>;
			const artifact = typeof finding.artifact === "string" ? finding.artifact : undefined;
			const findingSeverity = String(finding.severity ?? "").toLowerCase();
			const sev: IncidentSeverity =
				findingSeverity === "critical"
					? "critical"
					: findingSeverity === "high"
						? "high"
						: findingSeverity === "warning"
							? "warning"
							: "info";

			const domain = artifact ? normalizeDomainFromUrl(artifact) : undefined;
			const seed = JSON.stringify({ pluginKey, artifact, sev, threat: finding.threat_id ?? "" });
			signals.push({
				signal_id: normalizeSignalId("plugin_scan_finding", tsMs, seed),
				signal_type: "plugin_scan_finding",
				timestamp_ms: tsMs,
				agent_iid: agentIid,
				connector,
				plugin_key: pluginKey,
				severity: sev,
				artifact,
				domain,
				threat_id: typeof finding.threat_id === "string" ? finding.threat_id : undefined,
				reasons:
					typeof finding.title === "string"
						? [finding.title]
						: typeof finding.reason === "string"
							? [finding.reason]
							: undefined,
				source: "plugin_scan",
				raw: finding,
			});
		}
		return signals;
	}

	// --- explicit incident event ---
	if (type === "incident") {
		const sessionId = getString(e, "session_id");
		const toolName = getString(e, "tool_name");
		const source = getString(e, "source");
		const matchedThreatId = getString(e, "matched_threat_id");

		// Ignore self-defense / tamper / revocation style incidents in correlation v1.
		// These are important, but mixing them into runtime/tool-call correlation tends to create noise.
		if (
			source === "integrity" ||
			toolName === "Integrity" ||
			matchedThreatId?.startsWith("INTEGRITY") ||
			sessionId?.startsWith("integrity_") ||
			source === "licensing" ||
			source === "revocation" ||
			matchedThreatId?.startsWith("LICENSE") ||
			sessionId?.startsWith("revocation_")
		) {
			return [];
		}

		const decision = getString(e, "decision") as "allow" | "ask" | "deny" | undefined;
		const reasons = Array.isArray(e.reasons)
			? (e.reasons as unknown[]).filter((x) => typeof x === "string").map((x) => String(x))
			: undefined;
		const severity = String(e.severity ?? "").toLowerCase() as IncidentSeverity;
		const sev: IncidentSeverity =
			severity === "critical" ||
			severity === "high" ||
			severity === "warning" ||
			severity === "info"
				? severity
				: decision === "deny"
					? "critical"
					: decision === "ask"
						? "warning"
						: "info";

		const seed = JSON.stringify({ sessionId, decision, reasons, sev });
		return [
			{
				signal_id: normalizeSignalId("explicit_incident", tsMs, seed),
				signal_type: "explicit_incident",
				timestamp_ms: tsMs,
				session_id: sessionId,
				agent_iid: agentIid,
				connector,
				decision,
				severity: sev,
				threat_id: matchedThreatId,
				reasons,
				source: source ?? "incident",
				raw: entry,
			},
		];
	}

	return [
		{
			signal_id: normalizeSignalId("unknown", tsMs, JSON.stringify(entry).slice(0, 500)),
			signal_type: "unknown",
			timestamp_ms: tsMs,
			agent_iid: agentIid,
			connector,
			severity: "info",
			raw: entry,
		},
	];
}

export function normalizeAuditEntriesToSignals(entries: unknown[]): NormalizedSignal[] {
	const out: NormalizedSignal[] = [];
	for (const e of entries) out.push(...normalizeAuditEntryToSignals(e));
	return out;
}
