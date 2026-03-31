export type IncidentSeverity = "info" | "warning" | "high" | "critical";

export type SignalType =
	| "runtime_verdict"
	| "plugin_scan_finding"
	| "explicit_incident"
	| "unknown";

export interface NormalizedSignal {
	signal_id: string;
	signal_type: SignalType;
	timestamp_ms: number;

	// Correlation keys (best-effort)
	session_id?: string;
	agent_iid?: string;
	connector?: string;

	plugin_key?: string;
	package_name?: string;
	domain?: string;
	file_path?: string;

	decision?: "allow" | "ask" | "deny";
	severity: IncidentSeverity;
	confidence?: number;
	user_override?: boolean;

	// Best-effort enrichment
	tool_name?: string;
	threat_id?: string;

	artifact?: string;
	reasons?: string[];
	source?: string;
	raw?: unknown;
}

export interface IncidentEventRef {
	signal_id: string;
	timestamp_ms: number;
	signal_type: SignalType;
	severity: IncidentSeverity;
	summary: string;
}

export interface Incident {
	incident_id: string;
	opened_at_ms: number;
	last_seen_ms: number;
	severity: IncidentSeverity;
	status: "open" | "acknowledged" | "contained" | "resolved" | "suppressed";

	// Primary correlation fields
	session_id?: string;
	agent_iid?: string;
	connector?: string;
	plugin_key?: string;
	package_name?: string;
	domain?: string;
	file_path?: string;

	events: IncidentEventRef[];
}
