// AI security posture fields for /v1/ingest (infra_scan_finding,
// mcp_inventory_finding, and the posture fields of plugin_scan_finding).
//
// Mirrors packages/core/src/posture-events.ts `projectPostureFields`. The
// client projection is not trusted: every field is re-validated here and any
// value outside its bounded shape is dropped. Targets, hostnames, file paths,
// server arguments, matched text and credentials are never accepted; only
// identifiers, enums, bounded numbers and sha256 digests are stored.

export const POSTURE_EVENT_TYPES = ["infra_scan_finding", "mcp_inventory_finding"] as const;

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SENSITIVE_PATTERN =
	/(?:^|[._:-])(?:api[_-]?key|access[_-]?token|authorization|bearer|cookie|credential|password|passwd|private[_-]?key|secret|session[_-]?token|client[_-]?secret|refresh[_-]?token|signature)(?:[._:-]|$)|^(?:sk[_-]|ghp_|github_pat_|xox[baprs]-|npm_|pypi-|AKIA)/i;
const JWT_LIKE_PATTERN = /^eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.(?:[A-Za-z0-9_-]{8,})?$/;
const PHONE_LIKE_PATTERN = /^(?:\d[.:-]?){8,15}$/;
const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const VULN_ID_PATTERN = /^(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})$/;
const COMPONENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._+/-]{0,79}$/;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const MCP_CATEGORY_PATTERN = /^(?:aig-)?mcp-[a-z0-9-]{1,48}$/;
const SKILL_RISK_TYPE_PATTERN = /^T0[1-9]$/;

const FINDING_KINDS = new Set(["cve", "advisory", "exposed_component", "mcp_server", "skill_rule"]);
const FINDING_SEVERITIES = new Set(["critical", "high", "medium", "low", "info", "unknown"]);
const APPLICABILITY = new Set(["confirmed", "unconfirmed"]);
const TRANSPORTS = new Set(["remote", "stdio"]);
const MCP_RISK_HINTS = new Set(["remote_mcp_url", "shell_wrapper_command", "broad_filesystem_access_arg"]);
const ATTESTATION_STATUSES = new Set([
	"approved",
	"unapproved",
	"quarantined",
	"unsigned",
	"unverifiable",
	"rejected",
]);
const DIGEST_KEYS = ["target_digest", "server_digest", "configuration_digest", "source_file_digest"] as const;
const MAX_RISK_CATEGORIES = 16;

function notSensitive(value: string): boolean {
	return !SENSITIVE_PATTERN.test(value) && !JWT_LIKE_PATTERN.test(value);
}

function identifier(value: unknown): string | undefined {
	return typeof value === "string" &&
		IDENTIFIER_PATTERN.test(value) &&
		notSensitive(value) &&
		!PHONE_LIKE_PATTERN.test(value)
		? value
		: undefined;
}

function label(value: unknown, pattern: RegExp): string | undefined {
	return typeof value === "string" && pattern.test(value) && notSensitive(value) ? value : undefined;
}

function member(value: unknown, allowed: Set<string>): string | undefined {
	return typeof value === "string" && allowed.has(value) ? value : undefined;
}

/** Validated posture fields of one untrusted event; unknown or malformed values are omitted. */
export function projectPostureFields(event: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	const set = (key: string, value: unknown) => {
		if (value !== undefined) out[key] = value;
	};
	set("scan_id", identifier(event.scan_id));
	set("finding_kind", member(event.finding_kind, FINDING_KINDS));
	set("finding_severity", member(event.finding_severity, FINDING_SEVERITIES));
	set("vuln_id", label(event.vuln_id, VULN_ID_PATTERN));
	if (typeof event.cvss === "number" && Number.isFinite(event.cvss) && event.cvss >= 0 && event.cvss <= 10) {
		out.cvss = Math.round(event.cvss * 10) / 10;
	}
	set("component", label(event.component, COMPONENT_PATTERN));
	set("fingerprint", label(event.fingerprint, COMPONENT_PATTERN));
	set("component_version", label(event.component_version, VERSION_PATTERN));
	set("applicability", member(event.applicability, APPLICABILITY));
	set("mcp_server_name", identifier(event.mcp_server_name));
	set("mcp_transport", member(event.mcp_transport, TRANSPORTS));
	if (Array.isArray(event.risk_categories)) {
		out.risk_categories = [
			...new Set(
				event.risk_categories.filter(
					(value): value is string =>
						typeof value === "string" && (MCP_RISK_HINTS.has(value) || MCP_CATEGORY_PATTERN.test(value)),
				),
			),
		].slice(0, MAX_RISK_CATEGORIES);
	}
	set("attestation_status", member(event.attestation_status, ATTESTATION_STATUSES));
	set("plugin_version", label(event.plugin_version, VERSION_PATTERN));
	set("skill_risk_type", label(event.skill_risk_type, SKILL_RISK_TYPE_PATTERN));
	for (const key of DIGEST_KEYS) {
		const value = event[key];
		if (typeof value === "string" && HASH_PATTERN.test(value)) out[key] = value;
	}
	return out;
}
