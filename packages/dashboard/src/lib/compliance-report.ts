import { supabase } from "./supabase";
import { errorCode } from "./workspace-settings";

/**
 * Client for the `compliance-report` Edge Function (docs/compliance-report.md).
 *
 * The server returns a sealed `aidr.compliance-report/v1` document. The browser
 * checks its shape and recomputes the SHA-256 of its canonical JSON before any
 * preview or download is offered, so a truncated or altered response is shown as
 * an error rather than as evidence. Signature verification is left to
 * `aidr compliance verify`, which can pin the operator's public key.
 */

const COMPLIANCE_REPORT_SCHEMA = "aidr.compliance-report/v1";
const COMPLIANCE_MAX_PERIOD_DAYS = 366;
const DAY_MS = 86_400_000;

export const COMPLIANCE_SECTION_KEYS = [
	"tenant_profile",
	"protection_coverage",
	"data_protection_activity",
	"policy_inventory",
	"access_identity",
	"incidents",
	"ai_security_posture",
	"data_flows",
	"retention_deletion",
] as const;
export type ComplianceSectionKey = (typeof COMPLIANCE_SECTION_KEYS)[number];

export type JsonValue =
	| string
	| number
	| boolean
	| null
	| JsonValue[]
	| { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

interface ComplianceSignature {
	algorithm: string;
	key_id: string;
	public_key_spki_b64: string;
	signed_payload: string;
	value_b64: string;
}

export interface ComplianceReport {
	schema: string;
	report_id: string;
	generated_at: string;
	generated_by: { user_id: string; role: string };
	period: { from: string; to: string; days: number };
	statement: string;
	sections: Record<ComplianceSectionKey, JsonObject>;
	limitations: string[];
	integrity: {
		canonicalization: string;
		hash_algorithm: string;
		hashed_scope: string;
		sha256: string;
		signature: ComplianceSignature | null;
	};
}

export type ComplianceResult<T> = { ok: true; value: T } | { ok: false; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function canonicalize(value: unknown): unknown {
	if (value === null || typeof value === "string" || typeof value === "boolean") return value;
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new Error("non_finite_number");
		return value;
	}
	if (Array.isArray(value)) return value.map(canonicalize);
	if (isRecord(value)) {
		const out: Record<string, unknown> = {};
		for (const key of Object.keys(value).sort()) out[key] = canonicalize(value[key]);
		return out;
	}
	throw new Error("unsupported_value");
}

/** aidr-canonical-json/v1 (same rules as the server and `aidr compliance verify`). */
function canonicalJson(value: unknown): string {
	return JSON.stringify(canonicalize(value));
}

async function sha256Hex(text: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Recompute the report hash exactly as the issuer did. */
export async function reportHashMatches(report: ComplianceReport): Promise<boolean> {
	const { integrity, ...body } = report;
	try {
		return (await sha256Hex(canonicalJson(body))) === integrity.sha256;
	} catch {
		return false;
	}
}

function validSignature(value: unknown): value is ComplianceSignature | null {
	if (value === null) return true;
	return (
		isRecord(value) &&
		value.algorithm === "ed25519" &&
		typeof value.key_id === "string" &&
		typeof value.public_key_spki_b64 === "string" &&
		typeof value.signed_payload === "string" &&
		typeof value.value_b64 === "string"
	);
}

/** Structural check of a server report; null when anything is missing. */
export function parseComplianceReport(value: unknown): ComplianceReport | null {
	if (!isRecord(value) || value.schema !== COMPLIANCE_REPORT_SCHEMA) return null;
	if (typeof value.report_id !== "string" || typeof value.generated_at !== "string") return null;
	if (typeof value.statement !== "string") return null;
	const by = value.generated_by;
	if (!isRecord(by) || typeof by.user_id !== "string" || typeof by.role !== "string") return null;
	const period = value.period;
	if (
		!isRecord(period) ||
		typeof period.from !== "string" ||
		typeof period.to !== "string" ||
		!Number.isSafeInteger(period.days)
	)
		return null;
	const sections = value.sections;
	if (!isRecord(sections) || COMPLIANCE_SECTION_KEYS.some((key) => !isRecord(sections[key]))) {
		return null;
	}
	if (
		!Array.isArray(value.limitations) ||
		value.limitations.some((item) => typeof item !== "string")
	)
		return null;
	const integrity = value.integrity;
	if (
		!isRecord(integrity) ||
		typeof integrity.sha256 !== "string" ||
		!/^[a-f0-9]{64}$/.test(integrity.sha256) ||
		integrity.canonicalization !== "aidr-canonical-json/v1" ||
		!validSignature(integrity.signature)
	)
		return null;
	return value as unknown as ComplianceReport;
}

export interface CompliancePeriod {
	from: string;
	to: string;
}

/** Last `days` days ending now. */
export function presetPeriod(days: number, now: number = Date.now()): CompliancePeriod {
	return { from: new Date(now - days * DAY_MS).toISOString(), to: new Date(now).toISOString() };
}

/**
 * Whole UTC days from `fromDay` through `toDay` (inclusive). The end is capped at
 * `now`, so a range that ends today covers today up to the current moment.
 */
export function customPeriod(
	fromDay: string,
	toDay: string,
	now: number = Date.now(),
): ComplianceResult<CompliancePeriod> {
	const day = /^\d{4}-\d{2}-\d{2}$/;
	if (!day.test(fromDay) || !day.test(toDay)) return { ok: false, error: "invalid_period" };
	const from = Date.parse(`${fromDay}T00:00:00.000Z`);
	const end = Date.parse(`${toDay}T00:00:00.000Z`) + DAY_MS;
	if (!Number.isFinite(from) || !Number.isFinite(end))
		return { ok: false, error: "invalid_period" };
	const to = Math.min(end, now);
	if (to <= from) return { ok: false, error: "invalid_period" };
	if (to - from > COMPLIANCE_MAX_PERIOD_DAYS * DAY_MS)
		return { ok: false, error: "period_too_long" };
	return {
		ok: true,
		value: { from: new Date(from).toISOString(), to: new Date(to).toISOString() },
	};
}

export async function generateComplianceReport(
	tenantId: string,
	period: CompliancePeriod,
): Promise<ComplianceResult<ComplianceReport>> {
	try {
		const { data, error } = await supabase.functions.invoke("compliance-report", {
			body: { tenant_id: tenantId, from: period.from, to: period.to },
		});
		if (error)
			return { ok: false, error: (await errorCode(error)) ?? "compliance_report_unavailable" };
		const report = isRecord(data) && data.ok === true ? parseComplianceReport(data.report) : null;
		if (!report || report.sections.tenant_profile.tenant_id !== tenantId) {
			return { ok: false, error: "compliance_report_malformed" };
		}
		if (!(await reportHashMatches(report)))
			return { ok: false, error: "compliance_report_hash_mismatch" };
		return { ok: true, value: report };
	} catch {
		return { ok: false, error: "compliance_report_unavailable" };
	}
}

const ERROR_TEXT: Readonly<Record<string, string>> = {
	mfa_required:
		"Compliance reports need a multi-factor (AAL2) session. Sign in again with your second factor and retry.",
	sso_required:
		"This workspace requires single sign-on. Sign in with your organization's identity provider.",
	session_revoked: "Your session was revoked. Sign in again.",
	compliance_role_insufficient: "Only workspace owners and admins can generate compliance reports.",
	compliance_forbidden:
		"Only active owners and admins of this workspace can generate compliance reports.",
	workspace_forbidden: "You are not an active member of this workspace.",
	workspace_not_active: "Reports can only be generated for an active workspace.",
	rate_limited: "Too many reports were requested. Wait a minute and try again.",
	invalid_period: "Choose a valid period: the end must be after the start and not in the future.",
	period_too_long: "A report can cover at most 366 days.",
	period_in_future: "The period cannot end in the future.",
	compliance_report_hash_mismatch:
		"The report received does not match its own SHA-256, so it is not shown. Generate it again.",
	compliance_report_malformed:
		"The report received is incomplete, so it is not shown. Generate it again.",
};

export function complianceErrorText(code: string): string {
	return (
		ERROR_TEXT[code] ??
		"The compliance report could not be generated. No partial report was produced; try again later."
	);
}
