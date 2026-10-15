import type { DashboardMessageKey } from "../i18n/en";
import { edgeErrorCode } from "./agent-lifecycle";
import { supabase } from "./supabase";

/**
 * License status, signed-license import and the customer usage report.
 *
 * Status comes from `tenant_license_status` (any active member). The import
 * goes to the `license-admin` Edge Function, which verifies the vendor
 * signature server-side and only STAGES the license; a platform operator who
 * is not a member of this workspace applies it (separation of duty). The
 * usage report uses the `aidr-usage-report-v1` contract shared with
 * scripts/onprem-usage-report.mjs and is customer-attested, not signed.
 */

const DAY_MS = 24 * 60 * 60 * 1000;
export const MAX_LICENSE_FILE_BYTES = 64 * 1024;
const USAGE_REPORT_FORMAT = "aidr-usage-report-v1";

interface LicenseTerms {
	licenseId: string;
	seats: number;
	expiresAt: string;
	graceEndsAt: string;
}

export interface LicenseStatus {
	mode: string;
	canManage: boolean;
	admission: { kind: string; seats: number; expiresAt: string; revoked: boolean } | null;
	license: (LicenseTerms & { planId: string; notBefore: string; appliedAt: string | null }) | null;
	pending: (LicenseTerms & { id: string; submittedAt: string }) | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
const isDate = (value: unknown): value is string =>
	typeof value === "string" && Number.isFinite(Date.parse(value));
const isCount = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

export function readLicenseStatus(value: unknown): LicenseStatus | null {
	if (!isRecord(value) || typeof value.can_manage !== "boolean") return null;
	let admission: LicenseStatus["admission"] = null;
	if (value.admission !== null && value.admission !== undefined) {
		const a = value.admission;
		if (
			!isRecord(a) ||
			typeof a.kind !== "string" ||
			!isCount(a.seats) ||
			!isDate(a.expires_at) ||
			typeof a.revoked !== "boolean"
		)
			return null;
		admission = { kind: a.kind, seats: a.seats, expiresAt: a.expires_at, revoked: a.revoked };
	}
	let license: LicenseStatus["license"] = null;
	if (value.license !== null && value.license !== undefined) {
		const l = value.license;
		if (
			!isRecord(l) ||
			typeof l.license_id !== "string" ||
			typeof l.plan_id !== "string" ||
			!isCount(l.seats) ||
			!isDate(l.not_before) ||
			!isDate(l.expires_at) ||
			!isDate(l.grace_ends_at) ||
			(l.applied_at !== null && !isDate(l.applied_at))
		)
			return null;
		license = {
			licenseId: l.license_id,
			planId: l.plan_id,
			seats: l.seats,
			notBefore: l.not_before,
			expiresAt: l.expires_at,
			graceEndsAt: l.grace_ends_at,
			appliedAt: (l.applied_at as string | null) ?? null,
		};
	}
	let pending: LicenseStatus["pending"] = null;
	if (value.pending !== null && value.pending !== undefined) {
		const p = value.pending;
		if (
			!isRecord(p) ||
			typeof p.id !== "string" ||
			typeof p.license_id !== "string" ||
			!isCount(p.seats) ||
			!isDate(p.expires_at) ||
			!isDate(p.grace_ends_at) ||
			!isDate(p.submitted_at)
		)
			return null;
		pending = {
			id: p.id,
			licenseId: p.license_id,
			seats: p.seats,
			expiresAt: p.expires_at,
			graceEndsAt: p.grace_ends_at,
			submittedAt: p.submitted_at,
		};
	}
	return {
		mode: typeof value.mode === "string" ? value.mode : "unconfigured",
		canManage: value.can_manage,
		admission,
		license,
		pending,
	};
}

export async function fetchLicenseStatus(tenantId: string): Promise<LicenseStatus | null> {
	try {
		const { data, error } = await supabase.rpc("tenant_license_status", { p_tenant_id: tenantId });
		return error ? null : readLicenseStatus(data);
	} catch {
		return null;
	}
}

type LicenseBannerLevel = "none" | "expires_30" | "expires_7" | "grace" | "expired";

export interface LicenseBanner {
	level: LicenseBannerLevel;
	/** Whole days until the license end (expires_30/expires_7) or the grace end (grace). */
	days: number;
	expiresAt: string | null;
	graceEndsAt: string | null;
}

/**
 * Expiry banner at 30 and 7 days before the license end, during the grace
 * period and after it. Without a stored signed license the admission end
 * (which already includes grace) is used for both dates. Trials, pilots and
 * revoked admissions have their own messages elsewhere.
 */
export function licenseBanner(status: LicenseStatus | null, now: number): LicenseBanner {
	const none: LicenseBanner = { level: "none", days: 0, expiresAt: null, graceEndsAt: null };
	if (!status) return none;
	let expiresAt: string;
	let graceEndsAt: string;
	if (status.license) {
		({ expiresAt, graceEndsAt } = status.license);
	} else if (
		status.admission &&
		status.admission.kind === "licensed" &&
		!status.admission.revoked
	) {
		expiresAt = status.admission.expiresAt;
		graceEndsAt = status.admission.expiresAt;
	} else return none;
	const expires = Date.parse(expiresAt);
	const graceEnds = Date.parse(graceEndsAt);
	if (now >= graceEnds) return { level: "expired", days: 0, expiresAt, graceEndsAt };
	if (now >= expires) {
		return {
			level: "grace",
			days: Math.max(0, Math.ceil((graceEnds - now) / DAY_MS)),
			expiresAt,
			graceEndsAt,
		};
	}
	const days = Math.ceil((expires - now) / DAY_MS);
	if (days <= 7) return { level: "expires_7", days, expiresAt, graceEndsAt };
	if (days <= 30) return { level: "expires_30", days, expiresAt, graceEndsAt };
	return { ...none, expiresAt, graceEndsAt };
}

const SUBMIT_ERRORS: Record<string, DashboardMessageKey> = {
	workspace_role_insufficient: "license.err.role",
	workspace_forbidden: "license.err.role",
	mfa_required: "license.err.mfa",
	license_rejected: "license.err.rejected",
	license_registry_unavailable: "license.err.registry",
	license_registry_empty: "license.err.registry",
	license_registry_invalid: "license.err.registry",
	license_bound_to_other_tenant: "license.err.otherTenant",
	rate_limited: "license.err.rateLimited",
	payload_too_large: "license.err.tooLarge",
};

export function licenseSubmitErrorKey(code: string | null): DashboardMessageKey {
	return (
		(code && Object.hasOwn(SUBMIT_ERRORS, code) && SUBMIT_ERRORS[code]) || "license.err.unavailable"
	);
}

/** Parse a picked file as a JSON object without trusting anything else about it. */
export function parseLicenseFile(text: string): Record<string, unknown> | null {
	if (text.length === 0 || text.length > MAX_LICENSE_FILE_BYTES) return null;
	try {
		const value: unknown = JSON.parse(text);
		return isRecord(value) && value.format === "aidr-license-v1" ? value : null;
	} catch {
		return null;
	}
}

export type SubmitLicenseResult =
	| {
			ok: true;
			licenseId: string;
			seats: number;
			expiresAt: string;
			graceEndsAt: string;
			status: string;
	  }
	| { ok: false; code: string | null; reason: string | null };

export async function submitLicense(
	tenantId: string,
	license: Record<string, unknown>,
): Promise<SubmitLicenseResult> {
	try {
		const { data, error } = await supabase.functions.invoke<unknown>("license-admin", {
			body: { action: "submit", tenant_id: tenantId, license },
		});
		if (error) {
			let reason: string | null = null;
			const ctx = isRecord(error) ? error.context : null;
			if (ctx instanceof Response) {
				try {
					const body: unknown = await ctx.clone().json();
					reason = isRecord(body) && typeof body.reason === "string" ? body.reason : null;
				} catch {
					reason = null;
				}
			}
			return { ok: false, code: await edgeErrorCode(error), reason };
		}
		if (
			!isRecord(data) ||
			data.ok !== true ||
			data.status !== "pending" ||
			!isRecord(data.license)
		) {
			return { ok: false, code: null, reason: null };
		}
		const l = data.license;
		if (
			typeof l.license_id !== "string" ||
			!isCount(l.seats) ||
			!isDate(l.expires_at) ||
			!isDate(l.grace_ends_at)
		) {
			return { ok: false, code: null, reason: null };
		}
		return {
			ok: true,
			licenseId: l.license_id,
			seats: l.seats,
			expiresAt: l.expires_at,
			graceEndsAt: l.grace_ends_at,
			status: typeof l.status === "string" ? l.status : "valid",
		};
	} catch {
		return { ok: false, code: null, reason: null };
	}
}

// --- Usage report (aidr-usage-report-v1) -----------------------------------

const REPORT_FIELDS = [
	"format",
	"customer_id",
	"license_id",
	"generated_at",
	"seats_licensed",
	"devices_enrolled",
	"devices_active_30d",
	"license_state",
	"updates_until",
	"deployment_version",
] as const;

export type UsageReportFields = {
	format: typeof USAGE_REPORT_FORMAT;
	customer_id: string | null;
	license_id: string | null;
	generated_at: string;
	seats_licensed: number;
	devices_enrolled: number;
	devices_active_30d: number;
	license_state: "valid" | "grace" | "expired" | "not_yet_valid" | "unverified" | "unlicensed";
	updates_until: string | null;
	deployment_version: string;
};

/** Same canonical form as scripts/license-verify.mjs `canonicalJson`. */
function canonicalJson(value: unknown): string {
	if (value === null || typeof value === "boolean" || typeof value === "string")
		return JSON.stringify(value);
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new Error("non-finite number");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	if (isRecord(value)) {
		return `{${Object.keys(value)
			.sort()
			.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
			.join(",")}}`;
	}
	throw new Error("unsupported value");
}

async function sha256Hex(text: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function stateAt(
	terms: Record<string, unknown>,
	now: number,
): UsageReportFields["license_state"] | null {
	const notBefore = Date.parse(String(terms.not_before));
	const expires = Date.parse(String(terms.expires_at));
	const graceEnds = Date.parse(String(terms.grace_ends_at));
	if (![notBefore, expires, graceEnds].every(Number.isFinite)) return null;
	if (now < notBefore) return "not_yet_valid";
	if (now < expires) return "valid";
	if (now < graceEnds) return "grace";
	return "expired";
}

/** Build the report fields from `tenant_usage_report` facts (mirrors the script). */
export function usageReportFields(
	facts: unknown,
	now: number,
	deploymentVersion: string,
): UsageReportFields | null {
	if (!isRecord(facts)) return null;
	if (
		!isCount(facts.seats_licensed) ||
		!isCount(facts.devices_enrolled) ||
		!isCount(facts.devices_active_30d)
	)
		return null;
	let customerId: string | null = null;
	let licenseId: string | null = null;
	let state: UsageReportFields["license_state"];
	let updatesUntil: string | null = null;
	if (isRecord(facts.license)) {
		const terms = facts.license;
		const computed = stateAt(terms, now);
		if (!computed || typeof terms.license_id !== "string") return null;
		state = computed;
		licenseId = terms.license_id;
		customerId = typeof terms.customer_id === "string" ? terms.customer_id : null;
		updatesUntil = new Date(String(terms.grace_ends_at)).toISOString();
	} else if (isRecord(facts.admission) && facts.admission.kind === "licensed") {
		licenseId = typeof facts.admission.reference === "string" ? facts.admission.reference : null;
		state = "unverified";
	} else state = "unlicensed";
	return {
		format: USAGE_REPORT_FORMAT,
		customer_id: customerId,
		license_id: licenseId,
		generated_at: new Date(now).toISOString(),
		seats_licensed: facts.seats_licensed,
		devices_enrolled: facts.devices_enrolled,
		devices_active_30d: facts.devices_active_30d,
		license_state: state,
		updates_until: updatesUntil,
		deployment_version: deploymentVersion,
	};
}

export type UsageReport = UsageReportFields & { report_sha256: string };

export async function sealUsageReport(fields: UsageReportFields): Promise<UsageReport> {
	const ordered = Object.fromEntries(
		REPORT_FIELDS.map((key) => [key, fields[key]]),
	) as UsageReportFields;
	return { ...ordered, report_sha256: await sha256Hex(canonicalJson(ordered)) };
}

export async function fetchUsageReport(
	tenantId: string,
	now: number,
	deploymentVersion: string,
): Promise<UsageReport | null> {
	try {
		const { data, error } = await supabase.rpc("tenant_usage_report", { p_tenant_id: tenantId });
		if (error) return null;
		const fields = usageReportFields(data, now, deploymentVersion);
		return fields ? await sealUsageReport(fields) : null;
	} catch {
		return null;
	}
}
