import type { DashboardMessageKey } from "../i18n/en";
import { englishT, type Translate } from "../i18n/I18nProvider";
import { supabase } from "./supabase";

/**
 * Browser client for the `operator-admin` Edge Function (platform-operator console).
 *
 * The function is the only authority on who is an operator and whether the session
 * is at AAL2: it checks an active `platform_operators` row first (403 `forbidden`)
 * and the assurance level second (403 `mfa_required`). Nothing here infers either
 * from client state, and every response is shape-checked so a drifted or empty
 * body is reported as unavailable rather than rendered as data.
 */

export const OPERATOR_PAGE_SIZE = 25;
export const MAX_SEATS = 100_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const PLAN_ID = /^[a-z][a-z0-9_-]{0,31}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

interface OperatorAdmission {
	kind: string;
	planId: string | null;
	seats: number | null;
	expiresAt: string | null;
	active: boolean;
}

export interface OperatorTenant {
	id: string;
	/** Withheld (null) for personal workspaces, whose names derive from a person. */
	name: string | null;
	kind: string;
	status: string;
	createdAt: string;
	admission: OperatorAdmission | null;
}

export interface TenantPage {
	tenants: OperatorTenant[];
	nextCursor: string | null;
}

export interface TenantUsage {
	tenant: { id: string; kind: string; status: string; createdAt: string };
	admissionMode: string;
	admission: (OperatorAdmission & { startsAt: string | null; revokedAt: string | null }) | null;
	allowedAgents: number | null;
	agents: { enrolled: number; active7d: number };
	members: number;
}

export type OperatorCall<T> =
	| { ok: true; result: T }
	| { ok: false; status: number | null; code: string | null; reason?: string | null };

export type GrantLicenseInput = {
	tenant_id: string;
	plan_id: string;
	seats: number;
	expires_at: string;
	reference: string;
	owner_user_id?: string;
};

/** Caller-safe text for each documented error code. Unknown codes use a fixed fallback. */
const OPERATOR_ERRORS: Record<string, DashboardMessageKey> = {
	invalid_tenant: "op.err.tenant",
	invalid_plan: "op.err.plan",
	invalid_seats: "op.err.seats",
	invalid_expiry: "op.err.expiry",
	invalid_reference: "op.err.reference",
	invalid_owner: "op.err.owner",
	invalid_reason: "op.err.reason",
	invalid_page: "op.err.page",
	invalid_grant: "op.err.grant",
	owner_required: "op.err.ownerRequired",
	owner_not_eligible: "op.err.ownerNotEligible",
	tenant_closed: "op.err.closed",
	tenant_not_found: "op.err.notFound",
	admission_operator_required: "op.err.admissionOperator",
	admission_mode_not_licensed: "op.err.admissionMode",
	operator_action_unavailable: "op.err.unavailable",
	authorization_unavailable: "op.err.authorization",
	assurance_unavailable: "op.err.assurance",
	payload_too_large: "op.err.tooLarge",
	invalid_json: "op.err.rejected",
	invalid_action: "op.err.rejected",
	origin_not_allowed: "op.err.origin",
	invalid_license: "op.err.license",
	license_expired: "op.err.licenseExpired",
	license_not_yet_valid: "op.err.licenseNotYetValid",
	license_import_not_pending: "op.err.licenseNotPending",
	license_import_mismatch: "op.err.licenseMismatch",
	license_bound_to_other_tenant: "op.err.licenseOtherTenant",
	license_registry_unavailable: "op.err.licenseRegistry",
	license_registry_empty: "op.err.licenseRegistry",
	license_registry_invalid: "op.err.licenseRegistry",
};

export function operatorErrorMessage(
	code: string | null,
	fallback: string,
	t: Translate = englishT,
): string {
	const key = code && Object.hasOwn(OPERATOR_ERRORS, code) ? OPERATOR_ERRORS[code] : undefined;
	return key ? t(key, { max: MAX_SEATS.toLocaleString("en-US") }) : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
const isDate = (value: unknown): value is string =>
	typeof value === "string" && Number.isFinite(Date.parse(value));
const optionalDate = (value: unknown): string | null | undefined =>
	value === null ? null : isDate(value) ? value : undefined;
const count = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

export function isUuid(value: string): boolean {
	return UUID.test(value);
}

/** Mirrors the server's single-line reference bound (trimmed 1–200, no control characters). */
export function validReference(value: string): boolean {
	const trimmed = value.trim();
	return trimmed.length >= 1 && trimmed.length <= 200 && !CONTROL.test(value);
}

function parseAdmission(value: unknown): OperatorAdmission | null | undefined {
	if (value === null) return null;
	if (!isRecord(value) || typeof value.kind !== "string" || typeof value.active !== "boolean")
		return undefined;
	const expiresAt = optionalDate(value.expires_at ?? null);
	if (expiresAt === undefined) return undefined;
	if (value.seats !== null && value.seats !== undefined && !count(value.seats)) return undefined;
	return {
		kind: value.kind,
		planId: typeof value.plan_id === "string" ? value.plan_id : null,
		seats: count(value.seats) ? value.seats : null,
		expiresAt,
		active: value.active,
	};
}

function parseTenant(value: unknown): OperatorTenant | null {
	if (!isRecord(value) || typeof value.id !== "string" || !UUID.test(value.id)) return null;
	if (typeof value.kind !== "string" || typeof value.status !== "string") return null;
	if (!isDate(value.created_at)) return null;
	if (value.name !== null && typeof value.name !== "string") return null;
	const admission = parseAdmission(value.admission ?? null);
	if (admission === undefined) return null;
	return {
		id: value.id.toLowerCase(),
		name: value.name,
		kind: value.kind,
		status: value.status,
		createdAt: value.created_at,
		admission,
	};
}

export function parseTenantPage(value: unknown): TenantPage | null {
	if (!isRecord(value) || !Array.isArray(value.tenants)) return null;
	const tenants = value.tenants.map(parseTenant);
	if (tenants.some((tenant) => tenant === null)) return null;
	const next = value.next_cursor;
	if (next !== null && (typeof next !== "string" || !UUID.test(next))) return null;
	return { tenants: tenants as OperatorTenant[], nextCursor: next };
}

export function parseTenantUsage(value: unknown, tenantId: string): TenantUsage | null {
	if (!isRecord(value) || !isRecord(value.tenant) || !isRecord(value.agents)) return null;
	const tenant = value.tenant;
	if (typeof tenant.id !== "string" || tenant.id.toLowerCase() !== tenantId) return null;
	if (typeof tenant.kind !== "string" || typeof tenant.status !== "string") return null;
	if (!isDate(tenant.created_at) || typeof value.admission_mode !== "string") return null;
	if (!count(value.agents.enrolled) || !count(value.agents.active_7d) || !count(value.members))
		return null;
	if (value.allowed_agents !== null && !count(value.allowed_agents)) return null;
	const base = parseAdmission(value.admission ?? null);
	if (base === undefined) return null;
	let admission: TenantUsage["admission"] = null;
	if (base && isRecord(value.admission)) {
		const startsAt = optionalDate(value.admission.starts_at ?? null);
		const revokedAt = optionalDate(value.admission.revoked_at ?? null);
		if (startsAt === undefined || revokedAt === undefined) return null;
		admission = { ...base, startsAt, revokedAt };
	}
	return {
		tenant: {
			id: tenantId,
			kind: tenant.kind,
			status: tenant.status,
			createdAt: tenant.created_at,
		},
		admissionMode: value.admission_mode,
		admission,
		allowedAgents: count(value.allowed_agents) ? value.allowed_agents : null,
		agents: { enrolled: value.agents.enrolled, active7d: value.agents.active_7d },
		members: value.members,
	};
}

async function errorBody(
	error: unknown,
): Promise<{ status: number | null; code: string | null; reason?: string | null }> {
	if (isRecord(error) && error.context instanceof Response) {
		const status = error.context.status;
		try {
			const body: unknown = await error.context.clone().json();
			return {
				status,
				code: isRecord(body) && typeof body.error === "string" ? body.error : null,
				...(isRecord(body) && typeof body.reason === "string" ? { reason: body.reason } : {}),
			};
		} catch {
			return { status, code: null };
		}
	}
	return { status: null, code: null };
}

/**
 * POST one action. The access token is passed explicitly so a response is always
 * bound to the session snapshot the console was rendered for.
 */
export async function callOperatorAdmin(
	accessToken: string,
	body: Record<string, unknown>,
): Promise<OperatorCall<Record<string, unknown>>> {
	try {
		const { data, error } = await supabase.functions.invoke<unknown>("operator-admin", {
			body,
			headers: { Authorization: `Bearer ${accessToken}` },
		});
		if (error) return { ok: false, ...(await errorBody(error)) };
		if (
			!isRecord(data) ||
			data.ok !== true ||
			data.action !== body.action ||
			!isRecord(data.result)
		) {
			return {
				ok: false,
				status: null,
				code:
					isRecord(data) && typeof data.error === "string"
						? data.error
						: "operator_action_unavailable",
			};
		}
		return { ok: true, result: data.result };
	} catch {
		return { ok: false, status: null, code: null };
	}
}

/** A licence a workspace admin verified and staged; the operator applies it. */
export interface PendingLicenseImport {
	id: string;
	tenantId: string;
	licenseId: string;
	seats: number;
	planId: string;
	expiresAt: string;
	graceEndsAt: string;
	submittedAt: string;
	/** The signed document, sent back unchanged so operator-admin re-verifies it. */
	document: Record<string, unknown>;
}

export function parseLicenseImports(value: unknown): PendingLicenseImport[] | null {
	if (!isRecord(value) || !Array.isArray(value.imports)) return null;
	const rows: PendingLicenseImport[] = [];
	for (const row of value.imports) {
		if (
			!isRecord(row) ||
			typeof row.id !== "string" ||
			!UUID.test(row.id) ||
			typeof row.tenant_id !== "string" ||
			!UUID.test(row.tenant_id) ||
			typeof row.license_id !== "string" ||
			!count(row.seats) ||
			typeof row.plan_id !== "string" ||
			!isDate(row.expires_at) ||
			!isDate(row.grace_ends_at) ||
			!isDate(row.submitted_at) ||
			!isRecord(row.document)
		)
			return null;
		rows.push({
			id: row.id.toLowerCase(),
			tenantId: row.tenant_id.toLowerCase(),
			licenseId: row.license_id,
			seats: row.seats,
			planId: row.plan_id,
			expiresAt: row.expires_at,
			graceEndsAt: row.grace_ends_at,
			submittedAt: row.submitted_at,
			document: row.document,
		});
	}
	return rows;
}

/** The applied import an `apply_license` result must carry. */
export function appliedLicense(
	value: unknown,
): { licenseId: string; seats: number; graceEndsAt: string } | null {
	if (!isRecord(value) || value.status !== "granted" || !isRecord(value.import)) return null;
	const row = value.import;
	if (
		row.status !== "applied" ||
		typeof row.license_id !== "string" ||
		!count(row.seats) ||
		!isDate(row.grace_ends_at)
	)
		return null;
	return { licenseId: row.license_id, seats: row.seats, graceEndsAt: row.grace_ends_at };
}
