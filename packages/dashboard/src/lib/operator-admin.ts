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
	| { ok: false; status: number | null; code: string | null };

export type GrantLicenseInput = {
	tenant_id: string;
	plan_id: string;
	seats: number;
	expires_at: string;
	reference: string;
	owner_user_id?: string;
};

/** Caller-safe text for each documented error code. Unknown codes use a fixed fallback. */
const OPERATOR_ERRORS: Record<string, string> = {
	invalid_tenant: "That tenant id is not valid.",
	invalid_plan: "That plan id is not an active plan.",
	invalid_seats: `Seats must be a whole number from 1 to ${MAX_SEATS.toLocaleString("en-US")}.`,
	invalid_expiry: "The expiry must be a future date and time.",
	invalid_reference: "Enter a single-line reference of up to 200 characters.",
	invalid_owner: "The owner must be a user id (UUID).",
	invalid_reason: "Enter a single-line reason of up to 200 characters.",
	invalid_page: "The page cursor was rejected. Reload the tenant list.",
	invalid_grant: "The licence grant was rejected. Check each field.",
	owner_required:
		"This tenant has more than one owner (or none). Enter the owner user id to grant the licence to.",
	owner_not_eligible: "That user is not a current owner of an active tenant.",
	tenant_closed: "The tenant is not active, so it cannot be licensed.",
	tenant_not_found: "No tenant has that id.",
	admission_operator_required:
		"You are not an admission operator for this tenant (or you are a member of it). Licences need a separate, unexpired admission-operator grant.",
	admission_mode_not_licensed:
		"Licensed grants need the deployment admission mode set to cloud or onprem.",
	operator_action_unavailable:
		"The operator service did not confirm this action. Nothing is shown as done; check the logs and retry.",
	authorization_unavailable: "Operator authorization could not be checked. Retry shortly.",
	assurance_unavailable: "The session assurance level could not be checked. Retry shortly.",
	payload_too_large: "The request was too large.",
	invalid_json: "The request was rejected.",
	invalid_action: "The request was rejected.",
	origin_not_allowed:
		"This dashboard origin is not allowed to call the operator service (AIDR_ALLOWED_ORIGINS).",
};

export function operatorErrorMessage(code: string | null, fallback: string): string {
	return (code && OPERATOR_ERRORS[code]) ?? fallback;
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

async function errorBody(error: unknown): Promise<{ status: number | null; code: string | null }> {
	if (isRecord(error) && error.context instanceof Response) {
		const status = error.context.status;
		try {
			const body: unknown = await error.context.clone().json();
			return { status, code: isRecord(body) && typeof body.error === "string" ? body.error : null };
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
