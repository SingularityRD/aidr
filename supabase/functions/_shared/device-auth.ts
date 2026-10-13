export interface DevicePollStateInput {
	nowMs: number;
	expiresAtIso: string;
	authorizedAt: string | null;
	userId: string | null;
	pilotApproved: boolean;
	exchangedAt: string | null;
}

export type DevicePollState =
	| { status: "expired"; httpStatus: 401; error: "device_code_expired" }
	| {
			status: "pending";
			httpStatus: 200;
			error: "authorization_pending";
	  }
	| { status: "forbidden"; httpStatus: 403; error: "pilot_not_approved" }
	| { status: "already_exchanged"; httpStatus: 409; error: "already_exchanged" }
	| { status: "approved"; httpStatus: 200 };

export function evaluateDevicePollState(input: DevicePollStateInput): DevicePollState {
	if (input.nowMs > Date.parse(input.expiresAtIso)) {
		return { status: "expired", httpStatus: 401, error: "device_code_expired" };
	}
	if (!input.authorizedAt || !input.userId) {
		return { status: "pending", httpStatus: 200, error: "authorization_pending" };
	}
	if (!input.pilotApproved) {
		return { status: "forbidden", httpStatus: 403, error: "pilot_not_approved" };
	}
	if (input.exchangedAt) {
		return { status: "already_exchanged", httpStatus: 409, error: "already_exchanged" };
	}
	return { status: "approved", httpStatus: 200 };
}

export interface DeviceVerifyStateInput {
	nowMs: number;
	expiresAtIso: string;
	authorizedAt: string | null;
	pilotApproved: boolean;
}

export type DeviceVerifyState =
	| { status: "expired"; httpStatus: 400; error: "device_code_expired" }
	| { status: "forbidden"; httpStatus: 403; error: "pilot_not_approved" }
	| { status: "already_authorized"; httpStatus: 409; error: "device_code_already_authorized" }
	| { status: "ok"; httpStatus: 200 };

export function evaluateDeviceVerifyState(input: DeviceVerifyStateInput): DeviceVerifyState {
	if (input.nowMs > Date.parse(input.expiresAtIso)) {
		return { status: "expired", httpStatus: 400, error: "device_code_expired" };
	}
	if (!input.pilotApproved) {
		return { status: "forbidden", httpStatus: 403, error: "pilot_not_approved" };
	}
	if (input.authorizedAt) {
		return { status: "already_authorized", httpStatus: 409, error: "device_code_already_authorized" };
	}
	return { status: "ok", httpStatus: 200 };
}

// ── Remote-phishing hardening (CP-1, RFC 8628 §5.4) ─────────────────────────
//
// device-start records who asked for the code (the trusted-ingress attested IP,
// what the device reported about itself, the requested access and the time),
// /verify shows it before anything is bound, and device-verify only binds a
// session the browser looked up first and the user explicitly confirmed.

/** The only access a device enrollment can request today: a tenant API key. */
export const DEVICE_REQUESTED_SCOPE = "tenant";
export const DEFAULT_DEVICE_TTL_MINUTES = 10;
/** Upper bound for the code lifetime: a phished link stops working quickly. */
export const MAX_DEVICE_TTL_MINUTES = 15;

export type DeviceRequesterContext = {
	runtime: string | null;
	runtime_version: string | null;
	os: string | null;
	hostname: string | null;
};

// Printable, no control/format characters, bounded. Device-reported values are
// displayed as "reported by the device", never trusted for authorization.
function reportedText(value: unknown, max: number, pattern = /^[\p{L}\p{N} ._:()+/@-]+$/u): string | null {
	if (typeof value !== "string") return null;
	const text = value.trim();
	return text.length >= 1 && [...text].length <= max && pattern.test(text) ? text : null;
}

/** What the starting device says about itself; malformed fields are dropped. */
export function parseDeviceStartContext(body: unknown): DeviceRequesterContext {
	const value = body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
	return {
		runtime: reportedText(value.agent_runtime, 32, /^[a-z0-9][a-z0-9_.-]*$/),
		runtime_version: reportedText(value.agent_runtime_version, 64),
		os: reportedText(value.os, 32),
		hostname: reportedText(value.hostname, 64, /^[A-Za-z0-9][A-Za-z0-9._-]*$/),
	};
}

/** Code lifetime in minutes (default 10, 1..15); null when malformed. */
export function deviceTtlMinutes(raw: string | null | undefined): number | null {
	if (raw === undefined || raw === null) return DEFAULT_DEVICE_TTL_MINUTES;
	if (!/^\d{1,3}$/.test(raw.trim())) return null;
	const minutes = Number(raw.trim());
	return minutes >= 1 && minutes <= MAX_DEVICE_TTL_MINUTES ? minutes : null;
}

/** "true"/"false" switch; unset is false, anything else is a misconfiguration. */
export function booleanSetting(raw: string | null | undefined): boolean | null {
	if (raw === undefined || raw === null || raw.trim() === "") return false;
	const value = raw.trim().toLowerCase();
	return value === "true" ? true : value === "false" ? false : null;
}

export type DeviceVerifyCommand =
	| { action: "lookup"; userCode: string }
	| { action: "authorize"; userCode: string; deviceSessionId: string };

const USER_CODE = /^[A-Z0-9]{8}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Canonical user code: upper-case, separators removed (ABCD-EFGH == abcdefgh). */
export function normalizeUserCode(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const code = value.replace(/[\s-]/g, "").toUpperCase();
	return USER_CODE.test(code) ? code : null;
}

/**
 * `lookup` returns the device details without binding anything. `authorize`
 * must name the session the lookup returned and carry an explicit
 * confirmation, so a link-prefilled code can never be bound in one request.
 */
export function parseDeviceVerifyCommand(
	body: Record<string, unknown>,
): { ok: true; command: DeviceVerifyCommand } | { ok: false; status: 400; error: string } {
	if (body.user_code === undefined || body.user_code === null || body.user_code === "") {
		return { ok: false, status: 400, error: "missing_user_code" };
	}
	const userCode = normalizeUserCode(body.user_code);
	if (!userCode) return { ok: false, status: 400, error: "device_code_invalid" };
	const action = body.action ?? "authorize";
	if (action === "lookup") return { ok: true, command: { action, userCode } };
	if (action !== "authorize") return { ok: false, status: 400, error: "invalid_action" };
	if (body.confirmed !== true || typeof body.device_session_id !== "string" || !UUID.test(body.device_session_id)) {
		return { ok: false, status: 400, error: "device_confirmation_required" };
	}
	return { ok: true, command: { action, userCode, deviceSessionId: body.device_session_id.toLowerCase() } };
}

export type DeviceSessionDetailsRow = {
	id: string;
	user_code: string;
	created_at: string;
	expires_at: string;
	requested_ip?: string | null;
	requested_runtime?: string | null;
	requested_runtime_version?: string | null;
	requested_os?: string | null;
	requested_hostname?: string | null;
	requested_scope?: string | null;
};

/** What /verify shows before the user decides. */
export function deviceSessionDetails(row: DeviceSessionDetailsRow): Record<string, unknown> {
	return {
		device_session_id: row.id,
		user_code: row.user_code,
		requested_at: row.created_at,
		expires_at: row.expires_at,
		requester_ip: row.requested_ip ?? null,
		runtime: row.requested_runtime ?? null,
		runtime_version: row.requested_runtime_version ?? null,
		os: row.requested_os ?? null,
		hostname: row.requested_hostname ?? null,
		requested_scope: row.requested_scope ?? DEVICE_REQUESTED_SCOPE,
	};
}
