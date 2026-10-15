import type { DashboardMessageKey } from "../i18n/en";
import { supabase } from "./supabase";

/**
 * Browser client for the `agent-lifecycle` Edge Function (seat lifecycle).
 *
 * Retiring an agent frees its seat and revokes the device key the enrollment
 * issued; local detection on the device keeps enforcing. The function is the
 * only authority on role (owner/admin) and step-up (AAL2); nothing here infers
 * either from client state.
 */

export const AUTO_RETIRE_MIN_DAYS = 7;
export const AUTO_RETIRE_MAX_DAYS = 365;

export type LifecycleResult<T> = { ok: true; value: T } | { ok: false; code: string | null };

const LIFECYCLE_ERRORS: Record<string, DashboardMessageKey> = {
	workspace_role_insufficient: "agents.retire.err.role",
	workspace_forbidden: "agents.retire.err.role",
	mfa_required: "agents.retire.err.mfa",
	agent_not_found: "agents.retire.err.notFound",
	invalid_days: "agents.autoRetire.err.days",
	rate_limited: "agents.retire.err.rateLimited",
};

/** Message key for a documented error code; unknown codes use the generic failure. */
export function lifecycleErrorKey(code: string | null): DashboardMessageKey {
	return (
		(code && Object.hasOwn(LIFECYCLE_ERRORS, code) && LIFECYCLE_ERRORS[code]) ||
		"agents.retire.err.unavailable"
	);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

/** The `error` code an Edge Function returned with a non-2xx status, if any. */
export async function edgeErrorCode(error: unknown): Promise<string | null> {
	if (isRecord(error) && error.context instanceof Response) {
		try {
			const body: unknown = await error.context.clone().json();
			return isRecord(body) && typeof body.error === "string" ? body.error : null;
		} catch {
			return null;
		}
	}
	return null;
}

async function invoke(
	body: Record<string, unknown>,
): Promise<LifecycleResult<Record<string, unknown>>> {
	try {
		const { data, error } = await supabase.functions.invoke<unknown>("agent-lifecycle", { body });
		if (error) return { ok: false, code: await edgeErrorCode(error) };
		if (!isRecord(data) || data.ok !== true) return { ok: false, code: null };
		return { ok: true, value: data };
	} catch {
		return { ok: false, code: null };
	}
}

export async function retireAgent(
	tenantId: string,
	agentId: string,
	note?: string,
): Promise<LifecycleResult<{ status: "retired" | "already_retired"; revokedKeys: number }>> {
	const result = await invoke({
		action: "retire",
		tenant_id: tenantId,
		agent_id: agentId,
		...(note?.trim() ? { note: note.trim() } : {}),
	});
	if (!result.ok) return result;
	const { status, agent_id: returned, revoked_keys: revoked } = result.value;
	if ((status !== "retired" && status !== "already_retired") || returned !== agentId) {
		return { ok: false, code: null };
	}
	return {
		ok: true,
		value: {
			status,
			revokedKeys: typeof revoked === "number" && Number.isSafeInteger(revoked) ? revoked : 0,
		},
	};
}

export function validAutoRetireDays(value: number | null): boolean {
	return (
		value === null ||
		(Number.isSafeInteger(value) && value >= AUTO_RETIRE_MIN_DAYS && value <= AUTO_RETIRE_MAX_DAYS)
	);
}

export async function setAutoRetire(
	tenantId: string,
	days: number | null,
): Promise<LifecycleResult<number | null>> {
	if (!validAutoRetireDays(days)) return { ok: false, code: "invalid_days" };
	const result = await invoke({ action: "set_auto_retire", tenant_id: tenantId, days });
	if (!result.ok) return result;
	if (result.value.auto_retire_offline_days !== days) return { ok: false, code: null };
	return { ok: true, value: days };
}

/** The tenant's auto-retirement period (RLS: active members read it). null = off. */
export async function readAutoRetireDays(
	tenantId: string,
): Promise<LifecycleResult<number | null>> {
	try {
		const { data, error } = await supabase
			.from("agent_retirement_settings")
			.select("auto_retire_offline_days")
			.eq("tenant_id", tenantId)
			.maybeSingle();
		if (error) return { ok: false, code: null };
		const days =
			(data as { auto_retire_offline_days?: unknown } | null)?.auto_retire_offline_days ?? null;
		if (days !== null && (typeof days !== "number" || !validAutoRetireDays(days))) {
			return { ok: false, code: null };
		}
		return { ok: true, value: days };
	} catch {
		return { ok: false, code: null };
	}
}
