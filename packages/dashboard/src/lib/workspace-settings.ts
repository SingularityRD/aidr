import { supabase } from "./supabase";

/** Client for the `tenant-settings` Edge Function. Every answer is validated. */

export interface WorkspaceSettings {
	workspace: {
		id: string;
		name: string;
		kind: string;
		status: string;
		retentionDays: number;
		createdAt: string;
	};
	role: string;
	canEdit: boolean;
	/**
	 * Retention is an owner-only decision (the service answers an admin's change
	 * with 403 `workspace_role_insufficient`). An older service that omits the
	 * flag is read as `false`: the control is hidden, never offered and refused.
	 */
	canEditRetention: boolean;
	canClose: boolean;
	retentionBounds: { min: number; max: number };
}

export type WorkspaceResult<T> = { ok: true; value: T } | { ok: false; error: string };

export interface WorkspaceClosure {
	runId: string;
	status: string;
	backupException: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The service's machine-readable error code, if the failed response carried one. */
export async function errorCode(error: unknown): Promise<string | null> {
	const context = (error as { context?: unknown } | null | undefined)?.context;
	if (!(context instanceof Response)) return null;
	try {
		const body: unknown = await context.clone().json();
		return isRecord(body) &&
			typeof body.error === "string" &&
			/^[a-z][a-z0-9_]{0,63}$/.test(body.error)
			? body.error
			: null;
	} catch {
		return null;
	}
}

function readWorkspace(value: unknown, tenantId: string): WorkspaceSettings["workspace"] | null {
	if (
		!isRecord(value) ||
		value.id !== tenantId ||
		typeof value.name !== "string" ||
		typeof value.kind !== "string" ||
		typeof value.status !== "string" ||
		!Number.isSafeInteger(value.retention_days) ||
		typeof value.created_at !== "string"
	)
		return null;
	return {
		id: value.id,
		name: value.name,
		kind: value.kind,
		status: value.status,
		retentionDays: value.retention_days as number,
		createdAt: value.created_at,
	};
}

export async function loadWorkspaceSettings(
	tenantId: string,
): Promise<WorkspaceResult<WorkspaceSettings>> {
	try {
		const { data, error } = await supabase.functions.invoke("tenant-settings", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": tenantId },
		});
		if (error) return { ok: false, error: (await errorCode(error)) ?? "workspace_unavailable" };
		const workspace =
			isRecord(data) && data.ok === true ? readWorkspace(data.workspace, tenantId) : null;
		const permissions = isRecord(data) ? data.permissions : null;
		const bounds = isRecord(data) ? data.retention_bounds : null;
		if (
			!workspace ||
			!isRecord(data) ||
			typeof data.role !== "string" ||
			!isRecord(permissions) ||
			typeof permissions.can_edit !== "boolean" ||
			typeof permissions.can_close !== "boolean" ||
			(permissions.can_edit_retention !== undefined &&
				typeof permissions.can_edit_retention !== "boolean") ||
			!isRecord(bounds) ||
			!Number.isSafeInteger(bounds.min) ||
			!Number.isSafeInteger(bounds.max) ||
			(bounds.min as number) < 1 ||
			(bounds.min as number) > (bounds.max as number)
		)
			return { ok: false, error: "workspace_unavailable" };
		return {
			ok: true,
			value: {
				workspace,
				role: data.role,
				canEdit: permissions.can_edit,
				canEditRetention: permissions.can_edit === true && permissions.can_edit_retention === true,
				canClose: permissions.can_close,
				retentionBounds: { min: bounds.min as number, max: bounds.max as number },
			},
		};
	} catch {
		return { ok: false, error: "workspace_unavailable" };
	}
}

export async function updateWorkspaceSettings(
	tenantId: string,
	changes: { name?: string; retentionDays?: number; confirmRetentionReduction?: boolean },
): Promise<WorkspaceResult<WorkspaceSettings["workspace"]>> {
	try {
		const { data, error } = await supabase.functions.invoke("tenant-settings", {
			method: "PATCH",
			body: {
				tenant_id: tenantId,
				action: "update",
				...(changes.name !== undefined ? { name: changes.name } : {}),
				...(changes.retentionDays !== undefined ? { retention_days: changes.retentionDays } : {}),
				...(changes.confirmRetentionReduction ? { confirm_retention_reduction: true } : {}),
			},
		});
		if (error) return { ok: false, error: (await errorCode(error)) ?? "workspace_update_failed" };
		const workspace =
			isRecord(data) && data.ok === true ? readWorkspace(data.workspace, tenantId) : null;
		return workspace
			? { ok: true, value: workspace }
			: { ok: false, error: "workspace_update_failed" };
	} catch {
		return { ok: false, error: "workspace_update_failed" };
	}
}

export async function closeWorkspace(
	tenantId: string,
	confirmName: string,
): Promise<WorkspaceResult<WorkspaceClosure>> {
	try {
		const { data, error } = await supabase.functions.invoke("tenant-settings", {
			method: "PATCH",
			body: { tenant_id: tenantId, action: "close", confirm_name: confirmName },
		});
		if (error) return { ok: false, error: (await errorCode(error)) ?? "workspace_closure_failed" };
		const closure = isRecord(data) && data.ok === true ? data.closure : null;
		if (
			!isRecord(closure) ||
			typeof closure.run_id !== "string" ||
			typeof closure.status !== "string"
		)
			return { ok: false, error: "workspace_closure_failed" };
		return {
			ok: true,
			value: {
				runId: closure.run_id,
				status: closure.status,
				backupException:
					typeof closure.backup_exception === "string" ? closure.backup_exception : null,
			},
		};
	} catch {
		return { ok: false, error: "workspace_closure_failed" };
	}
}

export interface SessionAssurance {
	currentLevel: "aal1" | "aal2";
	requireMfa: boolean;
}

/** MFA status for this session in the selected tenant (identity-security `status`). */
export async function loadSessionAssurance(
	tenantId: string,
): Promise<WorkspaceResult<SessionAssurance>> {
	try {
		const { data, error } = await supabase.functions.invoke("identity-security", {
			body: { action: "status", tenant_id: tenantId },
		});
		if (error) return { ok: false, error: "assurance_unavailable" };
		if (
			!isRecord(data) ||
			data.ok !== true ||
			(data.current_assurance !== "aal1" && data.current_assurance !== "aal2") ||
			typeof data.require_mfa !== "boolean"
		)
			return { ok: false, error: "assurance_unavailable" };
		return {
			ok: true,
			value: { currentLevel: data.current_assurance, requireMfa: data.require_mfa },
		};
	} catch {
		return { ok: false, error: "assurance_unavailable" };
	}
}
