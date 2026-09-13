export const FLEET_COMMAND_TYPES = [
	"agent_pause",
	"network_isolate",
] as const;
export type FleetCommandType = (typeof FLEET_COMMAND_TYPES)[number];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const RESULT_CODE = /^[a-z][a-z0-9_]{0,63}$/;

export function isUuid(value: unknown): value is string {
	return typeof value === "string" && UUID.test(value);
}

function parseCommon(body: Record<string, unknown>):
	| { ok: true; reason: string; idempotencyKey: string; ttlSeconds: number }
	| { ok: false; error: string } {
	const reason = typeof body.reason === "string" ? body.reason.trim() : "";
	if (reason.length < 12 || reason.length > 500) {
		return { ok: false, error: "invalid_reason" };
	}
	if (typeof body.idempotency_key !== "string" || !IDEMPOTENCY_KEY.test(body.idempotency_key)) {
		return { ok: false, error: "invalid_idempotency_key" };
	}
	const ttl = body.ttl_seconds === undefined ? 300 : body.ttl_seconds;
	if (!Number.isSafeInteger(ttl) || Number(ttl) < 30 || Number(ttl) > 3600) {
		return { ok: false, error: "invalid_ttl_seconds" };
	}
	return { ok: true, reason, idempotencyKey: body.idempotency_key, ttlSeconds: Number(ttl) };
}

export function parseQueueBody(body: Record<string, unknown>):
	| { ok: true; agentId: string; commandType: FleetCommandType; reason: string; idempotencyKey: string; ttlSeconds: number }
	| { ok: false; error: string } {
	if (!isUuid(body.agent_id)) return { ok: false, error: "invalid_agent_id" };
	if (!FLEET_COMMAND_TYPES.includes(body.command_type as FleetCommandType)) {
		return { ok: false, error: "invalid_command_type" };
	}
	const common = parseCommon(body);
	if (!common.ok) return common;
	return {
		agentId: body.agent_id,
		commandType: body.command_type as FleetCommandType,
		...common,
	};
}

export function parseRollbackBody(body: Record<string, unknown>):
	| { ok: true; rollbackOf: string; reason: string; idempotencyKey: string; ttlSeconds: number }
	| { ok: false; error: string } {
	if (!isUuid(body.rollback_of)) return { ok: false, error: "invalid_rollback_of" };
	// A rollback derives its target and reverse action from the original command;
	// callers must not be able to redirect either field.
	const common = parseCommon(body);
	if (!common.ok) return common;
	return {
		rollbackOf: body.rollback_of,
		...common,
	};
}

export function reverseCommandType(value: unknown): "agent_resume" | "network_release" | null {
	if (value === "agent_pause") return "agent_resume";
	if (value === "network_isolate") return "network_release";
	return null;
}

export function parseDeviceResult(body: Record<string, unknown>):
	| { ok: true; commandId: string; stage: "ack" | "result"; outcome: string; resultCode: string | null }
	| { ok: false; error: string } {
	const commandId = body.command_id;
	if (!isUuid(commandId)) return { ok: false, error: "invalid_command_id" };
	const stage = body.action;
	const outcome = body.outcome;
	if (stage !== "ack" && stage !== "result") return { ok: false, error: "invalid_stage" };
	if (typeof outcome !== "string") return { ok: false, error: "invalid_outcome" };
	if (stage === "ack" && outcome !== "accepted" && outcome !== "rejected") {
		return { ok: false, error: "invalid_outcome" };
	}
	if (stage === "result" && outcome !== "succeeded" && outcome !== "failed") {
		return { ok: false, error: "invalid_outcome" };
	}
	const code = body.result_code ?? null;
	if (code !== null && (typeof code !== "string" || !RESULT_CODE.test(code))) {
		return { ok: false, error: "invalid_result_code" };
	}
	if ((outcome === "rejected" || outcome === "failed") && code === null) {
		return { ok: false, error: "result_code_required" };
	}
	return { ok: true, commandId, stage, outcome, resultCode: code as string | null };
}

export function deviceCommandView(row: Record<string, unknown>) {
	return {
		id: row.id,
		command_type: row.command_type,
		expires_at: row.expires_at,
		attempt: row.attempts,
		rollback_of: row.rollback_of,
	};
}

export function effectiveCommandState(row: Record<string, unknown>, now = Date.now()): string {
	const state = String(row.state ?? "unknown");
	const expiry = typeof row.expires_at === "string" ? Date.parse(row.expires_at) : NaN;
	if (Number.isFinite(expiry) && expiry <= now) {
		if (state === "pending") return "expired";
		if (state === "delivered" || state === "acknowledged") return "outcome_unknown";
	}
	return state;
}

export function rpcStatus(code: string | undefined): number {
	if (code === "42501") return 403;
	if (code === "22023") return 400;
	if (code === "PT409" || code === "23505") return 409;
	return 503;
}
