import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	deviceCommandView,
	effectiveCommandState,
	parseDeviceResult,
	parseQueueBody,
	parseRollbackBody,
	reverseCommandType,
	rpcStatus,
} from "../commands.ts";

const agent = "11111111-1111-4111-8111-111111111111";
const command = "22222222-2222-4222-8222-222222222222";
const key = "customer-incident-2026-09-12";

describe("fleet response input contracts", () => {
	it("accepts bounded declarative commands only", () => {
		expect(parseQueueBody({
			agent_id: agent, command_type: "network_isolate",
			reason: "Confirmed exfiltration attempt", idempotency_key: key,
		})).toEqual({
			ok: true, agentId: agent, commandType: "network_isolate",
			reason: "Confirmed exfiltration attempt", idempotencyKey: key, ttlSeconds: 300,
		});
		for (const invalid of [
			{ command_type: "shell_exec" }, { command_type: "credential_revoke" },
			{ reason: "short" }, { ttl_seconds: 29 }, { ttl_seconds: 3601 },
			{ idempotency_key: "short" }, { agent_id: "../another-tenant" },
		]) {
			expect(parseQueueBody({
				agent_id: agent, command_type: "agent_pause",
				reason: "Incident response action", idempotency_key: key,
				...invalid,
			}).ok).toBe(false);
		}
	});

	it("derives rollback action and target from the original command", () => {
		expect(reverseCommandType("agent_pause")).toBe("agent_resume");
		expect(reverseCommandType("network_isolate")).toBe("network_release");
		expect(reverseCommandType("process_terminate")).toBeNull();
		expect(parseRollbackBody({
			rollback_of: command, reason: "Containment no longer required",
			idempotency_key: "rollback-incident-2026-09-12",
		})).toMatchObject({ ok: true, rollbackOf: command, ttlSeconds: 300 });
		expect(parseRollbackBody({ rollback_of: "other", reason: "Valid long reason", idempotency_key: key }).ok).toBe(false);
	});

	it("bounds device outcomes to a status and code, not arbitrary execution output", () => {
		expect(parseDeviceResult({
			action: "ack", command_id: command, outcome: "accepted",
		})).toMatchObject({ ok: true, stage: "ack" });
		expect(parseDeviceResult({
			action: "result", command_id: command, outcome: "failed",
			result_code: "os_permission_denied",
		})).toMatchObject({ ok: true, resultCode: "os_permission_denied" });
		for (const bad of [
			{ action: "ack", outcome: "executed" },
			{ action: "result", outcome: "failed" },
			{ action: "result", outcome: "succeeded", result_code: "contains secret text" },
			{ action: "result", outcome: "succeeded", command_id: "another-agent" },
		]) {
			expect(parseDeviceResult({ command_id: command, ...bad }).ok).toBe(false);
		}
		expect(deviceCommandView({
			id: command, command_type: "agent_pause", expires_at: "2030-01-01",
			attempts: 2, rollback_of: null, reason: "Sensitive incident context",
			actor_user_id: agent,
		})).not.toHaveProperty("reason");
		expect(effectiveCommandState({ state: "pending", expires_at: "2026-01-01" },
			Date.parse("2026-02-01"))).toBe("expired");
		expect(effectiveCommandState({ state: "delivered", expires_at: "2026-01-01" },
			Date.parse("2026-02-01"))).toBe("outcome_unknown");
		expect(effectiveCommandState({ state: "succeeded", expires_at: "2026-01-01" },
			Date.parse("2026-02-01"))).toBe("succeeded");
	});

	it("maps only explicit database denial and conflict codes to client responses", () => {
		expect(rpcStatus("42501")).toBe(403);
		expect(rpcStatus("22023")).toBe(400);
		expect(rpcStatus("PT409")).toBe(409);
		expect(rpcStatus("23505")).toBe(409);
		expect(rpcStatus("XX000")).toBe(503);
	});
});

describe("fleet response database and Edge wiring", () => {
	const functions = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
	const source = readFileSync(resolve(functions, "revocations/index.ts"), "utf8");
	const attestationSource = readFileSync(resolve(functions, "revocations/attestation.ts"), "utf8");
	const migration = readFileSync(resolve(functions, "../migrations/20260912000016_fleet_response_commands.sql"), "utf8");
	const offboarding = readFileSync(resolve(functions, "../migrations/20260912140002_fleet_response_offboarding.sql"), "utf8");

	it("requires an agent-bound installation/key attestation before command RPCs", () => {
		expect(source).toContain("deviceAttestationError(values.device_attestation, identity)");
		expect(attestationSource).toContain("device_attestation_required");
		expect(source.indexOf("deviceAttestationError(values.device_attestation, identity)")).toBeLessThan(
			source.indexOf('db.rpc("poll_fleet_response_command"'),
	);
	});

	it("requires operator step-up and a service-side session barrier", () => {
		expect(source).toContain("checkIdentityBarrier(db, accessToken, auth.user.id, tenantId)");
		expect(source).toContain('assurance.currentLevel !== "aal2"');
		expect(source).toContain('!["owner", "admin"].includes');
		expect(source).toContain("agent_bound_key_required");
		expect(source).toContain("consumeTenantRateLimit");
	});

	it("keeps queue transitions atomic and commands tenant/agent scoped", () => {
		expect(migration).toContain("where a.id=p_agent_id and a.tenant_id=p_tenant_id");
		expect(migration).toContain("v_original.state <> 'succeeded'");
		expect(migration).not.toContain("foreign key(agent_id, tenant_id)");
		expect(migration).toContain("unique(tenant_id, idempotency_key)");
		expect(migration).toContain("pg_advisory_xact_lock");
		expect(migration).toContain("for update skip locked limit 1");
		expect(migration).toContain("delivery_lease_until");
		expect(migration).toContain("'outcome_unknown'");
		expect(migration).toContain("rollback_already_requested");
		expect(migration).toContain("v_original.state <> 'succeeded'");
		expect(migration).toContain("k.key_hash=p_key_hash and not k.revoked");
		expect(migration).toContain("alter table public.fleet_response_commands enable row level security");
		expect(migration).toContain("revoke all on public.fleet_response_commands from public, anon, authenticated");
		expect(migration).toContain("fleet.response.queued");
	});

	it("retains command evidence through endpoint deletion and schedules its own legal-hold-aware receipt", () => {
		expect(migration).not.toContain("foreign key(agent_id, tenant_id)");
		expect(offboarding).toContain("'fleet_response_commands','security_audit','delete_records'");
		expect(offboarding).toContain("tenant_offboarding_fleet_response_phase");
		expect(offboarding).toContain("r.status<>'completed'");
		expect(offboarding).toContain("run_tenant_offboarding_batch");
	});
});
