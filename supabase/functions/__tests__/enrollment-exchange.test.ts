import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { entitlementWindow, validateEnrollmentBody } from "../enroll/contract.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const sql = readFileSync(join(ROOT, "supabase", "migrations", "20260912000017_enrollment_exchange_atomic.sql"), "utf8");
const enrollSource = readFileSync(join(ROOT, "supabase", "functions", "enroll", "index.ts"), "utf8");
const pollSource = readFileSync(join(ROOT, "supabase", "functions", "device-poll", "index.ts"), "utf8");

describe("bounded enrollment contract", () => {
	it("rejects oversized, malformed and control-character identities before issuing a key", () => {
		expect(validateEnrollmentBody({ iid: " iid-1 ", agent_runtime: "claude" })).toEqual({
			iid: "iid-1", agent_runtime: "claude", agent_runtime_version: null,
		});
		for (const body of [null, [], {}, { iid: " " }, { iid: "x".repeat(129) },
			{ iid: "one\ntwo" }, { iid: "valid", agent_runtime: "x".repeat(129) },
			{ iid: "valid", agent_runtime_version: 7 }]) {
			expect(validateEnrollmentBody(body)).toBeNull();
		}
	});

	it("places 72-hour grace after 168-hour validity and bounds operator config", () => {
		const at = new Date("2026-09-12T00:00:00.000Z");
		expect(entitlementWindow(at, "168", "72")).toEqual({
			issuedAt: "2026-09-12T00:00:00.000Z",
			expiresAt: "2026-09-19T00:00:00.000Z",
			graceUntil: "2026-09-22T00:00:00.000Z",
		});
		for (const [ttl, grace] of [["0", "72"], ["721", "72"], ["168", "169"],
			["NaN", "72"], ["168.5", "72"], ["", "72"]]) {
			expect(entitlementWindow(at, ttl, grace)).toBeNull();
		}
	});
});

describe("atomic one-time exchanges", () => {
	it("commits API-key hash and token consumption in one restricted RPC", () => {
		const exchange = sql.split("create function public.exchange_enrollment_token(")[1]?.split("\nend;\n$$;")[0] ?? "";
		expect(exchange).toContain("for update;");
		expect(exchange).toContain("public.register_agent_for_ingest(");
		expect(exchange).toContain("if v_agent.seat_exceeded then");
		expect(exchange.indexOf("insert into public.api_keys")).toBeGreaterThan(0);
		expect(exchange.indexOf("update public.enrollment_tokens set consumed_at")).toBeGreaterThan(exchange.indexOf("insert into public.api_keys"));
		expect(sql).toContain("grant execute on function public.exchange_enrollment_token(text, text, text, text, text) to service_role");
		expect(enrollSource).toContain('supabase.rpc("exchange_enrollment_token"');
		expect(enrollSource).not.toContain('supabase.rpc("consume_enrollment_token"');
		expect(enrollSource).toContain("readBoundedJson(req, MAX_ENROLL_BODY_BYTES)");
	});

	it("persists the device enrollment token before consuming the session", () => {
		const exchange = sql.split("create function public.issue_device_enrollment_token(")[1]?.split("\nend;\n$$;")[0] ?? "";
		expect(exchange).toContain("for update;");
		expect(exchange.indexOf("insert into public.enrollment_tokens")).toBeGreaterThan(0);
		expect(exchange.indexOf("update public.device_sessions set exchanged_at")).toBeGreaterThan(exchange.indexOf("insert into public.enrollment_tokens"));
		expect(sql).toContain("grant execute on function public.issue_device_enrollment_token(text, text, timestamptz) to service_role");
		expect(pollSource).toContain('supabase.rpc("issue_device_enrollment_token"');
		expect(pollSource).not.toContain('supabase.rpc(\n\t\t"exchange_device_session"');
	});
});
