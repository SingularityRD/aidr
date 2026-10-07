// Static contract for 20261007000200_detection_exceptions.sql (Docker/Postgres
// is not available to this suite; the SQL text itself is pinned here).
//
// Pins: the table is private (RLS, no browser grant, restrictive identity
// barrier), the 30-day window and the self-defense ban are database
// constraints, writes are only service-role SECURITY DEFINER RPCs with an
// explicit pg_temp search_path that re-check owner/admin and audit every change,
// and the connector feed returns only unexpired, unrevoked exceptions for the
// requesting principal with a forward-only change high-water mark.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { maskNonExecutableSql } from "../../../scripts/lib/migration-contract.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SQL = readFileSync(join(ROOT, "supabase", "migrations", "20261007000200_detection_exceptions.sql"), "utf8");
const compact = (text: string) => text.replace(/\s+/g, " ").toLowerCase();
const ALL = compact(SQL);
/** Executable SQL only (comments and string bodies masked), for grant checks. */
const EXECUTABLE = compact(maskNonExecutableSql(SQL).masked);

function functionBody(name: string): string {
	const start = SQL.indexOf(`create or replace function ${name}(`);
	expect(start, `${name} is defined`).toBeGreaterThanOrEqual(0);
	const end = SQL.indexOf("\n$$;", start);
	return compact(SQL.slice(start, end));
}

describe("detection exceptions migration", () => {
	it("is the only migration for this feature", () => {
		const migrations = readdirSync(join(ROOT, "supabase", "migrations"))
			.filter((name) => name.endsWith(".sql"))
			.sort();
		expect(migrations.filter((name) => name.includes("detection_exception"))).toEqual([
			"20261007000200_detection_exceptions.sql",
		]);
	});

	it("keeps both tables private behind RLS and the identity barrier", () => {
		for (const table of ["detection_exceptions", "detection_exception_tenant_state"]) {
			expect(EXECUTABLE).toContain(`alter table public.${table} enable row level security`);
			expect(EXECUTABLE).toContain(`revoke all on public.${table} from public, anon, authenticated, service_role`);
			expect(EXECUTABLE).toContain(
				`create policy tenant_identity_access_restrict on public.${table} as restrictive for all to authenticated using (public.tenant_identity_access_allowed(tenant_id))`,
			);
			expect(EXECUTABLE).not.toMatch(new RegExp(`grant [a-z, ]+ on public\\.${table} to [a-z_, ]*\\b(anon|authenticated)\\b`));
		}
		expect(EXECUTABLE).toContain("grant select on public.detection_exceptions to service_role");
	});

	it("enforces the bounded window, the self-defense ban and the subject shape as constraints", () => {
		expect(ALL).toContain("check (expires_at > created_at and expires_at <= created_at + interval '30 days')");
		expect(ALL).toContain("check (upper(rule_id) not like 'clt-self-%' and upper(rule_id) not like 'clt-canary-%')");
		expect(ALL).toContain("expires_at timestamptz not null");
		expect(ALL).toContain("constraint detection_exceptions_subject_shape check");
		expect(ALL).toContain("references public.agents (id, tenant_id) on delete cascade");
	});

	it("writes only through service-role SECURITY DEFINER RPCs that re-check owner/admin and audit", () => {
		for (const [name, signature, auditAction] of [
			["public.create_detection_exception", "(uuid, uuid, jsonb)", "detection_exception.created"],
			["public.revoke_detection_exception", "(uuid, uuid, uuid, text)", "detection_exception.revoked"],
		] as const) {
			const body = functionBody(name);
			expect(body).toContain("security definer");
			expect(body).toMatch(/set search_path = [a-z_, ]*pg_temp/);
			expect(body).toContain("app.ai_governance_actor_role(p_tenant_id, p_actor_user_id)");
			expect(body).toContain("v_role not in ('owner', 'admin')");
			expect(body).toContain("pg_advisory_xact_lock");
			expect(body).toContain(`app.ai_governance_audit(p_tenant_id, p_actor_user_id, '${auditAction}'`);
			expect(EXECUTABLE).toContain(`revoke all on function ${name}${signature} from public, anon, authenticated`);
			expect(EXECUTABLE).toContain(`grant execute on function ${name}${signature} to service_role`);
		}
		const create = functionBody("public.create_detection_exception");
		expect(create).toContain("v_expires > v_now + interval '30 days'");
		expect(create).toContain("detection_exception_protected_rule");
		expect(create).toContain("detection_exception_subject_unknown");
		expect(create).toContain("detection_exception_quota");
	});

	it("feeds connectors only active exceptions for exactly the requesting principal", () => {
		const feed = functionBody("public.detection_exceptions_for_principal");
		expect(feed).toContain("security definer");
		expect(feed).toContain("d.revoked_at is null");
		expect(feed).toContain("d.expires_at > clock_timestamp()");
		expect(feed).toContain("d.created_at <= clock_timestamp()");
		expect(feed).toContain("d.subject_kind = 'user' and p_user_id is not null and d.subject_user_id = p_user_id");
		expect(feed).toContain("d.subject_kind = 'agent' and p_agent_id is not null and d.subject_agent_id = p_agent_id");
		expect(feed).toContain("order by d.id limit 500");
		expect(feed).toContain("detection_exception_tenant_state");
		expect(EXECUTABLE).toContain(
			"grant execute on function public.detection_exceptions_for_principal(uuid, uuid, uuid) to service_role",
		);
		expect(EXECUTABLE).not.toMatch(/grant execute on function [^;]*detection[^;]* to [a-z_, ]*\b(anon|authenticated)\b/);
	});

	it("advances the change high-water mark on every write and never lowers it", () => {
		const touch = functionBody("app.touch_detection_exception_state");
		expect(touch).toContain("set changed_at = greatest(s.changed_at, excluded.changed_at)");
		expect(EXECUTABLE).toContain(
			"create trigger detection_exceptions_touch_state after insert or update or delete on public.detection_exceptions",
		);
	});

	it("emits the wire shape core verifies", () => {
		const wire = functionBody("app.detection_exception_json");
		for (const key of [
			"id",
			"rule_id",
			"artifact_sha256",
			"subject_kind",
			"subject_value",
			"created_at",
			"expires_at",
			"created_by",
			"reason",
		]) {
			expect(wire).toContain(`'${key}'`);
		}
	});
});
