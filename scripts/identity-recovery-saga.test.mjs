import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const migration = await readFile(
	new URL("../supabase/migrations/20260922000008_identity_recovery_completion_saga.sql", import.meta.url),
	"utf8",
);

const body = (name) => {
	const start = migration.indexOf(`function public.${name}`);
	assert.notEqual(start, -1, `${name} is missing`);
	const end = migration.indexOf("\n$$;", start);
	assert.notEqual(end, -1, `${name} is unterminated`);
	return migration.slice(start, end);
};

test("break-glass reserves by proof and consumes only in the completion transaction", () => {
	assert.match(migration, /drop function if exists public\.consume_identity_recovery_code\(text, text, text\)/i);
	const begin = body("begin_identity_break_glass_recovery");
	const complete = body("complete_identity_break_glass_recovery");
	assert.match(begin, /recovery_proof_challenge_hash is distinct from p_proof_challenge_hash/i);
	assert.match(begin, /recovery_started_at <= clock_timestamp\(\) - interval '15 minutes'/i);
	assert.match(begin, /set recovery_proof_challenge_hash = p_proof_challenge_hash,[\s\S]+recovery_started_at = clock_timestamp\(\)/i);
	assert.doesNotMatch(begin, /set used_at/i);
	assert.match(complete, /recovery_proof_challenge_hash = p_proof_challenge_hash/i);
	assert.match(complete, /pg_advisory_xact_lock\(hashtextextended\(v_code\.user_id::text, 2611\)\)/i);
	assert.match(complete, /insert into public\.identity_user_session_state/i);
	assert.match(complete, /set used_at = v_barrier,[\s\S]+used_request_id = recovery_request_id/i);
	assert.ok(complete.indexOf("identity_user_session_state") < complete.indexOf("set used_at = v_barrier"));
});

test("same-proof email and break-glass retries update only an unbound unused grant", () => {
	for (const name of [
		"issue_identity_password_recovery_grant",
		"issue_identity_break_glass_password_recovery_grant",
	]) {
		const issue = body(name);
		assert.match(issue, /proof_challenge_hash = p_proof_challenge_hash[\s\S]+for update/i);
		assert.match(issue, /v_grant\.session_id is not null[\s\S]+v_grant\.used_at is not null/i);
		assert.match(issue, /set expires_at = p_expires_at,[\s\S]+auth_recovery_sent_at = v_recovery_sent_at/i);
	}
});

test("password recovery persists a retry before effects and consumes only with the final barrier", () => {
	assert.match(migration, /drop function if exists public\.consume_identity_password_recovery_grant\([\s\S]*?timestamptz[\s\S]*?\)/i);
	const begin = body("begin_identity_password_recovery_completion");
	const complete = body("complete_identity_password_recovery_completion");
	assert.match(begin, /completion_started_at is null[\s\S]+set completion_started_at = clock_timestamp\(\)/i);
	assert.match(begin, /completion_session_created_at = v_session_created_at/i);
	assert.match(begin, /v_grant\.completion_started_at is null[\s\S]+v_session_created_at <= v_state\.revoked_before/i);
	assert.doesNotMatch(begin, /set used_at/i);
	assert.match(complete, /mark_identity_session_revoked\([\s\S]+password_recovery/i);
	assert.match(complete, /set used_at = v_barrier/i);
	assert.ok(complete.indexOf("mark_identity_session_revoked") < complete.indexOf("set used_at = v_barrier"));
});

test("all recovery saga RPCs remain service-role-only", () => {
	for (const name of [
		"begin_identity_break_glass_recovery",
		"complete_identity_break_glass_recovery",
		"begin_identity_password_recovery_completion",
		"complete_identity_password_recovery_completion",
	]) {
		assert.match(
			migration,
			new RegExp(`revoke all on function public\\.${name}\\([\\s\\S]+?from public, anon, authenticated;[\\s\\S]+?grant execute on function public\\.${name}\\([\\s\\S]+?to service_role;`, "i"),
		);
	}
});

class BreakGlassSaga {
	code = { proof: null, used: false };
	factors = new Set(["factor-a", "factor-b"]);
	grantRecoveryEvent = 0;

	run(proof, failAt = null) {
		if (this.code.proof !== null && this.code.proof !== proof) return "denied";
		this.code.proof ??= proof;
		for (const factor of [...this.factors]) this.factors.delete(factor);
		if (failAt === "factors") return "retry";
		this.grantRecoveryEvent += 1;
		if (failAt === "link-or-grant") return "retry";
		if (failAt === "audit") return "retry";
		if (failAt === "complete") return "retry";
		this.code.used = true;
		return "ok";
	}
}

test("injected break-glass failures retain the credential for the same proof", () => {
	for (const failure of ["factors", "link-or-grant", "audit", "complete"]) {
		const saga = new BreakGlassSaga();
		assert.equal(saga.run("proof-a", failure), "retry");
		assert.equal(saga.code.used, false, `${failure} must not consume the code`);
		assert.equal(saga.run("proof-b"), "denied", `${failure} must not permit proof takeover`);
		assert.equal(saga.run("proof-a"), "ok", `${failure} must be resumable`);
		assert.equal(saga.code.used, true);
		assert.equal(saga.factors.size, 0, "factor deletion is idempotent");
	}
});

class PasswordSaga {
	started = false;
	used = false;
	password = "old";

	run(requestedPassword, failAt = null) {
		if (this.used) return "completed";
		this.started = true;
		if (failAt === "barrier") return "retry";
		if (failAt === "signout") return "retry";
		this.password = requestedPassword;
		if (failAt === "password") return "retry";
		if (failAt === "complete") return "retry";
		this.used = true;
		return "ok";
	}
}

test("injected password-recovery failures retain the grant until final completion", () => {
	for (const failure of ["barrier", "signout", "password", "complete"]) {
		const saga = new PasswordSaga();
		assert.equal(saga.run("new-password", failure), "retry");
		assert.equal(saga.started, true);
		assert.equal(saga.used, false, `${failure} must not consume the grant`);
		assert.equal(saga.run("new-password"), "ok", `${failure} must be resumable`);
		assert.equal(saga.used, true);
		assert.equal(saga.password, "new-password");
		assert.equal(saga.run("attacker-password"), "completed");
		assert.equal(saga.password, "new-password", "completed replay must not apply a new password");
	}
});
