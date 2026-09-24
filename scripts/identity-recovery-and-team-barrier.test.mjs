import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const migration = await readFile(
	new URL("../supabase/migrations/20260922000007_identity_recovery_and_team_barrier_hardening.sql", import.meta.url),
	"utf8",
);

const functionBody = (name) => {
	const start = migration.indexOf(`create function public.${name}`);
	assert.notEqual(start, -1, `${name} is missing`);
	const end = migration.indexOf("\n$$;", start);
	assert.notEqual(end, -1, `${name} body is unterminated`);
	return migration.slice(start, end);
};

test("recovery grants are armed only from a fresh native GoTrue recovery event", () => {
	assert.match(migration, /add column proof_challenge_hash text/i);
	assert.match(migration, /add column auth_recovery_sent_at timestamptz/i);
	assert.match(migration, /set used_at = coalesce\(used_at, clock_timestamp\(\)\)/i);
	assert.match(migration, /drop function if exists public\.issue_identity_password_recovery_grant\(text, uuid, timestamptz\)/i);

	for (const name of [
		"issue_identity_password_recovery_grant",
		"issue_identity_break_glass_password_recovery_grant",
	]) {
		const sql = functionBody(name);
		assert.match(sql, /p_proof_challenge_hash !~ '\^\[0-9a-f\]\{64\}\$'/i);
		assert.match(sql, /nullif\(u\.recovery_token, ''\) is not null/i);
		assert.match(sql, /u\.recovery_sent_at >= p_recovery_requested_after/i);
		assert.match(sql, /proof_challenge_hash, auth_recovery_sent_at/i);
	}
});

test("bind and consume require the proof, exact recovery event, fresh session, and live barrier", () => {
	assert.match(migration, /drop function if exists public\.bind_identity_password_recovery_grant\(uuid, uuid, uuid\)/i);
	assert.match(migration, /drop function if exists public\.consume_identity_password_recovery_grant\(uuid, uuid, uuid\)/i);
	for (const name of [
		"bind_identity_password_recovery_grant",
		"consume_identity_password_recovery_grant",
	]) {
		const sql = functionBody(name);
		assert.match(sql, /p_proof_verifier !~ '\^\[A-Za-z0-9_-\]\{43\}\$'/i);
		assert.match(sql, /extensions\.digest\(p_proof_verifier, 'sha256'\)/i);
		assert.match(sql, /coalesce\(u\.recovery_token, ''\) = ''/i);
		assert.match(sql, /u\.recovery_sent_at = g\.auth_recovery_sent_at/i);
		assert.match(sql, /from auth\.sessions s[\s\S]+s\.id = p_session_id and s\.user_id = p_user_id/i);
		assert.match(sql, /v_session_created_at < v_grant\.auth_recovery_sent_at/i);
		assert.match(sql, /p_access_token_issued_at < date_trunc\('second', v_grant\.auth_recovery_sent_at\)/i);
		assert.match(sql, /pg_advisory_xact_lock\(hashtextextended\(p_user_id::text, 2611\)\)/i);
		assert.match(sql, /global_revoke_pending_session_id is not null/i);
		assert.match(sql, /v_session_created_at <= v_state\.revoked_before/i);
	}
});

test("team creation serializes with revocation and checks the identity barrier before inserts", () => {
	const start = migration.indexOf("create or replace function public.create_team_tenant");
	assert.notEqual(start, -1);
	const sql = migration.slice(start);
	const lock = sql.indexOf("pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611))");
	const barrier = sql.indexOf("tenant_identity_access_allowed(v_team_id)");
	const tenantInsert = sql.indexOf("insert into public.tenants");
	assert.ok(lock >= 0 && barrier > lock && tenantInsert > barrier);
	assert.match(sql, /raise exception 'identity barrier rejected' using errcode = '42501'/i);
});

const hash = (value) => createHash("sha256").update(value).digest("hex");
const canUseGrant = ({
	verifier,
	challenge,
	recoverySentAt,
	currentRecoverySentAt = recoverySentAt,
	recoveryToken = "",
	sessionCreatedAt,
	jwtIssuedAt,
	revokedBefore = null,
	pending = false,
	consumed = false,
}) => hash(verifier) === challenge
	&& recoveryToken === ""
	&& currentRecoverySentAt === recoverySentAt
	&& sessionCreatedAt >= recoverySentAt
	&& jwtIssuedAt >= Math.floor(recoverySentAt / 1000) * 1000
	&& !pending
	&& !consumed
	&& (revokedBefore === null || sessionCreatedAt > revokedBefore);

test("old or revoked OTP sessions cannot take over a proof-bound recovery grant", () => {
	const verifier = "a".repeat(43);
	const grant = {
		verifier,
		challenge: hash(verifier),
		recoverySentAt: 20_500,
		sessionCreatedAt: 21_000,
		jwtIssuedAt: 20_000,
	};
	assert.equal(canUseGrant(grant), true, "the exact fresh recovery session is accepted");
	assert.equal(canUseGrant({ ...grant, verifier: "b".repeat(43) }), false, "wrong proof is rejected");
	assert.equal(canUseGrant({ ...grant, recoveryToken: "not-consumed" }), false, "generic OTP before recovery verification is rejected");
	assert.equal(canUseGrant({ ...grant, sessionCreatedAt: 19_000, jwtIssuedAt: 30_000 }), false, "refreshing an old OTP session is rejected");
	assert.equal(canUseGrant({ ...grant, revokedBefore: 21_000 }), false, "a revoked recovery session is rejected");
	assert.equal(canUseGrant({ ...grant, pending: true }), false, "a pending global revocation is rejected");
	assert.equal(canUseGrant({ ...grant, consumed: true }), false, "a consumed grant cannot be replayed");
	assert.equal(canUseGrant({ ...grant, currentRecoverySentAt: 22_000 }), false, "a later recovery event invalidates the grant");
});
