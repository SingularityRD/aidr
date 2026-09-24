import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const migration = await readFile(
	new URL("../supabase/migrations/20260922000006_identity_global_revocation_saga.sql", import.meta.url),
	"utf8",
);

function functionBody(name) {
	const match = migration.match(
		new RegExp(`create or replace function ${name.replaceAll(".", "\\.")}\\([^]*?\\n\\$\\$;`, "i"),
	);
	assert.ok(match, `missing function ${name}`);
	return match[0];
}

test("pending global revocation is paired and denies ordinary tenant access", () => {
	assert.match(migration, /add column global_revoke_pending_session_id uuid/i);
	assert.match(migration, /add column global_revoke_pending_at timestamptz/i);
	assert.match(migration, /identity_user_session_state_global_revoke_pending_pair/i);
	const access = functionBody("public.tenant_identity_access_allowed");
	assert.match(access, /s\.global_revoke_pending_session_id is not null[\s\S]*or[\s\S]*s\.revoked_before is not null/i);
});

test("begin binds a retry to one session and rejects completed old JWT replay", () => {
	const begin = functionBody("public.begin_identity_global_revocation");
	const lock = begin.indexOf("pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611))");
	const read = begin.indexOf("select s.* into v_state");
	const sessionGuard = begin.indexOf("v_state.global_revoke_pending_session_id is distinct from p_session_id");
	const issuanceGuard = begin.indexOf("p_access_token_issued_at <= v_state.revoked_before");
	const barrier = begin.indexOf("public.mark_identity_session_revoked(");
	const pending = begin.indexOf("set global_revoke_pending_session_id = p_session_id");
	assert.ok(lock >= 0 && read > lock && sessionGuard > read && issuanceGuard > sessionGuard);
	assert.ok(barrier > issuanceGuard && pending > barrier);
	assert.match(begin, /v_state\.global_revoke_pending_session_id = p_session_id[\s\S]*v_state\.global_revoke_pending_at/i);
});

test("completion requires the pending session and clears it after a final barrier", () => {
	const complete = functionBody("public.complete_identity_global_revocation");
	const lock = complete.indexOf("pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611))");
	const match = complete.indexOf("v_pending_session_id is distinct from p_session_id");
	const barrier = complete.indexOf("public.mark_identity_session_revoked(");
	const clear = complete.indexOf("set global_revoke_pending_session_id = null");
	assert.ok(lock >= 0 && match > lock && barrier > match && clear > barrier);
});

test("global revoke saga RPCs remain service-role-only", () => {
	for (const signature of [
		"begin_identity_global_revocation(uuid, uuid, uuid, timestamptz)",
		"complete_identity_global_revocation(uuid, uuid, uuid)",
	]) {
		const escaped = signature.replace(/[()]/g, "\\$&");
		assert.match(migration, new RegExp(`revoke all on function public\\.${escaped}\\s+from public, anon, authenticated`, "i"));
		assert.match(migration, new RegExp(`grant execute on function public\\.${escaped}\\s+to service_role`, "i"));
	}
});

test("the state machine allows only pending retry or a JWT newer than the final barrier", () => {
	const begin = (state, sessionId, issuedAt, nextBarrier) => {
		if (state && state.pendingSessionId !== sessionId && issuedAt <= state.barrier) return false;
		return { barrier: nextBarrier, pendingSessionId: sessionId };
	};
	const complete = (state, sessionId, nextBarrier) => {
		if (!state || state.pendingSessionId !== sessionId) return false;
		return { barrier: nextBarrier, pendingSessionId: null };
	};

	const started = begin(null, "session-a", 10, 20);
	assert.deepEqual(started, { barrier: 20, pendingSessionId: "session-a" });
	const retried = begin(started, "session-a", 10, 30);
	assert.deepEqual(retried, { barrier: 30, pendingSessionId: "session-a" });
	const completed = complete(retried, "session-a", 40);
	assert.deepEqual(completed, { barrier: 40, pendingSessionId: null });
	assert.equal(begin(completed, "session-a", 10, 50), false);
	assert.deepEqual(begin(completed, "session-b", 41, 50), {
		barrier: 50,
		pendingSessionId: "session-b",
	});
});
