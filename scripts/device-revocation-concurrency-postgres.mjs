// Run after `supabase start && supabase db reset --local --no-seed`:
//   AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr node scripts/device-revocation-concurrency-postgres.mjs
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.ok(container, "AIDR_RLS_TEST_DB_CONTAINER must name the disposable Supabase db container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");

const identities = Array.from({ length: 5 }, () => randomUUID());
const sessions = identities.map(() => ({
	deviceHash: randomBytes(32).toString("hex"),
	tokenHash: randomBytes(32).toString("hex"),
	userCode: randomBytes(4).toString("hex").toUpperCase(),
}));

const dockerArgs = [
	"exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
	"-U", "postgres", "-d", "postgres", "-q", "-At",
];

function runPsql(sql) {
	const result = spawnSync("docker", dockerArgs, {
		input: sql,
		encoding: "utf8",
		maxBuffer: 4 * 1024 * 1024,
		timeout: 120_000,
	});
	if (result.error) throw result.error;
	assert.equal(result.status, 0, `PostgreSQL regression failed:\n${result.stdout}\n${result.stderr}`);
	return result.stdout;
}

function startPsql(sql) {
	const child = spawn("docker", dockerArgs, { stdio: ["pipe", "pipe", "pipe"] });
	let stdout = "";
	let stderr = "";
	child.stdout.setEncoding("utf8");
	child.stderr.setEncoding("utf8");
	child.stdout.on("data", (chunk) => { stdout += chunk; });
	child.stderr.on("data", (chunk) => { stderr += chunk; });
	child.stdin.end(sql);
	const completed = new Promise((resolve, reject) => {
		child.on("error", reject);
		child.on("close", (code) => {
			if (code === 0) resolve(stdout);
			else reject(new Error(`PostgreSQL regression failed:\n${stdout}\n${stderr}`));
		});
	});
	// Attach a handler immediately; callers still await the original promise.
	// This prevents a fast Docker failure from becoming an unhandled rejection
	// while the coordinator is probing the database lock below.
	void completed.catch(() => undefined);
	return completed;
}

async function waitForUserLock(user) {
	for (let attempt = 0; attempt < 100; attempt += 1) {
		const output = runPsql(String.raw`
select not pg_try_advisory_lock(hashtextextended('${user}'::text, 2611));
`);
		if (/^t$/m.test(output)) return;
		await new Promise((resolve) => setTimeout(resolve, 50));
	}
	throw new Error(`Timed out waiting for the user advisory lock: ${user}`);
}

const setup = String.raw`
\set ON_ERROR_STOP on
${identities.map((user, index) => `
insert into auth.users(id, email, aud, role, instance_id, raw_app_meta_data, raw_user_meta_data)
values ('${user}', 'device-race-${user}@example.invalid', 'authenticated', 'authenticated',
  '00000000-0000-0000-0000-000000000000', '{}'::jsonb, '{}'::jsonb);
insert into public.pilot_applications(user_id, tenant_id, status)
values ('${user}', '${user}', 'approved');
insert into public.device_sessions(device_code_hash, user_code, status, user_id, tenant_id,
  authorized_at, expires_at)
values ('${sessions[index].deviceHash}', '${sessions[index].userCode}',
  ${index < 2 || index === 4 ? "'pending', null, null, null" : `'authorized', '${user}', '${user}', now()`},
  now() + interval '10 minutes');
`).join("\n")}
`;

function revocationTransaction(user, marker) {
	return String.raw`
\set ON_ERROR_STOP on
begin;
select public.mark_identity_session_revoked('${user}', null, '${user}', 'user_global_signout');
\echo ${marker}
select pg_sleep(5);
commit;
`;
}

const admissionMode = runPsql("select mode from app.tenant_admission_config where singleton;").trim();
runPsql("update app.tenant_admission_config set mode = 'pilot' where singleton;");
try {
runPsql(setup);

// Revocation wins: authorization waits for the shared user lock, observes the
// committed barrier, and must not bind the pending device session.
{
	const user = identities[0];
	const session = sessions[0];
	const revoke = startPsql(revocationTransaction(user, "REVOCATION_A_LOCK_HELD"));
	await waitForUserLock(user);
	const authorize = startPsql(String.raw`
\set ON_ERROR_STOP on
select 'AUTHORIZE_A_COUNT=' || count(*) from public.authorize_device_session(
  '${session.userCode}', '${user}', '${user}', now() - interval '1 minute'
);
`);
	const [revokeOutput, authorizeOutput] = await Promise.all([revoke, authorize]);
	assert.match(revokeOutput, /REVOCATION_A_LOCK_HELD/);
	assert.match(authorizeOutput, /AUTHORIZE_A_COUNT=0/);
	assert.match(runPsql(String.raw`
do $$ begin
  if not exists (
    select 1 from public.device_sessions
    where device_code_hash = '${session.deviceHash}' and user_id is null and authorized_at is null
  ) then raise exception 'revocation-first authorization bound a stale device session'; end if;
end $$;
select 'SCENARIO_A_OK';
`), /SCENARIO_A_OK/);
}

// Authorization wins: revocation waits for the same lock, then expires the
// newly bound session. A later issuer must reject it.
{
	const user = identities[1];
	const session = sessions[1];
	const authorize = startPsql(String.raw`
\set ON_ERROR_STOP on
begin;
select 'AUTHORIZE_B_COUNT=' || count(*) from public.authorize_device_session(
  '${session.userCode}', '${user}', '${user}', now() - interval '1 minute'
);
\echo AUTHORIZATION_B_LOCK_HELD
select pg_sleep(5);
commit;
`);
	await waitForUserLock(user);
	const revoke = startPsql(revocationTransaction(user, "REVOCATION_B_LOCK_HELD"));
	const [authorizeOutput, revokeOutput] = await Promise.all([authorize, revoke]);
	assert.match(authorizeOutput, /AUTHORIZE_B_COUNT=1/);
	assert.match(revokeOutput, /REVOCATION_B_LOCK_HELD/);
	assert.match(runPsql(String.raw`
do $$
declare v_result jsonb;
begin
  if not exists (
    select 1 from public.device_sessions d
    join public.identity_user_session_state s on s.user_id = d.user_id
    where d.device_code_hash = '${session.deviceHash}'
      and d.user_id = '${user}' and d.authorized_at <= s.revoked_before
      and d.expires_at <= s.revoked_before
  ) then raise exception 'authorization-first session escaped global revocation'; end if;
  v_result := public.issue_device_enrollment_token(
    '${session.deviceHash}', '${session.tokenHash}', now() + interval '10 minutes'
  );
  if v_result->>'status' <> 'already_exchanged_or_invalid'
  then raise exception 'revoked device session issued an enrollment token'; end if;
end $$;
select 'SCENARIO_B_OK';
`), /SCENARIO_B_OK/);
}

// Issuance wins: revocation follows it under the same lock and expires the
// unconsumed enrollment token before the revocation transaction commits.
{
	const user = identities[2];
	const session = sessions[2];
	const issue = startPsql(String.raw`
\set ON_ERROR_STOP on
begin;
select 'ISSUE_C_STATUS=' || (public.issue_device_enrollment_token(
  '${session.deviceHash}', '${session.tokenHash}', now() + interval '10 minutes'
)->>'status');
\echo ISSUE_C_LOCK_HELD
select pg_sleep(5);
commit;
`);
	await waitForUserLock(user);
	const revoke = startPsql(revocationTransaction(user, "REVOCATION_C_LOCK_HELD"));
	const [issueOutput, revokeOutput] = await Promise.all([issue, revoke]);
	assert.match(issueOutput, /ISSUE_C_STATUS=issued/);
	assert.match(revokeOutput, /REVOCATION_C_LOCK_HELD/);
	assert.match(runPsql(String.raw`
do $$ begin
  if not exists (
    select 1 from public.enrollment_tokens e
    join public.identity_user_session_state s on s.user_id = e.user_id
    where e.token_hash = '${session.tokenHash}' and e.consumed_at is null
      and e.expires_at <= s.revoked_before
  ) then raise exception 'issued enrollment token escaped global revocation'; end if;
end $$;
select 'SCENARIO_C_OK';
`), /SCENARIO_C_OK/);
}

// Revocation wins against an already-authorized session: the issuer waits,
// rechecks the barrier, and cannot create an enrollment token.
{
	const user = identities[3];
	const session = sessions[3];
	const revoke = startPsql(revocationTransaction(user, "REVOCATION_D_LOCK_HELD"));
	await waitForUserLock(user);
	const issue = startPsql(String.raw`
\set ON_ERROR_STOP on
select 'ISSUE_D_STATUS=' || (public.issue_device_enrollment_token(
  '${session.deviceHash}', '${session.tokenHash}', now() + interval '10 minutes'
)->>'status');
`);
	const [revokeOutput, issueOutput] = await Promise.all([revoke, issue]);
	assert.match(revokeOutput, /REVOCATION_D_LOCK_HELD/);
	assert.match(issueOutput, /ISSUE_D_STATUS=already_exchanged_or_invalid/);
	assert.match(runPsql(String.raw`
do $$ begin
  if exists (select 1 from public.enrollment_tokens where token_hash = '${session.tokenHash}')
  then raise exception 'revocation-first issuer created an enrollment token'; end if;
end $$;
select 'SCENARIO_D_OK';
`), /SCENARIO_D_OK/);
}

// A failed audit insert must roll back the device binding. The same user code
// can then be retried once and must produce exactly one audit row.
{
	const user = identities[4];
	const session = sessions[4];
	const output = runPsql(String.raw`
\set ON_ERROR_STOP on
begin;
alter table public.admin_audit_logs add constraint aidr_test_reject_device_audit
  check (action <> 'device.verify' or actor_user_id <> '${user}') not valid;
do $checks$
declare v_count integer; v_constraint text;
begin
  begin
    select count(*) into v_count from public.authorize_device_session(
      '${session.userCode}', '${user}', '${user}', now() - interval '1 minute'
    );
    raise exception 'device authorization unexpectedly committed without audit';
  exception when check_violation then
    get stacked diagnostics v_constraint = constraint_name;
    if v_constraint <> 'aidr_test_reject_device_audit' then raise; end if;
  end;
  if exists (select 1 from public.device_sessions
             where device_code_hash = '${session.deviceHash}' and authorized_at is not null) then
    raise exception 'audit failure left device authorized';
  end if;
  if exists (select 1 from public.admin_audit_logs
             where action = 'device.verify' and actor_user_id = '${user}') then
    raise exception 'audit failure left a receipt';
  end if;
end;
$checks$;
alter table public.admin_audit_logs drop constraint aidr_test_reject_device_audit;
select 'AUTHORIZE_E_COUNT=' || count(*) from public.authorize_device_session(
  '${session.userCode}', '${user}', '${user}', now() - interval '1 minute'
);
select 'AUTHORIZE_E_REPLAY_COUNT=' || count(*) from public.authorize_device_session(
  '${session.userCode}', '${user}', '${user}', now() - interval '1 minute'
);
do $checks$
begin
  if not exists (select 1 from public.device_sessions
                 where device_code_hash = '${session.deviceHash}' and user_id = '${user}'
                   and authorized_at is not null) then
    raise exception 'retry did not authorize device';
  end if;
  if (select count(*) from public.admin_audit_logs
      where action = 'device.verify' and actor_user_id = '${user}'
        and detail->>'device_session_id' =
            (select id::text from public.device_sessions where device_code_hash = '${session.deviceHash}')) <> 1 then
    raise exception 'retry did not write exactly one device audit receipt';
  end if;
end;
$checks$;
commit;
`);
	assert.match(output, /AUTHORIZE_E_COUNT=1/);
	assert.match(output, /AUTHORIZE_E_REPLAY_COUNT=0/);
}

console.log("Device revocation and audit atomicity passed: failed audit rolls back authorization, retry succeeds once.");
} finally {
	runPsql(`update app.tenant_admission_config set mode = '${admissionMode}' where singleton;`);
}
