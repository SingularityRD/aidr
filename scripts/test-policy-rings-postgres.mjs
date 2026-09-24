#!/usr/bin/env node
// Run: node scripts/test-policy-rings-postgres.mjs
// Requires ONLY Node and a locally cached docker postgres:17-alpine image.
// Never pulls, installs, uses a shared DB, publishes ports, or skips tests.
// Owns a random labelled container, with ephemeral data and --network none.
// Applies the real policy migration dependency chain; see fixture for base limits.
// Fixed 5s PostgreSQL statement / 4s lock timeouts (no retry of failed tests).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = new URL('../', import.meta.url);
const image = 'postgres:17-alpine';
const owner = randomUUID();
const container = `aidr-policy-rings-${owner}`;
const migrations = [
  '20260911000000_runtime_policy.sql',
  '20260911000002_policy_conflict_status.sql',
  '20260911000004_policy_rollout.sql',
  '20260913000002_policy_stage_cas.sql',
  '20260916000000_policy_rollout_rings.sql',
];
const policy = { command_default: 'deny' };
const hash = createHash('sha256').update(JSON.stringify(policy)).digest('hex');
const quote = (value) => `'${String(value).replaceAll("'", "''")}'`;
const json = (value) => `${quote(JSON.stringify(value))}::jsonb`;

function docker(args, input, timeout = 10_000) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    let expired = false;
    const timer = setTimeout(() => { expired = true; child.kill(); }, timeout);
    child.stdout.setEncoding('utf8').on('data', (part) => { stdout += part; });
    child.stderr.setEncoding('utf8').on('data', (part) => { stderr += part; });
    child.on('error', (error) => { clearTimeout(timer); reject(error); });
    child.stdin.on('error', (error) => { if (error.code !== 'EPIPE') reject(error); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (expired) reject(new Error(`docker ${args[0]} exceeded ${timeout}ms\n${stderr}`));
      else resolve({ code, stdout: stdout.trim(), stderr: stderr.trim() });
    });
    child.stdin.end(input);
  });
}
function checked(result) {
  assert.equal(result.code, 0, `command failed (${result.code})\n${result.stderr}\n${result.stdout}`);
  return result.stdout;
}
async function rawSql(text, application = 'policy-rings-test') {
  return docker(['exec', '-i', '-e', `PGAPPNAME=${application}`, container,
    'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose', '-U', 'postgres', '-d', 'postgres'], text);
}
async function sql(text) { return checked(await rawSql(text)); }
async function rpc(expression) { return sql(`set role service_role; select ${expression};`); }
async function rejected(expression, state, message, role = 'service_role') {
  const result = await rawSql(`set role ${role}; select ${expression};`);
  assert.notEqual(result.code, 0, `expected ${state}: ${expression}`);
  assert.match(result.stderr, new RegExp(`\\b${state}\\b`));
  if (message) assert.ok(result.stderr.includes(message), result.stderr);
}
async function statementRejected(statement, state, message) {
  const result = await rawSql(statement);
  assert.notEqual(result.code, 0, `expected ${state}: ${statement}`);
  assert.match(result.stderr, new RegExp(`\\b${state}\\b`));
  if (message) assert.ok(result.stderr.includes(message), result.stderr);
}

async function seed() {
  const f = { tenant: randomUUID(), otherTenant: randomUUID(), owner: randomUUID(), admin: randomUUID(), member: randomUUID(), viewer: randomUUID(), expired: randomUUID(), outsider: randomUUID(), agents: Array.from({ length: 6 }, () => randomUUID()), foreignAgent: randomUUID() };
  f.keys = f.agents.map(() => randomUUID().replaceAll('-', '').repeat(2));
  await sql(`truncate auth.users, public.tenants restart identity cascade;
    insert into auth.users(id) values ${[f.owner, f.admin, f.member, f.viewer, f.expired, f.outsider].map((id) => `(${quote(id)})`).join(',')};
    insert into public.tenants(id,name) values (${quote(f.tenant)},'A'),(${quote(f.otherTenant)},'B');
    insert into public.tenant_members(tenant_id,user_id,role,expires_at) values
      (${quote(f.tenant)},${quote(f.owner)},'owner',null),
      (${quote(f.tenant)},${quote(f.admin)},'admin',null),
      (${quote(f.tenant)},${quote(f.member)},'member',null),
      (${quote(f.tenant)},${quote(f.viewer)},'viewer',null),
      (${quote(f.tenant)},${quote(f.expired)},'admin',now()-interval '1 second'),
      (${quote(f.otherTenant)},${quote(f.outsider)},'owner',null);
    insert into public.entitlements(tenant_id,user_id,included_agents) values
      (${quote(f.tenant)},${quote(f.owner)},6),
      (${quote(f.otherTenant)},${quote(f.outsider)},1);
    insert into public.pilot_applications(tenant_id,user_id,status) values
      (${quote(f.tenant)},${quote(f.owner)},'approved'),
      (${quote(f.otherTenant)},${quote(f.outsider)},'approved');
    insert into public.agents(id,tenant_id,user_id,iid) values
      ${f.agents.map((id, i) => `(${quote(id)},${quote(f.tenant)},${quote(f.owner)},'agent-${i}')`).join(',')},
      (${quote(f.foreignAgent)},${quote(f.otherTenant)},${quote(f.outsider)},'foreign');
    insert into public.api_keys(tenant_id,user_id,agent_id,key_hash) values
      ${f.agents.map((id, i) => `(${quote(f.tenant)},${quote(f.owner)},${quote(id)},${quote(f.keys[i])})`).join(',')};`);
  return f;
}
function rings(...groups) {
  return groups.map((batches, i) => ({ ring_order: i + 1, batches: batches.map((agents, j) => ({ batch_order: j + 1, agent_ids: agents })) }));
}
function createExpr(f, plan, { user = f.owner, expected = 0, revision = 0 } = {}) {
  return `public.create_policy_rollout(${quote(f.tenant)},${quote(user)},${expected},${revision},${json(policy)},${json(plan)})`;
}
async function create(f, plan, options) { return JSON.parse(await rpc(createExpr(f, plan, options))); }
async function progress(f, r) { return JSON.parse(await rpc(`public.read_policy_rollout_progress(${quote(f.tenant)},${quote(r.rollout_id)})`)); }
async function receipt(f, i, version, digest = hash) {
  return rpc(`public.record_policy_receipt(${quote(f.keys[i])},${version},${digest === null ? 'null' : quote(digest)})`);
}
async function status(r, value) { await sql(`set role service_role; update public.policy_rollouts set status=${quote(value)} where id=${quote(r.rollout_id)};`); }
async function advance(f, r) {
  await sql(`select app.advance_policy_rollout(${quote(f.tenant)},${quote(r.rollout_id)},id) from public.policy_rollout_batches where rollout_id=${quote(r.rollout_id)} and status='active';`);
}
async function ageReceipt(f, i) {
  // Mutate clocks, never sleep five minutes or expand a timeout.
  await sql(`update public.policy_rollout_batches set started_at=now()-interval '7 minutes'
      where id in (select batch_id from public.policy_rollout_targets where agent_id=${quote(f.agents[i])});
    update public.agent_policy_receipts set received_at=now()-interval '6 minutes' where agent_id=${quote(f.agents[i])};
    update public.policy_rollout_targets set last_receipt_at=now()-interval '6 minutes' where agent_id=${quote(f.agents[i])};`);
}
function batchStatuses(p) { return p.rings.flatMap((ring) => ring.batches.map((batch) => batch.status)); }
async function assertBlocked(f, r) {
  await advance(f, r);
  assert.deepEqual(batchStatuses(await progress(f, r)), ['active', 'pending']);
  assert.equal(await sql(`select count(*) from public.agent_policy_assignments where agent_id=${quote(f.agents[2])};`), '0');
}
const cases = [];
const test = (name, run) => cases.push({ name, run });

test('CAS concurrent creation: real advisory-lock waiter, one winner, loser leaves no rows', async (f) => {
  const expression = createExpr(f, rings([[f.agents[0]]]));
  const winner = rawSql(`begin; set role service_role; select ${expression}; select pg_sleep(1); commit;`, 'rings-cas-winner');
  // Keep both promises handled even if an assertion fails.
  let loser;
  try {
    const deadline = Date.now() + 2_000;
    while (await sql("select count(*) from pg_stat_activity where application_name='rings-cas-winner' and wait_event='PgSleep';") !== '1') {
      assert.ok(Date.now() < deadline, 'winner never reached its held-lock barrier');
      await delay(10);
    }
    loser = rawSql(`set role service_role; select ${expression};`, 'rings-cas-loser');
    const waitingDeadline = Date.now() + 800;
    while (await sql("select count(*) from pg_locks l join pg_stat_activity a on a.pid=l.pid where a.application_name='rings-cas-loser' and l.locktype='advisory' and not l.granted;") !== '1') {
      assert.ok(Date.now() < waitingDeadline, 'second creation did not concurrently wait on tenant lock');
      await delay(10);
    }
    checked(await winner);
    const conflict = await loser;
    assert.notEqual(conflict.code, 0);
    assert.match(conflict.stderr, /PT409.*policy_revision_conflict/);
    assert.equal(await sql('select count(*) from public.runtime_policy_revisions;'), '1');
    assert.equal(await sql('select count(*) from public.policy_rollouts;'), '1');
    assert.equal(await sql('select count(*) from public.policy_rollout_targets;'), '1');
    assert.equal(await sql('select count(*) from public.admin_audit_logs;'), '1');
  } finally { await Promise.allSettled([winner, ...(loser ? [loser] : [])]); }
});

test('concurrent last receipts release exactly one next batch and assignment', async (f) => {
  const r = await create(f, rings([[f.agents[0], f.agents[1]], [f.agents[2]]], [[f.agents[3]]]));
  // Observe writes, not merely the final PK-constrained row count: an accidental
  // second upsert or activation must fail this test too. These are test-only
  // observers, installed after initial assignment and removed in finally.
  await sql(`create table app.test_ring_writes(kind text, row_id uuid);
    create function app.test_ring_observer() returns trigger language plpgsql as $$
    begin
      if tg_table_name='agent_policy_assignments' then
        insert into app.test_ring_writes values ('assignment',new.agent_id);
      elsif old.status is distinct from new.status then
        insert into app.test_ring_writes values (new.status,new.id);
      end if;
      return new;
    end $$;
    create trigger test_assignment_observer after insert or update on public.agent_policy_assignments for each row execute function app.test_ring_observer();
    create trigger test_batch_observer after update on public.policy_rollout_batches for each row execute function app.test_ring_observer();`);
  const first = rawSql(`begin; set role service_role; select public.record_policy_receipt(${quote(f.keys[0])},${r.version},${quote(hash)}); select pg_sleep(1); commit;`, 'rings-receipt-first');
  let second;
  try {
    const deadline = Date.now() + 2_000;
    while (await sql("select count(*) from pg_stat_activity where application_name='rings-receipt-first' and wait_event='PgSleep';") !== '1') {
      assert.ok(Date.now() < deadline, 'first receipt never reached held-lock barrier');
      await delay(10);
    }
    second = rawSql(`set role service_role; select public.record_policy_receipt(${quote(f.keys[1])},${r.version},${quote(hash)});`, 'rings-receipt-second');
    const waitingDeadline = Date.now() + 800;
    while (await sql("select count(*) from pg_locks l join pg_stat_activity a on a.pid=l.pid where a.application_name='rings-receipt-second' and l.locktype='advisory' and not l.granted;") !== '1') {
      assert.ok(Date.now() < waitingDeadline, 'second receipt did not concurrently wait on tenant lock');
      await delay(10);
    }
    assert.equal(checked(await first), 't');
    assert.equal(checked(await second), 't');
    assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'active', 'pending']);
    assert.equal(await sql("select count(*) from app.test_ring_writes where kind='active';"), '1');
    assert.equal(await sql("select count(*) from app.test_ring_writes where kind='completed';"), '1');
    assert.equal(await sql("select count(*) from app.test_ring_writes where kind='assignment';"), '1');
    assert.equal(await sql("select row_id from app.test_ring_writes where kind='assignment';"), f.agents[2]);
    assert.equal(await sql(`select count(*) from public.agent_policy_assignments where agent_id=${quote(f.agents[3])};`), '0');
    assert.equal(await receipt(f, 0, r.version), 't');
    assert.equal(await receipt(f, 1, r.version), 't');
    assert.equal(await sql('select count(*) from app.test_ring_writes;'), '3', 'duplicate refresh cannot release twice');
  } finally {
    await Promise.allSettled([first, ...(second ? [second] : [])]);
    await sql(`drop trigger test_assignment_observer on public.agent_policy_assignments;
      drop trigger test_batch_observer on public.policy_rollout_batches;
      drop function app.test_ring_observer(); drop table app.test_ring_writes;`);
  }
});

test('same-rollout duplicate target rolls back revision, plan and assignment', async (f) => {
  await rejected(createExpr(f, rings([[f.agents[0]], [f.agents[0]]])), 'PT409', 'policy_rollout_overlap');
  assert.equal(await sql('select (select count(*) from public.runtime_policy_revisions)+(select count(*) from public.policy_rollouts)+(select count(*) from public.agent_policy_assignments);'), '0');
});

test('cross-rollout overlap rejected while running and paused; disjoint plan allowed', async (f) => {
  const r = await create(f, rings([[f.agents[0]]]));
  for (const state of ['running', 'paused']) {
    if (state === 'paused') await status(r, state);
    await rejected(createExpr(f, rings([[f.agents[0]]]), { revision: 1 }), 'PT409', 'policy_rollout_overlap');
  }
  assert.equal((await create(f, rings([[f.agents[1]]]), { revision: 1 })).version, 2);
  assert.equal(await sql('select count(*) from public.runtime_policy_revisions;'), '2');
});

test('tenant owner/admin allowed; member/viewer/expired/foreign users forbidden', async (f) => {
  for (const user of [f.member, f.viewer, f.expired, f.outsider]) {
    await rejected(createExpr(f, rings([[f.agents[0]]]), { user }), '42501', 'policy_forbidden');
  }
  await create(f, rings([[f.agents[0]]]), { user: f.admin });
  await create(f, rings([[f.agents[1]]]), { revision: 1 });
});

test('inactive tenant forbidden; cross-tenant/nonexistent target rejected atomically', async (f) => {
  for (const target of [f.foreignAgent, randomUUID()]) await rejected(createExpr(f, rings([[target]])), '22023', 'invalid_policy_rollout_agents');
  await sql(`update public.tenants set status='suspended' where id=${quote(f.tenant)};`);
  await rejected(createExpr(f, rings([[f.agents[0]]])), '42501', 'policy_forbidden');
  assert.equal(await sql('select count(*) from public.runtime_policy_revisions;'), '0');
});

test('anon/authenticated cannot invoke management/receipt RPCs or access ring tables', async (f) => {
  for (const role of ['anon', 'authenticated']) {
    await rejected(createExpr(f, rings([[f.agents[0]]])), '42501', null, role);
    await rejected(`public.read_policy_rollout_progress(${quote(f.tenant)},null)`, '42501', null, role);
    await rejected(`public.record_policy_receipt(${quote(f.keys[0])},1,${quote(hash)})`, '42501', null, role);
    for (const table of ['policy_rollouts', 'policy_rollout_batches', 'policy_rollout_targets']) {
      await statementRejected(`set role ${role}; select * from public.${table};`, '42501');
    }
  }
  const r = await create(f, rings([[f.agents[0]]]));
  const other = JSON.parse(await rpc(`public.read_policy_rollout_progress(${quote(f.otherTenant)},${quote(r.rollout_id)})`));
  assert.equal(other.status, 'none');
});

test('published-version and revision CAS failures remain distinct', async (f) => {
  await rejected(createExpr(f, rings([[f.agents[0]]]), { expected: 1, revision: 1 }), 'PT409', 'policy_version_conflict');
  await create(f, rings([[f.agents[0]]]));
  await rejected(createExpr(f, rings([[f.agents[1]]])), 'PT409', 'policy_revision_conflict');
});

test('noncontiguous/out-of-order plans rejected and direct pending activation blocked', async (f) => {
  for (const plan of [
    [{ ring_order: 2, batches: [{ batch_order: 1, agent_ids: [f.agents[0]] }] }],
    [{ ring_order: 1, batches: [{ batch_order: 2, agent_ids: [f.agents[0]] }] }],
  ]) await rejected(createExpr(f, plan), 'PT409', 'policy_rollout_order_conflict');
  const r = await create(f, rings([[f.agents[0]], [f.agents[1]]], [[f.agents[2]]]));
  await statementRejected(`set role service_role; update public.policy_rollout_batches set status='active',started_at=now() where rollout_id=${quote(r.rollout_id)} and ring_order=2;`, 'PT409');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['active', 'pending', 'pending']);
});

test('direct active-batch completion rejects stale evidence despite cached acknowledgement', async (f) => {
  const r = await create(f, rings([[f.agents[0]], [f.agents[2]]]));
  await status(r, 'paused');
  assert.equal(await receipt(f, 0, r.version), 't');
  await ageReceipt(f, 0);
  await statementRejected(`set role service_role; update public.policy_rollout_batches set status='completed',completed_at=now()
    where rollout_id=${quote(r.rollout_id)} and status='active';`, 'PT409', 'policy_rollout_receipts_unconfirmed');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['active', 'pending']);
});

test('direct next-batch activation rejects stale completed predecessor, then accepts refresh', async (f) => {
  const r = await create(f, rings([[f.agents[0]]], [[f.agents[1]]]));
  await status(r, 'paused');
  assert.equal(await receipt(f, 0, r.version), 't');
  // A trusted worker may complete a fresh batch directly without releasing its
  // successor. This reaches the stale-predecessor guard without a second active
  // batch or incomplete predecessor masking the freshness check.
  await sql(`set role service_role; update public.policy_rollout_batches set status='completed',completed_at=now()
    where rollout_id=${quote(r.rollout_id)} and status='active';`);
  await ageReceipt(f, 0);
  await status(r, 'running');
  const activation = `set role service_role; update public.policy_rollout_batches set status='active',started_at=now()
    where rollout_id=${quote(r.rollout_id)} and status='pending';`;
  await statementRejected(activation, 'PT409', 'policy_rollout_receipts_unconfirmed');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'pending']);
  assert.equal(await receipt(f, 0, r.version), 't');
  await sql(activation);
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'active']);
});

test('direct rollout completion rejects stale evidence even when every batch is completed', async (f) => {
  const r = await create(f, rings([[f.agents[0]]]));
  await status(r, 'paused');
  assert.equal(await receipt(f, 0, r.version), 't');
  await sql(`set role service_role; update public.policy_rollout_batches set status='completed',completed_at=now()
    where rollout_id=${quote(r.rollout_id)} and status='active';`);
  await ageReceipt(f, 0);
  await status(r, 'running');
  const completion = `set role service_role; update public.policy_rollouts set status='completed',completed_at=now() where id=${quote(r.rollout_id)};`;
  await statementRejected(completion, 'PT409');
  assert.equal((await progress(f, r)).status, 'running');
  assert.equal(await receipt(f, 0, r.version), 't');
  await sql(completion);
  assert.equal((await progress(f, r)).status, 'completed');
});

test('direct batch insert cannot add a predecessor before an already active later ring', async (f) => {
  const r = await create(f, rings([[f.agents[0]]], [[f.agents[1]]]));
  assert.equal(await receipt(f, 0, r.version), 't');
  await statementRejected(`set role service_role; insert into public.policy_rollout_batches(tenant_id,rollout_id,ring_order,batch_order,target_count)
    values (${quote(f.tenant)},${quote(r.rollout_id)},1,2,1);`, 'PT409');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'active']);
});

test('direct batch insert cannot extend a completed or cancelled rollout', async (f) => {
  const completed = await create(f, rings([[f.agents[0]]]));
  assert.equal(await receipt(f, 0, completed.version), 't');
  const cancelled = await create(f, rings([[f.agents[1]]]), { revision: 1 });
  await status(cancelled, 'cancelled');
  for (const r of [completed, cancelled]) {
    await statementRejected(`set role service_role; insert into public.policy_rollout_batches(tenant_id,rollout_id,ring_order,batch_order,target_count)
      values (${quote(f.tenant)},${quote(r.rollout_id)},1,2,1);`, 'PT409');
  }
  assert.equal(await sql('select count(*) from public.policy_rollout_batches;'), '2');
});

test('ordered multi-target batches and rings advance only after all receipts', async (f) => {
  const r = await create(f, rings([[f.agents[0], f.agents[1]], [f.agents[2]]], [[f.agents[3]]]));
  assert.equal(await sql('select count(*) from public.agent_policy_assignments;'), '2');
  assert.equal(await receipt(f, 2, r.version), 'f', 'pending target has not been assigned');
  assert.equal(await receipt(f, 0, r.version), 't');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['active', 'pending', 'pending']);
  assert.equal(await receipt(f, 1, r.version), 't');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'active', 'pending']);
  assert.equal(await receipt(f, 2, r.version), 't');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'completed', 'active']);
  assert.equal(await receipt(f, 3, r.version), 't');
  const p = await progress(f, r);
  assert.equal(p.status, 'completed');
  assert.equal(p.rollout_progress.current, 4);
  assert.equal(p.rollout_progress.observed_ack_percent, 100);
  assert.equal(p.receipt_type, 'agent_reported_policy_loaded');
  assert.equal(await sql('select count(*) from public.tenant_runtime_policies;'), '0', 'targeted rollout must not publish tenant fallback');
});

test('unknown/unconfirmed target blocks advancement, including cached stamp without receipt', async (f) => {
  const r = await create(f, rings([[f.agents[0], f.agents[1]], [f.agents[2]]]));
  await assertBlocked(f, r);
  await receipt(f, 0, r.version);
  await sql(`update public.policy_rollout_targets set acknowledged_at=now(),last_receipt_at=now() where agent_id=${quote(f.agents[1])};`);
  await assertBlocked(f, r);
  const p = await progress(f, r);
  assert.equal(p.rollout_progress.current, 1, 'cached stamps alone are not confirmation');
});

test('stale receipt blocks final peer acknowledgement and next assignment', async (f) => {
  const r = await create(f, rings([[f.agents[0], f.agents[1]], [f.agents[2]]]));
  await receipt(f, 0, r.version);
  await ageReceipt(f, 0);
  await receipt(f, 1, r.version);
  await assertBlocked(f, r);
  const p = await progress(f, r);
  assert.equal(p.rollout_progress.current, 1);
  assert.equal(p.rollout_progress.stale, 1);
  await receipt(f, 0, r.version);
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'active']);
});

test('authoritative receipt timestamp, not fresh cached target stamp, gates advancement', async (f) => {
  const r = await create(f, rings([[f.agents[0], f.agents[1]], [f.agents[2]]]));
  await receipt(f, 0, r.version);
  await sql(`update public.agent_policy_receipts set received_at=now()-interval '6 minutes' where agent_id=${quote(f.agents[0])};`);
  await receipt(f, 1, r.version);
  await assertBlocked(f, r);
  assert.equal((await progress(f, r)).rollout_progress.current, 1);
});

test('changed or removed assignment invalidates earlier acknowledgement', async (f) => {
  const r = await create(f, rings([[f.agents[0], f.agents[1]], [f.agents[2]]]));
  await receipt(f, 0, r.version);
  await sql(`delete from public.agent_policy_assignments where agent_id=${quote(f.agents[0])};`);
  await receipt(f, 1, r.version);
  await assertBlocked(f, r);
  assert.equal((await progress(f, r)).rollout_progress.current, 1);
});

test('superseded assignment rejects old receipt and invalidates cached acknowledgement', async (f) => {
  const r = await create(f, rings([[f.agents[0], f.agents[1]], [f.agents[2]]]));
  assert.equal(await receipt(f, 0, r.version), 't');
  await sql(`insert into public.runtime_policy_revisions(tenant_id,version,policy,updated_by) values (${quote(f.tenant)},2,'{}',${quote(f.owner)});
    update public.agent_policy_assignments set version=2 where agent_id=${quote(f.agents[0])};`);
  assert.equal(await receipt(f, 0, r.version), 'f', 'historical revision receipt cannot acknowledge a superseded selection');
  assert.equal(await receipt(f, 1, r.version), 't');
  await assertBlocked(f, r);
  const p = await progress(f, r);
  assert.equal(p.rollout_progress.current, 1);
  assert.equal(p.rollout_progress.outdated, 1);
});

test('completed batch receipt refresh updates progress while later batch runs', async (f) => {
  const r = await create(f, rings([[f.agents[0]], [f.agents[1]]]));
  await receipt(f, 0, r.version);
  await ageReceipt(f, 0);
  assert.equal((await progress(f, r)).rollout_progress.stale, 1);
  const firstAck = await sql(`select acknowledged_at from public.policy_rollout_targets where agent_id=${quote(f.agents[0])};`);
  assert.equal(await receipt(f, 0, r.version), 't');
  const p = await progress(f, r);
  assert.deepEqual(batchStatuses(p), ['completed', 'active']);
  assert.equal(p.rollout_progress.current, 1);
  assert.equal(p.rollout_progress.stale, 0);
  assert.equal(await sql(`select last_receipt_at > now()-interval '1 minute' from public.policy_rollout_targets where agent_id=${quote(f.agents[0])};`), 't');
  assert.equal(await sql(`select acknowledged_at from public.policy_rollout_targets where agent_id=${quote(f.agents[0])};`), firstAck);
});

test('fully completed rollout can refresh aged receipts without reopening batches', async (f) => {
  const r = await create(f, rings([[f.agents[0]]]));
  await receipt(f, 0, r.version);
  await ageReceipt(f, 0);
  assert.equal((await progress(f, r)).rollout_progress.stale, 1);
  assert.equal(await receipt(f, 0, r.version), 't');
  const p = await progress(f, r);
  assert.equal(p.status, 'completed');
  assert.equal(p.rollout_progress.current, 1);
  assert.equal(p.rollout_progress.stale, 0);
  assert.equal(await sql(`select last_receipt_at > now()-interval '1 minute' from public.policy_rollout_targets where agent_id=${quote(f.agents[0])};`), 't');
});

test('stale completed prior ring blocks later completion until prior receipt refresh', async (f) => {
  const r = await create(f, rings([[f.agents[0]]], [[f.agents[1]]], [[f.agents[2]]]));
  assert.equal(await receipt(f, 0, r.version), 't');
  await ageReceipt(f, 0);
  assert.equal(await receipt(f, 1, r.version), 't');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'active', 'pending']);
  assert.equal(await sql(`select count(*) from public.agent_policy_assignments where agent_id=${quote(f.agents[2])};`), '0');
  assert.equal(await receipt(f, 0, r.version), 't', 'refreshing completed prior ring retries active advancement');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'completed', 'active']);
});

test('missing/null ring batches and agent lists reject as validation errors without partial rows', async (f) => {
  for (const plan of [
    [{ ring_order: 1 }],
    [{ ring_order: 1, batches: null }],
    [{ ring_order: 1, batches: [{ batch_order: 1 }] }],
    [{ ring_order: 1, batches: [{ batch_order: 1, agent_ids: null }] }],
  ]) await rejected(createExpr(f, plan), '22023', 'invalid_policy_rollout');
  assert.equal(await sql('select count(*) from public.policy_rollouts;'), '0');
});

test('malformed/null policy hash and unknown key/version cannot record or advance', async (f) => {
  const r = await create(f, rings([[f.agents[0]]]));
  for (const digest of [null, '', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64), 'a'.repeat(64)]) assert.equal(await receipt(f, 0, r.version, digest), 'f');
  assert.equal(await receipt(f, 0, 999), 'f');
  assert.equal(await rpc(`public.record_policy_receipt('unknown-key',1,${quote(hash)})`), 'f');
  assert.equal(await sql('select count(*) from public.agent_policy_receipts;'), '0');
  assert.equal((await progress(f, r)).status, 'running');
});

test('paused receipts do not advance; stale resume remains blocked until refreshed', async (f) => {
  const r = await create(f, rings([[f.agents[0]], [f.agents[2]]]));
  await status(r, 'paused');
  await receipt(f, 0, r.version);
  assert.deepEqual(batchStatuses(await progress(f, r)), ['active', 'pending']);
  await ageReceipt(f, 0);
  await status(r, 'running');
  await assertBlocked(f, r);
  await receipt(f, 0, r.version);
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'active']);
});

test('fresh paused receipt advances exactly once on resume', async (f) => {
  const r = await create(f, rings([[f.agents[0]], [f.agents[1]]]));
  await status(r, 'paused');
  await receipt(f, 0, r.version);
  await status(r, 'running');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['completed', 'active']);
  assert.equal(await sql('select count(*) from public.agent_policy_assignments;'), '2');
});

test('revoked key, expired membership and inactive tenant cannot acknowledge', async (f) => {
  const r = await create(f, rings([[f.agents[0]]]));
  await sql(`update public.api_keys set revoked=true where key_hash=${quote(f.keys[0])};`);
  assert.equal(await receipt(f, 0, r.version), 'f');
  await sql(`update public.api_keys set revoked=false; update public.tenant_members set expires_at=now()-interval '1 second' where user_id=${quote(f.owner)};`);
  assert.equal(await receipt(f, 0, r.version), 'f');
  await sql(`update public.tenant_members set expires_at=null; update public.tenants set status='suspended' where id=${quote(f.tenant)};`);
  assert.equal(await receipt(f, 0, r.version), 'f');
  assert.equal((await progress(f, r)).rollout_progress.current, 0);
});

test('previous key hash accepted only inside overlap; revoked key never accepted', async (f) => {
  const r = await create(f, rings([[f.agents[0], f.agents[1]]]));
  const previous = 'b'.repeat(64);
  await sql(`update public.api_keys set previous_hash=${quote(previous)},previous_hash_expires_at=now()+interval '1 minute',rotated_at=now() where key_hash=${quote(f.keys[0])};`);
  const expression = `public.record_policy_receipt(${quote(previous)},${r.version},${quote(hash)})`;
  assert.equal(await rpc(expression), 't');
  await sql(`update public.api_keys set previous_hash_expires_at=now()-interval '1 second' where key_hash=${quote(f.keys[0])};`);
  assert.equal(await rpc(expression), 'f');
  await sql(`update public.api_keys set previous_hash_expires_at=now()+interval '1 minute',revoked=true where key_hash=${quote(f.keys[0])};`);
  assert.equal(await rpc(expression), 'f');
});

test('deleted sole active target cannot vacuously complete or activate next batch', async (f) => {
  const r = await create(f, rings([[f.agents[0]], [f.agents[2]]]));
  await sql(`delete from public.agents where id=${quote(f.agents[0])};`);
  assert.equal(await receipt(f, 0, r.version), 'f');
  await assertBlocked(f, r);
});

test('ordinary stage cancels running/paused rollout and clears only its assignments', async (f) => {
  const r = await create(f, rings([[f.agents[0]], [f.agents[1]]]));
  await status(r, 'paused');
  const stage = JSON.parse(await rpc(`public.stage_runtime_policy(${quote(f.tenant)},${quote(f.owner)},0,1,'{}'::jsonb,array[${quote(f.agents[3])}::uuid])`));
  assert.equal(stage.version, 2);
  assert.equal((await progress(f, r)).status, 'cancelled');
  assert.deepEqual(batchStatuses(await progress(f, r)), ['cancelled', 'cancelled']);
  assert.equal(await sql('select count(*) from public.agent_policy_assignments;'), '1');
  assert.equal(await sql('select agent_id from public.agent_policy_assignments;'), f.agents[3]);
});

test('stage racing paused resume cleans the assignment released by the concurrent resume', async (f) => {
  const r = await create(f, rings([[f.agents[0]], [f.agents[1]]]));
  await status(r, 'paused');
  assert.equal(await receipt(f, 0, r.version), 't');
  const resume = rawSql(`begin; set role service_role; update public.policy_rollouts set status='running' where id=${quote(r.rollout_id)}; select pg_sleep(1); commit;`, 'rings-racing-resume');
  let stage;
  try {
    const deadline = Date.now() + 2_000;
    while (await sql("select count(*) from pg_stat_activity where application_name='rings-racing-resume' and wait_event='PgSleep';") !== '1') {
      assert.ok(Date.now() < deadline, 'resume never reached parent-lock barrier');
      await delay(10);
    }
    stage = rawSql(`set role service_role; select public.stage_runtime_policy(${quote(f.tenant)},${quote(f.owner)},0,1,'{}'::jsonb,array[${quote(f.agents[3])}::uuid]);`, 'rings-racing-stage');
    const waitingDeadline = Date.now() + 800;
    while (await sql("select count(*) from pg_locks l join pg_stat_activity a on a.pid=l.pid where a.application_name='rings-racing-stage' and l.locktype='transactionid' and not l.granted;") !== '1') {
      assert.ok(Date.now() < waitingDeadline, 'stage did not concurrently wait on the resume transaction');
      await delay(10);
    }
    checked(await resume);
    assert.equal(JSON.parse(checked(await stage)).version, 2);
    const p = await progress(f, r);
    assert.equal(p.status, 'cancelled');
    assert.deepEqual(batchStatuses(p), ['completed', 'cancelled']);
    assert.equal(await sql('select count(*) from public.agent_policy_assignments;'), '1');
    assert.equal(await sql('select agent_id from public.agent_policy_assignments;'), f.agents[3], 'concurrently released next-batch assignment must not survive cancellation');
  } finally { await Promise.allSettled([resume, ...(stage ? [stage] : [])]); }
});

test('cancelled staged selection can report lower published fallback version', async (f) => {
  const fallback = { command_default: 'allow' };
  const fallbackHash = createHash('sha256').update(JSON.stringify(fallback)).digest('hex');
  const published = JSON.parse(await rpc(`to_jsonb(public.publish_runtime_policy(${quote(f.tenant)},${quote(f.owner)},0,${json(fallback)}))`));
  assert.equal(published.version, 1);
  const r = await create(f, rings([[f.agents[0]], [f.agents[1]]]), { expected: 1, revision: 1 });
  assert.equal(r.version, 2);
  assert.equal(await receipt(f, 0, r.version), 't');
  const stage = JSON.parse(await rpc(`public.stage_runtime_policy(${quote(f.tenant)},${quote(f.owner)},1,2,'{}'::jsonb,array[${quote(f.agents[3])}::uuid])`));
  assert.equal(stage.version, 3);
  assert.equal((await progress(f, r)).status, 'cancelled');
  assert.equal(await receipt(f, 0, 1, fallbackHash), 't', 'current selected fallback supersedes the historical higher receipt');
  assert.equal(await sql(`select version from public.agent_policy_receipts where agent_id=${quote(f.agents[0])};`), '1');
  assert.equal(await receipt(f, 0, r.version), 'f', 'cancelled higher rollout version is no longer selected');
});

test('global publication cancels rollout, advances past staged revision and clears assignments', async (f) => {
  const r = await create(f, rings([[f.agents[0]], [f.agents[1]]]));
  const published = JSON.parse(await rpc(`to_jsonb(public.publish_runtime_policy(${quote(f.tenant)},${quote(f.owner)},0,'{}'::jsonb))`));
  assert.equal(published.version, 2);
  assert.equal((await progress(f, r)).status, 'cancelled');
  assert.equal(await sql('select count(*) from public.agent_policy_assignments;'), '0');
});

let owned = false;
let failures = 0;
const started = Date.now();
try {
  checked(await docker(['image', 'inspect', image, '--format', '{{.Id}}']));
  checked(await docker(['run', '--pull', 'never', '--detach', '--name', container,
    '--label', `aidr.policy-rings-test=${owner}`, '--network', 'none',
    '--tmpfs', '/var/lib/postgresql/data:rw', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
    image, 'postgres', '-c', 'statement_timeout=5000', '-c', 'lock_timeout=4000']));
  owned = true;
  console.log(`Owned PostgreSQL container: ${container} (${image}, --pull never, network none)`);
  const readyDeadline = Date.now() + 15_000;
  // The image's initialization server is socket-only and shuts down once;
  // TCP readiness avoids mistaking that temporary server for the final server.
  while ((await docker(['exec', container, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'])).code !== 0) {
    assert.ok(Date.now() < readyDeadline, 'PostgreSQL startup exceeded fixed 15s deadline');
    await delay(100);
  }
  await sql(readFileSync(new URL('scripts/fixtures/policy-rings-base.sql', root), 'utf8'));
  for (const name of migrations) {
    const source = readFileSync(new URL(`supabase/migrations/${name}`, root), 'utf8');
    await sql(source);
    console.log(`Applied real migration: ${name} sha256=${createHash('sha256').update(source).digest('hex')}`);
  }
  console.log(`Fixture scope: ${fileURLToPath(new URL('scripts/fixtures/policy-rings-base.sql', root))}`);
  for (const { name, run } of cases) {
    try {
      await run(await seed());
      console.log(`PASS ${name}`);
    } catch (error) {
      failures++;
      console.error(`FAIL ${name}\n${error.stack ?? error}`);
    }
  }
  console.log(`RESULT ${cases.length - failures}/${cases.length} passed; ${failures} failed; 0 skipped (${((Date.now() - started) / 1000).toFixed(1)}s)`);
  if (failures) process.exitCode = 1;
} catch (error) {
  console.error(error.stack ?? error);
  process.exitCode = 1;
} finally {
  if (owned) {
    try {
      const label = checked(await docker(['inspect', '--format', '{{index .Config.Labels "aidr.policy-rings-test"}}', container]));
      assert.equal(label, owner, 'refusing to remove a container not owned by this run');
      checked(await docker(['rm', '--force', '--volumes', container]));
      console.log(`Removed owned container: ${container}`);
    } catch (error) {
      console.error(`Owned-container cleanup failed: ${error.stack ?? error}`);
      process.exitCode = 1;
    }
  }
}
