#!/usr/bin/env node
/**
 * Real PostgreSQL regression, with no npm/Postgres-client dependency.
 *
 *   node scripts/test-invoice-finance-postgres.mjs
 *   node scripts/test-invoice-finance-postgres.mjs --image postgres:16
 *
 * Requires a LOCAL Docker daemon and an already cached official PostgreSQL image
 * (default postgres:17-alpine). Never pulls images or connects to an existing DB.
 * A uniquely named disposable container has no network, host ports or host mounts;
 * PGDATA lives in tmpfs and the container/volumes are removed in finally.
 * DOCKER_HOST / a remote Docker context are rejected. No DATABASE_URL is accepted.
 *
 * Scope: minimal prerequisite tables/roles, both shipped invoice migrations and
 * the new finance-authority migration applied VERBATIM, real SET ROLE checks,
 * separate committed preflight/transition transactions, and two genuinely
 * overlapping approval transactions. Not the complete Supabase migration chain,
 * PostgREST/JWT/Edge integration, deployment evidence, or a retention test.
 *
 * Concurrency proof: gate holds the existing entitlement row; A starts approving
 * order 105 and is observed waiting for gate. B starts approving DIFFERENT order
 * 106 and is observed waiting on A/gate while A is still blocked. Only then is
 * gate released. This exposes the stale subtotal bug without relying on sleeps
 * to make queries overlap. pg_blocking_pids/pg_stat_activity prove the schedule.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = new URL('../', import.meta.url);
const options = process.argv.slice(2);
if (options.includes('--help')) {
  console.log('Usage: node scripts/test-invoice-finance-postgres.mjs [--image postgres:17-alpine]');
  console.log('Local Docker + cached PostgreSQL image required; always creates/removes an isolated tmpfs DB.');
  process.exit(0);
}
assert(options.length === 0 || (options.length === 2 && options[0] === '--image'), 'Unknown arguments; use --help');
const image = options[1] ?? 'postgres:17-alpine';
assert(/^postgres:(?:1[5-9])(?:[.\w-]*)$/.test(image), 'Use a cached official postgres:15+ image');
const container = `aidr-invoice-finance-test-${randomUUID()}`;
const database = 'invoice_finance_regression';
const tenant = '00000000-0000-0000-0000-000000000001';
const finance = '00000000-0000-0000-0000-000000000013';
const sessions = [];
let containerCreated = false;

function command(args, timeout = 30_000) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { cwd: fileURLToPath(root), stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill(), timeout);
    child.stdout.on('data', data => { stdout += data; });
    child.stderr.on('data', data => { stderr += data; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`docker ${args.join(' ')} exited ${code}\n${stderr}\n${stdout}`));
      else resolve(stdout.trim());
    });
  });
}

class SqlSession {
  constructor(name) {
    this.name = name;
    this.buffer = '';
    this.errors = '';
    this.pending = null;
    this.closed = false;
    this.child = spawn('docker', ['exec', '-i', container, 'psql', '-X', '-q', '-A', '-t',
      '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database],
    { cwd: fileURLToPath(root), stdio: ['pipe', 'pipe', 'pipe'] });
    this.child.stdout.on('data', data => {
      this.buffer += data;
      const pending = this.pending;
      if (!pending) return;
      const index = this.buffer.indexOf(`${pending.marker}\n`);
      if (index < 0) return;
      const result = this.buffer.slice(0, index).trim();
      this.buffer = this.buffer.slice(index + pending.marker.length + 1);
      this.pending = null;
      clearTimeout(pending.timer);
      pending.resolve(result);
    });
    this.child.stderr.on('data', data => { this.errors += data; });
    this.child.on('error', error => this.fail(error));
    this.child.stdin.on('error', error => this.fail(error));
    this.exited = new Promise(resolve => this.child.on('close', code => {
      this.closed = true;
      this.fail(new Error(`${name}: psql exited ${code}\n${this.errors}\n${this.buffer}`));
      resolve();
    }));
    sessions.push(this);
  }

  fail(error) {
    if (!this.pending) return;
    clearTimeout(this.pending.timer);
    this.pending.reject(error);
    this.pending = null;
  }

  query(sql) {
    assert(!this.closed, `${this.name}: session already closed`);
    assert(!this.pending, `${this.name}: query already running`);
    return new Promise((resolve, reject) => {
      const marker = `test_end_${randomUUID().replaceAll('-', '')}`;
      const timer = setTimeout(() => {
        this.fail(new Error(`${this.name}: query timed out\n${this.errors}\n${this.buffer}`));
        this.child.kill();
      }, 45_000);
      this.pending = { marker, timer, resolve, reject };
      this.child.stdin.write(`${sql}\n\\echo ${marker}\n`);
    });
  }

  async initialize() {
    this.pid = Number(await this.query(`set application_name = '${this.name}';
      set statement_timeout = '30s'; set lock_timeout = '25s';
      set idle_in_transaction_session_timeout = '45s'; select pg_backend_pid();`));
    assert(Number.isSafeInteger(this.pid) && this.pid > 0);
    return this;
  }

  close() {
    if (!this.closed) this.child.stdin.end('\\q\n');
    return this.exited;
  }
}

async function load(session, path) {
  const sql = await readFile(new URL(path, root), 'utf8');
  const output = await session.query(sql);
  for (const line of output.split('\n')) if (line.startsWith('PASS ')) console.log(line);
  console.log(`Applied ${path}`);
}

async function waitForLock(observer, waiterPid, blockerPids) {
  const deadline = Date.now() + 15_000;
  let last;
  while (Date.now() < deadline) {
    last = JSON.parse(await observer.query(`select json_build_object(
      'state', state, 'wait_type', wait_event_type, 'wait_event', wait_event,
      'blockers', pg_blocking_pids(pid)) from pg_stat_activity where pid = ${waiterPid};`));
    if (last.state === 'active' && last.wait_type === 'Lock'
      && last.blockers.some(pid => blockerPids.includes(pid))) return last;
    // Poll only for observed lock state; elapsed time never establishes overlap.
    await delay(25);
  }
  throw new Error(`No deterministic overlap for PID ${waiterPid}: ${JSON.stringify(last)}`);
}

async function concurrentApprovals(observer) {
  const gate = await new SqlSession('finance_gate').initialize();
  const first = await new SqlSession('finance_approval_A').initialize();
  const second = await new SqlSession('finance_approval_B').initialize();
  await gate.query(`begin; select extra_agents from public.entitlements where tenant_id = '${tenant}' for update;`);
  await first.query('set role service_role;');
  await second.query('set role service_role;');
  const approval = order => `select public.record_invoice_approval('${tenant}', '${finance}',
    '00000000-0000-0000-0000-000000000${order}', 12345, 'USD', repeat('d',64));`;
  // Attach rejection handlers immediately: an unexpected early SQL error must
  // fail the test, not become an unhandled rejection while the observer waits.
  const resultA = first.query(approval(105)).then(value => ({ value }), error => ({ error }));
  const blockedA = await waitForLock(observer, first.pid, [gate.pid]);
  const resultB = second.query(approval(106)).then(value => ({ value }), error => ({ error }));
  const blockedB = await waitForLock(observer, second.pid, [first.pid, gate.pid]);
  assert.equal(blockedB.wait_event, 'advisory', 'second order must wait on the tenant lock');
  assert(blockedB.blockers.includes(first.pid), 'first approval must serialize the second');
  await waitForLock(observer, first.pid, [gate.pid]);
  console.log(`Observed overlap: A ${JSON.stringify(blockedA)}; B ${JSON.stringify(blockedB)}`);
  await gate.query('commit;');
  for (const result of await Promise.all([resultA, resultB])) {
    if (result.error) throw result.error;
    assert.equal(JSON.parse(result.value).status, 'paid');
  }
  await observer.query(`select test.assert(
      (select extra_agents = 34 from public.entitlements where tenant_id = '${tenant}')
      and (select sum(agents_granted) = 34 and count(*) = 4
        from public.enterprise_invoice_approvals where tenant_id = '${tenant}')
      and (select count(*) = 2 from public.admin_audit_logs
        where actor_user_id = '${finance}' and detail ->> 'order_id' in
          ('00000000-0000-0000-0000-000000000105', '00000000-0000-0000-0000-000000000106')),
      'overlapping different-order approvals must preserve 3 + 7 + 11 + 13 agents and both audits');`);
  console.log('PASS deterministic overlapping different-order same-tenant approvals: entitlement = ledger sum = 34; both audits committed');
}

async function cleanup() {
  if (!containerCreated) return;
  await command(['rm', '-f', '-v', container]);
  containerCreated = false;
  console.log(`Removed disposable container and DB: ${container}`);
}

try {
  // Refuse remote Docker endpoints even when the current context is misleading.
  assert(!process.env.DOCKER_HOST || /^(unix:|npipe:)/.test(process.env.DOCKER_HOST),
    'Refusing non-local DOCKER_HOST');
  const context = JSON.parse(await command(['context', 'inspect']));
  assert(/^(unix:|npipe:)/.test(context[0]?.Endpoints?.docker?.Host ?? ''),
    'Refusing a non-local Docker context');
  await command(['image', 'inspect', image]); // No implicit network pull.
  console.log(`Using cached ${image}; isolated container ${container}`);
  // Set before run so cleanup also handles an interrupted/partially failed run.
  containerCreated = true;
  await command(['run', '--detach', '--pull=never', '--name', container,
    '--network', 'none', '--tmpfs', '/var/lib/postgresql/data:rw',
    '-e', 'PGDATA=/var/lib/postgresql/data/pgdata',
    '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', `POSTGRES_DB=${database}`, image]);
  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      await command(['exec', container, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', '-d', database], 5_000);
      break;
    } catch (error) {
      if (Date.now() >= deadline) throw error;
      await delay(100);
    }
  }
  const db = await new SqlSession('finance_regression').initialize();
  console.log(`PostgreSQL ${await db.query('show server_version;')}`);
  await load(db, 'scripts/fixtures/invoice-finance-bootstrap.sql');
  await load(db, 'supabase/migrations/20260913000003_invoice_entitlement.sql');
  await load(db, 'supabase/migrations/20260914000000_invoice_approval_transition.sql');
  await load(db, 'scripts/fixtures/invoice-finance-seed.sql');
  await load(db, 'supabase/migrations/20260916000001_invoice_finance_authority.sql');
  await load(db, 'scripts/fixtures/invoice-finance-regression.sql');
  await concurrentApprovals(db);
  console.log('PASS all invoice finance PostgreSQL regressions');
} catch (error) {
  console.error(error.stack ?? error);
  process.exitCode = 1;
} finally {
  // Remove the isolated DB first: this also terminates any failed/blocking SQL
  // backend, ensuring psql session shutdown cannot wait on a held test lock.
  try { await cleanup(); } catch (error) { console.error(`CLEANUP FAILED: ${error.message}`); process.exitCode = 1; }
  await Promise.all(sessions.map(session => session.close()));
}
