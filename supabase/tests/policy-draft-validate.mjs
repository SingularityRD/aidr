#!/usr/bin/env node
// Usage: node supabase/tests/policy-draft-validate.mjs
// Requires only Node and Docker with cached postgres:17-alpine. Never uses a
// host port, network, host mount, existing database, or container removal.
// All data is on tmpfs; the stopped dedicated container is intentionally kept.
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const here = dirname(fileURLToPath(import.meta.url));
const migration = resolve(here, '../migrations/20260916000003_policy_document_draft_cas.sql');
const name = `policy-draft-validation-${Date.now()}-${randomUUID().slice(0, 8)}`;
const source = '# café 👋\r\nname: İstanbul\r\n';
if (createHash('sha256').update(source, 'utf8').digest('hex') !==
    'd42a86e0fc6548a5e8aab7e8460a1dd07addca543c8f096179f163a487218bb1') {
  throw new Error('Independent UTF8/CRLF reference hash mismatch');
}
function docker(args, required = true) {
  const result = spawnSync('docker', args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (required && result.status !== 0) throw new Error(`docker ${args[0]} exited ${result.status}`);
  return result.status;
}
const psqlArgs = ['exec', name, 'psql', '-X', '-U', 'postgres', '-d', 'postgres',
  '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose'];
const sql = command => docker([...psqlArgs, '-c', command]);
function session(command) {
  return new Promise((resolveSession, reject) => {
    const commands = (Array.isArray(command) ? command : [command]).flatMap(text => ['-c', text]);
    const child = spawn('docker', [...psqlArgs, ...commands], { stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', code => resolveSession(code));
  });
}
const tenant = n => `10000000-0000-0000-0000-${String(n).padStart(12, '0')}`;
const actor = '20000000-0000-0000-0000-000000000001';
const hash = text => createHash('sha256').update(text).digest('hex');
let created = false;
try {
  console.log(`Dedicated container: ${name}`);
  console.log(`Real migration SHA256: ${createHash('sha256').update(readFileSync(migration)).digest('hex')}`);
  docker(['run', '--detach', '--pull', 'never', '--network', 'none', '--name', name,
    '--env', 'POSTGRES_PASSWORD=isolated-policy-draft-only',
    '--env', 'POSTGRES_INITDB_ARGS=--encoding=UTF8',
    '--tmpfs', '/var/lib/postgresql/data', 'postgres:17-alpine']);
  created = true;
  let ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    if (docker(['exec', name, 'pg_isready', '-U', 'postgres'], false) === 0) {
      ready = true;
      break;
    }
    await delay(300);
  }
  if (!ready) throw new Error('Dedicated PostgreSQL did not become ready');
  for (const [host, container] of [
    [resolve(here, 'policy-draft-fixture.sql'), '/tmp/policy-draft-fixture.sql'],
    [migration, '/tmp/policy-draft-migration.sql'],
    [resolve(here, 'policy-draft-checks.sql'), '/tmp/policy-draft-checks.sql'],
  ]) {
    docker(['cp', host, `${name}:${container}`]);
    docker([...psqlArgs, '-f', container]);
  }
  // Both first-save clients use the absent-head precondition. The winner holds
  // its transaction open so the other connection must serialize behind it.
  const firstCommand = `begin; set local role service_role;
    do $$ begin begin
      perform public.save_policy_document_draft('${tenant(4)}','${actor}','race-first','${hash('race-first')}',null,null,null);
      insert into draft_test.race_outcomes values('first','winner');
      perform pg_sleep(1);
    exception when sqlstate 'PT409' then
      insert into draft_test.race_outcomes values('first','PT409');
    end; end $$; commit;`;
  const firstCodes = await Promise.all([session(firstCommand), session(firstCommand)]);
  if (firstCodes.some(code => code !== 0)) throw new Error(`Unexpected first-save error: ${firstCodes}`);
  sql(`select draft_test.check_result('concurrent first saves: exactly one winner, one PT409 and one version-1 row',
    (select count(*)=1 and min(version)=1 from public.team_policies where tenant_id='${tenant(4)}')
    and (select count(*)=2 and count(*) filter(where outcome='winner')=1 and count(*) filter(where outcome='PT409')=1 from draft_test.race_outcomes where kind='first'));`);
  sql(`set role service_role; select public.save_policy_document_draft('${tenant(5)}','${actor}','seed','${hash('seed')}',null,null,null);`);
  // Read the expected head before either RPC writes. Both require version 1;
  // holding the winning transaction open also exercises the waiting updater.
  const updateCommand = `begin; set local role service_role;
    do $$ declare expected uuid; begin
      select id into expected from public.team_policies where tenant_id='${tenant(5)}';
      begin
        perform public.save_policy_document_draft('${tenant(5)}','${actor}','race-update','${hash('race-update')}',expected,1,'${hash('seed')}');
        insert into draft_test.race_outcomes values('update','winner');
        perform pg_sleep(1);
      exception when sqlstate 'PT409' then
        insert into draft_test.race_outcomes values('update','PT409');
      end;
    end $$; commit;`;
  const updateCodes = await Promise.all([session(updateCommand), session(updateCommand)]);
  if (updateCodes.some(code => code !== 0)) throw new Error(`Unexpected update error: ${updateCodes}`);
  sql(`select draft_test.check_result('concurrent updates: exactly one winner, one PT409 and one new revision',
    (select count(*)=1 and min(version)=2 and min(content)='race-update' from public.team_policies where tenant_id='${tenant(5)}')
    and (select count(*)=2 and count(*) filter(where outcome='winner')=1 and count(*) filter(where outcome='PT409')=1 from draft_test.race_outcomes where kind='update'));`);
  // A session-level lock lets the expiry setup COMMIT while retaining the gate.
  // The waiter synchronizes on that actual lock and committed future expiry,
  // then blocks inside the real RPC until its membership has expired.
  const expiryHolder = [
    `set application_name='policy_draft_expiry_holder';`,
    `select pg_advisory_lock(hashtextextended('${tenant(1)}'::text,912));`,
    `update public.tenant_members set expires_at=clock_timestamp()+interval '1 second' where tenant_id='${tenant(1)}' and user_id='${actor}';`,
    'select pg_sleep(2);',
    `select pg_advisory_unlock(hashtextextended('${tenant(1)}'::text,912));`,
  ];
  const expiryWaiter = `do $$ declare ready boolean:=false; head public.team_policies%rowtype; begin
    for attempt in 1..300 loop
      select exists(select 1 from pg_locks l join pg_stat_activity a on a.pid=l.pid
        where a.application_name='policy_draft_expiry_holder' and l.locktype='advisory' and l.granted)
        and exists(select 1 from public.tenant_members where tenant_id='${tenant(1)}' and user_id='${actor}' and expires_at>clock_timestamp()) into ready;
      exit when ready;
      perform pg_stat_clear_snapshot();
      perform pg_sleep(0.01);
    end loop;
    if not ready then raise exception 'Expiry test synchronization failed'; end if;
    select * into head from public.team_policies where tenant_id='${tenant(1)}';
    perform draft_test.expect_state('membership expiring while blocked on real advisory lock is denied',
      format('select public.save_policy_document_draft(%L,%L,%L,%L,%L,%s,%L)',head.tenant_id,'${actor}',head.content,head.source_sha256,head.id,head.version,head.source_sha256),'42501');
  end $$;`;
  const expiryCodes = await Promise.all([session(expiryHolder), session(expiryWaiter)]);
  if (expiryCodes.some(code => code !== 0)) throw new Error(`Expiry concurrency error: ${expiryCodes}`);
  sql(`update public.tenant_members set expires_at=null where tenant_id='${tenant(1)}' and user_id='${actor}';`);
  // Deliberately continue after the error: subsequent statement must fail with
  // 25P02 and COMMIT must report ROLLBACK. No savepoint masks the transaction abort.
  docker([...psqlArgs, '-v', 'ON_ERROR_STOP=0', '-c', 'begin;',
    '-c', 'insert into draft_test.rollback_probe values(1);',
    '-c', `set local role service_role; select public.save_policy_document_draft('${tenant(1)}','${actor}','invalid','${'0'.repeat(64)}',null,null,null);`,
    '-c', 'insert into draft_test.rollback_probe values(2);', '-c', 'commit;']);
  sql(`select draft_test.check_result('uncaught RPC failure aborts entire explicit transaction',
    not exists(select 1 from draft_test.rollback_probe));
    table draft_test.results;
    do $$ begin
      if exists(select 1 from draft_test.results where not passed) then
        raise exception 'Policy draft validation has failed assertions';
      end if;
      raise notice 'ALL % POLICY DRAFT CHECKS PASSED', (select count(*) from draft_test.results);
    end $$;`);
  console.log(`PASS: migration, authorization, UTF8/CRLF, history, CAS concurrency, transaction rollback. Container: ${name}`);
} finally {
  if (created) {
    docker(['stop', name]);
    console.log(`Stopped and retained own container: ${name} (tmpfs database discarded; no docker rm).`);
  }
}
