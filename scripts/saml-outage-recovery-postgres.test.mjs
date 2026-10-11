// Full canonical migrations; native HMAC authority and atomic recovery in our
// own random offline PostgreSQL. No existing database, Auth or IdP is used.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { preparePayload, signPayload } from "./saml-outage-recovery.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-saml-outage-${randomUUID()}`;
const args = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=10000 -c lock_timeout=5000", container,
  "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const literal = value => `'${String(value).replaceAll("'", "''")}'`;
const json = value => `${literal(JSON.stringify(value))}::jsonb`;
function docker(args, input = "") {
  return new Promise((done, reject) => {
    const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 });
    let stdout = "", stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", code => done({ code, stdout: stdout.trim(), stderr }));
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}
async function sql(text) {
  const result = await docker(args, text);
  assert.equal(result.code, 0, result.stderr);
  return result.stdout;
}
async function denied(text, pattern) {
  const result = await docker(args, text);
  assert.notEqual(result.code, 0, "statement must fail closed");
  assert.match(result.stderr, pattern);
}
const rpc = async expression => JSON.parse(await sql(`set role service_role; select ${expression};`));
const approvals = (text, keys) => keys.map(key => ({ key_id: key.key_id,
  mac_hex: createHmac("sha256", Buffer.from(key.secret_hex, "hex")).update(text, "utf8").digest("hex") }));
const call = (text, proofs) => `public.recover_tenant_saml_outage(${literal(text)},${json(proofs)})`;

test("full SAML outage recovery requires two native operator approvals and immutable atomic evidence", { timeout: 600_000 }, async t => {
  const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
    "-e", "POSTGRES_PASSWORD=saml-outage-fixture-only", "supabase/postgres:17.11.0.004"]);
  assert.equal(started.code, 0, started.stderr);
  try {
    let ready = false;
    for (let i = 0; i < 150 && !ready; i++) {
      ready = (await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0;
      if (!ready) await delay(100);
    }
    assert.ok(ready);
    const bootstrap = await docker(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
      `grant create on schema storage to postgres;
       create table if not exists auth.sso_providers(id uuid primary key,disabled boolean);
       create table if not exists auth.saml_providers(id uuid primary key,sso_provider_id uuid references auth.sso_providers(id));
       create table if not exists auth.sessions(id uuid primary key,user_id uuid references auth.users(id) on delete cascade,aal text,not_after timestamptz,created_at timestamptz default now());
       create table if not exists auth.identities(id uuid primary key,user_id uuid references auth.users(id) on delete cascade,provider text,provider_id text,identity_data jsonb);
       grant select,insert,update,delete on auth.sso_providers,auth.saml_providers,auth.sessions,auth.identities to postgres;
       create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb $$;`);
    assert.equal(bootstrap.code, 0, bootstrap.stderr);
    await sql(`create table storage.buckets(id text primary key,name text,public boolean);
      create table storage.objects(id uuid primary key default gen_random_uuid(),bucket_id text,name text,metadata jsonb);
      create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name,'/') $$;`);
    const migrations = readdirSync(resolve(root,"supabase/migrations")).filter(name => name.endsWith(".sql")).sort();
    for (const name of migrations) {
      const result = await docker(args, `begin;\n${readFileSync(resolve(root,"supabase/migrations",name),"utf8")}\ncommit;`);
      assert.equal(result.code, 0, `${name}: ${result.stderr}`);
    }
    t.diagnostic(`Applied ${migrations.length} canonical migrations through ${migrations.at(-1)}`);
    async function fixture({ keyExpiry = "now()+interval '1 hour'" } = {}) {
      const tenant = randomUUID(), owner = randomUUID(), backup = randomUUID(), provider = randomUUID(), session = randomUUID();
      const keys = [0,1].map(() => ({ tenant_id: tenant,key_id:randomUUID(),operator_id:randomUUID(),secret_hex:randomBytes(32).toString("hex") }));
      await sql(`insert into auth.users(id,email,raw_app_meta_data) values
        (${literal(owner)},${literal(`outage-${owner}@example.invalid`)},'{"aidr_scim_provisioned":true}'),
        (${literal(backup)},${literal(`outage-${backup}@example.invalid`)},'{"aidr_scim_provisioned":true}');
        insert into public.tenants(id,name,kind,created_by) values (${literal(tenant)},'SAML outage fixture','enterprise',${literal(owner)});
        insert into public.tenant_members(tenant_id,user_id,role) values
          (${literal(tenant)},${literal(owner)},'owner'),(${literal(tenant)},${literal(backup)},'owner');
        insert into auth.sso_providers(id,disabled) values (${literal(provider)},false);
        insert into auth.saml_providers(id,sso_provider_id) values (gen_random_uuid(),${literal(provider)});
        insert into auth.identities(id,user_id,provider,provider_id,identity_data)
          select gen_random_uuid(),id,'sso:'||${literal(provider)},'directory-'||id,jsonb_build_object('sub','directory-'||id)
          from auth.users where id in (${literal(owner)},${literal(backup)});
        insert into public.tenant_identity_policies(tenant_id,require_mfa,break_glass_enabled,required_saml_provider_id,updated_by)
          values (${literal(tenant)},true,false,${literal(provider)},${literal(owner)});
        insert into auth.sessions(id,user_id,aal,not_after) values (${literal(session)},${literal(owner)},'aal2',now()-interval '1 hour');
        insert into app.tenant_saml_recovery_operator_keys(tenant_id,key_id,operator_id,secret,not_before,not_after) values
          ${keys.map(key => `(${literal(tenant)},${literal(key.key_id)},${literal(key.operator_id)},decode(${literal(key.secret_hex)},'hex'),now()-interval '2 hours',${keyExpiry})`).join(",")};
        update public.tenant_data_retention_policies set retention_days=0 where tenant_id=${literal(tenant)};`);
      const text = preparePayload({tenant_id:tenant,current_provider_id:provider,recovery_owner_id:owner,
        change_ref:"INC-SAML-OUTAGE-123",reason:"Restore owner access after complete provider outage"});
      const proofs = keys.map(key => signPayload(text,key)).map(({key_id,mac_hex}) => ({key_id,mac_hex}));
      return { tenant,owner,backup,provider,session,keys,text,proofs };
    }
    async function unchanged(f) {
      assert.equal(await sql(`select required_saml_provider_id from public.tenant_identity_policies where tenant_id=${literal(f.tenant)};`),f.provider);
      assert.equal(await sql(`select count(*) from public.tenant_saml_outage_recoveries where tenant_id=${literal(f.tenant)};`),"0");
      assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='identity.saml.outage_recovered';`),"0");
    }
    await t.test("service/browser cannot enroll or read custody keys; one key cannot impersonate two operators", async () => {
      const f = await fixture();
      for (const role of ["service_role","authenticated","anon"]) {
        await denied(`set role ${role}; select secret from app.tenant_saml_recovery_operator_keys;`,/permission denied/);
        await denied(`set role ${role}; update app.tenant_saml_recovery_operator_keys set enabled=false;`,/permission denied/);
      }
      await denied(`set role service_role; update public.tenant_identity_policies set required_saml_provider_id=null where tenant_id=${literal(f.tenant)};`,/permission denied/);
      await denied(`set role service_role; delete from public.tenant_identity_policies where tenant_id=${literal(f.tenant)};`,/permission denied/);
      await denied(`set role service_role; insert into public.tenant_identity_policies(tenant_id,required_saml_provider_id) values (${literal(f.tenant)},${literal(f.provider)});`,/permission denied/);
      await denied(`insert into app.tenant_saml_recovery_operator_keys(tenant_id,key_id,operator_id,secret,not_before,not_after)
        values (${literal(f.tenant)},gen_random_uuid(),gen_random_uuid(),decode(${literal(f.keys[0].secret_hex)},'hex'),now(),now()+interval '1 hour');`,/duplicate key/);
      await denied(`set role service_role; select ${call(f.text,[f.proofs[0],f.proofs[0]])};`,/saml_recovery_approval_invalid/);
      await unchanged(f);
    });
    await t.test("missing, forged, altered, foreign-tenant and wrong-purpose approvals refuse atomically", async () => {
      const f = await fixture(), foreign = await fixture();
      await denied(`set role service_role; select ${call(f.text,[f.proofs[0]])};`,/two_approvals_required/);
      await denied(`set role service_role; select ${call(f.text,[f.proofs[0],{...f.proofs[1],mac_hex:"0".repeat(64)}])};`,/approval_invalid/);
      const changed = JSON.stringify({...JSON.parse(f.text),change_ref:"INC-ALTERED"});
      await denied(`set role service_role; select ${call(changed,f.proofs)};`,/approval_invalid/);
      await denied(`set role service_role; select ${call(f.text,foreign.proofs)};`,/approval_invalid/);
      const wrong = JSON.stringify({...JSON.parse(f.text),purpose:"aidr.other.operation"});
      await denied(`set role service_role; select ${call(wrong,approvals(wrong,f.keys))};`,/invalid_request/);
      for (const role of ["anon","authenticated"]) await denied(`set role ${role}; select ${call(f.text,f.proofs)};`,/permission denied/);
      await unchanged(f);
    });
    await t.test("expired, revoked and stale-provider authority never suspends another policy", async () => {
      const f = await fixture(), expiredKeys = await fixture({keyExpiry:"now()-interval '1 hour'"});
      const now = Math.floor(Date.now()/1000), old = JSON.stringify({...JSON.parse(f.text),issued_at:now-600,expires_at:now-300});
      await denied(`set role service_role; select ${call(old,approvals(old,f.keys))};`,/approval_expired/);
      await denied(`set role service_role; select ${call(expiredKeys.text,expiredKeys.proofs)};`,/approval_invalid/);
      const stale = JSON.stringify({...JSON.parse(f.text),current_provider_id:randomUUID()});
      await denied(`set role service_role; select ${call(stale,approvals(stale,f.keys))};`,/policy_conflict/);
      await sql(`update app.tenant_saml_recovery_operator_keys set enabled=false where tenant_id=${literal(f.tenant)} and key_id=${literal(f.keys[1].key_id)};`);
      await denied(`set role service_role; select ${call(f.text,f.proofs)};`,/approval_invalid/);
      await unchanged(f); await unchanged(expiredKeys);
    });
    await t.test("demoted or deleted recovery owner cannot be replaced by receipt metadata", async () => {
      const f = await fixture();
      const candidate = JSON.stringify({...JSON.parse(f.text),recovery_owner_id:f.keys[0].operator_id});
      await denied(`set role service_role; select ${call(candidate,approvals(candidate,f.keys))};`,/owner_required/);
      await sql(`update public.tenant_members set role='member' where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`);
      await denied(`set role service_role; select ${call(f.text,f.proofs)};`,/owner_required/);
      await unchanged(f);
      const deleted = await fixture();
      await sql(`delete from auth.users where id=${literal(deleted.owner)};`);
      await denied(`set role service_role; select ${call(deleted.text,deleted.proofs)};`,/owner_required/);
      await unchanged(deleted);
    });
    await t.test("expired provider sessions recover only with both operator MACs and preserved hold/barriers", async () => {
      const f = await fixture();
      const oldSession = {aal:"aal2",session_id:f.session,saml_provider_id:f.provider,
        issued_at:new Date(Date.now()-7_200_000).toISOString(),expires_at:new Date(Date.now()-3_600_000).toISOString()};
      await denied(`set role service_role; select public.request_tenant_saml_policy_change(${literal(f.tenant)},${literal(f.owner)},null,
        'Owner requests normal SAML suspension','NORMAL-CHANGE',${json(oldSession)});`,/saml_policy_session_invalid/);
      const hold = await sql(`select public.admin_place_tenant_legal_hold(${literal(f.tenant)},${literal(f.owner)},'LEGAL-OUTAGE',
        'Fixture legal operator','Preserve all evidence during authorized SAML recovery');`);
      await sql(`insert into public.identity_user_session_state(user_id,revoked_before,global_revoke_pending_session_id,global_revoke_pending_at)
        values (${literal(f.owner)},now(),${literal(f.session)},now());`);
      const barrier = await sql(`select to_jsonb(s) from public.identity_user_session_state s where user_id=${literal(f.owner)};`);
      const result = await rpc(call(f.text,f.proofs));
      assert.equal(result.status,"recovered"); assert.equal(result.recovery_owner_id,f.owner);
      assert.deepEqual(new Set(result.operator_ids),new Set(f.keys.map(k=>k.operator_id)));
      assert.equal(await sql(`select require_mfa||':'||break_glass_enabled||':'||(required_saml_provider_id is null) from public.tenant_identity_policies where tenant_id=${literal(f.tenant)};`),"true:false:true");
      assert.equal(await sql(`select to_jsonb(s) from public.identity_user_session_state s where user_id=${literal(f.owner)};`),barrier);
      const fakeClaims = {sub:f.owner,role:"authenticated",aal:"aal2",session_id:randomUUID(),iat:Math.floor(Date.now()/1000)+1};
      assert.equal(await sql(`set role authenticated; set request.jwt.claims=${literal(JSON.stringify(fakeClaims))};
        select public.tenant_identity_access_allowed(${literal(f.tenant)});`),"f","a different fresh browser session still cannot pass the pending revocation barrier");
      assert.equal(await sql(`select count(*) from auth.sessions where user_id=${literal(f.owner)};`),"1","no login session is issued");
      assert.equal(await sql(`select released_at is null from public.tenant_legal_holds where id=${literal(hold)};`),"t");
      assert.equal(await sql(`select count(*) from public.tenant_saml_outage_recoveries where tenant_id=${literal(f.tenant)};`),"1");
      await denied(`set role service_role; select ${call(f.text,f.proofs)};`,/policy_conflict|nonce_consumed/);
      assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)} and action='identity.saml.outage_recovered';`),"1");
      await denied(`delete from public.tenant_saml_outage_recoveries where tenant_id=${literal(f.tenant)};`,/immutable/);
      await denied(`delete from public.admin_audit_logs where id=${literal(result.audit_log_id)};`,/append-only/);
      await denied(`delete from app.tenant_saml_recovery_operator_keys where tenant_id=${literal(f.tenant)};`,/immutable/);
    });
    await t.test("expiry or owner expiration during an audit write rolls back policy, nonce and evidence", async () => {
      for (const kind of ["proof","owner"]) {
        const f = await fixture();
        if (kind === "owner") await sql(`update public.tenant_members set expires_at=clock_timestamp()+interval '2 seconds'
          where tenant_id=${literal(f.tenant)} and user_id=${literal(f.owner)};`);
        const now = Math.floor(Date.now()/1000), text = kind === "proof"
          ? JSON.stringify({...JSON.parse(f.text),issued_at:now,expires_at:now+2}) : f.text;
        await sql(`create function public.__fixture_delay_saml_recovery_audit() returns trigger language plpgsql as $$
          begin if new.tenant_id=${literal(f.tenant)} and new.action='identity.saml.outage_recovered' then perform pg_sleep(3); end if; return new; end $$;
          create trigger fixture_delay_saml_recovery before insert on public.admin_audit_logs
          for each row execute function public.__fixture_delay_saml_recovery_audit();`);
        await denied(`set role service_role; select ${call(text,approvals(text,f.keys))};`,kind==="proof"?/approval_expired/:/owner_required/);
        await unchanged(f);
        await sql(`drop trigger fixture_delay_saml_recovery on public.admin_audit_logs; drop function public.__fixture_delay_saml_recovery_audit();`);
      }
    });
    await t.test("audit failure rolls back all recovery effects and the unspent nonce can retry", async () => {
      const f = await fixture();
      await sql(`create function public.__fixture_refuse_saml_recovery_audit() returns trigger language plpgsql as $$
        begin if new.tenant_id=${literal(f.tenant)} and new.action='identity.saml.outage_recovered' then
          raise exception 'fixture_audit_failed'; end if; return new; end $$;
        create trigger fixture_refuse_saml_recovery before insert on public.admin_audit_logs
        for each row execute function public.__fixture_refuse_saml_recovery_audit();`);
      await denied(`set role service_role; select ${call(f.text,f.proofs)};`,/fixture_audit_failed/);
      await unchanged(f);
      await sql(`drop trigger fixture_refuse_saml_recovery on public.admin_audit_logs; drop function public.__fixture_refuse_saml_recovery_audit();`);
      assert.equal((await rpc(call(f.text,f.proofs))).status,"recovered");
    });
    await t.test("offboarding revokes immediately, preserves held evidence and erases custody keys in fresh phase calls", async () => {
      const f = await fixture(); await rpc(call(f.text,f.proofs));
      const hold = await sql(`select public.admin_place_tenant_legal_hold(${literal(f.tenant)},${literal(f.owner)},'LEGAL-ERASURE',
        'Fixture legal operator','Preserve operator recovery evidence pending approved release');`);
      const run = (await rpc(`public.request_tenant_offboarding(${literal(f.tenant)},${literal(f.owner)})`)).run_id;
      assert.equal(await sql(`select count(*) from app.tenant_saml_recovery_operator_keys where tenant_id=${literal(f.tenant)} and enabled;`),"0");
      assert.equal((await rpc(`public.run_tenant_offboarding_batch(${literal(run)},100)`)).status,"blocked_legal_hold");
      assert.equal(await sql(`select count(*) from app.tenant_saml_recovery_operator_keys where tenant_id=${literal(f.tenant)};`),"2");
      assert.equal(await sql(`select count(*) from public.tenant_saml_outage_recoveries where tenant_id=${literal(f.tenant)};`),"1");
      await denied(`insert into app.tenant_saml_recovery_operator_keys(tenant_id,key_id,operator_id,secret,not_before,not_after)
        values (${literal(f.tenant)},gen_random_uuid(),gen_random_uuid(),extensions.gen_random_bytes(32),now(),now()+interval '1 hour');`,/tenant_inactive/);
      await sql(`update public.tenant_legal_holds set released_at=now(),released_by=${literal(f.owner)},
        release_reason='Fixture trusted release after hold preservation assertion' where id=${literal(hold)};`);
      let state;
      for (let i = 0; i < 120; i++) {
        state = await rpc(`public.run_tenant_offboarding_batch(${literal(run)},100)`);
        if(state.action === "invalidate_cache") await rpc(`public.ack_tenant_offboarding_cache(${literal(run)},array['outage-fixture-cache'],0)`);
        if(state.status === "completed") break;
      }
      assert.equal(state.status,"completed");
      assert.equal(await sql(`select count(*) from app.tenant_saml_recovery_operator_keys where tenant_id=${literal(f.tenant)};`),"0");
      assert.equal(await sql(`select count(*) from public.tenant_saml_outage_recoveries where tenant_id=${literal(f.tenant)};`),"0");
      assert.equal(await sql(`select status||':'||rows_deleted from public.tenant_offboarding_phase_receipts
        where run_id=${literal(run)} and phase='saml_recovery_operator_keys';`),"completed:2");
      assert.equal(await sql(`select count(*) from public.admin_audit_logs where tenant_id=${literal(f.tenant)};`),"0");
    });
  } finally { await docker(["rm","-f",container]); }
});
