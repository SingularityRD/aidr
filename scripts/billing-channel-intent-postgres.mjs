// Run only against a named disposable local Supabase DB after all migrations:
//   AIDR_TEST_DISPOSABLE_DB=1 AIDR_RLS_TEST_DB_CONTAINER=supabase_db_aidr node scripts/billing-channel-intent-postgres.mjs
// No provider calls. Sequential fixtures roll back. Concurrent connections
// require committed fixtures; reset/stop the guarded disposable DB after the gates.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const container = process.env.AIDR_RLS_TEST_DB_CONTAINER;
assert.equal(process.env.AIDR_TEST_DISPOSABLE_DB, "1", "confirm a disposable DB with AIDR_TEST_DISPOSABLE_DB=1");
assert.match(container ?? "", /^supabase_db_[A-Za-z0-9_.-]+$/, "name a disposable local Supabase DB container");

const pgArgs = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=15000 -c lock_timeout=12000",
  container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const quote = value => `'${String(value).replaceAll("'", "''")}'`;
const id = () => randomUUID();
const requestId = () => randomUUID().replaceAll("-", "");
const hash = "a".repeat(64);

function sql(statement) {
  const result = spawnSync("docker", pgArgs, { input: statement, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function sqlAsync(statement) {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", pgArgs, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    const timer = setTimeout(() => child.kill(), 20_000);
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.stdin.on("error", () => {});
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("close", code => { clearTimeout(timer); resolve({ code, stdout: stdout.trim(), stderr }); });
    child.stdin.end(statement);
  });
}

function session() {
  const child = spawn("docker", pgArgs, { stdio: ["pipe", "pipe", "pipe"] });
  let output = "", errors = "", pending;
  child.stdout.on("data", chunk => {
    output += chunk;
    if (!pending) return;
    const at = output.indexOf(`${pending.marker}\n`);
    if (at < 0) return;
    const value = output.slice(0, at).trim();
    output = output.slice(at + pending.marker.length + 1);
    clearTimeout(pending.timer);
    pending.resolve(value);
    pending = undefined;
  });
  child.stderr.on("data", chunk => { errors += chunk; });
  child.stdin.on("error", () => {});
  const closed = new Promise(resolve => child.once("close", code => {
    if (pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`psql exited ${code}: ${errors}`));
      pending = undefined;
    }
    resolve();
  }));
  child.once("error", error => {
    if (pending) {
      clearTimeout(pending.timer);
      pending.reject(error);
      pending = undefined;
    }
  });
  return {
    query(statement) {
      assert.equal(pending, undefined, "session query already pending");
      return new Promise((resolve, reject) => {
        const marker = `aidr_end_${requestId()}`;
        const timer = setTimeout(() => {
          reject(new Error(`psql query timed out: ${errors}`));
          pending = undefined;
          child.kill();
        }, 20_000);
        pending = { marker, timer, resolve, reject };
        child.stdin.write(`${statement}\n\\echo ${marker}\n`);
      });
    },
    async close() { if (!child.killed) child.stdin.end("\\q\n"); await closed; },
  };
}

const claim = (tenant, actor, request) => `public.claim_billing_checkout_intent(
  ${quote(tenant)},${quote(actor)},${quote(request)},${quote(hash)},2,'monthly','price_AidrFixture')`;
const approve = (tenant, actor, order) => `public.record_invoice_approval(
  ${quote(tenant)},${quote(actor)},${quote(order)},100,'USD',${quote(hash)})`;
// Race the migration's invoice INSERT trigger directly. The finance RPC also
// writes an append-only audit receipt; it is covered by the rollback-only case.
const insertApproval = (tenant, actor, order) => `insert into public.enterprise_invoice_approvals
  (order_id,tenant_id,approver,approver_user_id,amount_minor,currency,evidence_sha256,agents_granted)
  values (${quote(order)},${quote(tenant)},${quote(actor)},${quote(actor)},100,'USD',${quote(hash)},3)`;
const subscription = (provider, event, actor, tenant, sub, seats, at) =>
  `public.apply_billing_subscription_event(${quote(provider)},${quote(event)},${quote(at)}::timestamptz,
  ${quote(actor)},${quote(tenant)},${quote(sub)},'active',${seats},now() + interval '30 days',false)`;

function sequential() {
  const actor = id();
  const tenants = Array.from({ length: 3 }, id);
  const [replay, invoiceFirst, provider] = tenants;
  const order = id();
  const request = requestId();
  const stripe = `sub_${requestId()}`;
  const paddle = `sub_${requestId()}`;
  const statements = `
begin;
insert into auth.users(id,email,aud,role,instance_id,raw_app_meta_data,raw_user_meta_data)
values (${quote(actor)},${quote(`billing-channel-${actor}@example.invalid`)},'authenticated','authenticated',
  '00000000-0000-0000-0000-000000000000','{}'::jsonb,'{}'::jsonb);
insert into public.tenants(id,name,kind,created_by) values
  ${tenants.map(t => `(${quote(t)},'Billing channel fixture','enterprise',${quote(actor)})`).join(",\n  ")};
insert into public.tenant_members(tenant_id,user_id,role) values
  ${tenants.map(t => `(${quote(t)},${quote(actor)},'owner')`).join(",\n  ")};
insert into public.invoice_finance_operators(tenant_id,user_id) values
  ${tenants.map(t => `(${quote(t)},${quote(actor)})`).join(",\n  ")};
insert into public.enterprise_invoice_orders(id,tenant_id,request_id,created_by,requested_agents)
values (${quote(order)},${quote(invoiceFirst)},${quote(requestId())},${quote(actor)},3);
set role service_role;
do $test$
declare first_claim jsonb; replay_claim jsonb; result jsonb;
begin
  first_claim := ${claim(replay, actor, request)};
  replay_claim := ${claim(replay, actor, request)};
  if first_claim <> replay_claim or first_claim->>'status' <> 'claimed' then
    raise exception 'same-key replay changed checkout intent';
  end if;
  begin
    perform ${claim(replay, actor, requestId())};
    raise exception 'second checkout key was accepted';
  exception when unique_violation then
    if sqlerrm <> 'billing_channel_conflict' then raise; end if;
  end;
  begin
    perform public.claim_billing_checkout_intent(${quote(replay)},${quote(actor)},
      ${quote(request)},repeat('b',64),2,'monthly','price_AidrFixture');
    raise exception 'same key rebound to another request';
  exception when unique_violation then
    if sqlerrm <> 'billing_request_conflict' then raise; end if;
  end;
  result := ${approve(invoiceFirst, actor, order)};
  if result->>'status' <> 'paid' then raise exception 'invoice was not approved'; end if;
  begin
    perform ${claim(invoiceFirst, actor, requestId())};
    raise exception 'checkout followed a paid invoice';
  exception when unique_violation then
    if sqlerrm <> 'billing_channel_conflict' then raise; end if;
  end;

  result := ${subscription("stripe", `evt_${requestId()}`, actor, provider, stripe, 2, "2026-09-23T00:00:00Z")};
  if result->>'extra_agents' <> '2' then raise exception 'Stripe seat projection wrong'; end if;
  begin
    perform ${subscription("paddle", `evt_${requestId()}`, actor, provider, paddle, 3, "2026-09-23T00:00:01Z")};
    raise exception 'positive Stripe/Paddle overlap was accepted';
  exception when unique_violation then
    if sqlerrm <> 'billing_provider_conflict' then raise; end if;
  end;
  perform ${subscription("stripe", `evt_${requestId()}`, actor, provider, stripe, 0, "2026-09-23T00:00:02Z")};
  result := ${subscription("paddle", `evt_${requestId()}`, actor, provider, paddle, 3, "2026-09-23T00:00:03Z")};
  if result->>'extra_agents' <> '3' then raise exception 'Stripe-to-Paddle zero-seat handoff failed'; end if;
  begin
    perform ${subscription("stripe", `evt_${requestId()}`, actor, provider, stripe, 2, "2026-09-23T00:00:04Z")};
    raise exception 'positive Paddle/Stripe overlap was accepted';
  exception when unique_violation then
    if sqlerrm <> 'billing_provider_conflict' then raise; end if;
  end;
  perform ${subscription("paddle", `evt_${requestId()}`, actor, provider, paddle, 0, "2026-09-23T00:00:05Z")};
  result := ${subscription("stripe", `evt_${requestId()}`, actor, provider, stripe, 2, "2026-09-23T00:00:06Z")};
  if result->>'extra_agents' <> '2' then raise exception 'Paddle-to-Stripe zero-seat handoff failed'; end if;
end
$test$;
reset role;
do $test$
begin
  if (select count(*) from public.billing_checkout_intents where tenant_id=${quote(replay)}) <> 1
    or (select count(*) from public.billing_checkout_intents where tenant_id=${quote(invoiceFirst)}) <> 0
    or (select count(*) from public.enterprise_invoice_approvals where tenant_id=${quote(invoiceFirst)}) <> 1
    or (select count(*) from public.subscriptions where tenant_id=${quote(provider)} and extra_agents > 0) <> 1
    or (select extra_agents from public.entitlements where tenant_id=${quote(provider)}) <> 2
  then raise exception 'exclusive channel final state is wrong'; end if;
end
$test$;
rollback;
select 'BILLING_CHANNEL_ROLLBACK_OK';`;
  assert.match(sql(statements), /BILLING_CHANNEL_ROLLBACK_OK/);
  console.log("PASS same-key replay, second-key denial, invoice-first denial, Stripe/Paddle overlap and zero-seat handoff (rolled back)");
}

async function waitForAdvisoryWait(application) {
  for (let attempt = 0; attempt < 160; attempt++) {
    if (sql(`select exists(select 1 from pg_stat_activity where application_name=${quote(application)}
      and state='active' and wait_event='advisory');`) === "t") return;
    await delay(25);
  }
  throw new Error(`${application} did not wait on the tenant advisory lock`);
}

async function race(firstSql, firstAsService, secondSql, secondAsService, verify, name) {
  const first = session();
  let inTransaction = false;
  let second;
  try {
    await first.query(`begin; ${firstAsService ? "set role service_role;" : ""} ${firstSql};`);
    inTransaction = true;
    const application = `aidr_billing_${requestId()}`;
    second = sqlAsync(`set application_name=${quote(application)};
      ${secondAsService ? "set role service_role;" : ""} ${secondSql};`);
    void second.catch(() => undefined);
    await waitForAdvisoryWait(application);
    await first.query("commit;");
    inTransaction = false;
    const result = await second;
    assert.notEqual(result.code, 0, `${name}: concurrent second transition was accepted`);
    assert.match(result.stderr, /billing_channel_conflict/, `${name}: wrong concurrent rejection`);
    assert.equal(sql(verify), "t", `${name}: committed channel state is wrong`);
    console.log(`PASS ${name}: second transaction observed waiting on advisory lock, then rejected`);
  } finally {
    if (inTransaction) await first.query("rollback;").catch(() => undefined);
    if (second) await second.catch(() => undefined);
    await first.close();
  }
}

async function concurrent() {
  const actor = id();
  const claimFirst = id();
  const invoiceFirst = id();
  const orderA = id();
  const orderB = id();
  let fixtureCommitted = false;
  try {
    sql(`begin;
insert into auth.users(id,email,aud,role,instance_id,raw_app_meta_data,raw_user_meta_data)
values (${quote(actor)},${quote(`billing-race-${actor}@example.invalid`)},'authenticated','authenticated',
  '00000000-0000-0000-0000-000000000000','{}'::jsonb,'{}'::jsonb);
insert into public.tenants(id,name,kind,created_by) values
  (${quote(claimFirst)},'Billing claim-first race','enterprise',${quote(actor)}),
  (${quote(invoiceFirst)},'Billing invoice-first race','enterprise',${quote(actor)});
insert into public.tenant_members(tenant_id,user_id,role) values
  (${quote(claimFirst)},${quote(actor)},'owner'),(${quote(invoiceFirst)},${quote(actor)},'owner');
insert into public.invoice_finance_operators(tenant_id,user_id) values
  (${quote(claimFirst)},${quote(actor)}),(${quote(invoiceFirst)},${quote(actor)});
insert into public.enterprise_invoice_orders(id,tenant_id,request_id,created_by,requested_agents) values
  (${quote(orderA)},${quote(claimFirst)},${quote(requestId())},${quote(actor)},3),
  (${quote(orderB)},${quote(invoiceFirst)},${quote(requestId())},${quote(actor)},3);
commit;`);
    fixtureCommitted = true;

    await race(
      `select ${claim(claimFirst, actor, requestId())}`, true,
      insertApproval(claimFirst, actor, orderA), false,
      `select (select count(*) from public.billing_checkout_intents where tenant_id=${quote(claimFirst)})=1
        and (select count(*) from public.enterprise_invoice_approvals where tenant_id=${quote(claimFirst)})=0;`,
      "claim-first/invoice-second race",
    );
    await race(
      insertApproval(invoiceFirst, actor, orderB), false,
      `select ${claim(invoiceFirst, actor, requestId())}`, true,
      `select (select count(*) from public.enterprise_invoice_approvals where tenant_id=${quote(invoiceFirst)})=1
        and (select count(*) from public.billing_checkout_intents where tenant_id=${quote(invoiceFirst)})=0;`,
      "invoice-first/claim-second race",
    );
  } finally {
    if (fixtureCommitted) {
      // ponytail: no ad-hoc hard delete around append-only owner/audit triggers;
      // reset the named disposable DB after this gate instead.
      console.log(`RETAINED disposable billing race fixture actor=${actor} tenants=${claimFirst},${invoiceFirst}; reset this DB after gates`);
    }
  }
}

sequential();
await concurrent();
console.log("PASS billing channel intent real PostgreSQL gate");
