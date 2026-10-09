// Isolated PostgreSQL regression for terminally closed checkout intents.
// Uses only a disposable local container; it never contacts Stripe or Paddle.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

const container = `aidr-billing-resub-${randomUUID().slice(0, 8)}`;
const migration = readFileSync(
	new URL("../supabase/migrations/20260924000006_billing_resubscription_after_provider_close.sql", import.meta.url),
	"utf8",
);
const exactReplayMigration = readFileSync(
	new URL("../supabase/migrations/20260924000011_billing_checkout_exact_replay.sql", import.meta.url),
	"utf8",
);

function docker(args, input = "") {
	const result = spawnSync("docker", args, {
		input,
		encoding: "utf8",
		timeout: 60_000,
		maxBuffer: 4 * 1024 * 1024,
	});
	if (result.error) throw result.error;
	return result;
}

function sql(statement) {
	const result = docker(
		["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres"],
		statement,
	);
	assert.equal(result.status, 0, `PostgreSQL test failed:\n${result.stdout}\n${result.stderr}`);
	return result.stdout.trim();
}

test("only provider-proven terminal checkout intents permit a new billing channel", { timeout: 180_000 }, async () => {
	const started = docker([
		"run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
		"-e", "POSTGRES_PASSWORD=billing-resubscription-fixture-only", "postgres:17-alpine",
	]);
	assert.equal(started.status, 0, started.stderr);
	try {
		let ready = false;
		for (let attempt = 0; attempt < 100; attempt += 1) {
			if (docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"]).status === 0) {
				ready = true;
				break;
			}
			await delay(100);
		}
		assert.ok(ready, "isolated PostgreSQL did not start");

		const result = sql(`create role anon;
			create role authenticated;
			create role service_role bypassrls;
			create schema app;
			create table public.tenants(id uuid primary key, status text not null default 'active');
			create table public.tenant_members(
				tenant_id uuid not null, user_id uuid not null, role text not null, expires_at timestamptz
			);
			create or replace function public.assert_billing_actor(p_tenant_id uuid, p_actor_user_id uuid, p_roles text[])
			returns void language plpgsql as $$
			begin
				if not exists (
					select 1 from public.tenants t join public.tenant_members m on m.tenant_id = t.id
					where t.id = p_tenant_id and t.status = 'active' and m.user_id = p_actor_user_id
					  and m.role = any(p_roles) and (m.expires_at is null or m.expires_at > now())
				) then raise exception 'billing_forbidden' using errcode = '42501'; end if;
			end;
			$$;
			create table public.enterprise_invoice_approvals(tenant_id uuid not null, status text not null);
			create table public.subscriptions(
				id uuid primary key default gen_random_uuid(), user_id uuid not null, tenant_id uuid not null,
				provider text not null, provider_subscription_id text not null unique, status text not null,
				extra_agents integer not null, provider_event_id text
			);
			create table public.billing_checkout_intents(
				settlement_id uuid primary key default gen_random_uuid(), tenant_id uuid not null,
				actor_user_id uuid not null, request_id text not null, request_hash text not null,
				seats integer not null, billing_interval text not null, price_id text not null,
				provider text not null default 'stripe', checkout_session_id text,
				status text not null default 'claimed', created_at timestamptz not null default now(),
				updated_at timestamptz not null default now(),
				constraint billing_checkout_intents_status_check check (status in ('claimed','checkout_created','paid')),
				unique (tenant_id, request_id), unique (checkout_session_id)
			);
			create table public.billing_provider_payments(settlement_id uuid not null);
			create or replace function app.prevent_invoice_provider_billing_overlap()
			returns trigger language plpgsql as $$ begin return new; end; $$;
			create trigger enterprise_invoice_approvals_billing_guard
			before insert on public.enterprise_invoice_approvals
			for each row execute function app.prevent_invoice_provider_billing_overlap();
			grant usage on schema public, app to anon, authenticated, service_role;
			${migration}
			${exactReplayMigration}
			insert into public.tenants(id) values
				('00000000-0000-4000-8000-000000000001'),
				('00000000-0000-4000-8000-000000000002'),
				('00000000-0000-4000-8000-000000000003'),
				('00000000-0000-4000-8000-000000000004'),
				('00000000-0000-4000-8000-000000000005'),
				('00000000-0000-4000-8000-000000000006');
			insert into public.tenant_members(tenant_id,user_id,role) values
				('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000099','owner'),
				('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000099','owner'),
				('00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000099','owner'),
				('00000000-0000-4000-8000-000000000004','00000000-0000-4000-8000-000000000099','owner'),
				('00000000-0000-4000-8000-000000000005','00000000-0000-4000-8000-000000000099','owner'),
				('00000000-0000-4000-8000-000000000006','00000000-0000-4000-8000-000000000099','owner');
			insert into public.subscriptions(user_id,tenant_id,provider,provider_subscription_id,status,extra_agents,provider_event_id)
			values ('00000000-0000-4000-8000-000000000099','00000000-0000-4000-8000-000000000003',
				'stripe','sub_active_fixture','active',2,'evt_active_fixture');
			set role service_role;
			do $$ declare intent jsonb; begin
				intent := public.claim_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000099',
					'request-canceled-fixture-0001',repeat('a',64),2,'monthly','price_fixture');
				if intent->>'status' <> 'claimed' then raise exception 'initial checkout not claimed'; end if;
				intent := public.claim_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000099',
					'request-expired-fixture-0001',repeat('b',64),1,'monthly','price_fixture');
				if intent->>'status' <> 'claimed' then raise exception 'expired fixture checkout not claimed'; end if;
				intent := public.claim_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000004','00000000-0000-4000-8000-000000000099',
					'request-processing-fixture-0001',repeat('c',64),1,'monthly','price_fixture');
				if intent->>'status' <> 'claimed' then raise exception 'processing fixture checkout not claimed'; end if;
				intent := public.claim_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000006','00000000-0000-4000-8000-000000000099',
					'request-paid-replay-fixture',repeat('f',64),2,'monthly','price_fixture');
				if intent->>'status' <> 'claimed' then raise exception 'paid replay fixture checkout not claimed'; end if;
			end $$;
			reset role;
			update public.billing_checkout_intents set settlement_id='00000000-0000-4000-8000-000000000011'
			where tenant_id='00000000-0000-4000-8000-000000000001';
			update public.billing_checkout_intents set settlement_id='00000000-0000-4000-8000-000000000022'
			where tenant_id='00000000-0000-4000-8000-000000000002';
			update public.billing_checkout_intents set status='checkout_created',checkout_session_id='cs_expired_fixture'
			where tenant_id='00000000-0000-4000-8000-000000000002';
			update public.billing_checkout_intents set status='paid'
			where tenant_id='00000000-0000-4000-8000-000000000001';
			update public.billing_checkout_intents set settlement_id='00000000-0000-4000-8000-000000000066', status='paid'
			where tenant_id='00000000-0000-4000-8000-000000000006';
			insert into public.subscriptions(user_id,tenant_id,provider,provider_subscription_id,status,extra_agents,provider_event_id)
			values ('00000000-0000-4000-8000-000000000099','00000000-0000-4000-8000-000000000001',
				'stripe','sub_canceled_fixture','canceled',0,'evt_cancel_fixture');
			insert into public.subscriptions(user_id,tenant_id,provider,provider_subscription_id,status,extra_agents,provider_event_id)
			values ('00000000-0000-4000-8000-000000000099','00000000-0000-4000-8000-000000000006',
				'stripe','sub_paid_replay_fixture','active',2,'evt_paid_fixture');
			set role service_role;
			do $$ declare closed boolean; intent jsonb; begin
				closed := public.close_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000099',
					'00000000-0000-4000-8000-000000000011',
					'request-canceled-fixture-0001','evt_cancel_fixture','customer.subscription.updated',null,'sub_canceled_fixture');
				if closed is distinct from true then raise exception 'provider cancellation did not close intent'; end if;
				intent := public.claim_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000099',
					'request-resubscribe-fixture-0001',repeat('d',64),2,'monthly','price_fixture');
				if intent->>'status' <> 'claimed' then raise exception 'canceled subscription did not permit new checkout'; end if;

				closed := public.close_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000099',
					'00000000-0000-4000-8000-000000000022',
					'request-expired-fixture-0001','evt_expire_fixture','checkout.session.expired',
					'cs_wrong_fixture',null);
				if closed then raise exception 'mismatched checkout session was closed'; end if;
				closed := public.close_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000099',
					'00000000-0000-4000-8000-000000000022',
					'request-expired-fixture-0001','evt_expire_fixture','checkout.session.expired',
					'cs_expired_fixture',null);
				if closed is distinct from true then raise exception 'exact expired session did not close intent'; end if;
				intent := public.claim_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000099',
					'request-after-expiry-fixture',repeat('e',64),1,'monthly','price_fixture');
				if intent->>'status' <> 'claimed' then raise exception 'expired checkout did not permit new checkout'; end if;

				begin
					perform public.claim_billing_checkout_intent(
						'00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000099',
						'request-active-blocked-0001',repeat('f',64),1,'monthly','price_fixture');
					raise exception 'active subscription unexpectedly allowed a new checkout';
				exception when unique_violation then
					if sqlerrm <> 'billing_channel_conflict' then raise; end if;
				end;
				begin
					perform public.claim_billing_checkout_intent(
						'00000000-0000-4000-8000-000000000004','00000000-0000-4000-8000-000000000099',
						'request-processing-blocked',repeat('c',64),1,'monthly','price_fixture');
					raise exception 'processing checkout unexpectedly allowed a second key';
				exception when unique_violation then
					if sqlerrm <> 'billing_channel_conflict' then raise; end if;
				end;
				intent := public.claim_billing_checkout_intent(
					'00000000-0000-4000-8000-000000000006','00000000-0000-4000-8000-000000000099',
					'request-paid-replay-fixture',repeat('f',64),2,'monthly','price_fixture');
				if intent->>'status' <> 'paid' or intent->>'settlement_id' <> '00000000-0000-4000-8000-000000000066' then
					raise exception 'exact paid request replay did not return its stable original intent';
				end if;
				begin
					perform public.claim_billing_checkout_intent(
						'00000000-0000-4000-8000-000000000006','00000000-0000-4000-8000-000000000099',
						'request-paid-new-blocked',repeat('1',64),2,'monthly','price_fixture');
					raise exception 'fresh checkout bypassed the active subscription guard';
				exception when unique_violation then
					if sqlerrm <> 'billing_channel_conflict' then raise; end if;
				end;
			end $$;
			reset role;
			insert into public.enterprise_invoice_approvals(tenant_id,status)
			values ('00000000-0000-4000-8000-000000000005','pending');
			select 'BILLING_RESUBSCRIPTION_OK';`);
		assert.match(result, /BILLING_RESUBSCRIPTION_OK/);
		const gate = sql(`select
			(select status from public.billing_checkout_intents where tenant_id='00000000-0000-4000-8000-000000000001' and request_id='request-canceled-fixture-0001') = 'closed'
			and (select status from public.billing_checkout_intents where tenant_id='00000000-0000-4000-8000-000000000002' and request_id='request-expired-fixture-0001') = 'closed'
			and has_function_privilege('service_role','public.close_billing_checkout_intent(uuid,uuid,uuid,text,text,text,text,text)','EXECUTE')
			and not has_function_privilege('authenticated','public.close_billing_checkout_intent(uuid,uuid,uuid,text,text,text,text,text)','EXECUTE');`);
		assert.equal(gate, "t", "closed intent state and service-only closure permission should be preserved");
	} finally {
		docker(["rm", "--force", container]);
	}
});
