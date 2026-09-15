# Invoice finance authority

Migration `20260916000001_invoice_finance_authority.sql` replaces the actor-less approval RPC. Apply it before deploying the updated `invoice-entitlement` function; old clients that send `approver` must remove that field.

## Authorization

Customer owner/admin membership continues to allow invoice intake and reads, but never grants finance approval authority. `invoice_finance_operators` starts empty, including on databases with historical approvals. A database administrator must separately review and provision each `(tenant_id, user_id)` grant using the operator's authenticated `auth.users.id`. The Edge service role can read grants but cannot insert, update or delete them. Customers have no access to the grant table.

For example, through a trusted database-administrator connection (replace the UUIDs):

```sql
insert into public.invoice_finance_operators (tenant_id, user_id, expires_at)
values ('<tenant UUID>', '<reviewed finance user UUID>', now() + interval '30 days');

-- Revoke through the same trusted administrative channel:
update public.invoice_finance_operators set revoked_at = now()
where tenant_id = '<tenant UUID>' and user_id = '<finance user UUID>';
```

Finance operators do not need customer membership. They still need a valid user session, the tenant's identity-policy checks, an active tenant, and the separate unexpired/unrevoked grant. The tenant must have an active customer owner to hold the allocation.

Approval requests contain only `action`, `order_id`, `amount_minor`, `currency`, and `evidence_sha256`. The authenticated session supplies the actor UUID; any body-supplied approver/actor field is rejected. The approved amount and evidence remain out-of-band finance decisions, not independent payment verification.

The Edge handler rejects absent/revoked/expired finance authority before any RPC. The paid transaction independently locks/rechecks the grant and active tenant, binds the order to the tenant, records the actor UUID in the approval and audit, and serializes all approvals for a tenant before insert and sum. Revocations/suspensions committed before this transactional check deny the transition; revocations starting after its row locks wait for the in-flight transaction.

Legacy claimed approver labels remain readable, but `approver_user_id` is NULL for those rows and no authority is inferred from them. Historical approvals/allocations are not retroactively revalidated by this fix.

## Regression evidence

- Edge contract tests: customer owner/admin self-approval denied before RPC; separate finance fixture without customer membership succeeds; body spoofing rejected; transactional denial propagated; customer intake/read unchanged.
- Static migration contract tests: authority privileges, old overload removal, authenticated actor binding, and tenant-lock ordering.
- `node scripts/test-invoice-finance-postgres.mjs`: real PostgreSQL role/transaction tests and deterministically overlapping different-order approvals; uses an isolated Docker container with no exposed port. `--image postgres:16` selects the alternate cached image.

The PostgreSQL runner applies both shipped invoice migrations plus the new authority migration verbatim against minimal prerequisite tables. It is not evidence of a complete Supabase migration-chain deployment, PostgREST behavior, or live external payment validation.
