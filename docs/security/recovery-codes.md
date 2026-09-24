# Recovery-code issuance

Break-glass recovery codes reset the user's global AIDR Auth identity; they are not tenant-local credentials. A user may issue a code batch only for their own Auth user ID, from an AAL2 session, while actively belonging to the selected active tenant and with that tenant's break-glass policy enabled. Tenant owners and administrators cannot issue codes for another member, including a member whose Auth identity is also present in another tenant.

The `issue_identity_recovery_codes` RPC is service-role-only and independently rejects actor/target mismatches. The self-only migration also invalidates previously issued, unused codes where the issuer and target differ. The original codes are returned once; only hashes are stored.

Disabling break-glass policy and issuing codes serialize on the same tenant advisory lock, acquired before the issuer's per-user lock. A disable that wins first makes a queued issuance fail; an issuance that wins first is removed by the subsequent disable. Re-enabling the policy does not revive either batch.
