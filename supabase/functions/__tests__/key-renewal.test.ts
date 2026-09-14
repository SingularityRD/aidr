import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";
import {
	boundedOverlapHours,
	retiredSecretActive,
	rotationPlan,
} from "../_shared/key-rotation.ts";

const FUNCTIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MIGRATIONS_DIR = resolve(FUNCTIONS_DIR, "..", "migrations");
const ROTATION_MIGRATION = (() => {
	const name = readdirSync(MIGRATIONS_DIR).find((entry) => entry.endsWith("_key_rotation_overlap.sql"));
	if (!name) throw new Error("the key rotation overlap migration is missing");
	return readFileSync(join(MIGRATIONS_DIR, name), "utf8").replace(/\r\n/g, "\n");
})();
const EXCHANGE_RPC =
	ROTATION_MIGRATION.split("create or replace function public.exchange_enrollment_token(")[1]?.split(
		"\nend;\n$$;",
	)[0] ?? "";

const apiKeysSource = readFileSync(join(FUNCTIONS_DIR, "api-keys", "index.ts"), "utf8");
const enrollmentTokensSource = readFileSync(
	join(FUNCTIONS_DIR, "enrollment-tokens", "index.ts"),
	"utf8",
);
const verifySource = readFileSync(join(FUNCTIONS_DIR, "device-verify", "index.ts"), "utf8");

/** Renewal branch only, so revoke/delete scoping cannot satisfy the assertions. */
function renewalBranch(source: string): string {
	return source.split('if (action === "renew")')[1]?.split("// create")[0] ?? "";
}

type Query = { table: string; filters: Record<string, unknown> };

/**
 * PostgREST-shaped client for `authenticateTenantApiKey`. The active hash never
 * matches (as after a rotation); the retired-hash lookup answers with `row`.
 */
function keyDatabase(row: Record<string, unknown> | null) {
	const queries: Query[] = [];
	const client = {
		from(table: string) {
			const filters: Record<string, unknown> = {};
			const builder = {
				select: () => builder,
				eq(column: string, value: unknown) {
					filters[column] = value;
					return builder;
				},
				maybeSingle: () => {
					queries.push({ table, filters: { ...filters } });
					if (table === "api_keys") {
						return Promise.resolve({ data: "key_hash" in filters ? null : row, error: null });
					}
					if (table === "tenant_members") {
						return Promise.resolve({ data: { expires_at: null }, error: null });
					}
					if (table === "tenants") {
						return Promise.resolve({ data: { status: "active" }, error: null });
					}
					return Promise.resolve({ data: null, error: null });
				},
			};
			return builder;
		},
	};
	return { client, queries };
}

describe("bounded rotation window", () => {
	const now = Date.parse("2026-09-15T00:00:00.000Z");
	const presentedKey = "aidr_live_retired_secret";
	const retiredHash = createHash("sha256").update(presentedKey).digest("hex");
	const retiredExpiry = new Date(now + 60_000).toISOString();
	const rotatedRow = {
		user_id: "user-1",
		tenant_id: "tenant-1",
		revoked: false,
		previous_hash: retiredHash,
		previous_hash_expires_at: retiredExpiry,
	};

	it("keeps the previous secret usable only inside the overlap window", async () => {
		const { client, queries } = keyDatabase(rotatedRow);

		await expect(authenticateTenantApiKey(client, presentedKey, now)).resolves.toEqual({
			ok: true,
			userId: "user-1",
			tenantId: "tenant-1",
		});
		// The window closes exactly at its recorded deadline.
		await expect(
			authenticateTenantApiKey(client, presentedKey, Date.parse(retiredExpiry)),
		).resolves.toEqual({ ok: false, status: 401, error: "invalid_api_key" });
		await expect(
			authenticateTenantApiKey(client, presentedKey, Date.parse(retiredExpiry) + 1),
		).resolves.toEqual({ ok: false, status: 401, error: "invalid_api_key" });

		expect(queries.some((query) => query.table === "api_keys" && query.filters.previous_hash === retiredHash)).toBe(true);
	});

	it("refuses an unknown token instead of falling back to a retired hash", async () => {
		const { client, queries } = keyDatabase(rotatedRow);
		await expect(authenticateTenantApiKey(client, "aidr_live_never_issued", now)).resolves.toEqual({
			ok: false,
			status: 401,
			error: "invalid_api_key",
		});
		expect(
			queries.some(
				(query) =>
					query.table === "api_keys" &&
					query.filters.previous_hash ===
						createHash("sha256").update("aidr_live_never_issued").digest("hex"),
			),
		).toBe(true);
	});

	it("never rotates to a window longer than the retired secret's own validity", () => {
		expect(rotationPlan(now, 24, null)).toEqual({
			rotatedAt: new Date(now).toISOString(),
			previousHashExpiresAt: new Date(now + 24 * 60 * 60 * 1000).toISOString(),
		});
		expect(boundedOverlapHours("0")).toBe(1);
		expect(boundedOverlapHours("9999")).toBe(168);
		expect(boundedOverlapHours("not-a-number")).toBe(24);

		const ownExpiry = new Date(now + 300_000).toISOString();
		expect(rotationPlan(now, 168, ownExpiry).previousHashExpiresAt).toBe(ownExpiry);
		// A secret that is already dead has nothing to overlap.
		expect(rotationPlan(now, 24, new Date(now - 1).toISOString()).previousHashExpiresAt).toBeNull();
		expect(rotationPlan(now, 24, "not-a-timestamp").previousHashExpiresAt).toBeNull();
	});

	it("matches a retired hash only when it is the recorded predecessor", () => {
		const expiresAt = new Date(2_000_000).toISOString();
		const recorded = { previous_hash: "b".repeat(64), previous_hash_expires_at: expiresAt };
		expect(retiredSecretActive(recorded, "b".repeat(64), 1_000)).toBe(true);
		expect(retiredSecretActive(recorded, "b".repeat(64), 2_000_000)).toBe(false);
		expect(retiredSecretActive(recorded, "b".repeat(64), 2_000_001)).toBe(false);
		expect(retiredSecretActive(recorded, "c".repeat(64), 1_000)).toBe(false);
		expect(retiredSecretActive(null, "b".repeat(64), 1_000)).toBe(false);
		expect(retiredSecretActive({ previous_hash: "b".repeat(64) }, "b".repeat(64), 1_000)).toBe(false);
	});
});

describe("renewal action contract", () => {
	it("records the retired hash with a bounded, database-enforced window", () => {
		for (const table of ["api_keys", "enrollment_tokens"]) {
			expect(ROTATION_MIGRATION).toContain("add column if not exists previous_hash text");
			expect(ROTATION_MIGRATION).toContain("add column if not exists previous_hash_expires_at timestamptz");
			expect(ROTATION_MIGRATION).toContain("add column if not exists rotated_at timestamptz");
			expect(ROTATION_MIGRATION).toContain(`${table}_rotation_window_check`);
		}
		expect(ROTATION_MIGRATION).toContain("previous_hash ~ '^[a-f0-9]{64}$'");
		expect(ROTATION_MIGRATION).toContain("previous_hash_expires_at > rotated_at");
		expect(ROTATION_MIGRATION).toContain("previous_hash_expires_at <= rotated_at + interval '7 days'");

		// The exchange accepts the retired hash only inside its window and never
		// lets it shadow the active hash.
		expect(EXCHANGE_RPC).toContain("t.previous_hash = p_token_hash");
		expect(EXCHANGE_RPC).toContain("t.previous_hash_expires_at > now()");
		expect(EXCHANGE_RPC).toContain("order by (t.token_hash = p_token_hash) desc");
		expect(EXCHANGE_RPC.indexOf("t.token_hash = p_token_hash")).toBeLessThan(
			EXCHANGE_RPC.indexOf("t.previous_hash = p_token_hash"),
		);
		expect(EXCHANGE_RPC).toContain("for update;");
		expect(EXCHANGE_RPC).toContain("v_token.consumed_at is not null or v_token.expires_at <= now()");
		expect(EXCHANGE_RPC).toContain("public.register_agent_for_ingest(");
		expect(EXCHANGE_RPC).toContain("if v_agent.seat_exceeded then");
		expect(EXCHANGE_RPC.indexOf("insert into public.api_keys")).toBeGreaterThan(0);
		expect(EXCHANGE_RPC.indexOf("update public.enrollment_tokens set consumed_at")).toBeGreaterThan(
			EXCHANGE_RPC.indexOf("insert into public.api_keys"),
		);
		expect(ROTATION_MIGRATION).toContain(
			"grant execute on function public.exchange_enrollment_token(text, text, text, text, text) to service_role",
		);
	});

	it("scopes a renewal to the tenant and refuses an unknown or spent credential", () => {
		const apiKeyRenewal = renewalBranch(apiKeysSource);
		const tokenRenewal = renewalBranch(enrollmentTokensSource);

		expect(apiKeysSource).toContain('["create", "revoke", "renew"]');
		expect(enrollmentTokensSource).toContain('["create", "delete", "renew"]');

		expect(apiKeyRenewal).toContain('.eq("tenant_id", tenant.id)');
		expect(apiKeyRenewal).toContain('{ error: "key_not_found_or_not_owned" }');
		expect(apiKeyRenewal).toContain('{ error: "key_revoked" }');
		expect(apiKeyRenewal).toContain("previous_hash: currentHash");
		expect(apiKeyRenewal).toContain("previous_hash_expires_at: plan.previousHashExpiresAt");
		expect(apiKeyRenewal).toContain('.eq("key_hash", currentHash)');
		expect(apiKeyRenewal).toContain("rateLimitCreate(");
		expect(apiKeyRenewal).not.toContain("revoked: false");

		expect(tokenRenewal).toContain('.eq("tenant_id", tenantId)');
		expect(tokenRenewal).toContain('{ error: "token_not_found_or_not_owned" }');
		expect(tokenRenewal).toContain('{ error: "token_already_consumed" }');
		expect(tokenRenewal).toContain("previous_hash:");
		expect(tokenRenewal).toContain('.eq("token_hash", currentHash)');
		expect(tokenRenewal).toContain("rateLimitCreate(");
		expect(tokenRenewal).not.toContain("consumed_at: null");

		// The identity barrier still precedes the new action, and the renewal is
		// audited like every other credential lifecycle change.
		expect(apiKeysSource.indexOf("checkIdentityBarrier(")).toBeLessThan(apiKeysSource.indexOf('"renew"'));
		expect(enrollmentTokensSource.indexOf("checkIdentityBarrier(")).toBeLessThan(
			enrollmentTokensSource.indexOf('"renew"'),
		);
		expect(apiKeyRenewal).toContain('action: "api_key.renew"');
		expect(tokenRenewal).toContain('action: "enrollment_token.renew"');
	});

	it("surfaces the authorization window without adding an approval or bypass", () => {
		expect(verifySource).toContain("expires_at: session.expires_at");
		for (const source of [apiKeysSource, enrollmentTokensSource, ROTATION_MIGRATION]) {
			expect(source).not.toMatch(/approv|bypass/i);
		}
	});
});
