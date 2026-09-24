import { beforeAll, describe, expect, it, vi } from "vitest";
import { MAX_SCIM_GROUP_MEMBERS, SCIM_MEMBER_PAGE_SIZE } from "../member-pages.ts";
import { MAX_SCIM_GROUP_PAGE_SIZE } from "../scim.ts";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("the injected fake database must be used");
	},
}));

(globalThis as unknown as { Deno: unknown }).Deno = { serve: () => undefined };

let SupabaseScimStore: typeof import("../index.ts").SupabaseScimStore;
beforeAll(async () => {
	({ SupabaseScimStore } = await import("../index.ts"));
});

type Row = Record<string, unknown>;
type QueryResult = { data: Row[]; error: null; count?: number };

class CountingDatabase {
	queries = 0;
	readonly groups: Row[];
	readonly memberships = new Map<string, Row[]>();
	readonly users: Row[];

	constructor() {
		this.groups = Array.from({ length: 12 }, (_, groupIndex) => {
			const id = `10000000-0000-4000-8000-${String(groupIndex + 1).padStart(12, "0")}`;
			const row = {
				id,
				tenant_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
				external_id: `external-${groupIndex + 1}`,
				display_name: `Group ${groupIndex + 1}`,
				version: 1,
				created_at: "2026-01-01T00:00:00.000Z",
				updated_at: "2026-01-01T00:00:00.000Z",
			};
			this.memberships.set(id, Array.from({ length: MAX_SCIM_GROUP_MEMBERS }, (_, memberIndex) => ({
				group_id: id,
				user_id: `20000000-0000-4000-8000-${String(groupIndex * MAX_SCIM_GROUP_MEMBERS + memberIndex + 1).padStart(12, "0")}`,
			})));
			return row;
		});
		this.users = [...this.memberships.values()].flat().map(({ user_id }) => ({ id: user_id, user_name: `${user_id}@example.test` }));
	}

	from(table: string): CountingQuery {
		return new CountingQuery(this, table);
	}

	execute(query: CountingQuery): QueryResult {
		this.queries += 1;
		if (query.table === "scim_groups") {
			return { data: this.groups.slice(query.offset, query.end + 1), error: null, count: this.groups.length };
		}
		if (query.table === "scim_group_memberships") {
			const groupId = String(query.filters.get("group_id"));
			const rows = this.memberships.get(groupId) ?? [];
			return { data: rows.slice(query.offset, query.end + 1), error: null };
		}
		if (query.table === "scim_users") {
			const ids = new Set((query.ids ?? []).map(String));
			return { data: this.users.filter((row) => ids.has(String(row.id))), error: null };
		}
		throw new Error(`unexpected table ${query.table}`);
	}
}

class CountingQuery implements PromiseLike<QueryResult> {
	readonly filters = new Map<string, unknown>();
	ids: unknown[] | null = null;
	offset = 0;
	end = Number.MAX_SAFE_INTEGER;

	constructor(readonly database: CountingDatabase, readonly table: string) {}
	select(): this { return this; }
	eq(column: string, value: unknown): this { this.filters.set(column, value); return this; }
	order(): this { return this; }
	range(offset: number, end: number): this { this.offset = offset; this.end = end; return this; }
	in(_column: string, values: unknown[]): this { this.ids = values; return this; }
	then<TResult1 = QueryResult, TResult2 = never>(
		onfulfilled?: ((value: QueryResult) => TResult1 | PromiseLike<TResult1>) | null,
		onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
	): PromiseLike<TResult1 | TResult2> {
		return Promise.resolve(this.database.execute(this)).then(onfulfilled, onrejected);
	}
}

describe("SCIM group list hydration bounds", () => {
	it("caps worst-case page hydration query count and preserves a complete page", async () => {
		const database = new CountingDatabase();
		const store = new SupabaseScimStore(database as never);
		const page = await store.listGroups("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 0, MAX_SCIM_GROUP_PAGE_SIZE, null);
		const membershipReadsPerGroup = Math.ceil(MAX_SCIM_GROUP_MEMBERS / SCIM_MEMBER_PAGE_SIZE) + 1;
		const memberNameReads = Math.ceil((MAX_SCIM_GROUP_PAGE_SIZE * MAX_SCIM_GROUP_MEMBERS) / 200);
		const maximumQueries = 1 + MAX_SCIM_GROUP_PAGE_SIZE * membershipReadsPerGroup + memberNameReads;

		expect(page.total).toBe(12);
		expect(page.items).toHaveLength(MAX_SCIM_GROUP_PAGE_SIZE);
		expect(page.items.every((group) => group.members.length === MAX_SCIM_GROUP_MEMBERS)).toBe(true);
		expect(database.queries).toBeLessThanOrEqual(maximumQueries);
		expect(database.queries).toBe(maximumQueries);
	});
});
