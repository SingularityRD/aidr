import { describe, expect, it } from "vitest";
import {
	loadRevocationRows,
	MAX_REVOCATION_ROWS,
	type RevocationRow,
	type RevocationTable,
} from "../feed.ts";

const tenantId = "11111111-1111-4111-8111-111111111111";
const otherTenantId = "22222222-2222-4222-8222-222222222222";

function tableWithRows(rows: RevocationRow[], serverCap = Number.POSITIVE_INFINITY) {
	const calls: string[] = [];
	const table: RevocationTable = {
		select(columns, options) {
			calls.push(`select:${columns}:${options.count}`);
			return {
				or(filters) {
					calls.push(`or:${filters}`);
					const scoped = rows.filter((row) => row.tenant_id === null || row.tenant_id === tenantId);
					return {
						order(column, options) {
							calls.push(`order:${column}:${options.ascending}`);
							return {
								limit(count) {
									calls.push(`limit:${count}`);
									return Promise.resolve({
										data: scoped.slice(0, Math.min(count, serverCap)),
										count: scoped.length,
										error: null,
									});
								},
							};
						},
					};
				},
			};
		},
	};
	return { table, calls };
}

describe("signed revocation feed source", () => {
	it("scopes tenant and global rows before the limit", async () => {
		const otherRows = Array.from({ length: MAX_REVOCATION_ROWS }, () => ({
			kind: "artifact_id", value: "other", tenant_id: otherTenantId,
		}));
		const mine = { kind: "key_id", value: "revoked-key", tenant_id: tenantId };
		const global = { kind: "pack_id", value: "revoked-pack", tenant_id: null };
		const { table, calls } = tableWithRows([...otherRows, mine, global]);
		expect(await loadRevocationRows(table, tenantId)).toEqual({ ok: true, rows: [mine, global] });
		expect(calls).toEqual([
			"select:kind,value,tenant_id:exact",
			`or:tenant_id.is.null,tenant_id.eq.${tenantId}`,
			"order:id:false",
			`limit:${MAX_REVOCATION_ROWS + 1}`,
		]);
	});

	it("refuses to sign when the matching set exceeds the cap", async () => {
		const rows = Array.from({ length: MAX_REVOCATION_ROWS + 1 }, () => ({
			kind: "key_id", value: "revoked-key", tenant_id: tenantId,
		}));
		const { table } = tableWithRows(rows);
		expect(await loadRevocationRows(table, tenantId)).toEqual({
			ok: false, error: "revocation_feed_capacity_exceeded",
		});
	});

	it("detects a lower server-side row cap using the exact count", async () => {
		const rows = Array.from({ length: 1001 }, () => ({
			kind: "key_id", value: "revoked-key", tenant_id: tenantId,
		}));
		const { table } = tableWithRows(rows, 1000);
		expect(await loadRevocationRows(table, tenantId)).toEqual({
			ok: false, error: "revocation_feed_incomplete",
		});
	});

	it("fails closed when the exact count is unavailable", async () => {
		const table: RevocationTable = {
			select: () => ({
				or: () => ({
					order: () => ({
						limit: () => Promise.resolve({ data: [], count: null, error: null }),
					}),
				}),
			}),
		};
		expect(await loadRevocationRows(table, tenantId)).toEqual({ ok: false, error: "db_error" });
	});

	it("rejects a cross-tenant row returned by a faulty source", async () => {
		const badTable: RevocationTable = {
			select: () => ({
				or: () => ({
					order: () => ({
						limit: () => Promise.resolve({
							data: [{ kind: "key_id", value: "other", tenant_id: otherTenantId }],
							count: 1,
							error: null,
						}),
					}),
				}),
			}),
		};
		expect(await loadRevocationRows(badTable, tenantId)).toEqual({
			ok: false, error: "revocation_scope_mismatch",
		});
	});
});
