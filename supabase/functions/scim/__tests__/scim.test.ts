import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it } from "vitest";
import { collectMemberPages, MAX_SCIM_GROUP_MEMBERS, ScimMemberLimitError } from "../member-pages.ts";
import {
	createScimHandler,
	MAX_SCIM_GROUP_PAGE_SIZE,
	ScimConflictError,
	ScimInvalidValueError,
	type ScimCreateGroup,
	type ScimCreateUser,
	type ScimFilter,
	type ScimGroup,
	type ScimList,
	type ScimStore,
	type ScimTenant,
	type ScimUser,
} from "../scim.ts";

const tenantA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const tenantB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const now = "2026-09-12T10:00:00.000Z";

class MemoryStore implements ScimStore {
	tokens = new Map<string, ScimTenant>([["new-secret-with-at-least-thirty-two-bytes", { tenantId: tenantA, tokenId: "token-new" }], ["tenant-b-secret-with-at-least-32-bytes", { tenantId: tenantB, tokenId: "token-b" }]]);
	users = new Map<string, ScimUser>();
	groups = new Map<string, ScimGroup>();
	groupListRequests: Array<{ offset: number; limit: number }> = [];
	nextUser = 1;
	nextGroup = 1;

	authenticate(token: string): Promise<ScimTenant | null> { return Promise.resolve(this.tokens.get(token) ?? null); }
	key(tenant: string, id: string): string { return `${tenant}:${id}`; }

	listUsers(tenant: string, offset: number, limit: number, filter: ScimFilter | null): Promise<ScimList<ScimUser>> {
		let rows = [...this.users.entries()].filter(([key]) => key.startsWith(`${tenant}:`)).map(([, value]) => value);
		if (filter?.attribute === "userName") rows = rows.filter((row) => row.userName === filter.value.toLowerCase());
		if (filter?.attribute === "externalId") rows = rows.filter((row) => row.externalId === filter.value);
		return Promise.resolve({ items: rows.slice(offset, offset + limit), total: rows.length });
	}
	getUser(tenant: string, id: string): Promise<ScimUser | null> { return Promise.resolve(this.users.get(this.key(tenant, id)) ?? null); }
	createUser(tenant: string, input: ScimCreateUser): Promise<{ user: ScimUser; created: boolean }> {
		const existing = [...this.users.entries()].find(([key, row]) => key.startsWith(`${tenant}:`) && ((input.externalId && row.externalId === input.externalId) || row.userName === input.userName));
		if (existing) {
			const row = existing[1];
			if (row.externalId !== input.externalId || row.userName !== input.userName || row.displayName !== input.displayName || row.active !== input.active) throw new ScimConflictError("uniqueness", "replay differs");
			return Promise.resolve({ user: row, created: false });
		}
		const id = `00000000-0000-4000-8000-${String(this.nextUser++).padStart(12, "0")}`;
		const user: ScimUser = { id, ...input, version: 1, createdAt: now, updatedAt: now };
		this.users.set(this.key(tenant, id), user);
		return Promise.resolve({ user, created: true });
	}
	updateUser(tenant: string, id: string, input: ScimCreateUser, expected: number | null): Promise<ScimUser | null> {
		const current = this.users.get(this.key(tenant, id)); if (!current) return Promise.resolve(null);
		if (expected !== null && expected !== current.version) throw new ScimConflictError("versionMismatch", "version mismatch");
		const user = { ...current, ...input, version: current.version + 1, updatedAt: now }; this.users.set(this.key(tenant, id), user); return Promise.resolve(user);
	}
	async deactivateUser(tenant: string, id: string, expected: number | null): Promise<ScimUser | null> {
		const current = await this.getUser(tenant, id);
		if (!current) return null;
		if (!current.active) {
			if (expected !== null && expected !== current.version) throw new ScimConflictError("versionMismatch", "version mismatch");
			return current;
		}
		return this.updateUser(tenant, id, { externalId: current.externalId, userName: current.userName, displayName: current.displayName, active: false }, expected);
	}
	listGroups(tenant: string, offset: number, limit: number, filter: ScimFilter | null): Promise<ScimList<ScimGroup>> {
		this.groupListRequests.push({ offset, limit });
		let rows = [...this.groups.entries()].filter(([key]) => key.startsWith(`${tenant}:`)).map(([, value]) => value);
		if (filter?.attribute === "externalId") rows = rows.filter((row) => row.externalId === filter.value);
		if (filter?.attribute === "displayName") rows = rows.filter((row) => row.displayName === filter.value);
		return Promise.resolve({ items: rows.slice(offset, offset + limit), total: rows.length });
	}
	getGroup(tenant: string, id: string): Promise<ScimGroup | null> { return Promise.resolve(this.groups.get(this.key(tenant, id)) ?? null); }
	private validateMembers(tenant: string, members: string[]): void {
		for (const id of members) if (!this.users.has(this.key(tenant, id))) throw new ScimInvalidValueError("cross-tenant or unknown member");
	}
	createGroup(tenant: string, input: ScimCreateGroup): Promise<{ group: ScimGroup; created: boolean }> {
		this.validateMembers(tenant, input.members);
		const existing = [...this.groups.entries()].find(([key, row]) => key.startsWith(`${tenant}:`) && row.externalId === input.externalId);
		if (existing) {
			const row = existing[1];
			if (row.displayName !== input.displayName || JSON.stringify(row.members.map((m) => m.value)) !== JSON.stringify(input.members)) throw new ScimConflictError("uniqueness", "replay differs");
			return Promise.resolve({ group: row, created: false });
		}
		const id = `10000000-0000-4000-8000-${String(this.nextGroup++).padStart(12, "0")}`;
		const group: ScimGroup = { id, externalId: input.externalId, displayName: input.displayName, members: input.members.map((value) => ({ value })), version: 1, createdAt: now, updatedAt: now };
		this.groups.set(this.key(tenant, id), group); return Promise.resolve({ group, created: true });
	}
	updateGroup(tenant: string, id: string, input: ScimCreateGroup, expected: number | null): Promise<ScimGroup | null> {
		const current = this.groups.get(this.key(tenant, id)); if (!current) return Promise.resolve(null);
		if (expected !== null && expected !== current.version) throw new ScimConflictError("versionMismatch", "version mismatch");
		this.validateMembers(tenant, input.members);
		const group = { ...current, displayName: input.displayName, members: input.members.map((value) => ({ value })), version: current.version + 1, updatedAt: now };
		this.groups.set(this.key(tenant, id), group); return Promise.resolve(group);
	}
	deleteGroup(tenant: string, id: string, expected: number | null): Promise<boolean> {
		const current = this.groups.get(this.key(tenant, id)); if (!current) return Promise.resolve(false);
		if (expected !== null && expected !== current.version) throw new ScimConflictError("versionMismatch", "version mismatch");
		return Promise.resolve(this.groups.delete(this.key(tenant, id)));
	}
}

function request(path: string, init: RequestInit = {}, token = "new-secret-with-at-least-thirty-two-bytes"): Request {
	const headers = new Headers(init.headers); if (token) headers.set("Authorization", `Bearer ${token}`); if (init.body) headers.set("Content-Type", "application/scim+json");
	return new Request(`https://control.example/functions/v1/scim/v2/${path}`, { ...init, headers });
}

async function body(response: Response): Promise<Record<string, any>> { return response.json(); }

describe("SCIM v2 request boundary", () => {
	let store: MemoryStore; let handle: ReturnType<typeof createScimHandler>;
	beforeEach(() => { store = new MemoryStore(); handle = createScimHandler(store); });

	it("rejects absent, revoked and malformed bearer credentials", async () => {
		expect((await handle(request("Users", {}, ""))).status).toBe(401);
		expect((await handle(request("Users", {}, "revoked-secret-with-at-least-32-bytes"))).status).toBe(401);
		expect((await handle(new Request("https://control.example/functions/v1/scim/v2/Users", { headers: { Authorization: "Basic abc" } }))).status).toBe(401);
	});

	it("returns 413 promptly when an oversized stream never finishes cancellation", async () => {
		const bodyStream = new ReadableStream<Uint8Array>({
			start(controller) { controller.enqueue(new Uint8Array(1024 * 1024 + 1)); },
			cancel() { return new Promise<void>(() => undefined); },
		});
		const oversized = new Request("https://control.example/functions/v1/scim/v2/Users", {
			method: "POST",
			headers: { Authorization: "Bearer new-secret-with-at-least-thirty-two-bytes", "Content-Type": "application/scim+json" },
			body: bodyStream,
			duplex: "half",
		} as RequestInit);
		let timeout: ReturnType<typeof setTimeout> | undefined;
		const response = await Promise.race([
			handle(oversized),
			new Promise<Response>((resolve) => { timeout = setTimeout(() => resolve(new Response(null, { status: 599 })), 500); }),
		]);
		if (timeout !== undefined) clearTimeout(timeout);
		expect(response.status).toBe(413);
		expect(await body(response)).toMatchObject({ status: "413", detail: "request body is too large" });
		expect(store.users.size).toBe(0);
	});

	it("accepts a rotated credential while the old credential is revoked", async () => {
		store.tokens.set("old-secret-with-at-least-thirty-two-bytes", { tenantId: tenantA, tokenId: "old" });
		expect((await handle(request("ServiceProviderConfig", {}, "old-secret-with-at-least-thirty-two-bytes"))).status).toBe(200);
		store.tokens.delete("old-secret-with-at-least-thirty-two-bytes");
		expect((await handle(request("ServiceProviderConfig", {}, "old-secret-with-at-least-thirty-two-bytes"))).status).toBe(401);
		expect((await handle(request("ServiceProviderConfig"))).status).toBe(200);
	});

	it("advertises resource type URLs under the deployed SCIM base path", async () => {
		const response = await handle(request("ResourceTypes"));
		expect(response.status).toBe(200);
		expect((await body(response)).Resources.map((resource: { meta: { location: string } }) => resource.meta.location)).toEqual([
			"https://control.example/functions/v1/scim/v2/ResourceTypes/User",
			"https://control.example/functions/v1/scim/v2/ResourceTypes/Group",
		]);
		const user = await handle(request("ResourceTypes/User"));
		expect(user.status).toBe(200);
		expect(await body(user)).toMatchObject({ id: "User", name: "User" });
		expect((await handle(request("ResourceTypes/Unknown"))).status).toBe(404);
	});

	it("creates a user idempotently and ignores forged role/group metadata", async () => {
		const payload = { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], externalId: "entra-user-1", userName: "User@Example.com", displayName: "Admin Name", active: true, role: "owner", groups: [{ value: "admins" }], user_metadata: { groups: ["admin"] } };
		const first = await handle(request("Users", { method: "POST", body: JSON.stringify(payload) }));
		const replay = await handle(request("Users", { method: "POST", body: JSON.stringify(payload) }));
		expect(first.status).toBe(201); expect(replay.status).toBe(200); expect((await body(first)).id).toBe((await body(replay)).id);
		expect(store.users.size).toBe(1); expect([...store.users.values()][0]).not.toHaveProperty("role");
	});

	it("rejects a replay whose authoritative attributes differ", async () => {
		const base = { externalId: "entra-user-1", userName: "user@example.com", displayName: "User", active: true };
		expect((await handle(request("Users", { method: "POST", body: JSON.stringify(base) }))).status).toBe(201);
		const response = await handle(request("Users", { method: "POST", body: JSON.stringify({ ...base, active: false }) }));
		expect(response.status).toBe(409); expect((await body(response)).scimType).toBe("uniqueness");
	});

	it("keeps identical SCIM ids isolated by token tenant", async () => {
		const payload = { externalId: "same-id", userName: "same@example.com", active: true };
		const a = await handle(request("Users", { method: "POST", body: JSON.stringify(payload) }));
		const b = await handle(request("Users", { method: "POST", body: JSON.stringify(payload) }, "tenant-b-secret-with-at-least-32-bytes"));
		expect(a.status).toBe(201); expect(b.status).toBe(201); expect(store.users.size).toBe(2);
		const aId = (await body(a)).id;
		expect((await handle(request(`Users/${aId}`, {}, "tenant-b-secret-with-at-least-32-bytes"))).status).toBe(404);
	});

	it("paginates and filters users with bounded SCIM list metadata", async () => {
		for (let i = 0; i < 3; i++) await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: `u-${i}`, userName: `u${i}@example.com` }) }));
		const page = await handle(request("Users?startIndex=2&count=1")); const data = await body(page);
		expect(data).toMatchObject({ totalResults: 3, startIndex: 2, itemsPerPage: 1 });
		const filtered = await body(await handle(request('Users?filter=userName%20eq%20%22u2%40example.com%22')));
		expect(filtered.totalResults).toBe(1);
		expect((await handle(request("Users?count=201"))).status).toBe(400);
	});

	it("rejects pagination ranges whose derived last index is unsafe", async () => {
		const unsafeStart = Number.MAX_SAFE_INTEGER;
		const listUsers = store.listUsers.bind(store);
		let userListCalls = 0;
		store.listUsers = (tenant, offset, limit, filter) => {
			userListCalls += 1;
			return listUsers(tenant, offset, limit, filter);
		};
		for (const resource of ["Users", "Groups"]) {
			const response = await handle(request(`${resource}?startIndex=${unsafeStart}&count=3`));
			expect(response.status).toBe(400);
			expect(await body(response)).toMatchObject({ scimType: "invalidValue", detail: "pagination range exceeds the safe integer limit" });
		}
		expect(userListCalls).toBe(0);
		expect(store.groupListRequests).toEqual([]);
	});

	it("accepts the largest pagination range whose last index is safe", async () => {
		const response = await handle(request(`Groups?startIndex=${Number.MAX_SAFE_INTEGER}&count=2`));
		expect(response.status).toBe(200);
		expect(await body(response)).toMatchObject({ startIndex: Number.MAX_SAFE_INTEGER, itemsPerPage: 0 });
		expect(store.groupListRequests).toEqual([{ offset: Number.MAX_SAFE_INTEGER - 1, limit: 2 }]);
	});

	it("deactivates rather than globally deleting a user", async () => {
		const created = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-1", userName: "u1@example.com" }) })));
		expect((await handle(request(`Users/${created.id}`, { method: "DELETE", headers: { "If-Match": 'W/"1"' } }))).status).toBe(204);
		const inactive = await body(await handle(request(`Users/${created.id}`)));
		expect(inactive.active).toBe(false);
		expect((await handle(request(`Users/${created.id}`, { method: "DELETE", headers: { "If-Match": inactive.meta.version } }))).status).toBe(204);
		expect((await body(await handle(request(`Users/${created.id}`)))).meta.version).toBe(inactive.meta.version);
	});

	it("rejects mutable identity fields and stale ETags", async () => {
		const created = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-1", userName: "u1@example.com" }) })));
		const mutable = await handle(request(`Users/${created.id}`, { method: "PATCH", body: JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Replace", path: "userName", value: "attacker@example.com" }] }) }));
		expect(mutable.status).toBe(409); expect((await body(mutable)).scimType).toBe("mutability");
		const stale = await handle(request(`Users/${created.id}`, { method: "PATCH", headers: { "If-Match": 'W/"9"' }, body: JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Replace", path: "active", value: false }] }) }));
		expect(stale.status).toBe(412);
	});

	it("keeps a concurrent deactivation when a display-name PATCH reads an older user", async () => {
		const created = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-1", userName: "u1@example.com" }) })));
		const getUser = store.getUser.bind(store);
		store.getUser = async (tenant, id) => {
			const current = await getUser(tenant, id);
			if (current) store.users.set(store.key(tenant, id), { ...current, active: false, version: current.version + 1 });
			return current;
		};
		const response = await handle(request(`Users/${created.id}`, { method: "PATCH", body: JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Replace", path: "displayName", value: "Updated" }] }) }));
		expect(response.status).toBe(412);
		expect(store.users.get(store.key(tenantA, created.id))?.active).toBe(false);
	});

	it("keeps a concurrent deactivation when a full user PUT reads an older user", async () => {
		const created = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-1", userName: "u1@example.com" }) })));
		const getUser = store.getUser.bind(store);
		store.getUser = async (tenant, id) => {
			const current = await getUser(tenant, id);
			if (current) store.users.set(store.key(tenant, id), { ...current, active: false, version: current.version + 1 });
			return current;
		};
		const response = await handle(request(`Users/${created.id}`, { method: "PUT", body: JSON.stringify({ externalId: "u-1", userName: "u1@example.com", active: true }) }));
		expect(response.status).toBe(412);
		expect(store.users.get(store.key(tenantA, created.id))?.active).toBe(false);
	});

	it("applies group membership add/remove and rejects cross-tenant members", async () => {
		const a = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "a", userName: "a@example.com" }) })));
		const b = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "b", userName: "b@example.com" }) }, "tenant-b-secret-with-at-least-32-bytes")));
		const group = await body(await handle(request("Groups", { method: "POST", body: JSON.stringify({ externalId: "entra-group-immutable-id", displayName: "Security Admins", members: [{ value: a.id }] }) })));
		const removed = await handle(request(`Groups/${group.id}`, { method: "PATCH", body: JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Remove", path: `members[value eq \"${a.id}\"]` }] }) }));
		expect(removed.status).toBe(200); expect((await body(removed)).members).toEqual([]);
		const crossTenant = await handle(request(`Groups/${group.id}`, { method: "PATCH", body: JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Add", path: "members", value: [{ value: b.id }] }] }) }));
		expect(crossTenant.status).toBe(400);
	});

	it("rejects malformed member ids and resource paths as client errors", async () => {
		const malformedMember = await handle(request("Groups", {
			method: "POST",
			body: JSON.stringify({ externalId: "directory-group", displayName: "Operators", members: [{ value: "not-a-uuid" }] }),
		}));
		expect(malformedMember.status).toBe(400);
		expect(await body(malformedMember)).toMatchObject({ scimType: "invalidValue" });
		expect(store.groups.size).toBe(0);
		const malformedPath = await handle(request("Users/%ZZ"));
		expect(malformedPath.status).toBe(400);
	});

	it("removes every group member when PATCH Remove targets members without a value", async () => {
		const first = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-1", userName: "u1@example.com" }) })));
		const second = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-2", userName: "u2@example.com" }) })));
		const group = await body(await handle(request("Groups", { method: "POST", body: JSON.stringify({ externalId: "directory-group-id", displayName: "Operators", members: [{ value: first.id }, { value: second.id }] }) })));
		const removed = await handle(request(`Groups/${group.id}`, { method: "PATCH", body: JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Remove", path: "members" }] }) }));
		expect(removed.status).toBe(200);
		expect((await body(removed)).members).toEqual([]);
		expect(store.groups.get(store.key(tenantA, group.id))?.members).toEqual([]);
	});

	it("rejects a PATCH based on stale group membership when a directory update races it", async () => {
		const first = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-1", userName: "u1@example.com" }) })));
		const second = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-2", userName: "u2@example.com" }) })));
		const group = await body(await handle(request("Groups", { method: "POST", body: JSON.stringify({ externalId: "directory-group-id", displayName: "Operators", members: [{ value: first.id }] }) })));
		const getGroup = store.getGroup.bind(store);
		store.getGroup = async (tenant, id) => {
			const current = await getGroup(tenant, id);
			if (current) store.groups.set(store.key(tenant, id), { ...current, version: current.version + 1, members: [{ value: second.id }] });
			return current;
		};
		const response = await handle(request(`Groups/${group.id}`, { method: "PATCH", body: JSON.stringify({ schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Remove", path: `members[value eq \"${first.id}\"]` }] }) }));
		expect(response.status).toBe(412);
		expect(store.groups.get(store.key(tenantA, group.id))?.members).toEqual([{ value: second.id }]);
	});

	it("rejects a full group PUT when its membership read races a directory update", async () => {
		const first = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-1", userName: "u1@example.com" }) })));
		const second = await body(await handle(request("Users", { method: "POST", body: JSON.stringify({ externalId: "u-2", userName: "u2@example.com" }) })));
		const group = await body(await handle(request("Groups", { method: "POST", body: JSON.stringify({ externalId: "directory-group-id", displayName: "Operators", members: [{ value: first.id }] }) })));
		const getGroup = store.getGroup.bind(store);
		store.getGroup = async (tenant, id) => {
			const current = await getGroup(tenant, id);
			if (current) store.groups.set(store.key(tenant, id), { ...current, version: current.version + 1, members: [{ value: second.id }] });
			return current;
		};
		const response = await handle(request(`Groups/${group.id}`, { method: "PUT", body: JSON.stringify({ externalId: "directory-group-id", displayName: "Operators", members: [{ value: first.id }] }) }));
		expect(response.status).toBe(412);
		expect(store.groups.get(store.key(tenantA, group.id))?.members).toEqual([{ value: second.id }]);
	});

	it("rejects oversized group membership input before persistence", async () => {
		const response = await handle(request("Groups", {
			method: "POST",
			body: JSON.stringify({
				externalId: "oversized-directory-group",
				displayName: "Oversized",
				members: Array.from({ length: MAX_SCIM_GROUP_MEMBERS + 1 }, () => ({ value: "duplicate" })),
			}),
		}));
		expect(response.status).toBe(400);
		expect(await body(response)).toMatchObject({ scimType: "invalidValue", detail: `group membership exceeds the limit of ${MAX_SCIM_GROUP_MEMBERS}` });
		expect(store.groups.size).toBe(0);
	});

	it("caps aggregate member references across group PATCH operations", async () => {
		const groupId = "10000000-0000-4000-8000-000000000001";
		store.groups.set(store.key(tenantA, groupId), {
			id: groupId, externalId: "directory-group", displayName: "Operators", members: [], version: 1, createdAt: now, updatedAt: now,
		});
		const values = Array.from({ length: 101 }, () => ({ value: "22222222-2222-4222-8222-222222222222" }));
		const response = await handle(request(`Groups/${groupId}`, {
			method: "PATCH",
			body: JSON.stringify({
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: Array.from({ length: 100 }, () => ({ op: "Add", path: "members", value: values })),
			}),
		}));
		expect(response.status).toBe(400);
		expect((await body(response)).detail).toBe(`group membership exceeds the limit of ${MAX_SCIM_GROUP_MEMBERS}`);
		expect(store.groups.get(store.key(tenantA, groupId))?.version).toBe(1);
	});

	it("returns a clear client error when a PATCH has too many operations", async () => {
		const groupId = "10000000-0000-4000-8000-000000000001";
		store.groups.set(store.key(tenantA, groupId), {
			id: groupId, externalId: "directory-group", displayName: "Operators", members: [], version: 1, createdAt: now, updatedAt: now,
		});
		const response = await handle(request(`Groups/${groupId}`, {
			method: "PATCH",
			body: JSON.stringify({
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: Array.from({ length: 101 }, () => ({ op: "Remove", path: "members" })),
			}),
		}));
		expect(response.status).toBe(400);
		expect((await body(response)).detail).toBe("Operations must contain at most 100 entries");
	});

	it("refuses an oversized stored membership instead of building an unbounded response", async () => {
		const groupId = "10000000-0000-4000-8000-000000000001";
		store.groups.set(store.key(tenantA, groupId), {
			id: groupId,
			externalId: "oversized-directory-group",
			displayName: "Oversized",
			members: Array.from({ length: MAX_SCIM_GROUP_MEMBERS + 1 }, () => ({ value: "duplicate" })),
			version: 1,
			createdAt: now,
			updatedAt: now,
		});
		const response = await handle(request(`Groups/${groupId}`));
		expect(response.status).toBe(400);
		expect((await body(response)).detail).toBe(`group membership exceeds the limit of ${MAX_SCIM_GROUP_MEMBERS}`);
	});

	it("bounds each group independently across a paginated group response", async () => {
		const members = Array.from({ length: Math.floor(MAX_SCIM_GROUP_MEMBERS / 2) + 1 }, () => ({ value: "duplicate" }));
		for (const suffix of ["1", "2"]) {
			const groupId = `10000000-0000-4000-8000-00000000000${suffix}`;
			store.groups.set(store.key(tenantA, groupId), {
				id: groupId, externalId: `directory-group-${suffix}`, displayName: `Group ${suffix}`, members, version: 1, createdAt: now, updatedAt: now,
			});
		}
		const response = await handle(request("Groups?count=2"));
		expect(response.status).toBe(200);
		const page = await body(response);
		expect(page).toMatchObject({ totalResults: 2, itemsPerPage: 2 });
		expect(page.Resources.map((group: { members: unknown[] }) => group.members.length)).toEqual([
			members.length,
			members.length,
		]);
	});

	it("bounds aggregate group hydration and preserves startIndex pagination", async () => {
		const memberId = "22222222-2222-4222-8222-222222222222";
		for (let index = 1; index <= 12; index += 1) {
			const groupId = `10000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
			store.groups.set(store.key(tenantA, groupId), {
				id: groupId, externalId: `group-${index}`, displayName: `Group ${index}`,
				members: Array.from({ length: MAX_SCIM_GROUP_MEMBERS }, () => ({ value: memberId })),
				version: 1, createdAt: now, updatedAt: now,
			});
		}

		const first = await body(await handle(request("Groups?startIndex=1&count=200")));
		expect(store.groupListRequests[0]).toEqual({ offset: 0, limit: MAX_SCIM_GROUP_PAGE_SIZE });
		expect(first).toMatchObject({ startIndex: 1, itemsPerPage: MAX_SCIM_GROUP_PAGE_SIZE, totalResults: 12 });
		expect(first.Resources.reduce((sum: number, group: ScimGroup) => sum + group.members.length, 0))
			.toBe(MAX_SCIM_GROUP_PAGE_SIZE * MAX_SCIM_GROUP_MEMBERS);

		const nextStartIndex = first.startIndex + first.itemsPerPage;
		const second = await body(await handle(request(`Groups?startIndex=${nextStartIndex}&count=200`)));
		expect(store.groupListRequests[1]).toEqual({ offset: MAX_SCIM_GROUP_PAGE_SIZE, limit: MAX_SCIM_GROUP_PAGE_SIZE });
		expect(second).toMatchObject({ startIndex: nextStartIndex, itemsPerPage: 2, totalResults: 12 });
		expect(second.Resources).toHaveLength(2);
	});
});

describe("SCIM group member pagination", () => {
	it("hydrates members up to the cap despite a storage page cap below the requested size", async () => {
		const expected = Array.from({ length: MAX_SCIM_GROUP_MEMBERS }, (_, index) => `member-${index}`);
		const offsets: number[] = [];
		const members = await collectMemberPages(async (offset, limit) => {
			offsets.push(offset);
			return expected.slice(offset, offset + Math.min(limit, 137));
		});
		expect(members).toEqual(expected);
		expect(offsets).toEqual([0, 137, 274, 411, 548, 685, 822, 959, 1000]);
	});

	it("bounds exact maximum group membership to six reads including the look-ahead", async () => {
		const expected = Array.from({ length: MAX_SCIM_GROUP_MEMBERS }, (_, index) => `member-${index}`);
		let calls = 0;
		const members = await collectMemberPages(async (offset, limit) => {
			calls += 1;
			return expected.slice(offset, offset + limit);
		});
		expect(members).toHaveLength(MAX_SCIM_GROUP_MEMBERS);
		expect(calls).toBe(6);
	});

	it("stops after one look-ahead row when the collection cap is exceeded", async () => {
		const expected = Array.from({ length: 20 }, (_, index) => `member-${index}`);
		await expect(collectMemberPages((offset, limit) => Promise.resolve(expected.slice(offset, offset + limit)), 3, 5))
			.rejects.toEqual(new ScimMemberLimitError(5));
	});
});

describe("SCIM persistence authorization contract", () => {
	const migration = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../../../migrations/20260912000012_scim_directory.sql"), "utf8");
	it("uses exact immutable external group ids and excludes privileged owner roles", () => {
		expect(migration).toContain("external_group_id = sg.external_id");
		expect(migration).toContain("scim_group_role_mapping_is_immutable");
		expect(migration).toContain("role in ('admin', 'member', 'viewer')");
		expect(migration).not.toMatch(/role in \([^)]*owner/);
	});
	it("keeps every SCIM table service-only and protects manual memberships", () => {
		expect(migration).toContain("from public, anon, authenticated");
		expect(migration).toContain("scim_cannot_take_over_manual_membership");
		expect(migration).toContain("public.scim_managed_memberships");
	});
	it("stores only SHA-256 token hashes and supports overlapping rotation rows", () => {
		expect(migration).toContain("token_hash text not null unique");
		expect(migration).toContain("rotated_from uuid");
		expect(migration).toContain("foreign key (tenant_id, rotated_from) references public.scim_tokens(tenant_id, id)");
		expect(migration).toContain("st.revoked_at is null");
		expect(migration).toContain("st.expires_at is null or st.expires_at > now()");
	});
	it("paginates membership hydration independently for each group", () => {
		const source = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../index.ts"), "utf8");
		expect(source).toContain('.eq("tenant_id", tenantId).eq("group_id", groupId)');
		expect(source).toContain("membershipsByGroup.set(groupId, memberships)");
	});
});
