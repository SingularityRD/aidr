import { getBearerToken } from "../_shared/auth.ts";

const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_PAGE_SIZE = 200;

export type ScimRole = "admin" | "member" | "viewer";

export interface ScimTenant {
	tenantId: string;
	tokenId: string;
}

export interface ScimUser {
	id: string;
	externalId: string | null;
	userName: string;
	displayName: string | null;
	active: boolean;
	version: number;
	createdAt: string;
	updatedAt: string;
}

export interface ScimMember {
	value: string;
	display?: string;
}

export interface ScimGroup {
	id: string;
	externalId: string;
	displayName: string;
	members: ScimMember[];
	version: number;
	createdAt: string;
	updatedAt: string;
}

export interface ScimList<T> {
	items: T[];
	total: number;
}

export interface ScimCreateUser {
	externalId: string | null;
	userName: string;
	displayName: string | null;
	active: boolean;
}

export interface ScimCreateGroup {
	externalId: string;
	displayName: string;
	members: string[];
}

export interface ScimStore {
	authenticate(token: string): Promise<ScimTenant | null>;
	listUsers(tenantId: string, offset: number, limit: number, filter: ScimFilter | null): Promise<ScimList<ScimUser>>;
	getUser(tenantId: string, id: string): Promise<ScimUser | null>;
	createUser(tenantId: string, input: ScimCreateUser): Promise<{ user: ScimUser; created: boolean }>;
	updateUser(tenantId: string, id: string, input: ScimCreateUser, expectedVersion: number | null): Promise<ScimUser | null>;
	deactivateUser(tenantId: string, id: string, expectedVersion: number | null): Promise<ScimUser | null>;
	listGroups(tenantId: string, offset: number, limit: number, filter: ScimFilter | null): Promise<ScimList<ScimGroup>>;
	getGroup(tenantId: string, id: string): Promise<ScimGroup | null>;
	createGroup(tenantId: string, input: ScimCreateGroup): Promise<{ group: ScimGroup; created: boolean }>;
	updateGroup(tenantId: string, id: string, input: ScimCreateGroup, expectedVersion: number | null): Promise<ScimGroup | null>;
	deleteGroup(tenantId: string, id: string, expectedVersion: number | null): Promise<boolean>;
}

export interface ScimFilter {
	attribute: "userName" | "externalId" | "displayName";
	value: string;
}

export class ScimConflictError extends Error {
	constructor(readonly scimType: "uniqueness" | "mutability" | "versionMismatch", message: string) {
		super(message);
		this.name = "ScimConflictError";
	}
}

export class ScimInvalidValueError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ScimInvalidValueError";
	}
}

function headers(extra: Record<string, string> = {}): HeadersInit {
	return { "Content-Type": "application/scim+json", "Cache-Control": "no-store", ...extra };
}

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), { status, headers: headers(extra) });
}

function noContent(): Response {
	return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
}

function error(status: number, detail: string, scimType?: string): Response {
	return json(status, {
		schemas: [SCIM_ERROR_SCHEMA],
		status: String(status),
		...(scimType ? { scimType } : {}),
		detail,
	});
}

function location(req: Request, collection: "Users" | "Groups", id: string): string {
	const url = new URL(req.url);
	const marker = "/scim/";
	const prefix = url.pathname.includes(marker) ? url.pathname.slice(0, url.pathname.indexOf(marker) + marker.length - 1) : "";
	return `${url.origin}${prefix}/v2/${collection}/${encodeURIComponent(id)}`;
}

function userResource(req: Request, user: ScimUser): Record<string, unknown> {
	const resourceLocation = location(req, "Users", user.id);
	return {
		schemas: [SCIM_USER_SCHEMA],
		id: user.id,
		...(user.externalId ? { externalId: user.externalId } : {}),
		userName: user.userName,
		active: user.active,
		displayName: user.displayName ?? user.userName,
		meta: {
			resourceType: "User",
			created: user.createdAt,
			lastModified: user.updatedAt,
			version: `W/\"${user.version}\"`,
			location: resourceLocation,
		},
	};
}

function groupResource(req: Request, group: ScimGroup): Record<string, unknown> {
	const resourceLocation = location(req, "Groups", group.id);
	return {
		schemas: [SCIM_GROUP_SCHEMA],
		id: group.id,
		externalId: group.externalId,
		displayName: group.displayName,
		members: group.members.map((member) => ({ ...member, $ref: location(req, "Users", member.value) })),
		meta: {
			resourceType: "Group",
			created: group.createdAt,
			lastModified: group.updatedAt,
			version: `W/\"${group.version}\"`,
			location: resourceLocation,
		},
	};
}

function parsePath(pathname: string): { resource: string; id: string | null } | null {
	const marker = "/scim/";
	const suffix = pathname.includes(marker) ? pathname.slice(pathname.lastIndexOf(marker) + marker.length) : pathname.replace(/^\/+/, "");
	const parts = suffix.split("/").filter(Boolean).map(decodeURIComponent);
	if (parts[0]?.toLowerCase() !== "v2" || !parts[1] || parts.length > 3) return null;
	return { resource: parts[1], id: parts[2] ?? null };
}

function stringValue(value: unknown, field: string, options: { required?: boolean; max?: number } = {}): string | null {
	if (value === undefined || value === null) {
		if (options.required) throw new ScimInvalidValueError(`${field} is required`);
		return null;
	}
	if (typeof value !== "string") throw new ScimInvalidValueError(`${field} must be a string`);
	const normalized = value.trim();
	if (options.required && !normalized) throw new ScimInvalidValueError(`${field} is required`);
	if (normalized.length > (options.max ?? 512)) throw new ScimInvalidValueError(`${field} is too long`);
	return normalized || null;
}

function validUserName(value: unknown): string {
	const userName = stringValue(value, "userName", { required: true, max: 254 }) ?? "";
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userName)) throw new ScimInvalidValueError("userName must be an email address");
	return userName.toLowerCase();
}

function boolValue(value: unknown, fallback: boolean): boolean {
	if (value === undefined) return fallback;
	if (typeof value !== "boolean") throw new ScimInvalidValueError("active must be a boolean");
	return value;
}

function objectValue(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new ScimInvalidValueError("request body must be an object");
	return value as Record<string, unknown>;
}

async function readJson(req: Request): Promise<Record<string, unknown>> {
	const declared = Number(req.headers.get("content-length") ?? "0");
	if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw new ScimInvalidValueError("request body is too large");
	if (!req.body) throw new ScimInvalidValueError("request body is required");
	const reader = req.body.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.byteLength;
		if (size > MAX_BODY_BYTES) {
			await reader.cancel();
			throw new ScimInvalidValueError("request body is too large");
		}
		chunks.push(value);
	}
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
	try { return objectValue(JSON.parse(new TextDecoder().decode(bytes))); }
	catch (caught) {
		if (caught instanceof ScimInvalidValueError) throw caught;
		throw new ScimInvalidValueError("request body is not valid JSON");
	}
}

function parseUser(body: Record<string, unknown>): ScimCreateUser {
	return {
		externalId: stringValue(body.externalId, "externalId", { max: 255 }),
		userName: validUserName(body.userName),
		displayName: stringValue(body.displayName, "displayName", { max: 255 }),
		active: boolValue(body.active, true),
	};
}

function memberIds(value: unknown): string[] {
	if (value === undefined) return [];
	if (!Array.isArray(value)) throw new ScimInvalidValueError("members must be an array");
	const ids = value.map((item) => stringValue(objectValue(item).value, "members.value", { required: true, max: 64 }) ?? "");
	return [...new Set(ids)];
}

function parseGroup(body: Record<string, unknown>): ScimCreateGroup {
	return {
		externalId: stringValue(body.externalId, "externalId", { required: true, max: 255 }) ?? "",
		displayName: stringValue(body.displayName, "displayName", { required: true, max: 255 }) ?? "",
		members: memberIds(body.members),
	};
}

function parseFilter(raw: string | null, resource: "Users" | "Groups"): ScimFilter | null {
	if (!raw) return null;
	const match = /^([A-Za-z][A-Za-z0-9]*)\s+eq\s+"([^"\\]{1,512})"$/i.exec(raw.trim());
	if (!match) throw new ScimInvalidValueError("unsupported filter");
	const attribute = match[1] as ScimFilter["attribute"];
	const allowed = resource === "Users" ? ["userName", "externalId"] : ["displayName", "externalId"];
	if (!allowed.some((name) => name.toLowerCase() === attribute.toLowerCase())) throw new ScimInvalidValueError("unsupported filter attribute");
	const canonical = allowed.find((name) => name.toLowerCase() === attribute.toLowerCase()) as ScimFilter["attribute"];
	return { attribute: canonical, value: match[2] ?? "" };
}

function pagination(url: URL): { startIndex: number; offset: number; count: number } {
	const rawStart = url.searchParams.get("startIndex") ?? "1";
	const rawCount = url.searchParams.get("count") ?? "100";
	if (!/^\d+$/.test(rawStart) || !/^\d+$/.test(rawCount)) throw new ScimInvalidValueError("invalid pagination");
	const startIndex = Number(rawStart);
	const count = Number(rawCount);
	if (!Number.isSafeInteger(startIndex) || startIndex < 1 || !Number.isSafeInteger(count) || count < 0 || count > MAX_PAGE_SIZE) {
		throw new ScimInvalidValueError(`startIndex must be positive and count must be between 0 and ${MAX_PAGE_SIZE}`);
	}
	return { startIndex, offset: startIndex - 1, count };
}

function expectedVersion(req: Request): number | null {
	const value = req.headers.get("if-match");
	if (!value) return null;
	const match = /^W\/"(\d+)"$/.exec(value.trim());
	if (!match) throw new ScimInvalidValueError("If-Match must be a weak SCIM version");
	const version = Number(match[1]);
	if (!Number.isSafeInteger(version) || version < 1) throw new ScimInvalidValueError("If-Match version is invalid");
	return version;
}

function patchOperations(body: Record<string, unknown>): Array<Record<string, unknown>> {
	const schemas = body.schemas;
	if (!Array.isArray(schemas) || !schemas.includes(SCIM_PATCH_SCHEMA)) throw new ScimInvalidValueError("PatchOp schema is required");
	if (!Array.isArray(body.Operations) || body.Operations.length === 0 || body.Operations.length > 100) {
		throw new ScimInvalidValueError("Operations must be a non-empty array");
	}
	return body.Operations.map(objectValue);
}

function applyUserPatch(current: ScimUser, operations: Array<Record<string, unknown>>): ScimCreateUser {
	const next: ScimCreateUser = { externalId: current.externalId, userName: current.userName, displayName: current.displayName, active: current.active };
	for (const operation of operations) {
		const op = String(operation.op ?? "").toLowerCase();
		if (op !== "replace" && op !== "add") throw new ScimInvalidValueError("Users supports add/replace patch operations only");
		const path = String(operation.path ?? "").toLowerCase();
		if (path === "active") next.active = boolValue(operation.value, next.active);
		else if (path === "displayname") next.displayName = stringValue(operation.value, "displayName", { max: 255 });
		else if (path === "username" || path === "externalid") throw new ScimConflictError("mutability", `${path} is immutable`);
		else if (!path) {
			const value = objectValue(operation.value);
			if ("userName" in value || "externalId" in value) throw new ScimConflictError("mutability", "userName and externalId are immutable");
			if ("active" in value) next.active = boolValue(value.active, next.active);
			if ("displayName" in value) next.displayName = stringValue(value.displayName, "displayName", { max: 255 });
		} else throw new ScimInvalidValueError(`unsupported user patch path: ${path}`);
	}
	return next;
}

function operationMemberIds(value: unknown): string[] {
	return memberIds(Array.isArray(value) ? value : [value]);
}

function applyGroupPatch(current: ScimGroup, operations: Array<Record<string, unknown>>): ScimCreateGroup {
	const next: ScimCreateGroup = { externalId: current.externalId, displayName: current.displayName, members: current.members.map((member) => member.value) };
	for (const operation of operations) {
		const op = String(operation.op ?? "").toLowerCase();
		const path = String(operation.path ?? "");
		const normalizedPath = path.toLowerCase();
		if (normalizedPath === "externalid") throw new ScimConflictError("mutability", "externalId is immutable");
		if (normalizedPath === "displayname") {
			if (op !== "replace" && op !== "add") throw new ScimInvalidValueError("displayName supports add/replace only");
			next.displayName = stringValue(operation.value, "displayName", { required: true, max: 255 }) ?? "";
			continue;
		}
		if (normalizedPath === "members") {
			if (op === "remove" && operation.value === undefined) {
				next.members = [];
				continue;
			}
			const ids = operationMemberIds(operation.value);
			if (op === "replace") next.members = ids;
			else if (op === "add") next.members = [...new Set([...next.members, ...ids])];
			else if (op === "remove") next.members = next.members.filter((id) => !ids.includes(id));
			else throw new ScimInvalidValueError("unsupported group patch operation");
			continue;
		}
		const selection = /^members\[value eq "([^"\\]+)"\]$/i.exec(path);
		if (selection && op === "remove") {
			next.members = next.members.filter((id) => id !== selection[1]);
			continue;
		}
		throw new ScimInvalidValueError(`unsupported group patch path: ${path}`);
	}
	return next;
}

function listResponse(resources: unknown[], total: number, startIndex: number): Record<string, unknown> {
	return { schemas: [SCIM_LIST_SCHEMA], totalResults: total, startIndex, itemsPerPage: resources.length, Resources: resources };
}

function serviceProviderConfig(): Record<string, unknown> {
	return {
		schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
		patch: { supported: true }, bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
		filter: { supported: true, maxResults: MAX_PAGE_SIZE }, changePassword: { supported: false }, sort: { supported: false }, etag: { supported: true },
		authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "Tenant-scoped rotating SCIM bearer token", primary: true }],
	};
}

function resourceTypes(req: Request): Record<string, unknown> {
	const base = new URL(req.url).origin;
	return listResponse([
		{ schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "User", name: "User", endpoint: "/Users", schema: SCIM_USER_SCHEMA, meta: { location: `${base}/v2/ResourceTypes/User` } },
		{ schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "Group", name: "Group", endpoint: "/Groups", schema: SCIM_GROUP_SCHEMA, meta: { location: `${base}/v2/ResourceTypes/Group` } },
	], 2, 1);
}

async function userRoute(req: Request, store: ScimStore, tenant: ScimTenant, id: string | null): Promise<Response> {
	const method = req.method.toUpperCase();
	if (method === "GET" && !id) {
		const url = new URL(req.url); const page = pagination(url); const filter = parseFilter(url.searchParams.get("filter"), "Users");
		const result = await store.listUsers(tenant.tenantId, page.offset, page.count, filter);
		return json(200, listResponse(result.items.map((item) => userResource(req, item)), result.total, page.startIndex));
	}
	if (method === "GET" && id) {
		const user = await store.getUser(tenant.tenantId, id); return user ? json(200, userResource(req, user), { ETag: `W/\"${user.version}\"` }) : error(404, "User not found");
	}
	if (method === "POST" && !id) {
		const result = await store.createUser(tenant.tenantId, parseUser(await readJson(req)));
		const body = userResource(req, result.user);
		return json(result.created ? 201 : 200, body, { Location: location(req, "Users", result.user.id), ETag: `W/\"${result.user.version}\"` });
	}
	if ((method === "PUT" || method === "PATCH") && id) {
		const current = await store.getUser(tenant.tenantId, id); if (!current) return error(404, "User not found");
		const version = expectedVersion(req);
		const input = method === "PUT" ? parseUser(await readJson(req)) : applyUserPatch(current, patchOperations(await readJson(req)));
		if (input.userName !== current.userName || input.externalId !== current.externalId) throw new ScimConflictError("mutability", "userName and externalId are immutable");
		// PATCH carries forward active from the resource just read. Preserve a
		// concurrent deactivation even when the client omitted If-Match.
		const updated = await store.updateUser(tenant.tenantId, id, input, method === "PATCH" ? version ?? current.version : version);
		return updated ? json(200, userResource(req, updated), { ETag: `W/\"${updated.version}\"` }) : error(404, "User not found");
	}
	if (method === "DELETE" && id) {
		const updated = await store.deactivateUser(tenant.tenantId, id, expectedVersion(req));
		return updated ? noContent() : error(404, "User not found");
	}
	return error(405, "Method not allowed");
}

async function groupRoute(req: Request, store: ScimStore, tenant: ScimTenant, id: string | null): Promise<Response> {
	const method = req.method.toUpperCase();
	if (method === "GET" && !id) {
		const url = new URL(req.url); const page = pagination(url); const filter = parseFilter(url.searchParams.get("filter"), "Groups");
		const result = await store.listGroups(tenant.tenantId, page.offset, page.count, filter);
		return json(200, listResponse(result.items.map((item) => groupResource(req, item)), result.total, page.startIndex));
	}
	if (method === "GET" && id) {
		const group = await store.getGroup(tenant.tenantId, id); return group ? json(200, groupResource(req, group), { ETag: `W/\"${group.version}\"` }) : error(404, "Group not found");
	}
	if (method === "POST" && !id) {
		const result = await store.createGroup(tenant.tenantId, parseGroup(await readJson(req)));
		return json(result.created ? 201 : 200, groupResource(req, result.group), { Location: location(req, "Groups", result.group.id), ETag: `W/\"${result.group.version}\"` });
	}
	if ((method === "PUT" || method === "PATCH") && id) {
		const current = await store.getGroup(tenant.tenantId, id); if (!current) return error(404, "Group not found");
		const version = expectedVersion(req);
		const input = method === "PUT" ? parseGroup(await readJson(req)) : applyGroupPatch(current, patchOperations(await readJson(req)));
		if (input.externalId !== current.externalId) throw new ScimConflictError("mutability", "externalId is immutable");
		// PATCH derives the replacement member set from the version just read.
		// Always compare that version so a concurrent directory update cannot be lost.
		const updated = await store.updateGroup(tenant.tenantId, id, input, method === "PATCH" ? version ?? current.version : version);
		return updated ? json(200, groupResource(req, updated), { ETag: `W/\"${updated.version}\"` }) : error(404, "Group not found");
	}
	if (method === "DELETE" && id) return (await store.deleteGroup(tenant.tenantId, id, expectedVersion(req))) ? noContent() : error(404, "Group not found");
	return error(405, "Method not allowed");
}

export function createScimHandler(store: ScimStore): (req: Request) => Promise<Response> {
	return async (req: Request): Promise<Response> => {
		try {
			const token = getBearerToken(req.headers.get("Authorization"));
			if (!token) return error(401, "A bearer token is required", undefined);
			const tenant = await store.authenticate(token);
			if (!tenant) return json(401, { schemas: [SCIM_ERROR_SCHEMA], status: "401", detail: "Invalid bearer token" }, { "WWW-Authenticate": "Bearer" });
			const parsed = parsePath(new URL(req.url).pathname);
			if (!parsed) return error(404, "SCIM endpoint not found");
			if (req.method === "GET" && parsed.resource.toLowerCase() === "serviceproviderconfig" && !parsed.id) return json(200, serviceProviderConfig());
			if (req.method === "GET" && parsed.resource.toLowerCase() === "resourcetypes" && !parsed.id) return json(200, resourceTypes(req));
			if (parsed.resource.toLowerCase() === "users") return await userRoute(req, store, tenant, parsed.id);
			if (parsed.resource.toLowerCase() === "groups") return await groupRoute(req, store, tenant, parsed.id);
			return error(404, "SCIM resource not found");
		} catch (caught) {
			if (caught instanceof ScimConflictError) return error(caught.scimType === "versionMismatch" ? 412 : 409, caught.message, caught.scimType);
			if (caught instanceof ScimInvalidValueError) return error(400, caught.message, caught.message.includes("filter") ? "invalidFilter" : "invalidValue");
			console.error("[scim] request failed", caught instanceof Error ? caught.name : "unknown");
			return error(503, "SCIM service unavailable");
		}
	};
}
