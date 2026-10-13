// installer-download: catalog + signed URL contract for the dashboard Download page.
//
// The storage objects are signed with the release signature envelope of
// scripts/release-signing-lib.mjs (the primitive scripts/publish-installers.mjs uses),
// so this suite also proves the publisher and the Edge verifier agree on the format.
import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error -- plain .mjs release tooling without type declarations
import { signReleaseManifest } from "../../../scripts/release-signing-lib.mjs";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through InstallerDownloadDeps.client");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const NOW = Date.parse("2026-10-13T10:00:00.000Z");
const URL_BASE = "https://project.supabase.co/functions/v1/installer-download";
const SHA = (text: string) => createHash("sha256").update(text).digest("hex");

const keys = generateKeyPairSync("ed25519");
const PUBLIC_KEY_B64 = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64");

function signed(value: unknown, privateKey: KeyObject = keys.privateKey) {
	const raw = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
	const sig = Buffer.from(JSON.stringify(signReleaseManifest(raw, privateKey, "installer-catalog-1")));
	return { raw, sig };
}

function catalogDoc(overrides: Record<string, unknown> = {}) {
	return {
		schema_version: 1,
		type: "aidr-installer-catalog",
		product_id: "singularity-aidr",
		channel: "stable",
		version: "1.4.0",
		published_at: "2026-10-12T09:00:00.000Z",
		release_notes_url: "https://docs.example.com/releases/1.4.0",
		release: {
			tag: "v1.4.0", git_sha: "a".repeat(40), release_sequence: 7,
			manifest_path: "1.4.0/release/aidr-release.manifest.json", manifest_sha256: "b".repeat(64),
			signature_sha256: "c".repeat(64), signer_key_id: "release-key-1", signer_fingerprint: `sha256:${"d".repeat(64)}`,
		},
		files: [
			{ platform: "windows-x64", os: "windows", arch: "x64", file: "AIDR-Setup-1.4.0-x64.msi", path: "1.4.0/windows-x64/AIDR-Setup-1.4.0-x64.msi", size: 4096, sha256: SHA("win"), minimum_os: "Windows 10 / Windows Server 2016", format: "msi" },
			{ platform: "linux-x64", os: "linux", arch: "x64", file: "aidr-install-1.4.0-linux-x64.sh", path: "1.4.0/linux-x64/aidr-install-1.4.0-linux-x64.sh", size: 2048, sha256: SHA("linux"), minimum_os: "glibc 2.28", format: "sh" },
		],
		...overrides,
	};
}

function bucketObjects({ catalog = catalogDoc(), pointerOverrides = {}, catalogKey = keys.privateKey, pointerKey = keys.privateKey } = {}) {
	const manifest = signed(catalog, catalogKey);
	const pointer = signed({
		schema_version: 1, type: "aidr-installer-latest", product_id: "singularity-aidr", version: "1.4.0",
		release_sequence: 7, manifest_path: "1.4.0/manifest.json",
		manifest_sha256: createHash("sha256").update(manifest.raw).digest("hex"),
		published_at: "2026-10-12T09:00:00.000Z", ...pointerOverrides,
	}, pointerKey);
	return new Map<string, Buffer>([
		["latest.json", pointer.raw], ["latest.json.sig", pointer.sig],
		["1.4.0/manifest.json", manifest.raw], ["1.4.0/manifest.json.sig", manifest.sig],
	]);
}

interface Options {
	role?: string | null;
	expiresAt?: string | null;
	tenantStatus?: string;
	memberError?: boolean;
	admission?: Record<string, unknown> | null;
	admissionError?: boolean;
	rateAllowed?: boolean;
	rateError?: boolean;
	objects?: Map<string, Buffer>;
	storageError?: boolean;
	signedUrl?: string;
	auditStatus?: string;
	auditError?: boolean;
	env?: Record<string, string>;
}

const ACTIVE_ADMISSION = { status: "active", access_kind: "licensed", mode: "cloud", allowed_agents: 10, expires_at: "2027-01-01T00:00:00.000Z" };

function database(options: Options = {}) {
	const objects = options.objects ?? bucketObjects();
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const signCalls: Array<{ bucket: string; path: string; ttl: number; opts: unknown }> = [];
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => token === "valid-token"
				? { data: { user: { id: USER } }, error: null }
				: { data: { user: null }, error: new Error("invalid") }),
		},
		from(table: string) {
			const builder = {
				select: () => builder,
				eq: () => builder,
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: null, error: null };
					if (table === "tenant_identity_policies") return { data: null, error: null };
					if (table === "tenant_members") {
						if (options.memberError) return { data: null, error: new Error("db_down") };
						return options.role === null ? { data: null, error: null }
							: { data: { role: options.role ?? "member", expires_at: options.expiresAt ?? null }, error: null };
					}
					if (table === "tenants") return { data: { id: TENANT, status: options.tenantStatus ?? "active" }, error: null };
					throw new Error(`unexpected table ${table}`);
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			if (name === "get_tenant_admission") {
				return options.admissionError ? { data: null, error: { message: "down" } }
					: { data: options.admission === undefined ? ACTIVE_ADMISSION : options.admission, error: null };
			}
			if (name === "consume_tenant_rate_limit") {
				if (options.rateError) return { data: null, error: { message: "db_down" } };
				return { data: { allowed: options.rateAllowed ?? true, remaining: 3 }, error: null };
			}
			if (name === "record_installer_download") {
				return options.auditError ? { data: null, error: { message: "down" } }
					: { data: { status: options.auditStatus ?? "recorded" }, error: null };
			}
			throw new Error(`unexpected rpc ${name}`);
		}),
		storage: {
			from: (bucket: string) => ({
				download: async (path: string) => {
					if (options.storageError) return { data: null, error: { statusCode: "500", message: "storage down" } };
					const bytes = objects.get(path);
					return bytes ? { data: new Blob([bytes]), error: null } : { data: null, error: { statusCode: "404", message: "Object not found" } };
				},
				createSignedUrl: async (path: string, ttl: number, opts: unknown) => {
					signCalls.push({ bucket, path, ttl, opts });
					return { data: { signedUrl: options.signedUrl ?? `https://project.supabase.co/storage/v1/object/sign/${bucket}/${path}?token=signed-token` }, error: null };
				},
			}),
		},
	};
	return { db, rpcCalls, signCalls };
}

async function handlerWith(options: Options = {}) {
	const fake = database(options);
	const mod = await import("../installer-download/index.ts");
	const env: Record<string, string> = {
		SUPABASE_URL: "https://project.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
		AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64: PUBLIC_KEY_B64,
		...options.env,
	};
	const handle = mod.createInstallerDownloadHandler({
		env: (name) => env[name],
		client: () => fake.db as never,
		now: () => NOW,
	});
	return { ...fake, handle };
}

function get(token = "valid-token", tenant = TENANT): Request {
	return new Request(URL_BASE, { method: "GET", headers: { Authorization: `Bearer ${token}`, "X-AIDR-Tenant-ID": tenant } });
}

function post(body: unknown, token = "valid-token"): Request {
	return new Request(URL_BASE, {
		method: "POST",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

const DOWNLOAD = { tenant_id: TENANT, version: "1.4.0", platform: "windows-x64" };

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("installer-download catalog", () => {
	it("returns the verified catalog and managed enrollment to an entitled member", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(get());
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body.catalog.version).toBe("1.4.0");
		expect(body.catalog.release_notes_url).toBe("https://docs.example.com/releases/1.4.0");
		expect(body.catalog.files.map((file: { platform: string }) => file.platform)).toEqual(["windows-x64", "linux-x64"]);
		expect(body.catalog.files[0]).toEqual({
			platform: "windows-x64", os: "windows", arch: "x64", file: "AIDR-Setup-1.4.0-x64.msi",
			size: 4096, sha256: SHA("win"), minimum_os: "Windows 10 / Windows Server 2016", format: "msi",
		});
		// Storage paths are internal; the browser never sees them.
		expect(JSON.stringify(body)).not.toContain("1.4.0/windows-x64/");
		expect(body.managed_enrollment).toEqual({ available: true, control_plane_url: "https://project.supabase.co" });
		expect(rpcCalls.map((call) => call.name)).toEqual(["get_tenant_admission", "consume_tenant_rate_limit"]);
		expect(rpcCalls[1].args).toMatchObject({ p_endpoint: "installer-catalog", p_subject: USER });
	});

	it("offers managed enrollment only to roles that can enroll, at the public API origin", async () => {
		const viewer = await handlerWith({ role: "viewer", env: { AIDR_PUBLIC_API_ORIGIN: "https://api.customer.example" } });
		expect((await (await viewer.handle(get())).json()).managed_enrollment).toEqual({ available: false });
		const member = await handlerWith({ env: { AIDR_PUBLIC_API_ORIGIN: "https://api.customer.example" } });
		expect((await (await member.handle(get())).json()).managed_enrollment.control_plane_url).toBe("https://api.customer.example");
	});

	it("fails closed for unauthenticated, non-member, inactive and unentitled callers", async () => {
		const cases: Array<[Options, Request, number, string]> = [
			[{}, new Request(URL_BASE, { headers: { "X-AIDR-Tenant-ID": TENANT } }), 401, "missing_access_token"],
			[{}, get("forged-token"), 401, "invalid_access_token"],
			[{ role: null }, get(), 403, "tenant_not_authorized"],
			[{ expiresAt: "2026-01-01T00:00:00.000Z" }, get(), 403, "tenant_not_authorized"],
			[{ role: "auditor" }, get(), 403, "tenant_not_authorized"],
			[{ tenantStatus: "suspended" }, get(), 403, "tenant_not_authorized"],
			[{ admission: { status: "revoked" } }, get(), 403, "entitlement_required"],
			[{ admission: { status: "expired" } }, get(), 403, "entitlement_required"],
			[{ admission: { status: "not_entitled" } }, get(), 403, "entitlement_required"],
			[{ admission: { ...ACTIVE_ADMISSION, expires_at: "2026-10-01T00:00:00.000Z" } }, get(), 503, "admission_unavailable"],
			[{ admissionError: true }, get(), 503, "admission_unavailable"],
			[{ memberError: true }, get(), 503, "authorization_unavailable"],
			[{ rateAllowed: false }, get(), 429, "rate_limited"],
			[{ rateError: true }, get(), 503, "rate_limit_unavailable"],
		];
		for (const [options, request, status, error] of cases) {
			const { handle, signCalls } = await handlerWith(options);
			const response = await handle(request);
			expect(response.status, error).toBe(status);
			expect((await response.json()).error).toBe(error);
			expect(signCalls).toEqual([]);
			vi.resetModules();
		}
	});

	it("withholds the whole catalog unless both signatures and the pointer digest verify", async () => {
		const other = generateKeyPairSync("ed25519").privateKey;
		const tamperedCatalog = bucketObjects();
		tamperedCatalog.set("1.4.0/manifest.json", Buffer.from(tamperedCatalog.get("1.4.0/manifest.json")!.toString().replace(SHA("win"), SHA("evil"))));
		const unsignedPointer = bucketObjects();
		unsignedPointer.delete("latest.json.sig");
		const cases: Array<[Options, number, string]> = [
			[{ objects: bucketObjects({ catalogKey: other }) }, 503, "catalog_integrity_failed"],
			[{ objects: bucketObjects({ pointerKey: other }) }, 503, "catalog_integrity_failed"],
			[{ objects: tamperedCatalog }, 503, "catalog_integrity_failed"],
			[{ objects: unsignedPointer }, 503, "catalog_integrity_failed"],
			[{ objects: bucketObjects({ pointerOverrides: { manifest_sha256: "0".repeat(64) } }) }, 503, "catalog_integrity_failed"],
			[{ objects: bucketObjects({ catalog: catalogDoc({ files: [{ ...catalogDoc().files[0], path: "../../other-bucket/x.msi" }] }) }) }, 503, "catalog_integrity_failed"],
			[{ objects: bucketObjects({ catalog: catalogDoc({ release_notes_url: "javascript:alert(1)" }) }) }, 503, "catalog_integrity_failed"],
			[{ objects: new Map() }, 404, "installers_unpublished"],
			[{ storageError: true }, 503, "catalog_unavailable"],
		];
		for (const [options, status, error] of cases) {
			const { handle } = await handlerWith(options);
			const response = await handle(get());
			expect(response.status, error).toBe(status);
			const body = await response.json();
			expect(body.error).toBe(error);
			expect(body.catalog).toBeUndefined();
			vi.resetModules();
		}
	});

	it("names missing or unusable configuration before any work", async () => {
		const missing = await handlerWith({ env: { AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64: "" } });
		const response = await missing.handle(get());
		expect(response.status).toBe(500);
		expect(missing.db.auth.getUser).not.toHaveBeenCalled();
		vi.resetModules();
		for (const [env, variable] of [
			[{ AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64: "bm90LWEta2V5" }, "AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64"],
			[{ AIDR_INSTALLERS_BUCKET: "../packs" }, "AIDR_INSTALLERS_BUCKET"],
			[{ AIDR_PUBLIC_API_ORIGIN: "http://kong:8000" }, "AIDR_PUBLIC_API_ORIGIN"],
		] as const) {
			const { handle, db } = await handlerWith({ env });
			const result = await handle(get());
			expect(result.status).toBe(500);
			expect((await result.json()).invalid).toEqual([variable]);
			expect(db.auth.getUser).not.toHaveBeenCalled();
			vi.resetModules();
		}
	});
});

describe("installer-download signed URLs", () => {
	it("mints a short-lived URL for the current version and audits it first", async () => {
		const { handle, rpcCalls, signCalls } = await handlerWith({ env: { AIDR_INSTALLER_URL_TTL_SECONDS: "120" } });
		const response = await handle(post(DOWNLOAD));
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body).toEqual({
			ok: true,
			url: "https://project.supabase.co/storage/v1/object/sign/aidr-installers/1.4.0/windows-x64/AIDR-Setup-1.4.0-x64.msi?token=signed-token",
			expires_at: new Date(NOW + 120_000).toISOString(),
			version: "1.4.0", platform: "windows-x64", file: "AIDR-Setup-1.4.0-x64.msi", size: 4096, sha256: SHA("win"),
		});
		expect(signCalls).toEqual([{ bucket: "aidr-installers", path: "1.4.0/windows-x64/AIDR-Setup-1.4.0-x64.msi", ttl: 120, opts: { download: "AIDR-Setup-1.4.0-x64.msi" } }]);
		const audit = rpcCalls.find((call) => call.name === "record_installer_download");
		expect(audit?.args).toEqual({
			p_actor_user_id: USER, p_tenant_id: TENANT, p_version: "1.4.0", p_platform: "windows-x64",
			p_file_name: "AIDR-Setup-1.4.0-x64.msi", p_sha256: SHA("win"),
		});
		expect(JSON.stringify(audit?.args)).not.toMatch(/ip|user_agent/i);
		expect(rpcCalls.find((call) => call.name === "consume_tenant_rate_limit")?.args).toMatchObject({ p_endpoint: "installer-download" });
	});

	it("rebases the storage URL onto the public API origin and clamps the TTL", async () => {
		const { handle, signCalls } = await handlerWith({
			env: { SUPABASE_URL: "http://kong:8000", AIDR_PUBLIC_API_ORIGIN: "https://api.customer.example", AIDR_INSTALLER_URL_TTL_SECONDS: "86400" },
			signedUrl: "http://kong:8000/storage/v1/object/sign/aidr-installers/1.4.0/linux-x64/aidr-install-1.4.0-linux-x64.sh?token=t&download=aidr-install-1.4.0-linux-x64.sh",
		});
		const body = await (await handle(post({ ...DOWNLOAD, platform: "linux-x64" }))).json();
		expect(body.url).toBe("https://api.customer.example/storage/v1/object/sign/aidr-installers/1.4.0/linux-x64/aidr-install-1.4.0-linux-x64.sh?token=t&download=aidr-install-1.4.0-linux-x64.sh");
		expect(signCalls[0].ttl).toBe(900);
	});

	it("refuses other versions, unpublished platforms and malformed requests without minting a URL", async () => {
		const cases: Array<[unknown, number, string]> = [
			[{ ...DOWNLOAD, version: "1.3.0" }, 404, "installer_not_found"],
			[{ ...DOWNLOAD, platform: "linux-arm64" }, 404, "installer_not_found"],
			[{ ...DOWNLOAD, platform: "macos-arm64" }, 400, "invalid_request"],
			[{ ...DOWNLOAD, path: "../../aidr-packs/x" }, 400, "invalid_request"],
			[{ ...DOWNLOAD, tenant_id: "not-a-uuid" }, 400, "invalid_request"],
		];
		for (const [body, status, error] of cases) {
			const { handle, signCalls, rpcCalls } = await handlerWith();
			const response = await handle(post(body));
			expect(response.status, error).toBe(status);
			expect((await response.json()).error).toBe(error);
			expect(signCalls).toEqual([]);
			expect(rpcCalls.some((call) => call.name === "record_installer_download")).toBe(false);
			vi.resetModules();
		}
	});

	it("returns no URL when the audit row cannot be written or the database refuses it", async () => {
		for (const [options, status, error] of [
			[{ auditError: true }, 503, "audit_unavailable"],
			[{ auditStatus: "forbidden" }, 403, "tenant_not_authorized"],
			[{ auditStatus: "weird" }, 503, "audit_unavailable"],
			[{ signedUrl: "https://evil.example/storage/v1/object/sign/aidr-installers/x?token=t" }, 503, "download_unavailable"],
			[{ admission: { status: "revoked" } }, 403, "entitlement_required"],
		] as Array<[Options, number, string]>) {
			const { handle } = await handlerWith(options);
			const response = await handle(post(DOWNLOAD));
			expect(response.status, error).toBe(status);
			const body = await response.json();
			expect(body.error).toBe(error);
			expect(body.url).toBeUndefined();
			vi.resetModules();
		}
	});
});

describe("installer-download deployment contract", () => {
	const migration = readFileSync(join(ROOT, "supabase", "migrations", "20261013000600_installer_download_portal.sql"), "utf8");
	const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
	const manifest = JSON.parse(readFileSync(join(ROOT, "docs", "production-readiness", "edge-function-contract-manifest.json"), "utf8"));

	it("keeps the bucket private and the audit RPC service-role only", () => {
		expect(migration).toMatch(/values \('aidr-installers', 'aidr-installers', false\)\s*on conflict \(id\) do update set public = false;/);
		expect(migration).not.toMatch(/create policy/i);
		expect(migration).toContain("security definer");
		expect(migration).toContain("set search_path = pg_catalog, public, pg_temp");
		expect(migration).toMatch(/revoke all on function public\.record_installer_download\(uuid, uuid, text, text, text, text\)\s*from public, anon, authenticated;/);
		expect(migration).toMatch(/grant execute on function public\.record_installer_download\(uuid, uuid, text, text, text, text\)\s*to service_role;/);
		// The database re-checks membership and tenant status, and stores no network identifiers.
		expect(migration).toContain("t.status = 'active'");
		expect(migration).toContain("'installer.download'");
		expect(migration).not.toMatch(/inet|ip_address|user_agent/i);
		// The audit RPC accepts exactly the platforms the Edge Function serves.
		expect(migration).toContain("p_platform not in ('windows-x64', 'windows-arm64', 'linux-x64', 'linux-arm64')");
	});

	it("is deployed with gateway JWT verification and listed with this contract test", () => {
		expect(config).toMatch(/\[functions\.installer-download\][\s\S]*?verify_jwt = true/);
		expect(manifest.functions["installer-download"].tests).toContain("supabase/functions/__tests__/installer-download-contract.test.ts");
	});
});
