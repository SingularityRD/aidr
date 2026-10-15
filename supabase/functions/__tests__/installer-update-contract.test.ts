// installer-update: the device (API key) path to the signed installer catalog
// used by `aidr update`. The storage objects are signed with the release
// signature envelope of scripts/release-signing-lib.mjs, as publish-installers.mjs
// writes them.
import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error -- plain .mjs release tooling without type declarations
import { signReleaseManifest } from "../../../scripts/release-signing-lib.mjs";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through InstallerUpdateDeps.client");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const KEY_ID = "33333333-3333-4333-8333-333333333333";
const API_KEY = "aidr_device_key_for_tests";
const NOW = Date.parse("2026-10-13T10:00:00.000Z");
const URL_BASE = "https://project.supabase.co/functions/v1/installer-update";
const SHA = (text: string) => createHash("sha256").update(text).digest("hex");

const keys = generateKeyPairSync("ed25519");
const PUBLIC_KEY_B64 = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64");

function signed(value: unknown, privateKey: KeyObject = keys.privateKey) {
	const raw = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
	const sig = Buffer.from(JSON.stringify(signReleaseManifest(raw, privateKey, "installer-catalog-1")));
	return { raw, sig };
}

const LINUX_FILES = [
	{ file: "singularity-aidr_1.4.0_amd64.deb", format: "deb" },
	{ file: "singularity-aidr-1.4.0-1.x86_64.rpm", format: "rpm" },
	{ file: "singularity-aidr-1.4.0-linux-x64.tar.gz", format: "tar.gz" },
];

function catalogDoc(multiFormat = false) {
	return {
		schema_version: multiFormat ? 2 : 1,
		type: "aidr-installer-catalog",
		product_id: "singularity-aidr",
		channel: "stable",
		version: "1.4.0",
		published_at: "2026-10-12T09:00:00.000Z",
		release_notes_url: "https://docs.example.com/releases/1.4.0",
		release: { tag: "v1.4.0", git_sha: "a".repeat(40), release_sequence: 7 },
		files: [
			{ platform: "windows-x64", os: "windows", arch: "x64", file: "singularity-aidr-1.4.0-windows-x64.msi", path: "1.4.0/windows-x64/singularity-aidr-1.4.0-windows-x64.msi", size: 4096, sha256: SHA("win"), minimum_os: "Windows 10", format: "msi" },
			...(multiFormat
				? LINUX_FILES.map(({ file, format }) => ({ platform: "linux-x64", os: "linux", arch: "x64", file, path: `1.4.0/linux-x64/${file}`, size: 2048, sha256: SHA(format), minimum_os: "glibc 2.28", format }))
				: []),
		],
	};
}

function bucketObjects(catalogKey: KeyObject = keys.privateKey, multiFormat = false) {
	const manifest = signed(catalogDoc(multiFormat), catalogKey);
	const pointer = signed({
		schema_version: 1, type: "aidr-installer-latest", product_id: "singularity-aidr", version: "1.4.0",
		release_sequence: 7, manifest_path: "1.4.0/manifest.json",
		manifest_sha256: createHash("sha256").update(manifest.raw).digest("hex"),
		published_at: "2026-10-12T09:00:00.000Z",
	});
	return new Map<string, Buffer>([
		["latest.json", pointer.raw], ["latest.json.sig", pointer.sig],
		["1.4.0/manifest.json", manifest.raw], ["1.4.0/manifest.json.sig", manifest.sig],
	]);
}

interface Options {
	keyRow?: Record<string, unknown> | null;
	role?: string;
	tenantStatus?: string;
	admission?: Record<string, unknown>;
	admissionError?: boolean;
	rateAllowed?: boolean;
	objects?: Map<string, Buffer>;
	auditStatus?: string;
	env?: Record<string, string>;
}

const ACTIVE_ADMISSION = { status: "active", access_kind: "licensed", mode: "cloud", allowed_agents: 10, expires_at: "2027-01-01T00:00:00.000Z" };

function database(options: Options = {}) {
	const objects = options.objects ?? bucketObjects();
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const signCalls: string[] = [];
	const keyRow = options.keyRow === undefined
		? { id: KEY_ID, user_id: USER, tenant_id: TENANT, revoked: false, agent_id: null, scope: "tenant", install_limit: null, expires_at: null }
		: options.keyRow;
	const db = {
		auth: { getUser: vi.fn() },
		from(table: string) {
			const filters: Record<string, unknown> = {};
			const builder = {
				select: () => builder,
				eq: (column: string, value: unknown) => {
					filters[column] = value;
					return builder;
				},
				maybeSingle: async () => {
					if (table === "rate_limits") return { data: null, error: null };
					if (table === "api_keys") {
						return { data: filters.key_hash === SHA(API_KEY) ? keyRow : null, error: null };
					}
					if (table === "tenant_members") return { data: { role: options.role ?? "member", expires_at: null }, error: null };
					if (table === "tenants") return { data: { status: options.tenantStatus ?? "active" }, error: null };
					throw new Error(`unexpected table ${table}`);
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			if (name === "increment_rate_limit") return { data: 1, error: null };
			if (name === "tenant_admission_capacity") return { data: 10, error: null };
			if (name === "get_tenant_admission") {
				return options.admissionError ? { data: null, error: { message: "down" } } : { data: options.admission ?? ACTIVE_ADMISSION, error: null };
			}
			if (name === "consume_tenant_rate_limit") return { data: { allowed: options.rateAllowed ?? true, remaining: 3 }, error: null };
			if (name === "record_installer_download") return { data: { status: options.auditStatus ?? "recorded" }, error: null };
			throw new Error(`unexpected rpc ${name}`);
		}),
		storage: {
			from: (bucket: string) => ({
				download: async (path: string) => {
					const bytes = objects.get(path);
					return bytes ? { data: new Blob([bytes]), error: null } : { data: null, error: { statusCode: "404", message: "Object not found" } };
				},
				createSignedUrl: async (path: string) => {
					signCalls.push(path);
					return { data: { signedUrl: `https://project.supabase.co/storage/v1/object/sign/${bucket}/${path}?token=signed-token` }, error: null };
				},
			}),
		},
	};
	return { db, rpcCalls, signCalls };
}

async function handlerWith(options: Options = {}) {
	const fake = database(options);
	const mod = await import("../installer-update/index.ts");
	const env: Record<string, string> = {
		SUPABASE_URL: "https://project.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
		AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64: PUBLIC_KEY_B64,
		...options.env,
	};
	const handle = mod.createInstallerUpdateHandler({ env: (name) => env[name], client: () => fake.db as never, now: () => NOW });
	return { ...fake, handle };
}

const get = (key = API_KEY) => new Request(URL_BASE, { method: "GET", headers: { Authorization: `Bearer ${key}` } });
const post = (body: unknown, key = API_KEY) =>
	new Request(URL_BASE, { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: JSON.stringify(body) });

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("installer-update catalog (device credential)", () => {
	it("returns the exact signed bytes of the pointer and the catalog", async () => {
		const objects = bucketObjects();
		const { handle, rpcCalls } = await handlerWith({ objects });
		const response = await handle(get());
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body.version).toBe("1.4.0");
		const decode = (value: string) => Buffer.from(value, "base64");
		expect(decode(body.pointer.document_b64).equals(objects.get("latest.json")!)).toBe(true);
		expect(decode(body.pointer.signature_b64).equals(objects.get("latest.json.sig")!)).toBe(true);
		expect(decode(body.catalog.document_b64).equals(objects.get("1.4.0/manifest.json")!)).toBe(true);
		expect(decode(body.catalog.signature_b64).equals(objects.get("1.4.0/manifest.json.sig")!)).toBe(true);
		expect(rpcCalls.find((call) => call.name === "consume_tenant_rate_limit")?.args).toMatchObject({
			p_endpoint: "installer-update-catalog",
			p_subject: KEY_ID,
		});
	});

	it("fails closed for missing, unknown, revoked, narrower and unadmitted credentials", async () => {
		const cases: Array<[Options, Request, number, string]> = [
			[{}, new Request(URL_BASE), 401, "missing_api_key"],
			[{}, get("not-a-key"), 401, "invalid_api_key"],
			[{ keyRow: { id: KEY_ID, user_id: USER, tenant_id: TENANT, revoked: true, scope: "tenant", install_limit: null, expires_at: null } }, get(), 401, "invalid_api_key"],
			[{ keyRow: { id: KEY_ID, user_id: USER, tenant_id: TENANT, revoked: false, scope: "ingest:browser_guard", install_limit: 5, expires_at: null } }, get(), 403, "api_key_scope_denied"],
			[{ role: "viewer" }, get(), 403, "tenant_access_denied"],
			[{ tenantStatus: "suspended" }, get(), 403, "tenant_access_denied"],
			[{ admission: { status: "revoked" } }, get(), 403, "entitlement_required"],
			[{ admission: { status: "expired" } }, get(), 403, "entitlement_required"],
			[{ admissionError: true }, get(), 503, "admission_unavailable"],
			[{ rateAllowed: false }, get(), 429, "rate_limited"],
		];
		for (const [options, request, status, error] of cases) {
			const { handle, signCalls } = await handlerWith(options);
			const response = await handle(request);
			expect(response.status, error).toBe(status);
			const body = await response.json();
			expect(body.error).toBe(error);
			expect(body.catalog).toBeUndefined();
			expect(signCalls).toEqual([]);
			vi.resetModules();
		}
	});

	it("serves nothing when the stored catalog does not verify", async () => {
		const { handle } = await handlerWith({ objects: bucketObjects(generateKeyPairSync("ed25519").privateKey) });
		const response = await handle(get());
		expect(response.status).toBe(503);
		const body = await response.json();
		expect(body).toEqual({ error: "catalog_integrity_failed" });
	});

	it("names missing configuration before reading any credential", async () => {
		const { handle, rpcCalls } = await handlerWith({ env: { AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64: "" } });
		expect((await handle(get())).status).toBe(500);
		expect(rpcCalls).toEqual([]);
	});
});

describe("installer-update download URL (device credential)", () => {
	it("mints a URL for the current version only after the audit row is written", async () => {
		const { handle, rpcCalls, signCalls } = await handlerWith();
		const response = await handle(post({ version: "1.4.0", platform: "windows-x64" }));
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body.url).toBe("https://project.supabase.co/storage/v1/object/sign/aidr-installers/1.4.0/windows-x64/singularity-aidr-1.4.0-windows-x64.msi?token=signed-token");
		expect(body.sha256).toBe(SHA("win"));
		expect(signCalls).toEqual(["1.4.0/windows-x64/singularity-aidr-1.4.0-windows-x64.msi"]);
		expect(rpcCalls.find((call) => call.name === "record_installer_download")?.args).toEqual({
			p_actor_user_id: USER, p_tenant_id: TENANT, p_version: "1.4.0", p_platform: "windows-x64",
			p_format: "msi", p_file_name: "singularity-aidr-1.4.0-windows-x64.msi", p_sha256: SHA("win"),
		});
		expect(body.format).toBe("msi");
		expect(rpcCalls.find((call) => call.name === "consume_tenant_rate_limit")?.args).toMatchObject({ p_endpoint: "installer-update-download" });
	});

	it("hands out the installer in the format the endpoint was installed with", async () => {
		const objects = bucketObjects(keys.privateKey, true);
		for (const { file, format } of LINUX_FILES) {
			const { handle, rpcCalls, signCalls } = await handlerWith({ objects });
			const body = await (await handle(post({ version: "1.4.0", platform: "linux-x64", format }))).json();
			expect(body).toMatchObject({ ok: true, format, file, sha256: SHA(format) });
			expect(signCalls).toEqual([`1.4.0/linux-x64/${file}`]);
			expect(rpcCalls.find((call) => call.name === "record_installer_download")?.args).toMatchObject({ p_format: format, p_file_name: file });
			vi.resetModules();
		}
		// An endpoint that does not send a format (released before formats existed) gets the tarball.
		const { handle } = await handlerWith({ objects });
		expect(await (await handle(post({ version: "1.4.0", platform: "linux-x64" }))).json()).toMatchObject({ format: "tar.gz" });
	});

	it("refuses other versions, unknown fields and unpublished platforms, and an unaudited URL", async () => {
		const cases: Array<[Options, unknown, number, string]> = [
			[{ objects: bucketObjects(keys.privateKey, true) }, { version: "1.4.0", platform: "linux-x64", format: "msi" }, 404, "installer_not_found"],
			[{ objects: bucketObjects(keys.privateKey, true) }, { version: "1.4.0", platform: "linux-x64", format: "DEB" }, 400, "invalid_request"],
			[{}, { version: "1.4.0", platform: "windows-x64", format: "deb" }, 404, "installer_not_found"],
			[{}, { version: "1.3.0", platform: "windows-x64" }, 404, "installer_not_found"],
			[{}, { version: "1.4.0", platform: "linux-x64" }, 404, "installer_not_found"],
			[{}, { version: "1.4.0", platform: "macos-arm64" }, 400, "invalid_request"],
			[{}, { version: "1.4.0", platform: "windows-x64", path: "../x" }, 400, "invalid_request"],
			[{ auditStatus: "forbidden" }, { version: "1.4.0", platform: "windows-x64" }, 403, "tenant_access_denied"],
			[{ auditStatus: "weird" }, { version: "1.4.0", platform: "windows-x64" }, 503, "audit_unavailable"],
		];
		for (const [options, body, status, error] of cases) {
			const { handle } = await handlerWith(options);
			const response = await handle(post(body));
			expect(response.status, error).toBe(status);
			const parsed = await response.json();
			expect(parsed.error).toBe(error);
			expect(parsed.url).toBeUndefined();
			vi.resetModules();
		}
	});
});

describe("installer-update deployment contract", () => {
	it("authenticates the API key itself and is listed with this contract test", () => {
		const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
		const manifest = JSON.parse(readFileSync(join(ROOT, "docs", "production-readiness", "edge-function-contract-manifest.json"), "utf8"));
		expect(config).toMatch(/\[functions\.installer-update\][^[]*verify_jwt = false/);
		expect(manifest.functions["installer-update"].tests).toContain("supabase/functions/__tests__/installer-update-contract.test.ts");
	});
});
