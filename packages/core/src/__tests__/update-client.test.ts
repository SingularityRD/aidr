import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatUpdateNotice } from "../format.js";
import { ConfigSchema } from "../types.js";
import {
	parseCatalogPublicKey,
	type SignedDocument,
	verifyCatalogDocument,
	verifyPublishedCatalog,
} from "../update/catalog.js";
import {
	checkInstallerUpdate,
	compareReleaseVersions,
	installerUpdateNotice,
	installerUpdatesApply,
	readUpdateState,
	resolveUpdateSource,
} from "../update/check.js";
import {
	detectMdmManaged,
	effectiveAutoMode,
	installerLayoutFor,
	installerPlatform,
	LINUX_MDM_MARKER,
	trustedCatalogKeys,
} from "../update/environment.js";
import { downloadVerified, loadCatalog } from "../update/source.js";

const sha = (bytes: string | Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const catalogKey = generateKeyPairSync("ed25519");
const otherKey = generateKeyPairSync("ed25519");
const PUBLIC_B64 = catalogKey.publicKey.export({ type: "spki", format: "der" }).toString("base64");
const KEYS = [catalogKey.publicKey];
const INSTALLER = Buffer.from("singularity-aidr 1.5.0 linux tarball bytes");

function signDoc(value: unknown, key: KeyObject = catalogKey.privateKey): SignedDocument {
	const document = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
	const envelope = {
		schema_version: 1,
		algorithm: "Ed25519",
		key_id: "installer-catalog-1",
		signature_b64: sign(null, document, key).toString("base64"),
	};
	return { document, signature: Buffer.from(JSON.stringify(envelope)) };
}

function catalogValue(overrides: Record<string, unknown> = {}) {
	return {
		schema_version: 1,
		type: "aidr-installer-catalog",
		product_id: "singularity-aidr",
		channel: "stable",
		version: "1.5.0",
		published_at: "2026-10-12T09:00:00.000Z",
		release_notes_url: "https://docs.example.com/releases/1.5.0",
		release: { tag: "v1.5.0", git_sha: "a".repeat(40), release_sequence: 8 },
		files: [
			{
				platform: "linux-x64",
				os: "linux",
				arch: "x64",
				file: "singularity-aidr-1.5.0-linux-x64.tar.gz",
				path: "1.5.0/linux-x64/singularity-aidr-1.5.0-linux-x64.tar.gz",
				size: INSTALLER.length,
				sha256: sha(INSTALLER),
				minimum_os: "glibc 2.28",
				format: "tar.gz",
			},
		],
		...overrides,
	};
}

function published(
	options: {
		catalogKey?: KeyObject;
		pointerKey?: KeyObject;
		catalog?: Record<string, unknown>;
		digest?: string;
	} = {},
) {
	const catalog = signDoc(options.catalog ?? catalogValue(), options.catalogKey);
	const pointer = signDoc(
		{
			schema_version: 1,
			type: "aidr-installer-latest",
			product_id: "singularity-aidr",
			version: "1.5.0",
			release_sequence: 8,
			manifest_path: "1.5.0/manifest.json",
			manifest_sha256: options.digest ?? sha(catalog.document),
			published_at: "2026-10-12T09:00:00.000Z",
		},
		options.pointerKey,
	);
	return { pointer, catalog };
}

let dir: string;
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-update-core-"));
});
afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
	vi.restoreAllMocks();
});

function writeMirror(root: string, docs = published()) {
	mkdirSync(join(root, "1.5.0", "linux-x64"), { recursive: true });
	writeFileSync(join(root, "latest.json"), docs.pointer.document);
	writeFileSync(join(root, "latest.json.sig"), docs.pointer.signature);
	writeFileSync(join(root, "1.5.0", "manifest.json"), docs.catalog.document);
	writeFileSync(join(root, "1.5.0", "manifest.json.sig"), docs.catalog.signature);
	writeFileSync(
		join(root, "1.5.0", "linux-x64", "singularity-aidr-1.5.0-linux-x64.tar.gz"),
		INSTALLER,
	);
}

describe("signed installer catalog", () => {
	it("verifies the pointer, the pointer digest and the catalog", () => {
		const result = verifyPublishedCatalog(published(), KEYS);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.catalog.version).toBe("1.5.0");
			expect(result.catalog.files[0]?.sha256).toBe(sha(INSTALLER));
		}
	});

	it("rejects another signer, a broken digest, tampered bytes and no key", () => {
		expect(verifyPublishedCatalog(published({ catalogKey: otherKey.privateKey }), KEYS)).toEqual({
			ok: false,
			error: "signature_invalid",
		});
		expect(verifyPublishedCatalog(published({ pointerKey: otherKey.privateKey }), KEYS)).toEqual({
			ok: false,
			error: "signature_invalid",
		});
		expect(verifyPublishedCatalog(published({ digest: "0".repeat(64) }), KEYS)).toEqual({
			ok: false,
			error: "digest_mismatch",
		});
		const docs = published();
		const tampered = {
			document: Buffer.from(
				Buffer.from(docs.catalog.document).toString().replace(sha(INSTALLER), sha("evil")),
			),
			signature: docs.catalog.signature,
		};
		expect(verifyCatalogDocument(tampered, KEYS)).toEqual({
			ok: false,
			error: "signature_invalid",
		});
		expect(verifyPublishedCatalog(published(), [])).toEqual({ ok: false, error: "no_trusted_key" });
	});

	it("refuses a signed catalog whose entries escape the published layout", () => {
		const bad = catalogValue({ files: [{ ...catalogValue().files[0], path: "../../x.tar.gz" }] });
		expect(verifyPublishedCatalog(published({ catalog: bad }), KEYS)).toEqual({
			ok: false,
			error: "catalog_invalid",
		});
	});

	it("reads PEM, base64 SPKI and raw keys and refuses private or non-Ed25519 keys", () => {
		const raw = catalogKey.publicKey
			.export({ type: "spki", format: "der" })
			.subarray(12)
			.toString("base64");
		expect(parseCatalogPublicKey(PUBLIC_B64)).not.toBeNull();
		expect(parseCatalogPublicKey(raw)).not.toBeNull();
		expect(
			parseCatalogPublicKey(
				catalogKey.publicKey.export({ type: "spki", format: "pem" }).toString(),
			),
		).not.toBeNull();
		expect(
			parseCatalogPublicKey(
				catalogKey.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
			),
		).toBeNull();
		const rsa = generateKeyPairSync("rsa", { modulusLength: 1024 })
			.publicKey.export({ type: "spki", format: "pem" })
			.toString();
		expect(parseCatalogPublicKey(rsa)).toBeNull();
		expect(parseCatalogPublicKey("not a key")).toBeNull();
	});
});

describe("update sources", () => {
	it("reads a mirror directory and downloads only bytes that match the catalog", async () => {
		writeMirror(join(dir, "mirror"));
		const loaded = await loadCatalog({ kind: "mirror", location: join(dir, "mirror") }, KEYS);
		expect(loaded.ok).toBe(true);
		const file = loaded.ok ? loaded.catalog.files[0] : undefined;
		if (!file) throw new Error("the mirror catalog has no installer");
		const good = await downloadVerified(
			join(dir, "mirror", file.path),
			file,
			join(dir, "good.tar.gz"),
		);
		expect(good).toEqual({ ok: true, path: join(dir, "good.tar.gz") });
		const wrong = await downloadVerified(
			join(dir, "mirror", file.path),
			{ ...file, sha256: sha("other") },
			join(dir, "bad.tar.gz"),
		);
		expect(wrong).toEqual({ ok: false, error: "digest_mismatch" });
		expect(() => readFileSync(join(dir, "bad.tar.gz"))).toThrow();
		const short = await downloadVerified(
			join(dir, "mirror", file.path),
			{ ...file, size: 5 },
			join(dir, "short.tar.gz"),
		);
		expect(short).toEqual({ ok: false, error: "size_mismatch" });
	});

	it("finds the signed manifest next to a provided installer and pins the file name", async () => {
		writeMirror(join(dir, "mirror"));
		const installer = join(
			dir,
			"mirror",
			"1.5.0",
			"linux-x64",
			"singularity-aidr-1.5.0-linux-x64.tar.gz",
		);
		const check = await checkInstallerUpdate({
			currentVersion: "1.4.0",
			platform: "linux-x64",
			source: { kind: "file", installer },
			keys: KEYS,
		});
		expect(check).toMatchObject({ ok: true, status: "available", latest: "1.5.0" });
		writeFileSync(join(dir, "mirror", "1.5.0", "linux-x64", "renamed.tar.gz"), INSTALLER);
		const renamed = await checkInstallerUpdate({
			currentVersion: "1.4.0",
			platform: "linux-x64",
			source: {
				kind: "file",
				installer: join(dir, "mirror", "1.5.0", "linux-x64", "renamed.tar.gz"),
			},
			keys: KEYS,
		});
		expect(renamed).toMatchObject({ ok: false, error: "installer_not_in_catalog" });
	});

	it("talks to the portal with the device key and verifies what it returns", async () => {
		const docs = published();
		const calls: Array<{ url: string; auth: string | null }> = [];
		const fetchStub = vi.fn(async (url: string | URL, init?: RequestInit) => {
			calls.push({ url: String(url), auth: new Headers(init?.headers).get("authorization") });
			return new Response(
				JSON.stringify({
					ok: true,
					pointer: {
						document_b64: Buffer.from(docs.pointer.document).toString("base64"),
						signature_b64: Buffer.from(docs.pointer.signature).toString("base64"),
					},
					catalog: {
						document_b64: Buffer.from(docs.catalog.document).toString("base64"),
						signature_b64: Buffer.from(docs.catalog.signature).toString("base64"),
					},
				}),
				{ status: 200 },
			);
		});
		const loaded = await loadCatalog(
			{ kind: "portal", endpoint: "https://cp.example.com/functions", apiKey: "device-key" },
			KEYS,
			{ fetch: fetchStub as unknown as typeof fetch },
		);
		expect(loaded.ok).toBe(true);
		expect(calls).toEqual([
			{ url: "https://cp.example.com/functions/v1/installer-update", auth: "Bearer device-key" },
		]);
		const insecure = await loadCatalog(
			{ kind: "portal", endpoint: "http://cp.example.com", apiKey: "k" },
			KEYS,
			{ fetch: fetchStub as unknown as typeof fetch },
		);
		expect(insecure).toMatchObject({ ok: false, error: "source_insecure" });
		const denied = await loadCatalog(
			{ kind: "portal", endpoint: "https://cp.example.com", apiKey: "k" },
			KEYS,
			{
				fetch: (async () =>
					new Response(JSON.stringify({ error: "entitlement_required" }), {
						status: 403,
					})) as unknown as typeof fetch,
			},
		);
		expect(denied).toMatchObject({ ok: false, error: "entitlement_required" });
	});

	it("chooses --from, then the managed portal, then update.source", () => {
		const local = ConfigSchema.parse({});
		const managed = ConfigSchema.parse({
			mode: "managed",
			control_plane: { endpoint: "https://cp.example.com" },
		});
		expect(resolveUpdateSource(local, undefined)).toBeNull();
		expect(resolveUpdateSource(managed, "key")).toMatchObject({
			kind: "portal",
			endpoint: "https://cp.example.com",
		});
		expect(resolveUpdateSource(managed, undefined)).toBeNull();
		expect(
			resolveUpdateSource(
				ConfigSchema.parse({ update: { source: "https://mirror.example.com/aidr/" } }),
				undefined,
			),
		).toMatchObject({ kind: "mirror" });
		expect(resolveUpdateSource(managed, "key", "https://files.example.com/a.msi")).toMatchObject({
			kind: "file",
		});
		expect(
			resolveUpdateSource(local, undefined, "https://mirror.example.com/aidr/latest.json"),
		).toMatchObject({ kind: "mirror", location: "https://mirror.example.com/aidr/" });
		expect(resolveUpdateSource(local, undefined, dir)).toMatchObject({
			kind: "mirror",
			location: dir,
		});
	});

	it("orders versions by semver, prereleases before releases", () => {
		expect(compareReleaseVersions("1.4.0", "1.5.0")).toBeLessThan(0);
		expect(compareReleaseVersions("1.5.0-rc.1", "1.5.0")).toBeLessThan(0);
		expect(compareReleaseVersions("1.10.0", "1.9.0")).toBeGreaterThan(0);
		expect(compareReleaseVersions("1.5.0", "1.5.0")).toBe(0);
	});
});

describe("update environment", () => {
	it("maps platforms and recognises the installer layout", () => {
		expect(installerPlatform("win32", "x64")).toBe("windows-x64");
		expect(installerPlatform("linux", "arm64")).toBe("linux-arm64");
		expect(installerPlatform("darwin", "arm64")).toBeNull();
		const exists = (path: string) => path.endsWith(join("config", "release-public.pem"));
		expect(installerLayoutFor("/opt/singularity-aidr/bundle/bin/aidr", { exists })).toEqual({
			prefix: "/opt/singularity-aidr",
			bundle: "/opt/singularity-aidr/bundle",
			perUser: false,
		});
		expect(installerLayoutFor("/usr/bin/node", { exists })).toBeNull();
		expect(installerUpdatesApply("/usr/lib/node_modules/x/bin/aidr", { exists: () => false })).toBe(
			false,
		);
	});

	it("turns automatic updates off when device management owns the machine", () => {
		expect(
			detectMdmManaged({ platform: "linux", exists: (path) => path === LINUX_MDM_MARKER }),
		).toEqual({ managed: true, source: LINUX_MDM_MARKER });
		expect(detectMdmManaged({ platform: "linux", exists: () => false })).toEqual({
			managed: false,
		});
		const policy =
			"\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Singularity AIDR\r\n    MdmManaged    REG_DWORD    0x1\r\n";
		expect(
			detectMdmManaged({ platform: "win32", env: {}, exists: () => false, regQuery: () => policy })
				.managed,
		).toBe(true);
		expect(
			detectMdmManaged({
				platform: "win32",
				env: {},
				exists: () => false,
				regQuery: () => policy.replace("0x1", "0x0"),
			}).managed,
		).toBe(false);
		expect(
			detectMdmManaged({
				platform: "win32",
				env: { ProgramData: "C:\\ProgramData" },
				exists: (path) => path.includes("mdm-managed"),
				regQuery: () => null,
			}).managed,
		).toBe(true);
		expect(effectiveAutoMode("install", { managed: true, source: "x" })).toEqual({
			mode: "off",
			reason: "mdm",
		});
		expect(effectiveAutoMode(undefined, { managed: false })).toEqual({ mode: "notify" });
	});

	it("trusts the installer's key file over configuration and fails closed on a bad key", () => {
		const prefix = join(dir, "prefix");
		mkdirSync(join(prefix, "config"), { recursive: true });
		expect(trustedCatalogKeys({ prefix }, [PUBLIC_B64]).keys).toHaveLength(1);
		expect(trustedCatalogKeys({ prefix }, ["garbage"])).toMatchObject({
			keys: [],
			invalid: ["update.catalog_public_keys[0]"],
		});
		writeFileSync(
			join(prefix, "config", "installer-catalog-public.pem"),
			catalogKey.publicKey.export({ type: "spki", format: "pem" }).toString(),
		);
		const pinned = trustedCatalogKeys({ prefix }, [
			otherKey.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
		]);
		expect(pinned.source).toBe(join(prefix, "config", "installer-catalog-public.pem"));
		expect(pinned.keys[0]?.equals(catalogKey.publicKey)).toBe(true);
		writeFileSync(join(prefix, "config", "installer-catalog-public.pem"), "broken");
		expect(trustedCatalogKeys({ prefix }, [PUBLIC_B64])).toMatchObject({
			keys: [],
			invalid: [join(prefix, "config", "installer-catalog-public.pem")],
		});
	});
});

describe("session-start update notice", () => {
	function layoutFixture() {
		const prefix = join(dir, "prefix");
		mkdirSync(join(prefix, "bundle", "bin"), { recursive: true });
		mkdirSync(join(prefix, "config"), { recursive: true });
		writeFileSync(join(prefix, "bundle", "bin", "aidr"), "");
		writeFileSync(join(prefix, "config", "release-public.pem"), "release key placeholder");
		writeFileSync(
			join(prefix, "config", "installer-catalog-public.pem"),
			catalogKey.publicKey.export({ type: "spki", format: "pem" }).toString(),
		);
		writeMirror(join(dir, "mirror"));
		return { prefix, executable: join(prefix, "bundle", "bin", "aidr-session-start") };
	}

	it("names `aidr update`, caches the check and starts a background install only with auto=install", async () => {
		const { executable } = layoutFixture();
		const statePath = join(dir, "state.json");
		const config = ConfigSchema.parse({ update: { source: join(dir, "mirror") } });
		const base = {
			currentVersion: "1.4.0",
			executable,
			statePath,
			deps: { platform: "linux" as const, arch: "x64" },
		};
		const notice = await installerUpdateNotice({ ...base, config, now: 1_000 });
		expect(notice).toEqual({
			currentVersion: "1.4.0",
			latestVersion: "1.5.0",
			updateAvailable: true,
			action: "aidr_update",
		});
		expect(readUpdateState(statePath)).toMatchObject({ status: "available", latest: "1.5.0" });
		// Cached: the mirror is gone but the notice stays.
		rmSync(join(dir, "mirror"), { recursive: true });
		expect((await installerUpdateNotice({ ...base, config, now: 2_000 }))?.latestVersion).toBe(
			"1.5.0",
		);

		const started: string[] = [];
		const installing = await installerUpdateNotice({
			...base,
			config: ConfigSchema.parse({ update: { source: join(dir, "mirror"), auto: "install" } }),
			now: 3_000,
			startInstall: (aidr) => started.push(aidr),
		});
		expect(installing?.action).toBe("installing");
		expect(started).toEqual([join(dir, "prefix", "bundle", "bin", "aidr")]);
		// Not again within the interval.
		await installerUpdateNotice({
			...base,
			config: ConfigSchema.parse({ update: { auto: "install" } }),
			now: 4_000,
			startInstall: (aidr) => started.push(aidr),
		});
		expect(started).toHaveLength(1);
	});

	it("keeps notifying instead of starting a silent install on a per-machine Windows install", async () => {
		const { executable } = layoutFixture();
		const started: string[] = [];
		writeFileSync(join(dir, "prefix", "bundle", "bin", "aidr.exe"), "");
		const linux = catalogValue().files[0];
		const windows = {
			...linux,
			platform: "windows-x64",
			os: "windows",
			file: "a.msi",
			path: "1.5.0/windows-x64/a.msi",
			format: "msi",
		};
		writeMirror(join(dir, "mirror"), published({ catalog: catalogValue({ files: [windows] }) }));
		const notice = await installerUpdateNotice({
			config: ConfigSchema.parse({ update: { source: join(dir, "mirror"), auto: "install" } }),
			currentVersion: "1.4.0",
			executable,
			statePath: join(dir, "state.json"),
			deps: { platform: "win32", arch: "x64", env: {}, regQuery: () => null },
			startInstall: (aidr) => started.push(aidr),
		});
		expect(notice?.action).toBe("aidr_update");
		expect(started).toEqual([]);
	});

	it("is silent with auto=off, under device management and outside an installer layout", async () => {
		const { executable } = layoutFixture();
		const statePath = join(dir, "state.json");
		const config = ConfigSchema.parse({ update: { source: join(dir, "mirror") } });
		const deps = { platform: "linux" as const, arch: "x64" };
		expect(
			await installerUpdateNotice({
				config: ConfigSchema.parse({ update: { source: join(dir, "mirror"), auto: "off" } }),
				currentVersion: "1.4.0",
				executable,
				statePath,
				deps,
			}),
		).toBeNull();
		const mdmExists = (path: string) => path === LINUX_MDM_MARKER || readable(path);
		expect(
			await installerUpdateNotice({
				config,
				currentVersion: "1.4.0",
				executable,
				statePath,
				deps: { ...deps, exists: mdmExists },
			}),
		).toBeNull();
		expect(
			await installerUpdateNotice({
				config,
				currentVersion: "1.4.0",
				executable: "/usr/bin/node",
				statePath,
				deps,
			}),
		).toBeNull();
		expect(readUpdateState(statePath)).toBeNull();
	});
});

describe("update notice wording", () => {
	it("names `aidr update` for installer endpoints and keeps the generic notice otherwise", () => {
		const base = { currentVersion: "1.4.0", latestVersion: "1.5.0", updateAvailable: true };
		expect(formatUpdateNotice({ ...base, action: "aidr_update" })).toBe(
			"⬆️  Singularity AIDR v1.5.0 is available (you have v1.4.0). To install it, run: aidr update",
		);
		expect(formatUpdateNotice({ ...base, action: "installing" })).toContain(
			"being installed in the background",
		);
		expect(formatUpdateNotice(base)).toContain("Update available: v1.4.0 → v1.5.0");
	});
});

function readable(path: string): boolean {
	try {
		readFileSync(path);
		return true;
	} catch {
		return false;
	}
}
