import { generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { afterEach, describe, expect, it } from "vitest";
import { activatePackVersion, loadMergedIntelFromDisk } from "../../../packages/core/src/intel/loader.ts";
import {
	applyIngestResult,
	type EntitlementSnapshotV2,
	saveEntitlementKeyringFromState,
	saveManagedState,
} from "../../../packages/core/src/managed.ts";
// @ts-expect-error -- plain ESM publishing tool without type declarations
import * as publishing from "../../../scripts/intel-pack-keys.mjs";
// @ts-expect-error -- plain ESM publishing tool without type declarations
import { assertDeliverablePackKeys } from "../../../scripts/import-offline-pack.mjs";
import { capEntitlementTimes } from "../_shared/effective-seats.ts";
import {
	deriveTenantPackKey,
	entitledPackKeys,
	type PackKeyMaterial,
	parseSharedPackKeys,
} from "../_shared/pack-keys.ts";

// CP-2 regression. The control plane used to deliver HKDF(master, tenant) under
// one key_id ("aidr-pack-v1") to every tenant, so a shared/vendor pack could be
// decrypted by at most one tenant and nothing could publish a matching pack.
// These tests run the real issuance code (ingest's buildEntitlementSnapshot),
// the real publishing tool and the real endpoint loader end to end.

const here = dirname(fileURLToPath(import.meta.url));
const TENANT_A = "0a0a0a0a-1111-4111-8111-aaaaaaaaaaaa";
const TENANT_B = "0b0b0b0b-2222-4222-8222-bbbbbbbbbbbb";
const key32 = () => randomBytes(32).toString("base64");

// Deno's npm: imports and Deno.serve prevent importing the Edge entrypoint;
// compile only its real snapshot builder (as ingest-entitlement-time does).
function ingestSnapshotBuilder() {
	const source = readFileSync(resolve(here, "../ingest/index.ts"), "utf8");
	const ast = ts.createSourceFile("ingest/index.ts", source, ts.ScriptTarget.ES2022, true);
	const fn = ast.statements.find(
		(statement) => ts.isFunctionDeclaration(statement) && statement.name?.text === "buildEntitlementSnapshot",
	);
	if (!fn) throw new Error("buildEntitlementSnapshot not found in ingest/index.ts");
	const compiled = ts.transpileModule(`${fn.getText(ast)}\nexports.build = buildEntitlementSnapshot;`, {
		compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
	}).outputText;
	const exports: Record<string, unknown> = {};
	new Function("exports", "crypto", "capEntitlementTimes", compiled)(exports, { randomUUID }, capEntitlementTimes);
	return exports.build as (params: Record<string, unknown>) => EntitlementSnapshotV2 | null;
}

const workdirs: string[] = [];
const previousHome = process.env.HOME;
afterEach(() => {
	process.env.HOME = previousHome;
	for (const dir of workdirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});
function workdir(): string {
	const dir = mkdtempSync(join(tmpdir(), "aidr-pack-keys-"));
	workdirs.push(dir);
	return dir;
}

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value as Record<string, unknown>)
			.sort(([left], [right]) => left.localeCompare(right))
			.map(([key, child]) => [key, canonicalize(child)]),
	);
}

describe("pack key derivation contract", () => {
	it("derives byte-identical tenant keys on the control plane and in the publishing tool", async () => {
		const master = key32();
		for (const tenant of [TENANT_A, TENANT_B, TENANT_A.toUpperCase()]) {
			expect(await deriveTenantPackKey(master, tenant)).toEqual(publishing.deriveTenantPackKey(master, tenant));
		}
		const shared = `aidr-shared-pack-2026q4=${key32()},aidr-shared-pack-2027q1=${key32()}`;
		expect(parseSharedPackKeys(shared).keys).toEqual(publishing.parseSharedPackKeys(shared));
	});

	it("gives every key_id exactly one key value across tenants, and a new key_id on master rotation", async () => {
		const master = key32();
		const sharedKeys = `aidr-shared-pack-2026q4=${key32()}`;
		const byId = new Map<string, Set<string>>();
		for (const tenantId of [TENANT_A, TENANT_B, randomUUID()]) {
			for (const key of await entitledPackKeys({ masterB64: master, sharedKeys, tenantId })) {
				byId.set(key.key_id, (byId.get(key.key_id) ?? new Set()).add(key.key_b64));
			}
		}
		for (const [keyId, values] of byId) expect(values.size, keyId).toBe(1);
		expect(byId.has("aidr-pack-v1")).toBe(false);
		const a = await deriveTenantPackKey(master, TENANT_A);
		const rotated = await deriveTenantPackKey(key32(), TENANT_A);
		expect(rotated?.key_id).not.toBe(a?.key_id);
		expect(a?.key_id.startsWith(`aidr-tenant-pack-v2.${TENANT_A}.`)).toBe(true);
	});

	it("rejects a malformed shared key list as a whole and refuses non-UUID tenants", async () => {
		expect(parseSharedPackKeys(`aidr-shared-pack-ok=${key32()},aidr-pack-v1=${key32()}`)).toEqual({ keys: [], invalid: true });
		expect(parseSharedPackKeys(`aidr-shared-pack-short=${Buffer.alloc(16).toString("base64")}`).invalid).toBe(true);
		expect(parseSharedPackKeys(`aidr-shared-pack-x=${key32()},aidr-shared-pack-x=${key32()}`).invalid).toBe(true);
		expect(() => publishing.parseSharedPackKeys(`aidr-pack-v1=${key32()}`)).toThrow(/invalid shared pack key id/);
		expect(await deriveTenantPackKey(key32(), "tenant-1")).toBeNull();
		expect(await entitledPackKeys({ masterB64: "", sharedKeys: "", tenantId: TENANT_A })).toEqual([]);
	});
});

describe("encrypted premium pack round trip", () => {
	const buildSnapshot = ingestSnapshotBuilder();
	const publisher = generateKeyPairSync("ed25519");
	const entitlementSigner = generateKeyPairSync("ed25519");
	const entitlementPem = entitlementSigner.publicKey.export({ type: "spki", format: "pem" }).toString();

	function publishPack(root: string, packId: string, host: string, key: PackKeyMaterial): string {
		const dir = join(root, "publish", packId);
		mkdirSync(join(dir, "lists"), { recursive: true });
		writeFileSync(join(dir, "lists", "deny.txt"), `https://${host}/collect\n`);
		writeFileSync(
			join(dir, "manifest.json"),
			JSON.stringify({
				pack_id: packId,
				version: "1.0.0",
				issued_at: new Date().toISOString(),
				expires_at: "2099-01-01T00:00:00Z",
				key_id: "aidr-intel-test-signer",
				files: [{ kind: "url_denylist", path: "lists/deny.txt" }],
			}),
		);
		const manifest = publishing.encryptPackDirectory(dir, key);
		expect(manifest.files[0]).toMatchObject({ encrypted: true, cipher: "aes-256-gcm", key_id: key.key_id });
		expect(readFileSync(join(dir, "lists", "deny.txt"), "latin1")).not.toContain(host);
		writeFileSync(
			join(dir, "manifest.sig"),
			sign(null, readFileSync(join(dir, "manifest.json")), publisher.privateKey).toString("base64"),
		);
		return dir;
	}

	async function endpointLoad(root: string, tenantId: string, packKeys: PackKeyMaterial[], served: string[]) {
		const home = join(root, `home-${tenantId}`);
		const aidr = join(home, ".singularity-aidr");
		mkdirSync(aidr, { recursive: true });
		process.env.HOME = home;
		writeFileSync(join(aidr, "config.json"), JSON.stringify({ licensing: { public_keys_pem: [entitlementPem] } }));
		const snapshot = buildSnapshot({
			tenantId,
			includedAgents: 1,
			extraAgents: 1,
			allowedAgents: 2,
			premiumModules: ["premium_intel"],
			packKeys,
			revocationEpoch: 1,
			timing: { ttlHours: 168, graceHours: 72 },
		});
		expect(snapshot).not.toBeNull();
		const sigB64 = sign(null, Buffer.from(JSON.stringify(canonicalize(snapshot))), entitlementSigner.privateKey).toString("base64");
		const state = applyIngestResult(
			{},
			{ ok: true, status: 200, body: { entitlement_signed: { snapshot, sig_b64: sigB64, key_id: "test-entitlement" } } },
			72,
			{ publicKeysPem: [entitlementPem] },
		);
		await saveManagedState(join(aidr, "managed.json"), state);
		await saveEntitlementKeyringFromState(state);
		const packsDir = join(aidr, "intel", "packs");
		for (const dir of served) {
			const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
			cpSync(dir, join(packsDir, manifest.pack_id, manifest.version), { recursive: true });
			await activatePackVersion({ packId: manifest.pack_id, version: manifest.version, packsDir });
		}
		const trustedKeysPath = join(aidr, "intel", "trusted-keys.json");
		writeFileSync(
			trustedKeysPath,
			JSON.stringify({ "aidr-intel-test-signer": publisher.publicKey.export({ type: "spki", format: "pem" }).toString() }),
		);
		const merged = await loadMergedIntelFromDisk({ packsDir, trustedKeysPath });
		return { merged, availability: (merged as unknown as { availability: string }).availability };
	}

	it("lets every entitled tenant decrypt the shared pack and only its own tenant pack", async () => {
		const root = workdir();
		const master = key32();
		const sharedLine = `aidr-shared-pack-2026q4=${key32()}`;
		const [sharedKey] = publishing.parseSharedPackKeys(sharedLine);
		const keysA = await entitledPackKeys({ masterB64: master, sharedKeys: sharedLine, tenantId: TENANT_A });
		const keysB = await entitledPackKeys({ masterB64: master, sharedKeys: sharedLine, tenantId: TENANT_B });

		const sharedPack = publishPack(root, "aidr-premium-shared", "shared-intel.pack.test", sharedKey);
		const tenantPack = publishPack(root, "aidr-premium-tenant-a", "tenant-a-intel.pack.test", publishing.deriveTenantPackKey(master, TENANT_A));

		// Registration scope matches what packs-manifest serves (shared rows to all, tenant rows to their tenant).
		const manifestOf = (dir: string) => JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
		expect(() => assertDeliverablePackKeys(manifestOf(sharedPack), null)).not.toThrow();
		expect(() => assertDeliverablePackKeys(manifestOf(sharedPack), TENANT_B)).not.toThrow();
		expect(() => assertDeliverablePackKeys(manifestOf(tenantPack), TENANT_A)).not.toThrow();
		expect(() => assertDeliverablePackKeys(manifestOf(tenantPack), null)).toThrow(/cannot hold/);
		expect(() => assertDeliverablePackKeys(manifestOf(tenantPack), TENANT_B)).toThrow(/cannot hold/);

		const a = await endpointLoad(root, TENANT_A, keysA, [sharedPack, tenantPack]);
		expect(a.availability).toBe("available");
		expect([...a.merged.urlDenyHosts].sort()).toEqual(["shared-intel.pack.test", "tenant-a-intel.pack.test"]);

		const b = await endpointLoad(root, TENANT_B, keysB, [sharedPack]);
		expect(b.availability).toBe("available");
		expect([...b.merged.urlDenyHosts]).toEqual(["shared-intel.pack.test"]);

		// Tenant B cannot open tenant A's pack even if it obtained the bytes.
		const leaked = await endpointLoad(root, TENANT_B, keysB, [sharedPack, tenantPack]);
		expect(leaked.availability).toBe("unavailable");
		expect(leaked.merged.urlDenyHosts.has("tenant-a-intel.pack.test")).toBe(false);
	});

	it("refuses to register a pack under the retired shared-id-per-tenant key", () => {
		const manifest = {
			files: [{ path: "lists/deny.txt", encrypted: true, cipher: "aes-256-gcm", key_id: "aidr-pack-v1" }],
		};
		expect(() => assertDeliverablePackKeys(manifest, null)).toThrow(/cannot hold/);
		expect(() => assertDeliverablePackKeys(manifest, TENANT_A)).toThrow(/cannot hold/);
	});
});
