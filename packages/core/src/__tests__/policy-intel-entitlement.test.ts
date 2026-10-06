import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { emptyIntelMerged, type IntelMerged } from "../intel/types.js";
import { applyIngestResult, type EntitlementSnapshotV2, type ManagedState } from "../managed.js";
import { type Config, ConfigSchema } from "../types.js";

const loadPacks = vi.hoisted(() => vi.fn());
vi.mock("../intel/loader.js", () => ({ loadMergedIntelFromDisk: loadPacks }));

const NOW = Date.parse("2026-10-06T00:00:00.000Z");
const signer = generateKeyPairSync("ed25519");
const publicKeyPem = signer.publicKey.export({ type: "spki", format: "pem" }).toString();
let evaluatePolicy: typeof import("../policy.js")["evaluatePolicy"];
let previousCommercial: string | undefined;
let previousHome: string | undefined;
let previousUserProfile: string | undefined;
let dir: string;

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value)
			.sort(([left], [right]) => left.localeCompare(right))
			.map(([key, child]) => [key, canonicalize(child)]),
	);
}

function signedState(overrides: Partial<EntitlementSnapshotV2> = {}): ManagedState {
	const snapshot: EntitlementSnapshotV2 = {
		schema_version: 2,
		tenant_id: "tenant-a",
		subscription_tier: "pro",
		included_agents: 1,
		extra_agents: 1,
		allowed_agents: 2,
		premium_modules: ["premium_intel"],
		issued_at: new Date(NOW - 1_000).toISOString(),
		expires_at: new Date(NOW + 30_000).toISOString(),
		grace_until: new Date(NOW + 60_000).toISOString(),
		serial: "serial-a",
		revocation_epoch: 1,
		...overrides,
	};
	const sig = sign(
		null,
		Buffer.from(JSON.stringify(canonicalize(snapshot))),
		signer.privateKey,
	).toString("base64");
	return applyIngestResult(
		{},
		{
			ok: true,
			status: 200,
			body: { entitlement_signed: { snapshot, sig_b64: sig, key_id: "issuer" } },
		},
		72,
		{ publicKeysPem: [publicKeyPem] },
	);
}

function merged(host = "paid.example"): IntelMerged {
	return { ...emptyIntelMerged(), urlDenyHosts: new Set([host]), availability: "available" };
}

function config(overrides: Record<string, unknown> = {}): Config {
	return ConfigSchema.parse({
		mode: "managed",
		policy: { enabled: true },
		intel_packs: {
			enabled: true,
			packs_dir: join(dir, "packs"),
			trusted_keys_path: join(dir, "trust.json"),
		},
		licensing: { revocations_enabled: false },
		...overrides,
	});
}

async function inspect(cfg: Config, state: ManagedState = {}, host = "paid.example") {
	return evaluatePolicy("WebFetch", [{ type: "url", value: `https://${host}/` }], cfg, {}, state);
}

beforeEach(async () => {
	previousCommercial = process.env.AIDR_COMMERCIAL;
	previousHome = process.env.HOME;
	previousUserProfile = process.env.USERPROFILE;
	delete process.env.AIDR_COMMERCIAL;
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(NOW);
	dir = await mkdtemp(join(tmpdir(), "aidr-policy-entitlement-"));
	process.env.HOME = dir;
	process.env.USERPROFILE = dir;
	vi.resetModules();
	loadPacks.mockReset().mockResolvedValue(merged());
	({ evaluatePolicy } = await import("../policy.js"));
});

afterEach(async () => {
	vi.useRealTimers();
	if (previousCommercial === undefined) delete process.env.AIDR_COMMERCIAL;
	else process.env.AIDR_COMMERCIAL = previousCommercial;
	if (previousHome === undefined) delete process.env.HOME;
	else process.env.HOME = previousHome;
	if (previousUserProfile === undefined) delete process.env.USERPROFILE;
	else process.env.USERPROFILE = previousUserProfile;
	await rm(dir, { recursive: true, force: true });
});

describe("policy signed intel entitlement and cache boundaries", () => {
	it("does not expose a warm premium cache after module removal or revocation", async () => {
		const cfg = config();
		const paid = signedState();
		expect(await inspect(cfg, paid)).toMatchObject({
			decision: "deny",
			matchedThreatId: "INTEL-URL-001",
		});
		for (const state of [
			{},
			signedState({ premium_modules: [] }),
			{ ...paid, sync_disabled_reason: "revoked" },
			{ ...paid, entitlement_alg: "hmac-sha256" as const },
		]) {
			expect(await inspect(cfg, state)).toBeNull();
		}
		expect(loadPacks).toHaveBeenCalledTimes(1);
		expect(await inspect(cfg, paid)).toMatchObject({ decision: "deny" });
		expect(loadPacks).toHaveBeenCalledTimes(2);
	});

	it("stops a warm cache at signed grace expiry even within the cache TTL", async () => {
		const cfg = config();
		const paid = signedState({
			expires_at: new Date(NOW + 1_000).toISOString(),
			grace_until: new Date(NOW + 2_000).toISOString(),
		});
		expect(await inspect(cfg, paid)).toMatchObject({ decision: "deny" });
		vi.setSystemTime(NOW + 1_500);
		expect(await inspect(cfg, paid)).toMatchObject({ decision: "deny" });
		vi.setSystemTime(NOW + 2_000);
		expect(await inspect(cfg, paid)).toBeNull();
		expect(loadPacks).toHaveBeenCalledTimes(1);
	});

	it.each([
		{ tenant_id: "tenant-b" },
		{ serial: "serial-b" },
		{
			expires_at: new Date(NOW + 40_000).toISOString(),
			grace_until: new Date(NOW + 70_000).toISOString(),
		},
	])("reloads before using a changed signed grant %j", async (change) => {
		const cfg = config();
		loadPacks.mockResolvedValueOnce(merged()).mockResolvedValueOnce(merged("new.example"));
		expect(await inspect(cfg, signedState())).toMatchObject({ decision: "deny" });
		expect(await inspect(cfg, signedState(change))).toBeNull();
		expect(loadPacks).toHaveBeenCalledTimes(2);
	});

	it("does not reuse a pack from another configured directory or trust file", async () => {
		const paid = signedState();
		loadPacks.mockResolvedValueOnce(merged()).mockResolvedValueOnce(merged("other.example"));
		expect(await inspect(config(), paid)).toMatchObject({ decision: "deny" });
		expect(
			await inspect(
				config({
					intel_packs: {
						enabled: true,
						packs_dir: join(dir, "other-packs"),
						trusted_keys_path: join(dir, "other-trust.json"),
					},
				}),
				paid,
			),
		).toBeNull();
		expect(loadPacks).toHaveBeenCalledTimes(2);
	});

	it("keeps an operator URL denylist active without enabling paid packs", async () => {
		const denylist = join(dir, "operator-denylist.txt");
		await writeFile(denylist, "operator.example\n");
		const cfg = config({ intel: { enabled: true, url_denylist_path: denylist } });
		expect(await inspect(cfg, {}, "operator.example")).toMatchObject({
			decision: "deny",
			matchedThreatId: "INTEL-URL-001",
		});
		expect(await inspect(cfg)).toBeNull();
		expect(loadPacks).not.toHaveBeenCalled();
	});

	it("keeps explicitly configured public local packs available", async () => {
		expect(await inspect(config({ mode: "local" }))).toMatchObject({ decision: "deny" });
		expect(loadPacks).toHaveBeenCalledTimes(1);
	});

	it("does not bypass commercial premium rights by selecting local mode", async () => {
		process.env.AIDR_COMMERCIAL = "1";
		expect(await inspect(config({ mode: "local" }))).toBeNull();
		expect(loadPacks).not.toHaveBeenCalled();
	});

	it("uses the runtime's currently verified grant instead of a prior premium cache", async () => {
		const { evaluateToolCall } = await import("../evaluator.js");
		const aidrDir = join(dir, ".singularity-aidr");
		await mkdir(aidrDir, { recursive: true });
		const statePath = join(aidrDir, "managed.json");
		const configPath = join(aidrDir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify(
				config({
					auth: { api_key: "runtime-credential" },
					control_plane: { enabled: false },
					licensing: { public_keys_pem: [publicKeyPem], revocations_enabled: false },
					heuristics_enabled: false,
					url_check: { enabled: false },
					file_check: { enabled: false },
					package_check: { enabled: false },
					amsi_check: { enabled: false },
					logging: { enabled: false },
					incident: { enabled: false },
					response: { emit_incidents: false },
					cache: { enabled: false },
				}),
			),
		);
		const context = {
			configPath,
			threatsDir: resolve(__dirname, "..", "..", "..", "..", "threats"),
			allowlistsDir: resolve(__dirname, "..", "..", "..", "..", "allowlists"),
		};
		const request = {
			sessionId: "paid-policy-runtime",
			toolName: "WebFetch",
			toolInput: { url: "https://paid.example/" },
			artifacts: [{ type: "url" as const, value: "https://paid.example/" }],
		};
		await writeFile(statePath, JSON.stringify(signedState()));
		expect(await evaluateToolCall(request, context)).toMatchObject({
			decision: "deny",
			matchedThreatId: "INTEL-URL-001",
		});
		await writeFile(
			statePath,
			JSON.stringify(signedState({ serial: "basic-now", premium_modules: [] })),
		);
		const downgraded = await evaluateToolCall(request, context);
		expect(downgraded.matchedThreatId).not.toBe("INTEL-URL-001");
		expect(downgraded.category).not.toBe("managed_disabled");
		expect(loadPacks).toHaveBeenCalledTimes(1);
	});
});
