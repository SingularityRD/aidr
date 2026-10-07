// Contract for the public version-check endpoint served to `checkForUpdate()`
// (packages/core/src/version-check.ts POSTs `<gateway>/v1/version-check`).
//
// Pins: the response shape the client reads (`version`), the signed-manifest
// source (verified over exact bytes; tampered, expired or foreign manifests are
// refused rather than downgraded), the configured fallback, "unavailable"
// instead of an invented version, fail-closed rate limiting, and that no
// request field is ever written anywhere.

import { createHmac, generateKeyPairSync, sign } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { isNewerRelease, normalizeReleaseVersion, resolveLatestRelease } from "../_shared/release-version.ts";

const createClient = vi.hoisted(() => vi.fn());
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient }));

type Handler = (request: Request) => Promise<Response>;
let handle: Handler;
const env: Record<string, string | undefined> = {};
const INGRESS_SECRET = "version-check-ingress-test-secret-at-least-32-bytes";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const PUBLIC_KEY_B64 = publicKey.export({ type: "spki", format: "der" }).toString("base64");

function manifest(overrides: Record<string, unknown> = {}): Buffer {
	return Buffer.from(
		`${JSON.stringify(
			{
				schema_version: 1,
				type: "aidr-release",
				product_id: "singularity-aidr",
				channel: "stable",
				release_sequence: 7,
				release_tag: "v0.9.0",
				release_version: "0.9.0",
				git_sha: "a".repeat(40),
				issued_at: "2026-10-01T00:00:00.000Z",
				expires_at: "2099-01-01T00:00:00.000Z",
				signer: { key_id: "release-2026", fingerprint_sha256: `sha256:${"b".repeat(64)}` },
				...overrides,
			},
			null,
			2,
		)}\n`,
	);
}

function signatureFor(bytes: Buffer, keyId = "release-2026"): string {
	return JSON.stringify({
		schema_version: 1,
		algorithm: "Ed25519",
		key_id: keyId,
		signature_b64: sign(null, bytes, privateKey).toString("base64"),
	});
}

function useSignedManifest(bytes: Buffer, signature = signatureFor(bytes)): void {
	env.AIDR_RELEASE_MANIFEST_B64 = bytes.toString("base64");
	env.AIDR_RELEASE_MANIFEST_SIG = signature;
	env.AIDR_RELEASE_SIGNING_PUBLIC_KEY_B64 = PUBLIC_KEY_B64;
}

interface Database {
	counts: Map<string, number>;
	writes: Array<{ table: string; op: string; value: unknown }>;
	rpcCalls: Array<Record<string, unknown>>;
}

function database(options: { rateLimitDown?: boolean } = {}): Database {
	const state: Database = { counts: new Map(), writes: [], rpcCalls: [] };
	createClient.mockImplementation(() => ({
		rpc: async (name: string, args: { p_key: string; p_window_start: number; p_delta: number }) => {
			state.rpcCalls.push({ name, ...args });
			if (options.rateLimitDown) return { error: { message: "down" } };
			const key = `${args.p_key}:${args.p_window_start}`;
			state.counts.set(key, (state.counts.get(key) ?? 0) + args.p_delta);
			return { error: null };
		},
		from: (table: string) => {
			let key = "";
			let windowStart = 0;
			const query = {
				select: () => query,
				eq: (column: string, value: string | number) => {
					if (column === "key") key = String(value);
					if (column === "window_start") windowStart = Number(value);
					return query;
				},
				maybeSingle: async () => ({ data: { count: state.counts.get(`${key}:${windowStart}`) ?? 0 }, error: null }),
				insert: async (value: unknown) => {
					state.writes.push({ table, op: "insert", value });
					return { error: null };
				},
				upsert: async (value: unknown) => {
					state.writes.push({ table, op: "upsert", value });
					return { error: null };
				},
			};
			return query;
		},
	}));
	return state;
}

function request(body: unknown = { aidr_version: "0.8.1", agent_runtime: "claude-code", iid: "iid-secret-123" }, headers: Record<string, string> = {}): Request {
	return new Request("https://project.supabase.co/functions/v1/version-check", {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers },
		body: typeof body === "string" ? body : JSON.stringify(body),
	});
}

beforeAll(async () => {
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => env[name] },
		serve: (handler: Handler) => {
			handle = handler;
		},
	});
	await import("../version-check/index.ts");
});

afterAll(() => {
	vi.unstubAllGlobals();
});

beforeEach(() => {
	for (const key of Object.keys(env)) delete env[key];
	env.SUPABASE_URL = "https://project.supabase.co";
	env.SUPABASE_SERVICE_ROLE_KEY = "service-role";
	createClient.mockReset();
});

describe("version-check contract", () => {
	it("serves the signed release manifest's version in the shape checkForUpdate reads", async () => {
		database();
		useSignedManifest(manifest());
		const response = await handle(request());
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body).toEqual({ version: "0.9.0", source: "signed_release_manifest", channel: "stable", update_available: true });
		expect(response.headers.get("Cache-Control")).toBe("public, max-age=300");
	});

	it("refuses a tampered, expired, foreign or wrongly keyed manifest instead of downgrading to the fallback", async () => {
		database();
		env.AIDR_LATEST_RELEASE_VERSION = "0.1.0";
		const good = manifest();
		const tampered = Buffer.from(good.toString("utf8").replace("0.9.0", "9.9.9"));
		for (const [bytes, sig] of [
			[tampered, signatureFor(good)],
			[manifest({ expires_at: "2020-01-01T00:00:00.000Z" }), undefined],
			[manifest({ product_id: "someone-else" }), undefined],
			[good, signatureFor(good, "other-key")],
		] as const) {
			useSignedManifest(bytes, sig ?? signatureFor(bytes));
			const response = await handle(request());
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "latest_version_unavailable", reason: "release_manifest_invalid" });
		}
	});

	it("treats a half-configured manifest as unavailable", async () => {
		database();
		env.AIDR_RELEASE_MANIFEST_B64 = manifest().toString("base64");
		env.AIDR_LATEST_RELEASE_VERSION = "0.9.0";
		const response = await handle(request());
		expect(response.status).toBe(503);
		expect(((await response.json()) as Record<string, unknown>).reason).toBe("release_manifest_incomplete");
	});

	it("falls back to the configured version, and never invents one", async () => {
		database();
		env.AIDR_LATEST_RELEASE_VERSION = "v0.8.1";
		let response = await handle(request());
		expect(await response.json()).toEqual({ version: "0.8.1", source: "configured", update_available: false });

		delete env.AIDR_LATEST_RELEASE_VERSION;
		response = await handle(request());
		expect(response.status).toBe(503);
		expect(((await response.json()) as Record<string, unknown>).reason).toBe("latest_version_unconfigured");
	});

	it("never stores or keys on request fields (no PII storage)", async () => {
		const db = database();
		env.AIDR_LATEST_RELEASE_VERSION = "0.9.0";
		await handle(request());
		expect(db.writes).toEqual([]);
		expect(JSON.stringify(db.rpcCalls)).not.toContain("iid-secret-123");
		expect(db.rpcCalls.map((call) => call.p_key)).toEqual(["version-check:global:v1"]);
	});

	it("fails closed when rate-limit storage is unavailable and answers 429 over budget", async () => {
		database({ rateLimitDown: true });
		env.AIDR_LATEST_RELEASE_VERSION = "0.9.0";
		let response = await handle(request());
		expect(response.status).toBe(503);
		expect(((await response.json()) as Record<string, unknown>).error).toBe("rate_limit_unavailable");

		database();
		env.AIDR_VERSION_CHECK_RATE_LIMIT_PER_MINUTE = "1";
		expect((await handle(request())).status).toBe(200);
		response = await handle(request());
		expect(response.status).toBe(429);
		expect(response.headers.get("Retry-After")).toMatch(/^\d+$/);
	});

	it("adds a per-client bucket only for a proxy-signed client IP", async () => {
		const db = database();
		env.AIDR_LATEST_RELEASE_VERSION = "0.9.0";
		env.AIDR_DEVICE_START_INGRESS_SECRET = INGRESS_SECRET;
		const timestamp = String(Math.floor(Date.now() / 1000));
		const ip = "198.51.100.7";
		const signature = createHmac("sha256", INGRESS_SECRET).update(`version-check:v1\n${timestamp}\n${ip}`).digest("hex");
		await handle(request(undefined, { "x-aidr-client-ip": ip, "x-aidr-client-timestamp": timestamp, "x-aidr-client-signature": signature }));
		await handle(request(undefined, { "x-aidr-client-ip": "203.0.113.1", "x-aidr-client-timestamp": timestamp, "x-aidr-client-signature": "f".repeat(64) }));
		const keys = db.rpcCalls.map((call) => String(call.p_key));
		expect(keys.filter((key) => key.startsWith("version-check:v1:client:"))).toHaveLength(1);
		expect(keys.join(" ")).not.toContain(ip);
	});

	it("validates method, body and configuration", async () => {
		database();
		env.AIDR_LATEST_RELEASE_VERSION = "0.9.0";
		expect((await handle(new Request("https://x/functions/v1/version-check", { method: "GET" }))).status).toBe(405);
		expect((await handle(request("{not json"))).status).toBe(400);
		expect((await handle(request({ aidr_version: "not-a-version" }))).status).toBe(400);
		expect((await handle(request("x".repeat(5000)))).status).toBe(413);
		delete env.SUPABASE_SERVICE_ROLE_KEY;
		const response = await handle(request());
		expect(response.status).toBe(500);
		expect(JSON.stringify(await response.json())).toContain("SUPABASE_SERVICE_ROLE_KEY");
	});
});

describe("release version helpers", () => {
	it("compares and normalizes semver", () => {
		expect(normalizeReleaseVersion("v1.2.3")).toBe("1.2.3");
		expect(normalizeReleaseVersion("1.2")).toBeNull();
		expect(isNewerRelease("0.8.9", "0.9.0")).toBe(true);
		expect(isNewerRelease("0.9.0", "0.9.0")).toBe(false);
		expect(isNewerRelease("1.0.0", "0.9.9")).toBe(false);
		// A pre-release is older than its own final release, never the reverse.
		expect(isNewerRelease("1.4.0-rc.1", "1.4.0")).toBe(true);
		expect(isNewerRelease("1.4.0", "1.4.0-rc.1")).toBe(false);
	});

	it("accepts a raw 32-byte public key as well as SPKI DER", async () => {
		const bytes = manifest();
		const raw = publicKey.export({ type: "spki", format: "der" }).subarray(12).toString("base64");
		const result = await resolveLatestRelease(
			(name) =>
				({
					AIDR_RELEASE_MANIFEST_B64: bytes.toString("base64"),
					AIDR_RELEASE_MANIFEST_SIG: signatureFor(bytes),
					AIDR_RELEASE_SIGNING_PUBLIC_KEY_B64: raw,
				})[name],
		);
		expect(result).toMatchObject({ ok: true, version: "0.9.0", keyId: "release-2026" });
	});
});
