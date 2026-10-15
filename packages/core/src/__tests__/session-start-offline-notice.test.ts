import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatOfflineNotice, formatSessionStartMessage } from "../format.js";
import { setConfiguredLocale } from "../i18n/index.js";
import { runSessionStart } from "../session-start.js";
import { ConfigSchema } from "../types.js";

const originalFetch = globalThis.fetch;

describe("offline notice at session start (install-time offline policy)", () => {
	let root: string;
	let prevHome: string | undefined;

	beforeEach(async () => {
		prevHome = process.env.HOME;
		root = join(tmpdir(), `aidr-offline-notice-${Math.random().toString(16).slice(2)}`);
		await mkdir(root, { recursive: true });
		process.env.HOME = root;
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		setConfiguredLocale(undefined);
		vi.unstubAllEnvs();
		if (prevHome === undefined) delete process.env.HOME;
		else process.env.HOME = prevHome;
		await rm(root, { recursive: true, force: true });
	});

	async function startWith(controlPlane: Record<string, unknown>, fetchImpl: typeof fetch) {
		const aidrDir = join(root, ".singularity-aidr");
		const threatsDir = join(root, "threats");
		const allowlistsDir = join(root, "allowlists");
		const configPath = join(aidrDir, "config.json");
		await Promise.all([
			mkdir(aidrDir, { recursive: true }),
			mkdir(threatsDir, { recursive: true }),
			mkdir(allowlistsDir, { recursive: true }),
		]);
		const config = ConfigSchema.parse({
			mode: "managed",
			auth: { api_key: "aidr_agent_token" },
			control_plane: {
				enabled: true,
				endpoint: "https://control.example.test",
				timeout_seconds: 0.5,
				remote_policy_cache_path: join(aidrDir, "runtime-policy-cache.json"),
				...controlPlane,
			},
			organization: { support_contact_url: "https://corp.example/destek" },
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
		});
		await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf-8");
		globalThis.fetch = fetchImpl;
		return runSessionStart({
			plugins: [],
			threatsDir,
			allowlistsDir,
			version: "0.6.0",
			agentRuntime: "claude-code",
			configPath,
			aidrDirPath: aidrDir,
		});
	}

	const down = vi.fn(async () => {
		throw new TypeError("fetch failed");
	}) as unknown as typeof fetch;

	it("says local protection continues when the company chose keep_enforcing_local", async () => {
		const result = await startWith({ offline_policy: "keep_enforcing_local" }, down);
		expect(result.offline).toEqual({
			policy: "keep_enforcing_local",
			supportContact: "https://corp.example/destek",
		});
		const banner = formatSessionStartMessage("0.6.0", result);
		expect(banner).toContain("Local protection continues");
		expect(banner).toContain("Support: https://corp.example/destek");
	});

	it("warns that calls are blocked when block_after_grace has no usable policy left", async () => {
		const result = await startWith({ offline_policy: "block_after_grace" }, down);
		expect(result.offline?.policy).toBe("block_after_grace");
		expect(result.offline?.blocksAt).toBeUndefined();
		expect(formatSessionStartMessage("0.6.0", result)).toContain("BLOCKED until it is reachable");
	});

	it("says nothing when the control plane answers", async () => {
		const up = vi.fn(
			async () =>
				({
					ok: true,
					status: 200,
					json: async () => ({ ok: true }),
				}) as unknown as Response,
		) as unknown as typeof fetch;
		const result = await startWith({ offline_policy: "block_after_grace" }, up);
		expect(result.offline).toBeUndefined();
	});

	it("names the time and minutes left before the block, in English and Turkish", () => {
		const now = Date.parse("2026-10-14T10:00:00Z");
		const notice = {
			policy: "block_after_grace" as const,
			blocksAt: new Date(now + 42 * 60_000).toISOString(),
		};
		expect(formatOfflineNotice(notice, now)).toMatch(
			/BLOCKED from \d{4}-\d{2}-\d{2} \d{2}:\d{2} \(about 42 min/,
		);
		// vitest.config pins AIDR_LOCALE=en, which outranks the configured locale.
		vi.stubEnv("AIDR_LOCALE", "tr");
		expect(formatOfflineNotice(notice, now)).toMatch(
			/itibarıyla \(yaklaşık 42 dk sonra\) ENGELLENECEK/,
		);
		expect(formatOfflineNotice({ policy: "keep_enforcing_local" }, now)).toContain(
			"yerel koruma sürüyor",
		);
	});
});
