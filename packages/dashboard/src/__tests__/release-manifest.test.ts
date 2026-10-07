// @vitest-environment jsdom

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
	artifactFileName,
	fetchReleaseManifest,
	parseReleaseManifest,
	RELEASE_ARTIFACT_IDS,
	resolveReleaseManifestSource,
	verifyCommands,
} from "../onboarding/release-manifest";
import schema from "../onboarding/release-manifest.schema.json";
import { latestCheckIn, RUNTIME_CATALOG } from "../onboarding/runtime-catalog";

const REPO_ROOT = resolve(__dirname, "../../../..");

function artifact(overrides: Record<string, unknown> = {}) {
	return {
		id: "cursor",
		version: "1.4.0",
		url: "https://downloads.customer.example/aidr/1.4.0/aidr-cursor.vsix",
		sha256: "c".repeat(64),
		size: 2048,
		platforms: ["any"],
		...overrides,
	};
}

function manifest(overrides: Record<string, unknown> = {}) {
	return {
		version: "1.4.0",
		publishedAt: "2026-09-20T10:00:00Z",
		artifacts: [artifact()],
		...overrides,
	};
}

describe("release manifest contract", () => {
	it("keeps the JSON Schema, the TypeScript ids and the runtime catalog in lockstep", () => {
		const artifactSchema = schema.$defs.artifact;
		expect(artifactSchema.properties.id.enum).toEqual([...RELEASE_ARTIFACT_IDS]);
		expect(schema.required).toEqual(["version", "publishedAt", "artifacts"]);
		expect(artifactSchema.required).toEqual([
			"id",
			"version",
			"url",
			"sha256",
			"size",
			"platforms",
		]);
		expect(schema.additionalProperties).toBe(false);
		expect(artifactSchema.additionalProperties).toBe(false);
		expect(RUNTIME_CATALOG.map((entry) => entry.id)).toEqual([...RELEASE_ARTIFACT_IDS]);
	});

	it("accepts a valid manifest and returns a normalized copy", () => {
		const parsed = parseReleaseManifest(
			manifest({
				artifacts: [
					artifact({
						signature: "https://downloads.customer.example/aidr/1.4.0/aidr-cursor.vsix.sig",
					}),
					artifact({
						id: "cli",
						url: "https://downloads.customer.example/cli-linux",
						platforms: ["linux-x64"],
					}),
					artifact({
						id: "cli",
						url: "https://downloads.customer.example/cli-mac",
						platforms: ["darwin-arm64"],
					}),
				],
			}),
		);
		expect(parsed.artifacts).toHaveLength(3);
		expect(parsed.artifacts[0]?.signature).toMatch(/\.sig$/);
		expect(parseReleaseManifest(manifest({ artifacts: [] })).artifacts).toEqual([]);
	});

	it.each([
		[
			"an http: download URL",
			manifest({ artifacts: [artifact({ url: "http://downloads.customer.example/a.vsix" })] }),
			/must use https/,
		],
		[
			"a javascript: URL",
			manifest({ artifacts: [artifact({ url: "javascript:alert(1)" })] }),
			/must use https/,
		],
		[
			"a relative URL",
			manifest({ artifacts: [artifact({ url: "/aidr-cursor.vsix" })] }),
			/absolute https/,
		],
		[
			"embedded credentials",
			manifest({ artifacts: [artifact({ url: "https://u:p@downloads.customer.example/a" })] }),
			/credentials/,
		],
		[
			"an http: signature",
			manifest({ artifacts: [artifact({ signature: "http://downloads.customer.example/a.sig" })] }),
			/signature must use https/,
		],
		["a missing sha256", manifest({ artifacts: [artifact({ sha256: undefined })] }), /sha256/],
		[
			"an upper-case sha256",
			manifest({ artifacts: [artifact({ sha256: "C".repeat(64) })] }),
			/sha256/,
		],
		["a short sha256", manifest({ artifacts: [artifact({ sha256: "c".repeat(63) })] }), /sha256/],
		[
			"an unknown artifact id",
			manifest({ artifacts: [artifact({ id: "windsurf" })] }),
			/supported artifact/,
		],
		[
			"an unknown field",
			manifest({ artifacts: [artifact({ mirror: "https://x.example" })] }),
			/unsupported field "mirror"/,
		],
		["an unknown top-level field", manifest({ channel: "beta" }), /unsupported field "channel"/],
		["a zero size", manifest({ artifacts: [artifact({ size: 0 })] }), /size/],
		["a fractional size", manifest({ artifacts: [artifact({ size: 1.5 })] }), /size/],
		["no platforms", manifest({ artifacts: [artifact({ platforms: [] })] }), /platforms/],
		[
			"duplicate platforms",
			manifest({ artifacts: [artifact({ platforms: ["any", "any"] })] }),
			/platforms/,
		],
		[
			"a duplicate id and platform",
			manifest({ artifacts: [artifact(), artifact()] }),
			/duplicates cursor/,
		],
		["a non-semver version", manifest({ version: "latest" }), /semantic version/],
		["an invalid publishedAt", manifest({ publishedAt: "2026-09-20" }), /publishedAt/],
		["a non-object", [manifest()], /not a JSON object/],
	])("rejects %s", (_label, value, message) => {
		expect(() => parseReleaseManifest(value)).toThrow(message);
	});

	it("validates the output of scripts/generate-release-manifest.mjs with the browser validator", () => {
		const directory = mkdtempSync(join(tmpdir(), "aidr-dashboard-manifest-"));
		try {
			writeFileSync(join(directory, "aidr-claude-plugin-3.1.0.tar.gz"), "plugin");
			writeFileSync(join(directory, "aidr-claude-plugin-3.1.0.tar.gz.sig"), "sig");
			writeFileSync(join(directory, "aidr-browser-guard-chrome-3.1.0.zip"), "chrome");
			const result = spawnSync(
				process.execPath,
				[
					join(REPO_ROOT, "scripts/generate-release-manifest.mjs"),
					"--dir",
					directory,
					"--version",
					"3.1.0",
					"--base-url",
					"https://downloads.customer.example/aidr/3.1.0",
					"--published-at",
					"2026-09-24T00:00:00Z",
				],
				{ encoding: "utf8", timeout: 20_000 },
			);
			expect(result.status, result.stderr).toBe(0);
			const parsed = parseReleaseManifest(JSON.parse(result.stdout));
			expect(parsed.artifacts.map((entry) => entry.id)).toEqual([
				"claude-code",
				"browser-guard-chrome",
			]);
			expect(parsed.artifacts[0]?.signature).toBe(
				"https://downloads.customer.example/aidr/3.1.0/aidr-claude-plugin-3.1.0.tar.gz.sig",
			);
			expect(parsed.artifacts[1]?.platforms).toEqual(["chrome", "edge"]);
		} finally {
			rmSync(directory, { recursive: true, force: true });
		}
	});
});

describe("release manifest source", () => {
	const origin = "https://console.customer.example";

	it("is not configured without a runtime or build URL", () => {
		expect(resolveReleaseManifestSource(undefined, undefined, origin)).toEqual({
			configured: false,
		});
		expect(resolveReleaseManifestSource(null, "  ", origin)).toEqual({ configured: false });
	});

	it("accepts a same-origin path or an https URL, preferring runtime configuration", () => {
		expect(
			resolveReleaseManifestSource(
				"/release-manifest.json",
				"https://other.example/m.json",
				origin,
			),
		).toEqual({
			configured: true,
			url: `${origin}/release-manifest.json`,
		});
		expect(
			resolveReleaseManifestSource(undefined, "https://downloads.customer.example/m.json", origin),
		).toEqual({
			configured: true,
			url: "https://downloads.customer.example/m.json",
		});
		// A same-origin path stays valid on a loopback development server.
		expect(
			resolveReleaseManifestSource("/release-manifest.json", undefined, "http://localhost:5173"),
		).toEqual({
			configured: true,
			url: "http://localhost:5173/release-manifest.json",
		});
	});

	it.each([
		"http://downloads.customer.example/release-manifest.json",
		"//downloads.customer.example/release-manifest.json",
		"https://user:secret@downloads.customer.example/m.json",
		"javascript:alert(1)",
		"release-manifest.json",
		"/\\evil.example/m.json",
	])("rejects %s", (candidate) => {
		const source = resolveReleaseManifestSource(candidate, undefined, origin);
		expect(source.configured).toBe(true);
		expect("error" in source && source.error).toMatch(/HTTPS or same-origin/);
	});
});

describe("release manifest fetch", () => {
	it("fetches without credentials or redirects and validates the body", async () => {
		const fetchImpl = vi.fn(async () => new Response(JSON.stringify(manifest()), { status: 200 }));
		const parsed = await fetchReleaseManifest(
			"https://downloads.customer.example/m.json",
			fetchImpl,
		);
		expect(parsed.version).toBe("1.4.0");
		expect(fetchImpl).toHaveBeenCalledWith(
			"https://downloads.customer.example/m.json",
			expect.objectContaining({ credentials: "omit", redirect: "error", method: "GET" }),
		);
	});

	it("rejects HTTP errors, invalid JSON, oversized bodies and insecure artifacts", async () => {
		const url = "https://downloads.customer.example/m.json";
		await expect(
			fetchReleaseManifest(url, async () => new Response("", { status: 404 })),
		).rejects.toThrow(/HTTP 404/);
		await expect(
			fetchReleaseManifest(url, async () => new Response("{", { status: 200 })),
		).rejects.toThrow(/not valid JSON/);
		await expect(
			fetchReleaseManifest(
				url,
				async () => new Response(" ".repeat(1024 * 1024 + 1), { status: 200 }),
			),
		).rejects.toThrow(/larger than 1 MiB/);
		const insecure = manifest({
			artifacts: [artifact({ url: "http://downloads.customer.example/a.vsix" })],
		});
		await expect(
			fetchReleaseManifest(
				url,
				async () => new Response(JSON.stringify(insecure), { status: 200 }),
			),
		).rejects.toThrow(/must use https/);
	});
});

describe("verification helpers", () => {
	it("derives a shell-safe file name and per-OS digest checks", () => {
		const [cursor] = parseReleaseManifest(manifest()).artifacts;
		if (!cursor) throw new Error("expected one artifact");
		expect(artifactFileName(cursor)).toBe("aidr-cursor.vsix");
		const commands = verifyCommands(cursor);
		expect(commands.map((command) => command.label)).toEqual([
			"Linux",
			"macOS",
			"Windows PowerShell",
		]);
		for (const command of commands) {
			expect(command.command).toContain("c".repeat(64));
			expect(command.command).toContain("aidr-cursor.vsix");
		}
		expect(commands[0]?.command).toBe(
			`echo "${"c".repeat(64)}  aidr-cursor.vsix" | sha256sum --check`,
		);
		expect(
			artifactFileName({
				id: "cli",
				url: "https://downloads.customer.example/a/%24(reboot)%3B.bin",
			}),
		).toBe("aidr-cli.download");
		expect(artifactFileName({ id: "codex", url: "https://downloads.customer.example/" })).toBe(
			"aidr-codex.download",
		);
	});

	it("detects check-ins only for the matching runtime and browser family", () => {
		const byId = (id: string) => {
			const entry = RUNTIME_CATALOG.find((candidate) => candidate.id === id);
			if (!entry) throw new Error(`missing catalog entry ${id}`);
			return entry;
		};
		const agents = [
			{
				agent_runtime: "claude-code",
				agent_runtime_version: "2.1.0",
				last_seen: "2026-09-20T10:00:00Z",
			},
			{
				agent_runtime: "claude-code",
				agent_runtime_version: "2.1.0",
				last_seen: "2026-09-22T10:00:00Z",
			},
			{
				agent_runtime: "browser_guard",
				agent_runtime_version: "firefox-128",
				last_seen: "2026-09-21T10:00:00Z",
			},
			{ agent_runtime: null, agent_runtime_version: null, last_seen: "2026-09-23T10:00:00Z" },
		];
		expect(latestCheckIn(byId("claude-code"), agents)).toBe("2026-09-22T10:00:00.000Z");
		expect(latestCheckIn(byId("browser-guard-firefox"), agents)).toBe("2026-09-21T10:00:00.000Z");
		expect(latestCheckIn(byId("browser-guard-chrome"), agents)).toBeNull();
		expect(latestCheckIn(byId("cursor"), agents)).toBeNull();
		expect(latestCheckIn(byId("mcp-gateway"), agents)).toBeNull();
	});
});
