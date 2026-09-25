import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import aibomCommand, { type AiBomDependencies, runAiBom } from "../commands/aibom.js";

const SERIAL = "urn:uuid:0b6e1c55-6f1d-4d8c-9a55-1f6e0a3c2b10";
const initialExitCode = process.exitCode;

let root: string;
let project: string;

function deps(overrides: Partial<AiBomDependencies> = {}): AiBomDependencies {
	return {
		agents: () => [
			{
				id: "claude-code",
				label: "Claude Code",
				state: "installed",
				detail: "plugin registered",
				evidence: [join(root, "home", ".claude", "settings.json")],
			},
			{ id: "codex", label: "Codex", state: "not_detected", detail: "", evidence: [] },
		],
		collectOptions: {
			pluginRegistryPath: join(root, "no-registry.json"),
			pluginScanCachePath: join(root, "no-cache.json"),
			now: new Date("2026-09-25T09:00:00.000Z"),
		},
		serialNumber: SERIAL,
		configPath: join(root, "no-config.json"),
		...overrides,
	};
}

function captureStdout(): { text: () => string } {
	let text = "";
	vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
		text += String(chunk);
		return true;
	});
	return { text: () => text };
}

beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-cli-aibom-"));
	project = join(root, "project");
	await mkdir(project, { recursive: true });
	await writeFile(
		join(project, "package.json"),
		JSON.stringify({
			name: "demo",
			dependencies: { "@anthropic-ai/sdk": "0.30.1", react: "18.3.1" },
		}),
	);
	await writeFile(
		join(project, ".mcp.json"),
		JSON.stringify({
			mcpServers: {
				github: {
					command: "npx",
					args: [
						"-y",
						"@modelcontextprotocol/server-github",
						"--token",
						"ghp_supersecretvalue1234567890",
					],
					env: { GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_envsecretvalue1234567890" },
				},
			},
		}),
	);
});

afterEach(async () => {
	vi.restoreAllMocks();
	process.exitCode = initialExitCode;
	await rm(root, { recursive: true, force: true });
});

describe("aidr aibom", () => {
	it("prints a CycloneDX 1.6 BOM for the project to stdout", async () => {
		const stdout = captureStdout();
		await runAiBom({ path: project, config: [join(project, ".mcp.json")] }, deps());
		const bom = JSON.parse(stdout.text());
		expect(bom).toMatchObject({
			bomFormat: "CycloneDX",
			specVersion: "1.6",
			serialNumber: SERIAL,
			metadata: { timestamp: "2026-09-25T09:00:00.000Z", component: { name: "demo" } },
		});
		expect(bom.components.map((c: { "bom-ref": string }) => c["bom-ref"])).toEqual([
			"agent:claude-code",
			"pkg:npm/%40anthropic-ai/sdk@0.30.1",
		]);
		expect(bom.services).toHaveLength(1);
		expect(bom.services[0].name).toBe("github");
		expect(stdout.text()).not.toContain("ghp_");
		expect(stdout.text()).not.toContain("GITHUB_PERSONAL_ACCESS_TOKEN");
		expect(stdout.text()).not.toContain(join(root, "home"));
		expect(process.exitCode).toBe(initialExitCode);
	});

	it("emits the AIDR inventory with --format json", async () => {
		const stdout = captureStdout();
		await runAiBom({ path: project, format: "json", config: [join(project, ".mcp.json")] }, deps());
		const inventory = JSON.parse(stdout.text());
		expect(inventory.schema).toBe("aidr-ai-inventory/v1");
		expect(inventory.mcp_servers[0].args).toEqual([
			"-y",
			"@modelcontextprotocol/server-github",
			"--token",
			"[Redacted]",
		]);
	});

	it("writes a new 0600 file and refuses to overwrite an existing one", async () => {
		const output = join(root, "aibom.cdx.json");
		const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
		await runAiBom({ path: project, output, config: [join(project, ".mcp.json")] }, deps());
		const written = JSON.parse(await readFile(output, "utf8"));
		expect(written.bomFormat).toBe("CycloneDX");
		if (process.platform !== "win32") expect((await stat(output)).mode & 0o777).toBe(0o600);
		expect(stderr).toHaveBeenCalledWith(expect.stringContaining("AI-BOM written to"));

		await runAiBom({ path: project, output, config: [join(project, ".mcp.json")] }, deps());
		expect(stderr).toHaveBeenCalledWith(`${output} already exists; choose a new file name.`);
		expect(process.exitCode).toBe(1);
	});

	it("includes the AI infrastructure report configured in the policy", async () => {
		const report = join(root, "infra-scan.json");
		await writeFile(
			report,
			JSON.stringify({
				scannedAt: "2026-09-24T00:00:00.000Z",
				critical: 1,
				high: 0,
				cvesFound: 1,
				targets: [
					{
						url: "http://127.0.0.1:11434",
						reachable: true,
						matched: [{ product: "ollama", version: "0.1.30" }],
						cves: [
							{
								cveId: "CVE-2024-37032",
								product: "ollama",
								severity: "critical",
								cvss: 9.1,
								evaluated: true,
							},
						],
						error: null,
						requestsMade: 1,
					},
				],
			}),
		);
		const configPath = join(root, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({ policy: { ai_infrastructure: { enabled: true, report_path: report } } }),
		);
		const stdout = captureStdout();
		await runAiBom({ path: project, config: [join(project, ".mcp.json")] }, deps({ configPath }));
		const bom = JSON.parse(stdout.text());
		expect(bom.services.map((s: { "bom-ref": string }) => s["bom-ref"])).toContain(
			"infra:http://127.0.0.1:11434",
		);
		expect(bom.vulnerabilities.map((v: { id?: string }) => v.id)).toContain("CVE-2024-37032");
	});

	it("still emits the BOM but exits 1 when the inventory is incomplete", async () => {
		await writeFile(join(project, ".mcp.json"), "{ broken");
		const stdout = captureStdout();
		const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
		await runAiBom(
			{
				path: project,
				config: [join(project, ".mcp.json")],
				scanReport: join(root, "missing.json"),
			},
			deps(),
		);
		expect(JSON.parse(stdout.text()).bomFormat).toBe("CycloneDX");
		expect(stderr).toHaveBeenCalledWith(
			"Incomplete inventory: 1 MCP configuration file(s) could not be read.",
		);
		expect(stderr).toHaveBeenCalledWith(
			"Incomplete inventory: infrastructure scan report is missing.",
		);
		expect(process.exitCode).toBe(1);
	});

	it("rejects an unknown format and an unreadable project directory", async () => {
		const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
		await aibomCommand({ path: project, format: "spdx" });
		expect(stderr).toHaveBeenCalledWith('--format must be "cyclonedx-json" or "json".');
		expect(process.exitCode).toBe(1);
		process.exitCode = initialExitCode;
		await runAiBom({ path: join(root, "does-not-exist") }, deps());
		expect(stderr).toHaveBeenCalledWith(expect.stringContaining("is not a readable directory"));
		expect(process.exitCode).toBe(1);
	});
});
