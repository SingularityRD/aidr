import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildCycloneDxBom, type CycloneDxBom } from "../aibom/cyclonedx.js";
import {
	type AiInventory,
	aiInventoryGaps,
	collectAiInventory,
	displayPath,
	packageUrl,
} from "../aibom/inventory.js";
import {
	loadAiComponentCatalog,
	matchCatalogEntry,
	scanProjectForAiComponents,
} from "../aibom/project-scan.js";
import { getCveStats } from "../cve-checker.js";
import { redactMcpLaunch } from "../mcp-launch-redaction.js";

const SERIAL = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
const NOW = new Date("2026-09-25T08:00:00.000Z");

/** Credentials planted in the fixtures; none may appear in any export. */
const SECRETS = [
	"sk-live1234567890abcdefgh",
	"ghp_abcdefghijklmnopqrstuvwxyz0123",
	"s3cr3t-pass",
	"querytoken987",
	"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg",
	"hdr-bearer-value",
	"skillmatchedtext",
];

let root: string;
let project: string;
let home: string;
const previousHome = process.env.HOME;

async function writeJson(path: string, value: unknown): Promise<void> {
	await writeFile(path, JSON.stringify(value));
}

async function writeFixtureProject(dir: string): Promise<void> {
	await mkdir(join(dir, "models", "llm"), { recursive: true });
	await mkdir(join(dir, "node_modules", "dep"), { recursive: true });
	await writeJson(join(dir, "package.json"), {
		name: "support-agent",
		version: "2.3.0",
		dependencies: {
			"@anthropic-ai/sdk": "^0.30.0",
			"@langchain/core": "~0.2.0",
			openai: "4.20.1",
			react: "18.3.1",
		},
		devDependencies: { n8n: "0.200.0" },
	});
	await writeJson(join(dir, "package-lock.json"), {
		lockfileVersion: 3,
		packages: {
			"": { name: "support-agent" },
			"node_modules/@anthropic-ai/sdk": { version: "0.30.1" },
			"node_modules/react": { version: "18.3.1" },
			"node_modules/left-pad": { version: "1.3.0" },
		},
	});
	await writeFile(
		join(dir, "requirements.txt"),
		[
			"# AI stack",
			"langchain==0.0.100 \\",
			"    --hash=sha256:0000",
			'torch>=2.0 ; python_version > "3.8"',
			"requests==2.31.0",
			"",
		].join("\n"),
	);
	await writeFile(
		join(dir, "pyproject.toml"),
		[
			"[project]",
			'name = "support-agent-py"',
			"dependencies = [",
			'  "vllm[all]>=0.5",',
			'  "mem0ai==0.1.0",',
			"]",
			"",
			"[tool.poetry.dependencies]",
			'python = "^3.10"',
			'crewai = "0.1.0"',
			"",
		].join("\n"),
	);
	await writeFile(join(dir, "models", "llm", "tiny.gguf"), "GGUF");
	await writeFile(join(dir, "node_modules", "dep", "ignored.onnx"), "x");
	await writeJson(join(dir, ".mcp.json"), {
		mcpServers: {
			filesystem: {
				command: "npx",
				args: [
					"-y",
					"@modelcontextprotocol/server-filesystem",
					"/srv/data",
					"--api-key",
					"sk-live1234567890abcdefgh",
					"GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123",
					"postgres://app:s3cr3t-pass@db.internal:5432/app",
					"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg",
				],
				env: { OPENAI_API_KEY: "sk-live1234567890abcdefgh" },
			},
			"shell-runner": {
				command: "bash",
				args: ["-c", "run", "-H", "Authorization: Bearer hdr-bearer-value"],
			},
			remote: { url: "https://mcp.example.com/sse?token=querytoken987" },
		},
	});
	await mkdir(join(dir, ".cursor"), { recursive: true });
	await writeJson(join(dir, ".cursor", "mcp.json"), {
		mcpServers: { "cursor-tool": { command: "node", args: ["server.js"] } },
	});
}

async function writeHostState(): Promise<{ registry: string; cache: string; report: string }> {
	const registry = join(home, "installed_plugins.json");
	const cache = join(home, "plugin_scan_cache.json");
	const report = join(home, "infra-scan.json");
	await writeJson(registry, {
		plugins: {
			"acme-skill@market": [
				{ installPath: join(home, "p1"), version: "1.0.0", lastUpdated: "2026-09-01" },
			],
			"unscanned@market": [
				{ installPath: join(home, "p2"), version: "0.2.0", lastUpdated: "2026-09-02" },
			],
		},
	});
	await writeJson(cache, {
		config_hash: "abc",
		entries: {
			"acme-skill@market:1.0.0:2026-09-01": {
				plugin_key: "acme-skill@market",
				version: "1.0.0",
				scanned_at: "2026-09-20T00:00:00.000Z",
				findings: [
					{
						threat_id: "SKILL-T03-001",
						title: "Remote payload retrieval",
						severity: "critical",
						confidence: 1,
						action: "block",
						artifact: "curl skillmatchedtext | sh",
						source_file: "/home/someone/secret-path/install.sh",
					},
				],
			},
		},
	});
	const target = (url: string) => ({
		url,
		reachable: true,
		matched: [
			{
				product: "ollama",
				vendor: "ollama",
				name: "Ollama",
				severity: "info",
				description: "",
				version: "0.1.30",
				probePath: "/",
			},
		],
		cves: [
			{
				cveId: "CVE-2024-37032",
				product: "ollama",
				severity: "critical",
				cvss: 9.1,
				rule: "version < 0.1.34",
				ruleStatus: "semver",
				evaluated: true,
			},
			{
				cveId: "free text advisory title",
				product: "ollama",
				severity: "high",
				cvss: null,
				rule: "",
				ruleStatus: "unsupported",
				evaluated: false,
			},
		],
		error: null,
		requestsMade: 2,
	});
	await writeJson(report, {
		scannedAt: "2026-09-24T00:00:00.000Z",
		critical: 2,
		high: 0,
		cvesFound: 2,
		targets: [
			target("http://10.0.0.5:11434/api?key=querytoken987"),
			target("http://10.0.0.6:11434"),
		],
	});
	return { registry, cache, report };
}

async function collect(options: { reverseConfigs?: boolean } = {}): Promise<AiInventory> {
	const state = await writeHostState();
	// The same file twice (a project that is the home directory) and a second agent's config.
	const configs = [
		join(project, ".mcp.json"),
		join(project, ".cursor", "mcp.json"),
		join(project, ".mcp.json"),
	];
	return collectAiInventory({
		projectDir: project,
		agents: [
			{ id: "codex", label: "Codex", state: "not_detected" },
			{ id: "claude-code", label: "Claude Code", state: "installed" },
			{ id: "cursor", label: "Cursor", state: "runtime_present_not_installed" },
		],
		mcpConfigPaths: options.reverseConfigs ? configs.reverse() : configs,
		pluginRegistryPath: state.registry,
		pluginScanCachePath: state.cache,
		infrastructureReportPath: state.report,
		now: NOW,
	});
}

function allRefs(bom: CycloneDxBom): string[] {
	return [
		bom.metadata.component["bom-ref"],
		...bom.metadata.tools.components.map((c) => c["bom-ref"]),
		...bom.components.map((c) => c["bom-ref"]),
		...bom.services.map((s) => s["bom-ref"]),
		...bom.vulnerabilities.map((v) => v["bom-ref"]),
	];
}

function propertyValues(
	item: { properties?: Array<{ name: string; value: string }> },
	name: string,
): string[] {
	return (item.properties ?? []).filter((p) => p.name === name).map((p) => p.value);
}

beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-aibom-"));
	home = join(root, "home");
	project = join(home, "work", "support-agent");
	await mkdir(project, { recursive: true });
	process.env.HOME = home;
	await writeFixtureProject(project);
});

afterEach(async () => {
	process.env.HOME = previousHome;
	await rm(root, { recursive: true, force: true });
});

describe("MCP launch redaction", () => {
	it("removes flag values, credential assignments, URL secrets and opaque tokens", () => {
		const redacted = redactMcpLaunch("/usr/bin/env", [
			"-y",
			"@modelcontextprotocol/server-github",
			"--token",
			"abc",
			"--api-key=sk-live1234567890abcdefgh",
			"OPENAI_API_KEY=anything",
			"-H",
			"X-Custom: hdr-bearer-value",
			"https://user:s3cr3t-pass@api.example.com/v1/path?sig=querytoken987#frag",
			"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg",
			"/home/dev/project",
		]);
		expect(redacted.command).toBe("/usr/bin/env");
		expect(redacted.args).toEqual([
			"-y",
			"@modelcontextprotocol/server-github",
			"--token",
			"[Redacted]",
			"--api-key=[Redacted]",
			"OPENAI_API_KEY=[Redacted]",
			"-H",
			"[Redacted]",
			"https://api.example.com/v1/path",
			"[Redacted]",
			"/home/dev/project",
		]);
	});
});

describe("AI component catalog and project scan", () => {
	it("loads a valid data-driven catalog and matches exact, prefix and PEP 503 names", () => {
		const catalog = loadAiComponentCatalog();
		expect(catalog.packages.length).toBeGreaterThan(50);
		expect(matchCatalogEntry(catalog, "npm", "@langchain/openai")?.category).toBe(
			"llm-orchestration",
		);
		expect(matchCatalogEntry(catalog, "pypi", "Llama_Index.Core")?.name).toBe("llama-index-");
		expect(matchCatalogEntry(catalog, "pypi", "en_core_web_sm")?.type).toBe(
			"machine-learning-model",
		);
		expect(matchCatalogEntry(catalog, "npm", "react")).toBeUndefined();
	});

	it("reads manifests and lockfiles, resolves versions and finds model files", async () => {
		await symlink(join(root), join(project, "models", "loop")).catch(() => undefined);
		const scan = await scanProjectForAiComponents(project);
		expect(scan.name).toBe("support-agent");
		expect(scan.version).toBe("2.3.0");
		const byName = new Map(scan.packages.map((pkg) => [`${pkg.ecosystem}:${pkg.name}`, pkg]));
		expect([...byName.keys()]).toEqual([
			"npm:@anthropic-ai/sdk",
			"npm:@langchain/core",
			"npm:n8n",
			"npm:openai",
			"pypi:crewai",
			"pypi:langchain",
			"pypi:mem0ai",
			"pypi:torch",
			"pypi:vllm",
		]);
		expect(byName.get("npm:@anthropic-ai/sdk")).toMatchObject({
			version: "0.30.1",
			declared: "^0.30.0",
			version_source: "lockfile",
			manifests: ["package-lock.json", "package.json"],
		});
		expect(byName.get("npm:@langchain/core")).toMatchObject({ version: null, declared: "~0.2.0" });
		expect(byName.get("npm:openai")).toMatchObject({
			version: "4.20.1",
			version_source: "manifest-pin",
		});
		expect(byName.get("pypi:langchain")).toMatchObject({
			version: "0.0.100",
			cve_product: "langchain",
		});
		expect(byName.get("pypi:crewai")).toMatchObject({ version: "0.1.0" });
		expect(byName.get("pypi:vllm")).toMatchObject({ version: null, declared: ">=0.5" });
		expect(scan.model_files).toEqual([
			{ path: "models/llm/tiny.gguf", format: "gguf", size_bytes: 4 },
		]);
		expect(scan.model_scan_complete).toBe(true);
		expect(scan.manifests.every((manifest) => manifest.status === "read")).toBe(true);
	});

	it("reports an unparseable manifest as invalid instead of empty", async () => {
		await writeFile(join(project, "package.json"), "{ not json");
		const scan = await scanProjectForAiComponents(project);
		expect(scan.manifests).toContainEqual({
			path: "package.json",
			status: "invalid",
			dependencies: 0,
		});
		expect(scan.packages.some((pkg) => pkg.ecosystem === "npm" && pkg.name === "openai")).toBe(
			false,
		);
	});
});

describe("AI inventory", () => {
	it("collects agents, MCP servers, plugins, infrastructure and vulnerabilities", async () => {
		const inventory = await collect();
		expect(inventory.agents.map((agent) => agent.ref)).toEqual([
			"agent:claude-code",
			"agent:cursor",
		]);
		expect(inventory.project.path).toBe("~/work/support-agent");

		// The same configuration listed twice yields each server once.
		expect(inventory.mcp_servers.map((server) => server.name)).toEqual([
			"cursor-tool",
			"filesystem",
			"remote",
			"shell-runner",
		]);
		const [cursorTool, filesystem, remote, shell] = inventory.mcp_servers;
		expect(cursorTool?.agent).toBe("cursor");
		expect(filesystem?.agent).toBe("claude-code");
		expect(filesystem?.config_source).toBe("~/work/support-agent/.mcp.json");
		expect(filesystem?.args).toContain("[Redacted]");
		expect(remote).toMatchObject({ transport: "remote", endpoint: "https://mcp.example.com" });
		expect(shell?.risk_hints).toEqual(["shell_wrapper_command"]);
		for (const server of inventory.mcp_servers) expect(server.risk_categories).toHaveLength(14);

		expect(inventory.plugins).toMatchObject([
			{ key: "acme-skill@market", scan_status: "scanned", finding_count: 1 },
			{ key: "unscanned@market", scan_status: "not_scanned", finding_count: 0 },
		]);
		expect(inventory.infrastructure.map((service) => service.endpoint)).toEqual([
			"http://10.0.0.5:11434",
			"http://10.0.0.6:11434",
		]);

		const skill = inventory.vulnerabilities.find((v) => v.source === "skill-scan");
		expect(skill).toMatchObject({
			id: "SKILL-T03-001",
			severity: "critical",
			skill_risk_type: "T03",
			affects: [{ ref: "plugin:acme-skill@market", version: "1.0.0" }],
		});
		// One CVE on two endpoints is one record with two affected services.
		const ollama = inventory.vulnerabilities.find((v) => v.id === "CVE-2024-37032");
		expect(ollama?.affects.map((a) => a.ref)).toEqual([
			"infra:http://10.0.0.5:11434",
			"infra:http://10.0.0.6:11434",
		]);
		expect(ollama).toMatchObject({ severity: "critical", cvss: 9.1, applicability: "confirmed" });
		// Free-text advisory titles are not exported as identifiers.
		const advisory = inventory.vulnerabilities.filter(
			(v) => v.source === "infrastructure-scan" && v.id === null,
		);
		expect(advisory).toHaveLength(2);
		expect(advisory.every((v) => v.applicability === "unconfirmed")).toBe(true);

		if (getCveStats().total > 0) {
			expect(inventory.coverage.cve_index).toBe("available");
			const langchain = inventory.vulnerabilities.filter((v) =>
				v.affects.some((a) => a.ref === "pkg:pypi/langchain@0.0.100"),
			);
			expect(langchain.length).toBeGreaterThan(0);
			expect(langchain.every((v) => v.source === "cve-index")).toBe(true);
			const vllm = inventory.packages.find((pkg) => pkg.name === "vllm");
			expect(vllm?.vulnerability_check).toBe("not_evaluated_unpinned");
		}
		expect(aiInventoryGaps(inventory)).toEqual([]);
	});

	it("never exports credentials, environment values, matched text or plugin paths", async () => {
		const inventory = await collect();
		const text = `${JSON.stringify(inventory)}\n${JSON.stringify(buildCycloneDxBom(inventory, { serialNumber: SERIAL }))}`;
		for (const secret of SECRETS) expect(text).not.toContain(secret);
		expect(text).not.toContain("OPENAI_API_KEY");
		expect(text).not.toContain("secret-path");
		expect(text).not.toContain(home);
	});

	it("reports an unreadable infrastructure report and invalid MCP config as gaps", async () => {
		await writeFile(join(project, ".mcp.json"), "{ broken");
		const inventory = await collectAiInventory({
			projectDir: project,
			mcpConfigPaths: [join(project, ".mcp.json")],
			pluginRegistryPath: join(home, "none.json"),
			pluginScanCachePath: join(home, "none.json"),
			infrastructureReportPath: join(home, "missing-report.json"),
			now: NOW,
		});
		expect(inventory.coverage.infrastructure_report).toBe("missing");
		expect(aiInventoryGaps(inventory)).toEqual([
			"1 MCP configuration file(s) could not be read",
			"infrastructure scan report is missing",
		]);
	});

	it("shows the home directory as ~ and builds npm/PyPI purls", () => {
		expect(displayPath(join(home, "a", "b"))).toBe("~/a/b");
		expect(displayPath("/opt/elsewhere")).toBe("/opt/elsewhere");
		expect(packageUrl({ ecosystem: "npm", name: "@anthropic-ai/sdk", version: "0.30.1" })).toBe(
			"pkg:npm/%40anthropic-ai/sdk@0.30.1",
		);
		expect(packageUrl({ ecosystem: "pypi", name: "mem0ai", version: null })).toBe(
			"pkg:pypi/mem0ai",
		);
	});
});

describe("CycloneDX 1.6 BOM", () => {
	it("has the 1.6 document shape and correct component and service types", async () => {
		const bom = buildCycloneDxBom(await collect(), { serialNumber: SERIAL });
		expect(bom).toMatchObject({
			$schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
			bomFormat: "CycloneDX",
			specVersion: "1.6",
			serialNumber: SERIAL,
			version: 1,
		});
		expect(bom.metadata.timestamp).toBe(NOW.toISOString());
		expect(bom.metadata.tools.components[0]).toMatchObject({
			type: "application",
			name: "Singularity AIDR",
		});
		expect(bom.metadata.component).toMatchObject({
			type: "application",
			"bom-ref": "project",
			name: "support-agent",
			version: "2.3.0",
		});

		const component = (ref: string) => bom.components.find((c) => c["bom-ref"] === ref);
		expect(component("agent:claude-code")).toMatchObject({
			type: "application",
			name: "Claude Code",
		});
		expect(propertyValues(component("agent:cursor") ?? {}, "aidr:agent:protection_state")).toEqual([
			"runtime_present_not_installed",
		]);
		expect(component("pkg:npm/%40anthropic-ai/sdk@0.30.1")).toMatchObject({
			type: "library",
			group: "@anthropic-ai",
			name: "sdk",
			version: "0.30.1",
			purl: "pkg:npm/%40anthropic-ai/sdk@0.30.1",
			supplier: { name: "Anthropic" },
		});
		expect(component("pkg:pypi/torch")?.type).toBe("framework");
		expect(component("model-file:models/llm/tiny.gguf")?.type).toBe("machine-learning-model");
		expect(component("plugin:acme-skill@market")?.type).toBe("library");

		const remote = bom.services.find((s) => s.name === "remote");
		expect(remote).toMatchObject({
			endpoints: ["https://mcp.example.com"],
			"x-trust-boundary": true,
		});
		const riskFlags = (remote?.properties ?? []).filter((p) => p.name.startsWith("aidr:mcp:risk:"));
		expect(riskFlags).toHaveLength(14);
		expect(riskFlags.every((p) => p.value === "true" || p.value === "false")).toBe(true);
		const filesystem = bom.services.find((s) => s.name === "filesystem");
		expect(filesystem?.endpoints).toBeUndefined();
		expect(JSON.parse(propertyValues(filesystem ?? {}, "aidr:mcp:args")[0] ?? "[]")).toContain(
			"@modelcontextprotocol/server-filesystem",
		);
		const infra = bom.services.find((s) => s["bom-ref"] === "infra:http://10.0.0.5:11434");
		expect(infra).toMatchObject({ name: "ollama", version: "0.1.30" });

		const vuln = bom.vulnerabilities.find((v) => v.id === "CVE-2024-37032");
		expect(vuln).toMatchObject({
			source: { name: "AI Security Posture infrastructure scan" },
			ratings: [{ severity: "critical", score: 9.1 }],
			affects: [
				{
					ref: "infra:http://10.0.0.5:11434",
					versions: [{ version: "0.1.30", status: "affected" }],
				},
				{
					ref: "infra:http://10.0.0.6:11434",
					versions: [{ version: "0.1.30", status: "affected" }],
				},
			],
		});
		const text = JSON.stringify(bom);
		expect(text).not.toMatch(/infra[- ]?guard|tencent|\bAIG\b/i);
	});

	it("keeps bom-refs unique and every dependency and affects reference resolvable", async () => {
		const bom = buildCycloneDxBom(await collect(), { serialNumber: SERIAL });
		const refs = allRefs(bom);
		expect(new Set(refs).size).toBe(refs.length);
		const known = new Set(refs);
		for (const dependency of bom.dependencies) {
			expect(known.has(dependency.ref)).toBe(true);
			for (const ref of dependency.dependsOn) expect(known.has(ref)).toBe(true);
		}
		for (const vulnerability of bom.vulnerabilities)
			for (const affected of vulnerability.affects) expect(known.has(affected.ref)).toBe(true);

		const edges = new Map(bom.dependencies.map((d) => [d.ref, d.dependsOn]));
		expect(edges.get("agent:claude-code")).toEqual(
			expect.arrayContaining(["plugin:acme-skill@market", "plugin:unscanned@market"]),
		);
		expect(edges.get("agent:claude-code")?.filter((ref) => ref.startsWith("mcp:"))).toHaveLength(3);
		expect(edges.get("agent:cursor")).toHaveLength(1);
		expect(edges.get("project")).toEqual(
			expect.arrayContaining([
				"agent:claude-code",
				"agent:cursor",
				"model-file:models/llm/tiny.gguf",
			]),
		);
	});

	it("is deterministic regardless of input order and rejects a malformed serial number", async () => {
		const first = JSON.stringify(buildCycloneDxBom(await collect(), { serialNumber: SERIAL }));
		const second = JSON.stringify(
			buildCycloneDxBom(await collect({ reverseConfigs: true }), { serialNumber: SERIAL }),
		);
		expect(second).toBe(first);
		const bom = JSON.parse(first) as CycloneDxBom;
		const sortedRefs = (items: Array<{ "bom-ref": string }>) => items.map((i) => i["bom-ref"]);
		expect(sortedRefs(bom.components)).toEqual([...sortedRefs(bom.components)].sort());
		expect(sortedRefs(bom.services)).toEqual([...sortedRefs(bom.services)].sort());
		expect(sortedRefs(bom.vulnerabilities)).toEqual([...sortedRefs(bom.vulnerabilities)].sort());
		const inventory = await collect();
		expect(() => buildCycloneDxBom(inventory, { serialNumber: "not-a-urn" })).toThrow(/urn:uuid/);
		expect(buildCycloneDxBom(inventory).serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
	});
});
