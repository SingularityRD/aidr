import { discoverMcpServers } from "@singularityrd/aidr-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import discoverCommand, { type DiscoverDependencies, runDiscover } from "../commands/discover.js";

vi.mock("@singularityrd/aidr-core", async (importOriginal) => ({
	...(await importOriginal<typeof import("@singularityrd/aidr-core")>()),
	discoverMcpServers: vi.fn(),
}));

const initialExitCode = process.exitCode;

afterEach(() => {
	vi.restoreAllMocks();
	process.exitCode = initialExitCode;
});

describe("aidr discover", () => {
	it("reports malformed entries and exits unsuccessfully for incomplete coverage", async () => {
		vi.mocked(discoverMcpServers).mockResolvedValue({
			schema_version: 1,
			scanned_at: "2026-09-23T00:00:00.000Z",
			scope: "Local configuration discovery",
			sources: [{ path: "mcp.json", status: "read" }],
			coverage: {
				status: "partial",
				total_sources: 1,
				read_sources: 1,
				missing_sources: 0,
				invalid_sources: 0,
				servers_not_enumerated: 1,
				sources_not_enumerated: 0,
			},
			servers: [],
		});
		const output = vi.spyOn(console, "error").mockImplementation(() => {});

		await discoverCommand({ config: ["mcp.json"] });

		expect(output).toHaveBeenCalledWith(
			"Inventory coverage is partial; malformed server entries not enumerated: 1",
		);
		expect(process.exitCode).toBe(1);
	});

	it("uploads MCP inventory findings without paths, endpoints or arguments", async () => {
		vi.mocked(discoverMcpServers).mockResolvedValue({
			schema_version: 1,
			scanned_at: "2026-09-24T00:00:00.000Z",
			scope: "Local configuration discovery",
			sources: [{ path: "/home/username/.cursor/mcp.json", status: "read" }],
			coverage: {
				status: "read",
				total_sources: 1,
				read_sources: 1,
				missing_sources: 0,
				invalid_sources: 0,
				servers_not_enumerated: 0,
				sources_not_enumerated: 0,
			},
			servers: [
				{
					inventory_id: "a".repeat(64),
					name: "shell-runner",
					source: "/home/username/.cursor/mcp.json",
					transport: "remote",
					endpoint: "https://mcp.internal.example",
					risk_hints: ["remote_mcp_url", "shell_wrapper_command"],
					aig_categories: [],
					secret_findings: [],
					configuration_sha256: "b".repeat(64),
					attestation: { status: "unverifiable", keyring: "absent", approval_state: "unavailable" },
				},
			],
		} as Awaited<ReturnType<typeof discoverMcpServers>>);
		vi.spyOn(console, "log").mockImplementation(() => {});
		const upload = vi.fn<NonNullable<DiscoverDependencies["upload"]>>(async (events) => ({
			ok: true as const,
			delivered: events.length,
			total: events.length,
		}));

		await runDiscover({ upload: true }, { upload });

		const events = upload.mock.calls[0]?.[0] ?? [];
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			type: "mcp_inventory_finding",
			mcp_server_name: "shell-runner",
			mcp_transport: "remote",
			finding_severity: "critical",
			attestation_status: "unverifiable",
		});
		expect(events[0]?.risk_categories).toEqual(
			expect.arrayContaining(["remote_mcp_url", "shell_wrapper_command"]),
		);
		const serialized = JSON.stringify(events);
		expect(serialized).not.toContain("/home/username");
		expect(serialized).not.toContain("mcp.internal.example");
		expect(process.exitCode).not.toBe(1);
	});

	it("exits unsuccessfully when the inventory upload is refused", async () => {
		vi.mocked(discoverMcpServers).mockResolvedValue({
			schema_version: 1,
			scanned_at: "2026-09-24T00:00:00.000Z",
			scope: "Local configuration discovery",
			sources: [],
			coverage: {
				status: "read",
				total_sources: 0,
				read_sources: 0,
				missing_sources: 0,
				invalid_sources: 0,
				servers_not_enumerated: 0,
				sources_not_enumerated: 0,
			},
			servers: [],
		});
		vi.spyOn(console, "log").mockImplementation(() => {});
		const error = vi.spyOn(console, "error").mockImplementation(() => {});

		await runDiscover(
			{ upload: true },
			{
				upload: async () => ({
					ok: false,
					error: "control_plane_not_configured",
					delivered: 0,
					total: 0,
					queued: false,
				}),
			},
		);

		expect(String(error.mock.calls.at(-1)?.[0])).toContain("no control_plane.endpoint");
		expect(process.exitCode).toBe(1);
	});
	it("adds agent environment findings with --agents and uploads host, check id and count only", async () => {
		vi.mocked(discoverMcpServers).mockResolvedValue({
			schema_version: 1,
			scanned_at: "2026-09-25T00:00:00.000Z",
			scope: "Local configuration discovery",
			sources: [],
			coverage: {
				status: "read",
				total_sources: 0,
				read_sources: 0,
				missing_sources: 0,
				invalid_sources: 0,
				servers_not_enumerated: 0,
				sources_not_enumerated: 0,
			},
			servers: [],
		});
		const log = vi.spyOn(console, "log").mockImplementation(() => {});
		const upload = vi.fn<NonNullable<DiscoverDependencies["upload"]>>(async (events) => ({
			ok: true as const,
			delivered: events.length,
			total: events.length,
		}));

		await runDiscover(
			{ agents: true, upload: true },
			{
				upload,
				agentEnvironment: () => ({
					schema_version: 1,
					scanned_at: "2026-09-25T00:00:00.000Z",
					hosts: [
						{ host: "codex", detected: true, connector: true, evidence: ["/home/username/.codex"] },
					],
					findings: [
						{
							id: "cloud_credentials_in_env",
							severity: "medium",
							host: "environment",
							title: "Cloud credentials are exported",
							remediation: "Do not export them.",
							evidence: { names: ["AWS_SECRET_ACCESS_KEY"] },
							count: 1,
						},
					],
					unreadable: [],
					scope: "test",
				}),
			},
		);

		const printed = log.mock.calls.map((call) => String(call[0])).join("\n");
		expect(printed).toContain(
			"MEDIUM environment: Cloud credentials are exported [AWS_SECRET_ACCESS_KEY]",
		);
		const events = upload.mock.calls[0]?.[0] ?? [];
		expect(events).toHaveLength(1);
		expect(events[0]).toMatchObject({
			type: "agent_posture_finding",
			agent_host: "environment",
			check_id: "cloud_credentials_in_env",
			finding_count: 1,
		});
		expect(JSON.stringify(events)).not.toContain("AWS_SECRET_ACCESS_KEY");
		expect(process.exitCode).not.toBe(1);
	});

	it("prints AIG category ids and secret locations without secret values", async () => {
		vi.mocked(discoverMcpServers).mockResolvedValue({
			schema_version: 1,
			scanned_at: "2026-10-07T00:00:00.000Z",
			scope: "Local configuration discovery",
			sources: [{ path: "mcp.json", status: "read" }],
			coverage: {
				status: "read",
				total_sources: 1,
				read_sources: 1,
				missing_sources: 0,
				invalid_sources: 0,
				servers_not_enumerated: 0,
				sources_not_enumerated: 0,
			},
			servers: [
				{
					inventory_id: "a".repeat(64),
					name: "github",
					source: "mcp.json",
					transport: "stdio",
					endpoint: null,
					risk_hints: [],
					aig_categories: [
						{
							id: "mcp-01",
							name: "Token Mismanagement & Secret Exposure",
							risk: "critical",
							aidr_policy_action: "deny",
							basis: "evidence",
							evidence: ["hardcoded_secret:env:GITHUB_TOKEN:github_token"],
						},
					],
					secret_findings: [{ location: "env", key: "GITHUB_TOKEN", kind: "github_token" }],
					configuration_sha256: "b".repeat(64),
					attestation: {
						status: "unverifiable",
						keyring: "absent",
						approval_state: "unavailable",
						reason: "no_keyring",
					},
				},
			],
		});
		const log = vi.spyOn(console, "log").mockImplementation(() => {});

		await discoverCommand({});

		const text = log.mock.calls.map((call) => String(call[0])).join("\n");
		expect(text).toContain("AIG categories: mcp-01 Token Mismanagement & Secret Exposure (critical, evidence)");
		expect(text).toContain("Hardcoded secret: env GITHUB_TOKEN (github_token)");
		expect(process.exitCode).toBe(initialExitCode);
	});
});
