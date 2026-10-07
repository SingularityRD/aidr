import { afterEach, describe, expect, it, vi } from "vitest";
import { discoverMcpServers } from "@singularityrd/aidr-core";
import discoverCommand from "../commands/discover.js";

vi.mock("@singularityrd/aidr-core", () => ({ discoverMcpServers: vi.fn() }));

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
