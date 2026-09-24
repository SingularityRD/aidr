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
});
