// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn() } }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import {
	aiBomFileName,
	buildTenantAiBom,
	type FleetAgentRow,
	MCP_RISK_CATEGORY_IDS,
	type TenantAiBom,
} from "../lib/aibom";
import { supabase } from "../lib/supabase";
import { latestFindings, type PostureFindingRow, PosturePage } from "../ui/pages/PosturePage";

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const SERIAL = "urn:uuid:5b1f5a8e-2a8e-4c35-9f0a-6f3f5d1c9e21";
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const DIGEST_C = `sha256:${"c".repeat(64)}`;

function row(overrides: Partial<PostureFindingRow>): PostureFindingRow {
	return {
		id: 1,
		source: "infra_scan",
		finding_kind: "cve",
		severity: "critical",
		cvss: null,
		vuln_id: null,
		component: null,
		component_version: null,
		applicability: null,
		target_digest: null,
		mcp_server_name: null,
		mcp_transport: null,
		risk_categories: [],
		attestation_status: null,
		subject_digest: null,
		plugin_key: null,
		rule_id: null,
		skill_risk_type: null,
		observed_at: "2026-09-24T10:00:00.000Z",
		...overrides,
	};
}

const FINDINGS: PostureFindingRow[] = [
	row({
		id: 1,
		vuln_id: "CVE-2024-37032",
		component: "ollama",
		component_version: "0.1.30",
		cvss: "9.1",
		applicability: "confirmed",
		target_digest: DIGEST_A,
	}),
	row({
		id: 2,
		vuln_id: "CVE-2024-37032",
		component: "ollama",
		component_version: "0.1.30",
		cvss: "9.1",
		applicability: "confirmed",
		target_digest: DIGEST_B,
	}),
	row({
		id: 3,
		finding_kind: "exposed_component",
		severity: "info",
		component: "comfyui",
		target_digest: DIGEST_C,
	}),
	row({
		id: 4,
		source: "mcp_inventory",
		finding_kind: "mcp_server",
		mcp_server_name: "shell-runner",
		mcp_transport: "remote",
		risk_categories: ["remote_mcp_url", "shell_wrapper_command", "mcp-05"],
		attestation_status: "unverifiable",
		subject_digest: DIGEST_A,
	}),
	row({
		id: 5,
		source: "skill_scan",
		finding_kind: "skill_rule",
		plugin_key: "acme-skill",
		rule_id: "SKILL-T03-001",
		skill_risk_type: "T03",
		subject_digest: DIGEST_B,
	}),
	row({
		id: 6,
		source: "skill_scan",
		finding_kind: "skill_rule",
		severity: "high",
		plugin_key: "other-skill",
		rule_id: "SKILL-T03-001",
		skill_risk_type: "T03",
		subject_digest: DIGEST_C,
	}),
];

const AGENTS: FleetAgentRow[] = [
	{
		agent_runtime: "claude-code",
		agent_runtime_version: "0.6.0",
		last_seen: "2026-09-24T09:00:00.000Z",
	},
	{
		agent_runtime: "claude-code",
		agent_runtime_version: "0.6.0",
		last_seen: "2026-09-24T11:00:00.000Z",
	},
	{ agent_runtime: "cursor", agent_runtime_version: null, last_seen: "2026-09-23T11:00:00.000Z" },
];

function build(findings = FINDINGS, agents = AGENTS): TenantAiBom {
	return buildTenantAiBom({
		tenant: { id: TENANT_ID, name: "Example tenant" },
		agents,
		findings,
		runtimeLabels: new Map([
			["claude-code", "Claude Code"],
			["cursor", "Cursor"],
		]),
		postureWindowDays: 90,
		postureTruncated: false,
		generatedAt: "2026-09-25T10:00:00.000Z",
		serialNumber: SERIAL,
	});
}

function property(
	item: { properties: Array<{ name: string; value: string }> } | undefined,
	name: string,
) {
	return item?.properties.find((p) => p.name === name)?.value;
}

describe("tenant AI-BOM builder", () => {
	it("maps fleet runtimes, MCP servers, infrastructure and skills to CycloneDX 1.6", () => {
		const bom = build();
		expect(bom).toMatchObject({
			bomFormat: "CycloneDX",
			specVersion: "1.6",
			serialNumber: SERIAL,
			version: 1,
			metadata: {
				timestamp: "2026-09-25T10:00:00.000Z",
				component: { type: "application", "bom-ref": "tenant", name: "Example tenant" },
			},
		});
		expect(property(bom.metadata, "aidr:fleet:agent_count")).toBe("3");

		const claude = bom.components.find((c) => c["bom-ref"] === "agent:claude-code@0.6.0");
		expect(claude).toMatchObject({ type: "application", name: "Claude Code", version: "0.6.0" });
		expect(property(claude, "aidr:fleet:device_count")).toBe("2");
		expect(property(claude, "aidr:fleet:last_seen")).toBe("2026-09-24T11:00:00.000Z");
		expect(
			bom.components.find((c) => c["bom-ref"] === "agent:cursor@unknown")?.version,
		).toBeUndefined();

		const ollama = bom.components.find((c) => c.name === "ollama");
		expect(ollama).toMatchObject({ type: "application", version: "0.1.30" });
		expect(property(ollama, "aidr:infra:target_count")).toBe("2");
		expect(bom.components.find((c) => c.name === "comfyui")?.type).toBe("application");
		expect(bom.components.find((c) => c.name === "acme-skill")?.type).toBe("library");

		const [mcp] = bom.services;
		expect(mcp).toMatchObject({ name: "shell-runner", "x-trust-boundary": true });
		const flags = mcp?.properties.filter((p) => p.name.startsWith("aidr:mcp:risk:")) ?? [];
		expect(flags.map((p) => p.name)).toEqual(
			MCP_RISK_CATEGORY_IDS.map((id) => `aidr:mcp:risk:${id}`),
		);
		expect(flags.filter((p) => p.value === "true").map((p) => p.name)).toEqual([
			"aidr:mcp:risk:mcp-05",
		]);
		expect(
			mcp?.properties.filter((p) => p.name === "aidr:mcp:risk_hint").map((p) => p.value),
		).toEqual(["remote_mcp_url", "shell_wrapper_command"]);

		// One CVE on two scanned targets is one vulnerability record.
		const cve = bom.vulnerabilities.find((v) => v.id === "CVE-2024-37032");
		expect(cve).toMatchObject({
			ratings: [{ score: 9.1, severity: "critical" }],
			affects: [
				{
					ref: "infra-component:ollama@0.1.30",
					versions: [{ version: "0.1.30", status: "affected" }],
				},
			],
		});
		const rule = bom.vulnerabilities.find((v) => v.id === "SKILL-T03-001");
		expect(rule?.affects.map((a) => a.ref)).toEqual(["plugin:acme-skill", "plugin:other-skill"]);
		expect(bom.vulnerabilities).toHaveLength(2);
	});

	it("keeps references resolvable and output deterministic", () => {
		const bom = build();
		const refs = [
			bom.metadata.component["bom-ref"],
			...bom.metadata.tools.components.map((c) => c["bom-ref"]),
			...bom.components.map((c) => c["bom-ref"]),
			...bom.services.map((s) => s["bom-ref"]),
			...bom.vulnerabilities.map((v) => v["bom-ref"]),
		];
		expect(new Set(refs).size).toBe(refs.length);
		const known = new Set(refs);
		for (const dependency of bom.dependencies)
			for (const ref of [dependency.ref, ...dependency.dependsOn])
				expect(known.has(ref)).toBe(true);
		for (const vulnerability of bom.vulnerabilities)
			for (const affected of vulnerability.affects) expect(known.has(affected.ref)).toBe(true);

		const shuffled = JSON.stringify(build([...FINDINGS].reverse(), [...AGENTS].reverse()));
		expect(shuffled).toBe(JSON.stringify(bom));
		expect(JSON.stringify(bom)).not.toMatch(/infra[- ]?guard|tencent|\baig\b/i);
	});

	it("names the export file after the tenant and date", () => {
		expect(aiBomFileName("Example Tenant (EU)", "2026-09-25T10:00:00.000Z")).toBe(
			"aibom-example-tenant-eu-2026-09-25.cdx.json",
		);
		expect(aiBomFileName("", "2026-09-25T10:00:00.000Z")).toBe("aibom-tenant-2026-09-25.cdx.json");
	});
});

type Result = { data: unknown; error: { message: string } | null; count?: number | null };

/** jsdom's Blob has no `text()`; FileReader is available. */
function readBlob(blob: Blob): Promise<string> {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = () => resolve(String(reader.result));
		reader.onerror = () => reject(reader.error);
		reader.readAsText(blob);
	});
}

/** A query chain that answers successive awaits with successive results (pages). */
function chainFor(...results: Result[]) {
	const chain: Record<string, unknown> = {};
	for (const method of ["select", "eq", "gte", "order", "limit", "range"]) {
		chain[method] = vi.fn(() => chain);
	}
	let call = 0;
	chain.then = (resolve: (value: unknown) => unknown, reject?: (reason: unknown) => unknown) =>
		Promise.resolve(results[Math.min(call++, results.length - 1)]).then(resolve, reject);
	return chain;
}

function mockTables(posture: Result, ...agentPages: Result[]) {
	const chains = { posture_findings: chainFor(posture), agents: chainFor(...agentPages) };
	vi.mocked(supabase.from).mockImplementation(
		(table: string) => chains[table as keyof typeof chains] as never,
	);
	return chains;
}

describe("Posture page AI-BOM export", () => {
	let blobs: Blob[];

	beforeEach(() => {
		blobs = [];
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: TENANT_ID, name: "Example tenant" },
			isLoading: false,
		} as never);
		vi.mocked(supabase.from).mockReset();
		Object.defineProperty(URL, "createObjectURL", {
			configurable: true,
			value: vi.fn((blob: Blob) => {
				blobs.push(blob);
				return `blob:aibom-${blobs.length}`;
			}),
		});
		Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("exports the tenant's reported AI estate as a CycloneDX file", async () => {
		const chains = mockTables(
			{ data: FINDINGS, error: null },
			{
				data: AGENTS.map((agent, index) => ({ id: `agent-${index}`, ...agent })),
				error: null,
				count: AGENTS.length,
			},
		);
		render(
			<MemoryRouter>
				<PosturePage />
			</MemoryRouter>,
		);
		await screen.findByRole("region", { name: "Infrastructure exposure" });
		fireEvent.click(screen.getByRole("button", { name: "Export AI-BOM" }));

		const status = await screen.findByText(/AI-BOM ready/);
		expect(status).toHaveTextContent("vulnerability record(s)");
		const link = screen.getByRole("link", { name: /Save aibom-example-tenant-/ });
		expect(link).toHaveAttribute("href", "blob:aibom-1");
		expect(link.getAttribute("download")).toMatch(
			/^aibom-example-tenant-\d{4}-\d{2}-\d{2}\.cdx\.json$/,
		);

		expect(chains.agents.eq).toHaveBeenCalledWith("tenant_id", TENANT_ID);
		expect(chains.agents.range).toHaveBeenCalledWith(0, 999);
		expect(blobs[0]?.type).toBe("application/vnd.cyclonedx+json");
		const bom = JSON.parse(await readBlob(blobs[0] as Blob)) as TenantAiBom;
		expect(bom.bomFormat).toBe("CycloneDX");
		expect(bom.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
		// The page exports the latest observation of each finding.
		expect(bom).toEqual({
			...build(latestFindings(FINDINGS)),
			serialNumber: bom.serialNumber,
			metadata: { ...build(latestFindings(FINDINGS)).metadata, timestamp: bom.metadata.timestamp },
		});
	});

	it("pages the fleet until the exact count when the server caps a page", async () => {
		const rows = AGENTS.map((agent, index) => ({ id: `agent-${index}`, ...agent }));
		const chains = mockTables(
			{ data: FINDINGS, error: null },
			{ data: rows.slice(0, 2), error: null, count: 3 },
			{ data: rows.slice(2), error: null, count: 3 },
		);
		render(
			<MemoryRouter>
				<PosturePage />
			</MemoryRouter>,
		);
		await screen.findByRole("region", { name: "Infrastructure exposure" });
		fireEvent.click(screen.getByRole("button", { name: "Export AI-BOM" }));
		await screen.findByText(/AI-BOM ready/);
		expect(chains.agents.range).toHaveBeenNthCalledWith(1, 0, 999);
		expect(chains.agents.range).toHaveBeenNthCalledWith(2, 2, 1001);
		const bom = JSON.parse(await readBlob(blobs[0] as Blob)) as TenantAiBom;
		expect(bom.metadata.properties).toContainEqual({ name: "aidr:fleet:agent_count", value: "3" });
	});

	it("produces no file when the fleet count cannot be established", async () => {
		mockTables({ data: FINDINGS, error: null }, { data: [], error: null, count: null });
		render(
			<MemoryRouter>
				<PosturePage />
			</MemoryRouter>,
		);
		await screen.findByRole("region", { name: "Infrastructure exposure" });
		fireEvent.click(screen.getByRole("button", { name: "Export AI-BOM" }));
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("No file was produced"),
		);
		expect(URL.createObjectURL).not.toHaveBeenCalled();
	});

	it("produces no file when the fleet inventory cannot be read", async () => {
		mockTables(
			{ data: FINDINGS, error: null },
			{ data: null, error: { message: "permission denied" } },
		);
		render(
			<MemoryRouter>
				<PosturePage />
			</MemoryRouter>,
		);
		await screen.findByRole("region", { name: "Infrastructure exposure" });
		fireEvent.click(screen.getByRole("button", { name: "Export AI-BOM" }));
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("No file was produced"),
		);
		expect(URL.createObjectURL).not.toHaveBeenCalled();
		expect(screen.queryByText(/AI-BOM ready/)).not.toBeInTheDocument();
	});

	it("cannot export while posture data is unavailable", async () => {
		mockTables({ data: null, error: { message: "permission denied" } }, { data: [], error: null });
		render(
			<MemoryRouter>
				<PosturePage />
			</MemoryRouter>,
		);
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("this is not a clean result"),
		);
		expect(screen.getByRole("button", { name: "Export AI-BOM" })).toBeDisabled();
	});
});
