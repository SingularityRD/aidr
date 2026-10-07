// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: vi.fn() } } }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { DiscoveryPage } from "../ui/pages/DiscoveryPage";

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const SUMMARY = {
	collector_count: 1,
	partial_collector_count: 0,
	stale_collector_count: 1,
	observation_count: 1,
	unreachable_count: 0,
	never_seen_count: 0,
	stale_observation_count: 1,
	not_reported_count: 0,
	coverage_scope: "reported_collectors_only",
	reported_scope_state: "attention",
};
const COLLECTOR = {
	collector_id: "site-1",
	sequence: 4,
	stale_after_ms: 900_000,
	complete: true,
	expected_targets: 1,
	observed_targets: 1,
	reported_at: "2026-09-22T10:00:00.000Z",
	state: "stale",
};
const PARTIAL_COLLECTOR = {
	...COLLECTOR,
	collector_id: "site-2",
	sequence: 2,
	complete: false,
	expected_targets: 2,
	observed_targets: 1,
	state: "partial",
};
const ITEM = {
	target: "https://agent.example.test/",
	last_reported_at: "2026-09-22T10:00:00.000Z",
	last_reachable_at: "2026-09-22T10:00:00.000Z",
	reachable: true,
	attempts: 1,
	error_code: null,
	freshness: "stale",
	alert_state: "stale",
};

function response(data: unknown) {
	return { data, error: null } as never;
}

function renderPage() {
	return render(
		<MemoryRouter>
			<DiscoveryPage />
		</MemoryRouter>,
	);
}

describe("tenant discovery dashboard", () => {
	it("does not report an empty provider inventory while its request is pending", async () => {
		let finish: (() => void) | undefined;
		const pending = new Promise<never>((resolve) => {
			finish = () =>
				resolve(
					response({
						ok: true,
						collector: { collector_id: COLLECTOR.collector_id },
						provider_resources: [],
						truncated: false,
						next_resource: null,
					}),
				);
		});
		vi.mocked(supabase.functions.invoke).mockImplementation(async (_name, options) => {
			const action = (options?.body as Record<string, unknown>).action;
			if (action === "summary") return response({ ok: true, summary: SUMMARY });
			if (action === "list")
				return response({
					ok: true,
					coverage_scope: "reported_collectors_only",
					truncated: false,
					next_collector: null,
					collectors: [
						{
							...COLLECTOR,
							expected_targets: 0,
							observed_targets: 0,
							provider_evidence: {
								provider: "aws",
								scope_hash: "a".repeat(64),
								coverage: "tagged_resources",
								complete: true,
								observed_at: COLLECTOR.reported_at,
							},
						},
					],
				});
			if (action === "resources") return pending;
			return response({
				ok: true,
				collector: { collector_id: COLLECTOR.collector_id },
				items: [],
				truncated: false,
				next_target: null,
			});
		});
		renderPage();
		expect(await screen.findByText("Loading provider resources…")).toBeInTheDocument();
		expect(
			screen.queryByText("No resources reported within the configured scope."),
		).not.toBeInTheDocument();
		finish?.();
		expect(
			await screen.findByText("No resources reported within the configured scope."),
		).toBeInTheDocument();
	});
	it("renders typed provider resources separately and keeps failed collection partial", async () => {
		const provider = {
			provider: "aws",
			scope_hash: "a".repeat(64),
			coverage: "tagged_resources",
			complete: false,
			observed_at: COLLECTOR.reported_at,
		};
		vi.mocked(supabase.functions.invoke).mockImplementation(async (_name, options) => {
			const action = (options?.body as Record<string, unknown>).action;
			if (action === "summary") return response({ ok: true, summary: SUMMARY });
			if (action === "list")
				return response({
					ok: true,
					coverage_scope: "reported_collectors_only",
					collectors: [
						{
							...COLLECTOR,
							expected_targets: 0,
							observed_targets: 0,
							complete: false,
							state: "partial",
							provider_evidence: provider,
						},
					],
					truncated: false,
					next_collector: null,
				});
			if (action === "resources")
				return response({
					ok: true,
					collector: { collector_id: COLLECTOR.collector_id },
					provider_resources: [
						{
							provider: "aws",
							scope_hash: provider.scope_hash,
							resource_id: "arn:aws:s3:::approved-bucket",
							resource_type: "s3:bucket",
							scope_id: "aws:123456789012:eu-central-1",
							region: "eu-central-1",
							observed_at: COLLECTOR.reported_at,
							freshness: "stale",
							alert_state: "collection_partial",
						},
					],
					truncated: false,
					next_resource: null,
				});
			return response({
				ok: true,
				collector: { collector_id: COLLECTOR.collector_id },
				items: [],
				truncated: false,
				next_target: null,
			});
		});
		renderPage();
		expect(await screen.findByText("arn:aws:s3:::approved-bucket")).toBeInTheDocument();
		expect(screen.getByText("collection_partial")).toBeInTheDocument();
		expect(screen.queryByText("healthy")).not.toBeInTheDocument();
		expect(screen.getByText(/Only the configured scope is reported/)).toBeInTheDocument();
		expect(vi.mocked(supabase.functions.invoke)).toHaveBeenCalledWith("discovery", {
			body: {
				action: "resources",
				collector_id: COLLECTOR.collector_id,
				expected_sequence: COLLECTOR.sequence,
				limit: 100,
				tenant_id: TENANT_ID,
			},
		});
	});
	beforeEach(() => {
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: TENANT_ID, name: "Example tenant" },
		} as never);
		vi.mocked(supabase.functions.invoke).mockReset();
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("states reported-only scope and never turns no reports into an empty-estate claim", async () => {
		vi.mocked(supabase.functions.invoke)
			.mockResolvedValueOnce(
				response({
					ok: true,
					summary: {
						...SUMMARY,
						collector_count: 0,
						observation_count: 0,
						stale_collector_count: 0,
						stale_observation_count: 0,
						reported_scope_state: "unknown",
					},
				}),
			)
			.mockResolvedValueOnce(
				response({
					ok: true,
					coverage_scope: "reported_collectors_only",
					collectors: [],
					truncated: false,
					next_collector: null,
				}),
			);
		renderPage();

		expect(
			await screen.findByText(
				"No collector reports have been received. This does not mean the tenant has no infrastructure.",
			),
		).toBeInTheDocument();
		expect(screen.getByText("scope: reported_collectors_only")).toBeInTheDocument();
		expect(screen.getByText("unknown")).toBeInTheDocument();
		const calls = vi.mocked(supabase.functions.invoke).mock.calls as unknown as Array<
			[string, { body?: unknown }?]
		>;
		expect(calls.map(([, options]) => options?.body)).toEqual([
			{ action: "summary", tenant_id: TENANT_ID },
			{ action: "list", limit: 50, tenant_id: TENANT_ID },
		]);
	});

	it("shows the server's stale and partial coverage states for the selected collector", async () => {
		vi.mocked(supabase.functions.invoke)
			.mockResolvedValueOnce(response({ ok: true, summary: SUMMARY }))
			.mockResolvedValueOnce(
				response({
					ok: true,
					coverage_scope: "reported_collectors_only",
					collectors: [COLLECTOR, PARTIAL_COLLECTOR],
					truncated: false,
					next_collector: null,
				}),
			)
			.mockResolvedValueOnce(
				response({
					ok: true,
					collector: { collector_id: "site-1" },
					items: [ITEM],
					truncated: false,
					next_target: null,
				}),
			);
		renderPage();

		const collectorButton = await screen.findByRole("button", { name: "site-1" });
		expect(
			within(collectorButton.closest("tr") as HTMLElement).getByText("stale"),
		).toBeInTheDocument();
		const partialCollector = screen.getByRole("button", { name: "site-2" });
		expect(
			within(partialCollector.closest("tr") as HTMLElement).getByText("partial"),
		).toBeInTheDocument();
		const row = await screen.findByRole("row", { name: /agent\.example\.test/ });
		expect(within(row).getAllByText("stale")).toHaveLength(2);
		expect(within(row).getByText("reachable")).toBeInTheDocument();
		expect(within(row).getByText("legacy origin")).toBeInTheDocument();
		expect(screen.getByText("scope: reported_collectors_only")).toBeInTheDocument();
		const calls = vi.mocked(supabase.functions.invoke).mock.calls as unknown as Array<
			[string, { body?: unknown }?]
		>;
		expect(calls[2]?.[1]?.body).toEqual({
			action: "read",
			collector_id: "site-1",
			limit: 100,
			tenant_id: TENANT_ID,
		});
	});

	it("clears target health and reports malformed responses instead of rendering green", async () => {
		vi.mocked(supabase.functions.invoke)
			.mockResolvedValueOnce(response({ ok: true, summary: SUMMARY }))
			.mockResolvedValueOnce(
				response({
					ok: true,
					coverage_scope: "reported_collectors_only",
					collectors: [COLLECTOR],
					truncated: false,
					next_collector: null,
				}),
			)
			.mockResolvedValueOnce(
				response({
					ok: true,
					collector: { collector_id: "site-1" },
					items: [{ ...ITEM, freshness: "fresh", alert_state: "green" }],
					truncated: false,
					next_target: null,
				}),
			);
		renderPage();

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("Malformed discovery target list."),
		);
		expect(screen.queryByText("healthy")).not.toBeInTheDocument();
		expect(screen.getByText("Target details are unavailable.")).toBeInTheDocument();
	});

	it("refreshes the tenant-scoped summary through the authenticated Edge function", async () => {
		vi.mocked(supabase.functions.invoke)
			.mockResolvedValueOnce(response({ ok: true, summary: SUMMARY }))
			.mockResolvedValueOnce(
				response({
					ok: true,
					coverage_scope: "reported_collectors_only",
					collectors: [],
					truncated: false,
					next_collector: null,
				}),
			)
			.mockResolvedValueOnce(response({ ok: true, summary: SUMMARY }))
			.mockResolvedValueOnce(
				response({
					ok: true,
					coverage_scope: "reported_collectors_only",
					collectors: [],
					truncated: false,
					next_collector: null,
				}),
			);
		renderPage();
		await screen.findByText("scope: reported_collectors_only");
		fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
		await waitFor(() => expect(supabase.functions.invoke).toHaveBeenCalledTimes(4));
		expect(vi.mocked(supabase.functions.invoke).mock.calls[2]?.[1]?.body).toEqual({
			action: "summary",
			tenant_id: TENANT_ID,
		});
	});

	it("loads the next collector and target pages, then switches collector details", async () => {
		// New collectors report keyed pseudonyms; legacy origin rows stay readable.
		const secondItem = { ...ITEM, target: `tid1_${"c".repeat(64)}` };
		vi.mocked(supabase.functions.invoke).mockImplementation(async (_name, options) => {
			const body = options?.body as Record<string, unknown>;
			if (body.action === "summary") return response({ ok: true, summary: SUMMARY });
			if (body.action === "list")
				return response({
					ok: true,
					coverage_scope: "reported_collectors_only",
					collectors: body.after_collector ? [PARTIAL_COLLECTOR] : [COLLECTOR],
					truncated: !body.after_collector,
					next_collector: body.after_collector ? null : COLLECTOR.collector_id,
				});
			return response({
				ok: true,
				collector: { collector_id: body.collector_id },
				items: body.after_target ? [secondItem] : [ITEM],
				truncated: body.collector_id === COLLECTOR.collector_id && !body.after_target,
				next_target:
					body.collector_id === COLLECTOR.collector_id && !body.after_target ? ITEM.target : null,
			});
		});
		renderPage();

		fireEvent.click(await screen.findByRole("button", { name: "Load more collectors" }));
		fireEvent.click(await screen.findByRole("button", { name: "Load more targets" }));
		const pseudonymRow = await screen.findByRole("row", { name: /tid1_c{64}/ });
		expect(within(pseudonymRow).queryByText("legacy origin")).not.toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "site-2" }));
		await waitFor(() =>
			expect(vi.mocked(supabase.functions.invoke)).toHaveBeenCalledWith("discovery", {
				body: { action: "read", collector_id: "site-2", limit: 100, tenant_id: TENANT_ID },
			}),
		);
	});
});
