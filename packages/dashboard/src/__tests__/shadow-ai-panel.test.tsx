// @vitest-environment jsdom

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			getSession: vi.fn(),
			getUser: vi.fn(),
			signOut: vi.fn(),
			signInWithOAuth: vi.fn(),
			signInWithOtp: vi.fn(),
			exchangeCodeForSession: vi.fn(),
			onAuthStateChange: vi.fn(),
		},
		functions: { invoke: vi.fn() },
		from: vi.fn(),
		rpc: vi.fn(),
	},
	supabaseEnvError: null,
	supabaseProjectUrl: "https://tenant-project.supabase.co",
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import { PrivacyGuardPage } from "../ui/pages/PrivacyGuardPage";
import {
	parseShadowAiSummary,
	SHADOW_AI_SERVICES,
	serviceName,
	shadowAiEventSummary,
} from "../ui/shadow-ai";
import { installDashboardMocks, mockedSupabase, TEAM_ID } from "./helpers/dashboard-mocks";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

function shadowSummary(days: 7 | 30, overrides: Record<string, unknown> = {}) {
	const start = Date.parse("2026-09-24T00:00:00Z") - (days - 1) * 86_400_000;
	return {
		window_days: days,
		since: new Date(start).toISOString(),
		totals: {
			visits: 60,
			blocked_attempts: 7,
			sanctioned_visits: 45,
			unsanctioned_visits: 15,
			services: 3,
		},
		by_service: [
			{ service_id: "chatgpt", category: "chat", visits: 45, blocked: 0, sanctioned: true },
			{ service_id: "midjourney", category: "image", visits: 15, blocked: 0, sanctioned: false },
			{ service_id: "poe", category: "chat", visits: 0, blocked: 7, sanctioned: false },
		],
		by_category: [
			{ category: "chat", visits: 45, blocked: 7 },
			{ category: "image", visits: 15, blocked: 0 },
		],
		series: Array.from({ length: days }, (_, index) => ({
			day: new Date(start + index * 86_400_000).toISOString().slice(0, 10),
			visits: index === days - 1 ? 2 : 0,
			unsanctioned_visits: index === days - 1 ? 1 : 0,
			blocked: index === days - 1 ? 1 : 0,
		})),
		...overrides,
	};
}

function install(shadow: { data: unknown; error: { message: string; code?: string } | null }) {
	const mocks = installDashboardMocks({
		rpcResults: {
			privacy_guard_summary: { data: null, error: { code: "PGRST202", message: "missing" } },
			shadow_ai_summary: shadow as never,
		},
		tableResults: { events: { data: [], error: null }, agents: { data: [], error: null } },
	});
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: TEAM_ID, name: "Runtime team" },
		isLoading: false,
	} as never);
	return mocks;
}

function renderPage() {
	return render(
		<MemoryRouter>
			<PrivacyGuardPage />
		</MemoryRouter>,
	);
}

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe("Shadow AI panel", () => {
	it("shows visits, sanctioned vs unsanctioned, blocked attempts, top services and the trend", async () => {
		install({ data: shadowSummary(30), error: null });
		renderPage();
		const counters = await screen.findByRole("group", { name: "Shadow AI counters" });
		await waitFor(() => expect(within(counters).getByText("60")).toBeInTheDocument());
		expect(within(counters).getByText("15")).toBeInTheDocument();
		expect(within(counters).getByText("7")).toBeInTheDocument();
		expect(within(counters).getByText("75% of visits sanctioned")).toBeInTheDocument();
		expect(within(counters).getByText("3 service(s) · 30 days")).toBeInTheDocument();
		expect(mockedSupabase().rpc).toHaveBeenCalledWith("shadow_ai_summary", {
			p_tenant_id: TEAM_ID,
			p_days: 30,
		});

		const table = screen.getByRole("table", { name: "Top AI services" });
		const rows = within(table)
			.getAllByRole("row")
			.slice(1)
			.map((row) =>
				within(row)
					.getAllByRole("cell")
					.slice(0, 5)
					.map((cell) => cell.textContent),
			);
		expect(rows).toEqual([
			["ChatGPT", "Chat assistant", "sanctioned", "45", "0"],
			["Midjourney", "Image, video & voice", "unsanctioned", "15", "0"],
			["Poe", "Chat assistant", "unsanctioned", "0", "7"],
		]);
		const trend = screen.getByRole("img", {
			name: "60 AI service visits and 7 blocked attempts over 30 days",
		});
		expect(trend.children).toHaveLength(30);

		const policy = JSON.parse(screen.getByLabelText("Shadow AI policy JSON").textContent ?? "");
		expect(policy.shadowAi).toEqual({ mode: "monitor", sanctioned: ["chatgpt"], blocked: [] });
		expect(policy.customSites[0]).toMatchObject({ id: "internal-ai" });
		fireEvent.change(screen.getByLabelText("Shadow AI mode"), {
			target: { value: "block-unsanctioned" },
		});
		expect(
			JSON.parse(screen.getByLabelText("Shadow AI policy JSON").textContent ?? "").shadowAi.mode,
		).toBe("block-unsanctioned");
	});

	it("shows the panel as unavailable (not zeros) when the RPC is missing or malformed", async () => {
		install({
			data: null,
			error: { code: "PGRST202", message: "Could not find shadow_ai_summary" },
		});
		renderPage();
		const counters = await screen.findByRole("group", { name: "Shadow AI counters" });
		await screen.findByText("Shadow AI summary is unavailable.");
		expect(within(counters).getAllByText("—").length).toBeGreaterThanOrEqual(3);
		expect(within(counters).queryByText("0")).not.toBeInTheDocument();
		expect(screen.queryByText(/schema cache|Could not find/)).not.toBeInTheDocument();
		cleanup();

		install({ data: shadowSummary(30, { series: [] }), error: null });
		renderPage();
		expect(await screen.findByText("Malformed Shadow AI summary.")).toBeInTheDocument();
	});

	it("explains how to turn reporting on when there is no activity", async () => {
		install({
			data: shadowSummary(30, {
				totals: {
					visits: 0,
					blocked_attempts: 0,
					sanctioned_visits: 0,
					unsanctioned_visits: 0,
					services: 0,
				},
				by_service: [],
				by_category: [],
			}),
			error: null,
		});
		renderPage();
		expect(await screen.findByText(/No Shadow AI activity in this window/)).toBeInTheDocument();
	});
});

const POE_ASSET = "66666666-6666-4666-8666-666666666666";

function installDecisions(options: {
	role: "owner" | "admin" | "member" | "viewer";
	assets?: { data: unknown; error: { message: string } | null };
	reply?: { data: unknown; error: unknown };
	settings?: { data: unknown; error: { message: string } | null };
}) {
	const mocks = installDashboardMocks({
		rpcResults: {
			privacy_guard_summary: { data: null, error: { code: "PGRST202", message: "missing" } },
			shadow_ai_summary: { data: shadowSummary(30), error: null },
		},
		tableResults: {
			events: { data: [], error: null },
			agents: { data: [], error: null },
			tenant_ai_governance_settings: options.settings ?? { data: null, error: null },
			ai_assets: options.assets ?? {
				data: [
					{ id: POE_ASSET, identifier: "poe", status: "approved", version: 3 },
					{
						id: "77777777-7777-4777-8777-777777777777",
						identifier: "chat.corp.example",
						status: "banned",
						version: 1,
					},
				],
				error: null,
			},
		},
	});
	const invoke = mockedSupabase().functions.invoke;
	const fallback = invoke.getMockImplementation() as
		| ((name: string, request?: unknown) => Promise<unknown>)
		| undefined;
	invoke.mockImplementation(async (name: string, request?: unknown) =>
		name === "ai-governance"
			? (options.reply ?? {
					data: { ok: true, asset_id: POE_ASSET, version: 4, status: "banned" },
					error: null,
				})
			: fallback?.(name, request),
	);
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: TEAM_ID, name: "Runtime team" },
		currentRole: options.role,
		isLoading: false,
	} as never);
	return mocks;
}

const governanceCalls = () =>
	mockedSupabase()
		.functions.invoke.mock.calls.filter(([name]) => name === "ai-governance")
		.map(([, request]) => (request as { body: unknown }).body);

describe("Shadow AI allow / block decisions", () => {
	it("reads decisions only for catalogued services, so >1000 register hostnames cannot hide one", async () => {
		// 1500 hostname entries sort ahead of the catalogued service. An unfiltered
		// read is capped at 1000 rows by the API and would miss Poe's decision; the
		// read must be filtered to catalog ids so that row is always returned.
		const hostnames = Array.from({ length: 1500 }, (_, index) => ({
			id: `77777777-7777-4777-8777-${index.toString(16).padStart(12, "0")}`,
			identifier: `host-${index}.corp.example`,
			status: "banned",
			version: 1,
		}));
		const poe = { id: POE_ASSET, identifier: "poe", status: "approved", version: 3 };
		installDecisions({ role: "admin" });
		const base = mockedSupabase().from.getMockImplementation() as (table: string) => unknown;
		mockedSupabase().from.mockImplementation((table: string) => {
			if (table !== "ai_assets") return base(table);
			const filters: unknown[][] = [];
			const chain: Record<string, unknown> = {};
			for (const method of ["select", "eq", "in", "order", "limit", "range"]) {
				chain[method] = vi.fn((...args: unknown[]) => {
					filters.push([method, ...args]);
					return chain;
				});
			}
			chain.then = (resolve: (value: unknown) => unknown) => {
				const ids = filters.find(
					([method, column]) => method === "in" && column === "identifier",
				)?.[2] as string[] | undefined;
				const rows = [...hostnames, poe].filter((row) => !ids || ids.includes(row.identifier));
				return Promise.resolve({ data: rows.slice(0, 1000), error: null }).then(resolve);
			};
			return chain;
		});
		renderPage();
		const table = await screen.findByRole("table", { name: "Top AI services" });
		const row = within(table).getByRole("row", { name: /Poe/ });
		await waitFor(() => expect(within(row).getByText("allowed")).toBeInTheDocument());
		const assetChain = mockedSupabase()
			.from.mock.results.filter(
				(_, index) => mockedSupabase().from.mock.calls[index]?.[0] === "ai_assets",
			)
			.map((result) => result.value as { in: ReturnType<typeof vi.fn> })[0];
		expect(assetChain?.in).toHaveBeenCalledWith("identifier", Object.keys(SHADOW_AI_SERVICES));
	});

	it("lets an administrator block a detected service through the audited governance register", async () => {
		installDecisions({ role: "admin" });
		renderPage();
		const table = await screen.findByRole("table", { name: "Top AI services" });
		const poe = within(table).getByRole("row", { name: /Poe/ });
		await waitFor(() => expect(within(poe).getByText("allowed")).toBeInTheDocument());
		expect(within(poe).getByRole("button", { name: "Allow Poe" })).toBeDisabled();

		fireEvent.click(within(poe).getByRole("button", { name: "Block Poe" }));
		await screen.findByText(
			/Poe blocked\. Enrolled browsers apply it at their next policy refresh/,
		);
		// An existing register entry is updated with optimistic concurrency.
		expect(governanceCalls()).toEqual([
			{
				action: "upsert_asset",
				tenant_id: TEAM_ID,
				asset_id: POE_ASSET,
				expected_version: 3,
				fields: { status: "banned" },
			},
		]);

		// A service with no register entry is created as an ai_site with its catalog id.
		const midjourney = within(table).getByRole("row", { name: /Midjourney/ });
		fireEvent.click(within(midjourney).getByRole("button", { name: "Allow Midjourney" }));
		await waitFor(() => expect(governanceCalls()).toHaveLength(2));
		expect(governanceCalls()[1]).toEqual({
			action: "upsert_asset",
			tenant_id: TEAM_ID,
			fields: {
				asset_type: "ai_site",
				identifier: "midjourney",
				name: "Midjourney",
				status: "approved",
			},
		});
		// The GPO/MDM snippet stays available as the alternative.
		expect(screen.getByLabelText("Shadow AI policy JSON")).toBeInTheDocument();
	});

	it("explains a refused decision (AAL2 step-up) and changes nothing", async () => {
		installDecisions({
			role: "owner",
			reply: {
				data: null,
				error: {
					context: new Response(JSON.stringify({ error: "mfa_required" }), { status: 403 }),
				},
			},
		});
		renderPage();
		const table = await screen.findByRole("table", { name: "Top AI services" });
		const chatgpt = within(table).getByRole("row", { name: /ChatGPT/ });
		await waitFor(() =>
			expect(within(chatgpt).getByRole("button", { name: "Block ChatGPT" })).toBeEnabled(),
		);
		fireEvent.click(within(chatgpt).getByRole("button", { name: "Block ChatGPT" }));
		const alert = await screen.findByText(/Multi-factor verification \(AAL2\) is required/);
		expect(alert).toHaveAttribute("role", "alert");
		expect(within(chatgpt).queryByText("blocked")).toBeNull();
		expect(within(alert).getByRole("link", { name: "Verify now" })).toHaveAttribute(
			"href",
			expect.stringContaining("/auth/dlp-step-up?tenant="),
		);
	});

	it("is read-only for members and viewers", async () => {
		for (const role of ["member", "viewer"] as const) {
			installDecisions({ role });
			renderPage();
			const table = await screen.findByRole("table", { name: "Top AI services" });
			await waitFor(() => expect(within(table).getByText("allowed")).toBeInTheDocument());
			expect(within(table).queryByRole("button", { name: /^(Allow|Block) / })).toBeNull();
			cleanup();
		}
	});

	it("disables decisions when the register cannot be read, never showing them as undecided", async () => {
		installDecisions({
			role: "admin",
			assets: { data: null, error: { message: "permission denied" } },
		});
		renderPage();
		await screen.findByText("Allow/block decisions are unavailable.");
		const table = screen.getByRole("table", { name: "Top AI services" });
		expect(within(table).queryByRole("button", { name: /^(Allow|Block) / })).toBeNull();
		expect(governanceCalls()).toEqual([]);
	});
});

describe("Require native NER (signed Browser Guard policy)", () => {
	const panel = async () => {
		const heading = await screen.findByRole("heading", { name: "Require native NER" });
		return heading.closest("section") as HTMLElement;
	};

	it("lets an administrator require native NER through the audited governance action", async () => {
		installDecisions({
			role: "admin",
			reply: { data: { ok: true, require_native_ner: true, changed: true }, error: null },
		});
		renderPage();
		const section = await panel();
		await waitFor(() => expect(within(section).getByText("not required")).toBeInTheDocument());
		expect(
			within(section).getByText(/large uploads wait for the host's answer/),
		).toBeInTheDocument();
		const toggle = within(section).getByRole("checkbox", {
			name: "Require native NER for every enrolled browser",
		});
		expect(toggle).not.toBeChecked();
		await waitFor(() => expect(toggle).toBeEnabled());
		fireEvent.click(toggle);
		await within(section).findByText(/Native NER is now required/);
		expect(governanceCalls()).toEqual([
			{ action: "update_browser_guard_settings", tenant_id: TEAM_ID, require_native_ner: true },
		]);
		const reads = mockedSupabase().from.mock.calls.filter(
			([table]) => table === "tenant_ai_governance_settings",
		);
		expect(reads.length).toBeGreaterThanOrEqual(2);
	});

	it("shows the stored requirement and explains a four-eyes refusal to switch it off", async () => {
		installDecisions({
			role: "owner",
			settings: { data: [{ browser_guard_require_native_ner: true }], error: null },
			reply: {
				data: null,
				error: {
					context: new Response(JSON.stringify({ error: "browser_guard_four_eyes_required" }), {
						status: 403,
					}),
				},
			},
		});
		renderPage();
		const section = await panel();
		await waitFor(() => expect(within(section).getByText("required")).toBeInTheDocument());
		const toggle = within(section).getByRole("checkbox");
		expect(toggle).toBeChecked();
		fireEvent.click(toggle);
		const alert = await within(section).findByText(
			/switching off required native NER needs four-eyes/,
		);
		expect(alert).toHaveAttribute("role", "alert");
		expect(governanceCalls()).toEqual([
			{ action: "update_browser_guard_settings", tenant_id: TEAM_ID, require_native_ner: false },
		]);
	});

	it("is read-only for members and viewers", async () => {
		for (const role of ["member", "viewer"] as const) {
			installDecisions({
				role,
				settings: { data: [{ browser_guard_require_native_ner: true }], error: null },
			});
			renderPage();
			const section = await panel();
			await waitFor(() => expect(within(section).getByText("required")).toBeInTheDocument());
			expect(within(section).queryByRole("checkbox")).toBeNull();
			cleanup();
		}
	});

	it("shows an unreadable or malformed setting as unavailable, never as not required", async () => {
		for (const settings of [
			{ data: null, error: { message: "permission denied" } },
			{ data: [{ browser_guard_require_native_ner: "yes" }], error: null },
		]) {
			installDecisions({ role: "admin", settings });
			renderPage();
			const section = await panel();
			await within(section).findByText("The native NER setting is unavailable.");
			expect(within(section).queryByText("not required")).toBeNull();
			expect(within(section).getByRole("checkbox")).toBeDisabled();
			cleanup();
		}
		expect(governanceCalls()).toEqual([]);
	});
});

describe("Shadow AI read model", () => {
	it("mirrors the Browser Guard catalog ids, names and categories", async () => {
		// Imported by path: the extension package is outside this package's tsc rootDir.
		const catalogModule = resolve(REPO_ROOT, "packages/browser-guard/src/sites/catalog.ts");
		const { AI_SERVICES } = (await import(/* @vite-ignore */ catalogModule)) as {
			AI_SERVICES: ReadonlyArray<{ id: string; name: string; category: string }>;
		};
		expect(SHADOW_AI_SERVICES).toEqual(
			Object.fromEntries(AI_SERVICES.map((s) => [s.id, { name: s.name, category: s.category }])),
		);
	});

	it("rejects summaries for the wrong window, negative counts or bad ids", () => {
		expect(() => parseShadowAiSummary(shadowSummary(7), 30)).toThrow(
			"Malformed Shadow AI summary.",
		);
		expect(() =>
			parseShadowAiSummary(
				shadowSummary(30, {
					by_service: [
						{
							service_id: "https://poe.com",
							category: "chat",
							visits: 1,
							blocked: 0,
							sanctioned: false,
						},
					],
				}),
				30,
			),
		).toThrow("Malformed Shadow AI summary.");
		expect(() =>
			parseShadowAiSummary(
				shadowSummary(30, { totals: { ...shadowSummary(30).totals, visits: -1 } }),
				30,
			),
		).toThrow("Malformed Shadow AI summary.");
		expect(parseShadowAiSummary(shadowSummary(7), 7).series).toHaveLength(7);
	});

	it("summarises stored rows for the generic event feeds", () => {
		expect(
			shadowAiEventSummary({ service_id: "poe", action: "blocked", count: 3, sanctioned: false }),
		).toBe("Poe (unsanctioned): blocked ×3");
		expect(
			shadowAiEventSummary({ service_id: "claude", action: "visited", sanctioned: true }),
		).toBe("Claude (sanctioned): visited");
		expect(serviceName("other")).toBe("Other AI service");
		expect(serviceName("future-ai")).toBe("future-ai");
	});
});
