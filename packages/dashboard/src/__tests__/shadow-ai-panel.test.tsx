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
