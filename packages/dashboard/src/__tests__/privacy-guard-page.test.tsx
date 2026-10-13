// @vitest-environment jsdom

import { readFileSync } from "node:fs";
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
import { en } from "../i18n/en";
import { PrivacyGuardPage } from "../ui/pages/PrivacyGuardPage";
import {
	BROWSER_GUARD_DEFAULT_ENTITIES,
	managedPolicySnippet,
	PRIVACY_ENTITY_TYPES,
	parseBrowserGuardSettings,
	parsePrivacyEventRow,
	parsePrivacySummary,
	privacyEventSummary,
} from "../ui/privacy-guard";
import { installDashboardMocks, mockedSupabase, TEAM_ID } from "./helpers/dashboard-mocks";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const AGENT_ID = "a0000000-0000-4000-8000-000000000001";

function summary(days: 7 | 30, overrides: Record<string, unknown> = {}) {
	const start = Date.parse("2026-09-24T00:00:00Z") - (days - 1) * 86_400_000;
	return {
		window_days: days,
		since: new Date(start).toISOString(),
		totals: {
			scans: 48,
			prompts_protected: 41,
			items_masked: 1234,
			blocked_sends: 7,
			warned_sends: 3,
			allowed_sends: 7,
		},
		browser_installs: { enrolled: 12, active: 9 },
		by_entity: [
			{ entity_type: "EMAIL", items: 900 },
			{ entity_type: "TC_KIMLIK", items: 300 },
			{ entity_type: "SECRET", items: 34 },
		],
		by_site: [
			{ site: "chatgpt", scans: 30, items: 1000, blocked: 2 },
			{ site: "gemini", scans: 18, items: 234, blocked: 5 },
		],
		series: Array.from({ length: days }, (_, index) => ({
			day: new Date(start + index * 86_400_000).toISOString().slice(0, 10),
			scans: index === days - 1 ? 5 : 1,
			masked: index === days - 1 ? 3 : 1,
			warned: 0,
			blocked: index === days - 1 ? 1 : 0,
		})),
		...overrides,
	};
}

const RECENT_ROWS = [
	{
		id: 10,
		created_at: "2026-09-24T10:15:00Z",
		agent_id: AGENT_ID,
		payload: {
			type: "privacy_scan",
			site: "chatgpt",
			action: "masked",
			channel: "prompt",
			decision: "allow",
			entity_counts: { EMAIL: 2, TC_KIMLIK: 1 },
			findings_count: 3,
		},
	},
	{
		id: 9,
		created_at: "2026-09-24T09:00:00Z",
		agent_id: AGENT_ID,
		payload: {
			type: "privacy_scan",
			site: "gemini",
			action: "blocked",
			channel: "paste",
			decision: "deny",
			entity_counts: { SECRET: 1 },
			findings_count: 1,
		},
	},
	// Not a counts-only privacy row: never rendered.
	{ id: 8, created_at: "2026-09-24T08:00:00Z", agent_id: AGENT_ID, payload: { action: "leak" } },
];

function install(
	rpcData: unknown = summary(30),
	rpcError: { message: string; code?: string } | null = null,
) {
	const mocks = installDashboardMocks({
		rpcResults: { privacy_guard_summary: { data: rpcData, error: rpcError } },
		tableResults: {
			events: { data: RECENT_ROWS, error: null },
			agents: {
				data: [{ id: AGENT_ID, iid: "browser-profile-1", display_name: "Finance laptop" }],
				error: null,
			},
		},
	});
	// installDashboardMocks resets every mock, including the team hook.
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

describe("Browser Privacy Guard page", () => {
	it("shows tenant KPIs, breakdowns, the daily series and counts-only recent events", async () => {
		install();
		renderPage();

		const counters = await screen.findByRole("region", { name: "Browser privacy counters" });
		// Counts use the viewer's locale (1,234 in en-US, 1.234 in tr-TR).
		await waitFor(() =>
			expect(within(counters).getByText((1234).toLocaleString())).toBeInTheDocument(),
		);
		expect(within(counters).getByText("41")).toBeInTheDocument();
		expect(within(counters).getByText("7")).toBeInTheDocument();
		expect(within(counters).getByText("9")).toBeInTheDocument();
		expect(within(counters).getByText("of 12 enrolled")).toBeInTheDocument();

		const rpc = mockedSupabase().rpc;
		expect(rpc).toHaveBeenCalledWith("privacy_guard_summary", { p_tenant_id: TEAM_ID, p_days: 30 });

		const byEntity = screen.getByRole("region", { name: "By entity type" });
		expect(within(byEntity).getByText("Email address")).toBeInTheDocument();
		expect(within(byEntity).getByText("TC Kimlik No")).toBeInTheDocument();
		expect(within(byEntity).getByText("900 item(s)")).toBeInTheDocument();
		const bySite = screen.getByRole("region", { name: "By AI site" });
		expect(within(bySite).getByText("ChatGPT")).toBeInTheDocument();
		expect(within(bySite).getByText("18 send(s) · 234 item(s) · 5 blocked")).toBeInTheDocument();

		const series = screen.getByRole("img", { name: "34 scanned sends over 30 days" });
		expect(series.children).toHaveLength(30);

		const recentTable = screen.getByRole("region", { name: "Recent privacy events" });
		await waitFor(() =>
			expect(screen.getByText("Email address ×2, TC Kimlik No ×1")).toBeInTheDocument(),
		);
		expect(within(recentTable).getAllByText("Finance laptop")).toHaveLength(2);
		expect(within(recentTable).getByText("blocked")).toHaveClass("badge-deny");
		expect(within(recentTable).getByText("masked")).toHaveClass("badge-success");
		expect(within(recentTable).queryByText("leak")).not.toBeInTheDocument();

		const eventsRead = vi
			.mocked(mockedSupabase().from)
			.mock.results.find(
				(_result, index) => vi.mocked(mockedSupabase().from).mock.calls[index]?.[0] === "events",
			)?.value;
		expect(eventsRead.eq).toHaveBeenCalledWith("tenant_id", TEAM_ID);
		expect(eventsRead.eq).toHaveBeenCalledWith("type", "privacy_scan");
		expect(eventsRead.limit).toHaveBeenCalledWith(25);
	});

	it("switches the reporting window to 7 days", async () => {
		install();
		const rpc = mockedSupabase().rpc;
		rpc.mockImplementation(async (_name: string, args: { p_days: 7 | 30 }) => ({
			data: summary(args.p_days),
			error: null,
		}));
		renderPage();
		await screen.findByRole("img", { name: "34 scanned sends over 30 days" });

		fireEvent.click(screen.getByRole("button", { name: "7 days" }));
		await screen.findByRole("img", { name: "11 scanned sends over 7 days" });
		expect(rpc).toHaveBeenLastCalledWith("privacy_guard_summary", {
			p_tenant_id: TEAM_ID,
			p_days: 7,
		});
		expect(screen.getByRole("button", { name: "7 days" })).toHaveAttribute("aria-pressed", "true");
	});

	it("shows an unavailable summary instead of zeros when the RPC fails or is malformed", async () => {
		install(null, {
			code: "PGRST202",
			message: "Could not find privacy_guard_summary in the schema cache",
		});
		renderPage();
		expect(await screen.findByRole("alert")).toHaveTextContent("Privacy summary is unavailable.");
		expect(screen.getByRole("alert")).not.toHaveTextContent("schema cache");
		const counters = screen.getByRole("region", { name: "Browser privacy counters" });
		expect(within(counters).getAllByText("—")).toHaveLength(4);
		expect(within(counters).queryByText("0")).not.toBeInTheDocument();
		cleanup();

		install(summary(30, { series: [] }));
		renderPage();
		expect(await screen.findByRole("alert")).toHaveTextContent("Malformed privacy summary.");
	});

	it("gives administrators an enrollment path with an ingest-only key link and managed policy JSON", async () => {
		install();
		const writeText = vi.fn(async (_text: string) => undefined);
		Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
		renderPage();

		const panel = screen.getByRole("region", { name: "Enroll browsers" });
		expect(within(panel).getByRole("link", { name: "API Keys" })).toHaveAttribute(
			"href",
			"/api-keys?type=browser_guard",
		);
		expect(within(panel).getByText(/Create a Browser Guard ingest-only key/)).toBeInTheDocument();
		expect(within(panel).getByText(/do not deploy a tenant key here/)).toBeInTheDocument();
		const policy = JSON.parse(
			within(panel).getByLabelText("Managed policy JSON").textContent ?? "",
		);
		expect(policy).toEqual({
			mode: "auto",
			enabledEntities: BROWSER_GUARD_DEFAULT_ENTITIES,
			literals: [],
			telemetry: {
				controlPlaneUrl: "https://tenant-project.supabase.co",
				apiKey: "<paste a Browser Guard ingest-only key created on the API Keys page>",
			},
		});

		fireEvent.change(within(panel).getByLabelText("Guard mode"), { target: { value: "block" } });
		expect(
			JSON.parse(within(panel).getByLabelText("Managed policy JSON").textContent ?? "").mode,
		).toBe("block");
		fireEvent.click(within(panel).getByRole("button", { name: "Copy policy JSON" }));
		await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
		expect(JSON.parse(writeText.mock.calls[0]?.[0] ?? "").mode).toBe("block");
		expect(await within(panel).findByText(/Replace the apiKey placeholder/)).toBeInTheDocument();
	});
});

describe("Browser Privacy Guard read model", () => {
	it("keeps the entity vocabulary aligned with the privacy engine", () => {
		const source = readFileSync(resolve(REPO_ROOT, "packages/privacy/src/types.ts"), "utf8");
		const list = /ENTITY_TYPES = \[([\s\S]*?)\] as const/.exec(source)?.[1] ?? "";
		expect(PRIVACY_ENTITY_TYPES).toEqual(
			[...list.matchAll(/'([A-Z_]+)'/g)].map((match) => match[1]),
		);
	});

	it("offers exactly the extension's default entity types in the managed-policy snippet", async () => {
		// Imported by path: the extension package is outside this package's tsc rootDir.
		const policyModule = resolve(REPO_ROOT, "packages/browser-guard/src/background/policy.ts");
		const { DEFAULT_POLICY } = (await import(/* @vite-ignore */ policyModule)) as {
			DEFAULT_POLICY: { enabledEntities: readonly string[] };
		};
		expect(BROWSER_GUARD_DEFAULT_ENTITIES).toEqual(DEFAULT_POLICY.enabledEntities);
		expect(BROWSER_GUARD_DEFAULT_ENTITIES).not.toContain("USERNAME");
		expect(BROWSER_GUARD_DEFAULT_ENTITIES).not.toContain("LOCATION");
		const snippet = JSON.parse(managedPolicySnippet({ controlPlaneUrl: null, mode: "auto" }));
		expect(snippet.enabledEntities).toEqual([...DEFAULT_POLICY.enabledEntities]);
	});

	it("rejects summaries for the wrong window or with negative counts", () => {
		expect(() => parsePrivacySummary(summary(7), 30)).toThrow("Malformed privacy summary.");
		expect(() =>
			parsePrivacySummary(summary(30, { browser_installs: { enrolled: 1, active: -1 } }), 30),
		).toThrow("Malformed privacy summary.");
		expect(parsePrivacySummary(summary(7), 7).series).toHaveLength(7);
	});

	it("projects stored rows as counts only and summarizes them for the generic feeds", () => {
		const row = parsePrivacyEventRow(RECENT_ROWS[0]);
		expect(row).toEqual({
			id: 10,
			createdAt: "2026-09-24T10:15:00Z",
			agentId: AGENT_ID,
			site: "chatgpt",
			action: "masked",
			channel: "prompt",
			entityCounts: [
				["EMAIL", 2],
				["TC_KIMLIK", 1],
			],
			findingsCount: 3,
			nativeNer: null,
		});
		expect(parsePrivacyEventRow(RECENT_ROWS[2])).toBeNull();
		// native_ner is carried as its status enum only; anything else reads as NER off.
		const withNer = (native_ner: unknown) =>
			parsePrivacyEventRow({
				...RECENT_ROWS[0],
				payload: { ...(RECENT_ROWS[0]?.payload as Record<string, unknown>), native_ner },
			})?.nativeNer;
		expect(withNer("used")).toBe("used");
		expect(withNer("unavailable")).toBe("unavailable");
		for (const bad of ["USED", "skipped", true, null]) expect(withNer(bad)).toBeNull();
		expect(parseBrowserGuardSettings(null)).toEqual({ requireNativeNer: false });
		expect(parseBrowserGuardSettings({ browser_guard_require_native_ner: true })).toEqual({
			requireNativeNer: true,
		});
		for (const bad of [{}, [], "true", { browser_guard_require_native_ner: 1 }]) {
			expect(() => parseBrowserGuardSettings(bad)).toThrow("Malformed Browser Guard settings.");
		}
		expect(privacyEventSummary(RECENT_ROWS[0]?.payload)).toBe("ChatGPT prompt: masked, 3 item(s)");
		expect(managedPolicySnippet({ controlPlaneUrl: null, mode: "monitor" })).toContain(
			"https://<your-project>.supabase.co",
		);
	});

	it("registers /privacy-guard as a protected route without replacing the public privacy notice", () => {
		const main = readFileSync(resolve(REPO_ROOT, "packages/dashboard/src/main.tsx"), "utf8");
		expect(main).toMatch(/path: "\/privacy-guard",[\s\S]{0,240}?loader: requireSessionLoader/);
		expect(main).toContain('{ path: "privacy", element: <PublicInfoPage kind="privacy" /> }');
		const layout = readFileSync(
			resolve(REPO_ROOT, "packages/dashboard/src/ui/AppLayout.tsx"),
			"utf8",
		);
		expect(layout).toContain('<NavLink to="/privacy-guard">{t("nav.browserPrivacy")}</NavLink>');
		expect(en["nav.browserPrivacy"]).toBe("Browser Privacy");
	});
});
