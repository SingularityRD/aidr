// @vitest-environment jsdom

import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const rpc = vi.hoisted(() => vi.fn());
const invoke = vi.hoisted(() => vi.fn());
const team = vi.hoisted(() => ({
	value: {
		currentTeam: { id: "22222222-2222-4222-8222-222222222222", name: "Acme Security" } as {
			id: string;
			name: string;
		} | null,
		currentRole: "owner" as string | null,
		isLoading: false,
		roleResolved: true,
	},
}));
vi.mock("../lib/supabase", () => ({
	supabase: { rpc, functions: { invoke } },
	supabaseEnvError: null,
	supabaseProjectUrl: "https://project.supabase.co",
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: () => team.value }));

import { en } from "../i18n/en";
import { frameworkCoverage, parseGovernanceScorecard, topRisks } from "../lib/governance";
import { GOVERNANCE_STATEMENT, renderGovernanceReport } from "../ui/governance-print";
import { GovernancePage } from "../ui/pages/GovernancePage";
import { acceptableUseNotice, managedPolicySnippet } from "../ui/privacy-guard";

const TENANT = "22222222-2222-4222-8222-222222222222";
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

interface Fixtures {
	governanceScorecardFixture(days?: 7 | 30 | 90): Record<string, unknown>;
	emptyGovernanceScorecardFixture(): Record<string, unknown>;
}
interface BrowserPolicy {
	validateAcceptableUseNotice(raw: unknown): unknown;
}

let fixtures: Fixtures;
let browserPolicy: BrowserPolicy;

beforeAll(async () => {
	const load = (path: string) => import(pathToFileURL(resolve(REPO_ROOT, path)).href);
	fixtures = (await load("supabase/functions/__tests__/governance-fixtures.ts")) as Fixtures;
	browserPolicy = (await load("packages/browser-guard/src/background/policy.ts")) as BrowserPolicy;
});

beforeEach(() => {
	rpc.mockReset();
	invoke.mockReset();
	team.value = {
		currentTeam: { id: TENANT, name: "Acme Security" },
		currentRole: "owner",
		isLoading: false,
		roleResolved: true,
	};
});

afterEach(() => {
	cleanup();
	vi.restoreAllMocks();
});

function renderPage() {
	return render(
		<MemoryRouter>
			<GovernancePage />
		</MemoryRouter>,
	);
}

function scorecardReplies(card: () => Record<string, unknown>) {
	rpc.mockImplementation(async (name: string, args: Record<string, unknown>) => {
		if (name === "governance_scorecard") {
			const days = args.p_days as 7 | 30 | 90;
			return {
				data: {
					...card(),
					window_days: days,
					trend: (card().trend as unknown[]).slice(0, days).concat(
						Array.from(
							{ length: Math.max(0, days - (card().trend as unknown[]).length) },
							(_, i) => ({
								day: `2026-10-${String(i + 1).padStart(2, "0")}`,
								allow: 0,
								ask: 0,
								deny: 0,
								masked: 0,
								blocked: 0,
							}),
						),
					),
				},
				error: null,
			};
		}
		if (name === "set_governance_settings") {
			return {
				data: {
					digest_enabled: args.p_digest_enabled,
					digest_cadence: args.p_digest_cadence,
					digest_recipients: args.p_digest_recipients,
					digest_next_at: "2026-09-28T06:00:00+00:00",
					digest_last_at: null,
					digest_last_status: null,
					oversight_fast_seconds: args.p_oversight_fast_seconds,
					oversight_min_decisions: args.p_oversight_min_decisions,
					oversight_fast_share: args.p_oversight_fast_share,
					updated_at: "2026-09-25T10:00:00+00:00",
				},
				error: null,
			};
		}
		throw new Error(`unexpected rpc ${name}`);
	});
}

describe("GovernancePage", () => {
	it("is limited to owners and admins", () => {
		team.value = { ...team.value, currentRole: "member" };
		renderPage();
		expect(screen.getByRole("alert")).toHaveTextContent("Only workspace owners and admins");
		expect(rpc).not.toHaveBeenCalled();
	});

	it("shows the scorecard computed from the workspace's records", async () => {
		scorecardReplies(() => fixtures.governanceScorecardFixture(30));
		renderPage();
		await screen.findByRole("heading", { name: "Top risks" });
		expect(rpc).toHaveBeenCalledWith("governance_scorecard", { p_tenant_id: TENANT, p_days: 30 });

		const risks = screen.getByRole("region", { name: "Top risks" });
		expect(within(risks).getByTestId("risk-incidents-critical")).toHaveTextContent(
			"1 critical incident still open",
		);
		expect(within(risks).getByTestId("risk-oversight-review")).toHaveTextContent(
			"1 approver to review",
		);
		expect(within(risks).getByTestId("risk-admins-without-mfa")).toHaveTextContent(
			"1 owner or admin without MFA",
		);

		for (const id of ["nist-ai-rmf", "iso-iec-42001", "eu-ai-act", "kvkk-gdpr"])
			expect(screen.getByTestId(`coverage-${id}`)).toHaveTextContent("%");

		const oversight = screen.getByRole("region", { name: "Human oversight" });
		expect(within(oversight).getByText("43 s")).toBeInTheDocument();
		expect(within(oversight).getByText("fast.approver@acme.example")).toBeInTheDocument();
		expect(within(oversight).getAllByTestId("review-prompt")).toHaveLength(1);
		expect(within(oversight).getByText(/not a finding about the person/)).toBeInTheDocument();

		const browser = screen.getByRole("region", { name: "Browser Guard and acceptable use" });
		expect(within(browser).getAllByText("acme-aup", { selector: "td" })).toHaveLength(2);
		expect(within(browser).getByText("81%")).toBeInTheDocument();

		const matrix = screen.getByRole("region", { name: "Framework control matrix" });
		expect(within(matrix).getByText("MAP 3.5")).toBeInTheDocument();
		expect(within(matrix).getByText("Art. 26(6)")).toBeInTheDocument();
	});

	it("shows empty states when nothing has reported, without inventing figures", async () => {
		scorecardReplies(() => fixtures.emptyGovernanceScorecardFixture());
		renderPage();
		expect(
			await screen.findByText(/No coding agents or browser installs are enrolled yet/),
		).toBeInTheDocument();
		expect(screen.getByText("No decisions were reported in this window.")).toBeInTheDocument();
		expect(screen.getByText("No approval decisions in this window.")).toBeInTheDocument();
		expect(screen.getByText(/No acknowledgements reported/)).toBeInTheDocument();
		expect(screen.getByTestId("risk-nothing-reporting")).toBeInTheDocument();
		expect(screen.getByTestId("risk-runtime-policy-missing")).toBeInTheDocument();
	});

	it("refuses a malformed answer instead of showing zeros", async () => {
		rpc.mockResolvedValue({ data: { window_days: 30, usage: {} }, error: null });
		renderPage();
		expect(await screen.findByRole("alert")).toHaveTextContent("incomplete");
		expect(screen.queryByRole("heading", { name: "Top risks" })).toBeNull();
	});

	it("maps the identity barrier refusal to an actionable message", async () => {
		rpc.mockResolvedValue({
			data: null,
			error: { code: "42501", message: "governance_identity_barrier" },
		});
		renderPage();
		expect(await screen.findByRole("alert")).toHaveTextContent("sign-in policy");
	});

	it("switches windows and saves the summary schedule and oversight thresholds", async () => {
		scorecardReplies(() => fixtures.governanceScorecardFixture(30));
		renderPage();
		await screen.findByRole("heading", { name: "Scheduled summary" });
		fireEvent.click(screen.getByRole("button", { name: "7 days" }));
		await waitFor(() =>
			expect(rpc).toHaveBeenCalledWith("governance_scorecard", { p_tenant_id: TENANT, p_days: 7 }),
		);
		await screen.findByRole("heading", { name: "Scheduled summary" });

		fireEvent.click(screen.getByLabelText("Send a scheduled governance summary"));
		fireEvent.change(screen.getByLabelText("Frequency"), { target: { value: "monthly" } });
		fireEvent.change(screen.getByLabelText("Fast approval (seconds)"), { target: { value: "45" } });
		fireEvent.change(screen.getByLabelText("Fast-approval share (%)"), { target: { value: "85" } });
		fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
		await waitFor(() =>
			expect(rpc).toHaveBeenCalledWith("set_governance_settings", {
				p_tenant_id: TENANT,
				p_digest_enabled: true,
				p_digest_cadence: "monthly",
				p_digest_recipients: "owners_admins",
				p_oversight_fast_seconds: 45,
				p_oversight_min_decisions: 10,
				p_oversight_fast_share: 0.85,
			}),
		);
		expect(await screen.findByText(/Saved. Next summary/)).toBeInTheDocument();

		fireEvent.change(screen.getByLabelText("Fast-approval share (%)"), { target: { value: "20" } });
		fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
		expect(await screen.findByText(/between 50% and 100%/)).toBeInTheDocument();
	});

	it("sends a test summary and explains a missing mail transport", async () => {
		scorecardReplies(() => fixtures.governanceScorecardFixture(30));
		invoke.mockResolvedValueOnce({
			data: { ok: true, status: "sent", recipients: 2, delivered: 2 },
			error: null,
		});
		renderPage();
		fireEvent.click(await screen.findByRole("button", { name: "Send a test summary now" }));
		expect(
			await screen.findByText("Test summary delivered to 2 of 2 recipient(s)."),
		).toBeInTheDocument();
		expect(invoke).toHaveBeenCalledWith("governance-digest", {
			body: { action: "send_test", tenant_id: TENANT },
		});

		invoke.mockResolvedValueOnce({
			data: null,
			error: Object.assign(new Error("Edge Function returned a non-2xx status code"), {
				context: new Response(JSON.stringify({ error: "mail_not_configured" }), { status: 409 }),
			}),
		});
		fireEvent.click(screen.getByRole("button", { name: "Send a test summary now" }));
		expect(await screen.findByText(/no e-mail transport configured/)).toBeInTheDocument();
	});
});

describe("governance export and risks", () => {
	it("prints the scorecard with the control matrix, counts only", () => {
		const card = parseGovernanceScorecard(fixtures.governanceScorecardFixture(30), 30);
		const html = renderGovernanceReport(card, frameworkCoverage(card.signals), "Acme <Security>");
		expect(html).toContain("Acme &lt;Security&gt;");
		expect(html).not.toContain("<Security>");
		expect(html).toContain("Framework control matrix");
		expect(html).toContain("GOVERN 1.6");
		expect(html).toContain("A.6.2.8");
		expect(html).toContain("Art. 26(6)");
		expect(html).toContain("KVKK Art. 12");
		expect(html).toContain("not a certification");
		expect(html).not.toContain("fast.approver@acme.example");
		expect(html).not.toMatch(/<script/i);
	});

	it("derives risks only from the numbers present", () => {
		const card = parseGovernanceScorecard(fixtures.governanceScorecardFixture(30), 30);
		const ids = topRisks(card, 20).map((r) => r.id);
		expect(ids[0]).toBe("incidents-critical");
		expect(ids).toEqual(
			expect.arrayContaining([
				"retention-short",
				"aup-coverage",
				"mcp-unapproved",
				"approvals-expired",
			]),
		);
		expect(ids).not.toContain("nothing-reporting");
		expect(ids).not.toContain("runtime-policy-missing");
	});
});

describe("acceptable-use notice in the managed policy snippet", () => {
	it("emits only notices the extension accepts", () => {
		const good = acceptableUseNotice({
			id: "acme-aup",
			version: "2",
			title: " Using AI at Acme ",
			text: "Do not paste customer records.",
			url: "https://intranet.acme.example/ai",
		});
		expect(good.ok).toBe(true);
		if (!good.ok) return;
		expect(browserPolicy.validateAcceptableUseNotice(good.value)).toEqual(good.value);
		const snippet = JSON.parse(
			managedPolicySnippet({ controlPlaneUrl: null, mode: "auto", acceptableUse: good.value }),
		);
		expect(snippet.acceptableUse).toEqual(good.value);
		expect(
			JSON.parse(managedPolicySnippet({ controlPlaneUrl: null, mode: "auto" })).acceptableUse,
		).toBeUndefined();

		for (const bad of [
			{ id: "bad id", version: "1", title: "t", text: "x", url: "" },
			{ id: "a", version: "0", title: "t", text: "x", url: "" },
			{ id: "a", version: "1.5", title: "t", text: "x", url: "" },
			{ id: "a", version: "1", title: "", text: "x", url: "" },
			{ id: "a", version: "1", title: "t", text: "x".repeat(4001), url: "" },
			{ id: "a", version: "1", title: "t", text: "bell\u0007", url: "" },
			{ id: "a", version: "1", title: "t", text: "x", url: "http://acme.example" },
		]) {
			const result = acceptableUseNotice(bad);
			expect(result.ok, JSON.stringify(bad)).toBe(false);
			expect(
				browserPolicy.validateAcceptableUseNotice({
					...bad,
					version: Number(bad.version),
					url: bad.url || undefined,
				}),
			).toBeNull();
		}
	});
});

describe("governance statement wording", () => {
	it("shows the on-screen statement with the same English text as the printed report", () => {
		// The page renders the catalog copy so it can be translated; the printed
		// report keeps the English constant. They must not drift apart.
		expect(en["gsc.statement"]).toBe(GOVERNANCE_STATEMENT);
	});
});
