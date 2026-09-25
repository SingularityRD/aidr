// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	AgentProfileEditor,
	parseProfileRevision,
	publishCommand,
	templateDocument,
} from "../enterprise/agent-profile-editor";
import { DlpPolicyHistory, parseDlpRevisionSummary } from "../enterprise/dlp-history";

const TENANT = "11111111-1111-4111-8111-111111111111";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke } }, supabaseEnvError: null }));

type Body = Record<string, unknown>;

function httpError(status: number, body: Body) {
	return {
		data: null,
		error: Object.assign(new Error("Edge Function returned a non-2xx status code"), {
			context: new Response(JSON.stringify(body), { status }),
		}),
	};
}

function bodies(action?: string): Body[] {
	return invoke.mock.calls
		.map(([, options]) => (options as { body: Body }).body)
		.filter((body) => !action || body.action === action);
}

beforeEach(() => vi.clearAllMocks());
afterEach(cleanup);

const dlp = (version: number, rules: string[]) => ({
	version,
	tenantId: TENANT,
	labels: [],
	rules: rules.map((id) => ({ id, tenantId: TENANT })),
	exceptions: [],
});

describe("DLP revision history", () => {
	function install(overrides: Record<string, (body: Body) => unknown> = {}) {
		invoke.mockImplementation(async (_fn: string, { body }: { body: Body }) => {
			const custom = overrides[String(body.action)];
			if (custom) return custom(body);
			if (body.action === "dlp_policy_history") {
				return {
					data: {
						ok: true,
						revisions: [3, 2, 1].map((version) => ({
							version,
							created_at: "2026-09-27T10:00:00.000Z",
							updated_by: "u",
							counts: { labels: 0, rules: version, exceptions: 0 },
						})),
						next_before_version: null,
					},
					error: null,
				};
			}
			if (body.action === "read_dlp_policy_revision") {
				const version = Number(body.version);
				const rules =
					version === 1
						? ["alpha"]
						: version === 2
							? ["alpha", "beta"]
							: ["alpha", "beta", "gamma"];
				return {
					data: { ok: true, revision: { version, policy: dlp(version, rules) } },
					error: null,
				};
			}
			throw new Error(`unexpected ${String(body.action)}`);
		});
	}

	it("loads only on request, then diffs a revision against the current one", async () => {
		install();
		const restored = vi.fn();
		render(
			<DlpPolicyHistory tenantId={TENANT} currentVersion={3} canManage onRestored={restored} />,
		);
		expect(invoke).not.toHaveBeenCalled();
		fireEvent.click(screen.getByRole("button", { name: "Show revision history" }));
		const table = await screen.findByRole("table", { name: "DLP policy revisions" });
		expect(within(table).getAllByRole("row")).toHaveLength(4);
		fireEvent.click(screen.getByRole("button", { name: "Compare version 1 with current" }));
		const diff = await screen.findByLabelText("DLP diff from version 1 to version 3");
		expect(diff.textContent).toContain('+       "id": "gamma"');
		expect(screen.getByText(/Version 1 → version 3 \(\+\d+ \/ −\d+ lines\)/)).toBeInTheDocument();
		expect(bodies("read_dlp_policy_revision").map((body) => body.version)).toEqual([1, 3]);
	});

	it("rolls back after confirmation and hands the restored revision to the editor", async () => {
		install({
			restore_dlp_policy: (body) => ({
				data: {
					ok: true,
					version: 4,
					restored_from: body.version,
					policy: dlp(4, ["alpha"]),
					saved: true,
				},
				error: null,
			}),
		});
		const restored = vi.fn();
		render(
			<DlpPolicyHistory tenantId={TENANT} currentVersion={3} canManage onRestored={restored} />,
		);
		fireEvent.click(screen.getByRole("button", { name: "Show revision history" }));
		fireEvent.click(await screen.findByRole("button", { name: "Roll back to version 1" }));
		fireEvent.click(screen.getByRole("button", { name: "Confirm rollback to version 1" }));
		await waitFor(() => expect(restored).toHaveBeenCalledWith(4, dlp(4, ["alpha"])));
		expect(bodies("restore_dlp_policy")).toEqual([
			{ action: "restore_dlp_policy", tenant_id: TENANT, version: 1, expected_version: 3 },
		]);
		expect(screen.getByRole("status")).toHaveTextContent("Version 1 restored as version 4.");
	});

	it("reports a four-eyes filing and a refused rollback with the validation detail", async () => {
		let calls = 0;
		install({
			restore_dlp_policy: () => {
				calls += 1;
				return calls === 1
					? { data: { ok: true, pending_approval: true, change_request_id: "r1" }, error: null }
					: httpError(400, {
							error: "invalid_dlp_policy",
							issues: [
								{
									path: ["exceptions"],
									message: "DLP_EXPIRED_EXCEPTION_DOMINANCE: 2 of 3 expired",
								},
							],
						});
			},
		});
		const restored = vi.fn();
		render(
			<DlpPolicyHistory tenantId={TENANT} currentVersion={3} canManage onRestored={restored} />,
		);
		fireEvent.click(screen.getByRole("button", { name: "Show revision history" }));
		fireEvent.click(await screen.findByRole("button", { name: "Roll back to version 2" }));
		fireEvent.click(screen.getByRole("button", { name: "Confirm rollback to version 2" }));
		expect(await screen.findByText(/filed for approval/)).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Roll back to version 1" }));
		fireEvent.click(screen.getByRole("button", { name: "Confirm rollback to version 1" }));
		const alert = await screen.findByRole("alert");
		expect(alert).toHaveTextContent("no longer valid");
		expect(alert).toHaveTextContent("exceptions: DLP_EXPIRED_EXCEPTION_DOMINANCE");
		expect(restored).not.toHaveBeenCalled();
	});

	it("hides rollback from non-managers and rejects malformed rows", async () => {
		install();
		render(
			<DlpPolicyHistory
				tenantId={TENANT}
				currentVersion={3}
				canManage={false}
				onRestored={vi.fn()}
			/>,
		);
		fireEvent.click(screen.getByRole("button", { name: "Show revision history" }));
		await screen.findByRole("table", { name: "DLP policy revisions" });
		expect(screen.queryByRole("button", { name: /Roll back/ })).toBeNull();
		expect(parseDlpRevisionSummary({ version: 1, created_at: "x", counts: {} })).toBeNull();
		expect(
			parseDlpRevisionSummary({
				version: 0,
				created_at: "2026-09-27T10:00:00Z",
				counts: { labels: 0, rules: 0, exceptions: 0 },
			}),
		).toBeNull();
	});
});

describe("agent permission profile editor", () => {
	const staged = {
		version: 1,
		default_profile: "ci-agent",
		profiles: [{ name: "ci-agent", default: "deny" }],
	};
	const older = { version: 1, profiles: [{ name: "reviewer", default: "deny" }] };

	function install(overrides: Record<string, (body: Body) => unknown> = {}) {
		invoke.mockImplementation(async (_fn: string, { body }: { body: Body }) => {
			const custom = overrides[String(body.action)];
			if (custom) return custom(body);
			switch (body.action) {
				case "read_agent_profiles":
					return {
						data: {
							ok: true,
							staged: true,
							version: 2,
							policy: staged,
							policy_sha256: "b".repeat(64),
							updated_at: "2026-09-28T10:00:00.000Z",
						},
						error: null,
					};
				case "agent_profile_history":
					return {
						data: {
							ok: true,
							revisions: [2, 1].map((version) => ({
								version,
								policy_sha256: String(version).repeat(64),
								profile_count: 1,
								restored_from: null,
								created_at: "2026-09-28T10:00:00.000Z",
							})),
						},
						error: null,
					};
				case "read_agent_profile_revision":
					return {
						data: { ok: true, revision: { version: body.version, policy: older } },
						error: null,
					};
				case "validate_agent_profiles":
					return String(body.source).includes("Bad")
						? {
								data: {
									ok: true,
									valid: false,
									errors: ["profiles.0.name: must be a lowercase name"],
								},
								error: null,
							}
						: {
								data: { ok: true, valid: true, profiles: ["ci-agent"], diagnostics: [] },
								error: null,
							};
				default:
					throw new Error(`unexpected ${String(body.action)}`);
			}
		});
	}

	function renderEditor(canManage = true) {
		return render(
			<MemoryRouter>
				<AgentProfileEditor tenantId={TENANT} canManage={canManage} />
			</MemoryRouter>,
		);
	}

	it("loads the staged document, validates with the server schema and shows the exact publication command", async () => {
		install();
		renderEditor();
		const editor = (await screen.findByLabelText(
			"Agent profile document (JSON or YAML)",
		)) as HTMLTextAreaElement;
		expect(JSON.parse(editor.value)).toEqual(staged);
		expect(screen.getByLabelText("Signed profile publishing commands")).toHaveTextContent(
			`--revision 2`,
		);
		fireEvent.change(editor, { target: { value: '{"version":1,"profiles":[{"name":"Bad"}]}' } });
		fireEvent.click(screen.getByRole("button", { name: "Validate" }));
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"profiles.0.name: must be a lowercase name",
		);
		fireEvent.change(editor, { target: { value: JSON.stringify(staged) } });
		fireEvent.click(screen.getByRole("button", { name: "Validate" }));
		expect(await screen.findByText(/Valid: ci-agent/)).toBeInTheDocument();
	});

	it("stages against the loaded revision and reloads", async () => {
		install({
			stage_agent_profiles: () => ({
				data: { ok: true, staged: true, version: 3, policy: staged },
				error: null,
			}),
		});
		renderEditor();
		await screen.findByLabelText("Agent profile document (JSON or YAML)");
		fireEvent.change(screen.getByLabelText("Profile template"), {
			target: { value: "locked-down" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Stage for publication" }));
		expect(await screen.findByText(/staged as revision 3/)).toBeInTheDocument();
		const [stage] = bodies("stage_agent_profiles");
		expect(stage).toMatchObject({ tenant_id: TENANT, expected_version: 2 });
		expect(JSON.parse(String(stage?.source)).profiles[0].name).toBe("locked-down");
		expect(bodies("read_agent_profiles")).toHaveLength(2);
	});

	it("reports four-eyes filing, server validation errors, and routes AAL1 to step-up", async () => {
		install({
			stage_agent_profiles: () => ({
				data: { ok: true, pending_approval: true, change_request_id: "r1" },
				error: null,
			}),
		});
		renderEditor();
		fireEvent.click(await screen.findByRole("button", { name: "Stage for publication" }));
		expect(await screen.findByText(/filed for approval/)).toBeInTheDocument();
		cleanup();

		install({
			stage_agent_profiles: () =>
				httpError(400, { error: "invalid_agent_profiles", errors: ["profiles: at least 1"] }),
		});
		renderEditor();
		fireEvent.click(await screen.findByRole("button", { name: "Stage for publication" }));
		expect(await screen.findByText("profiles: at least 1")).toBeInTheDocument();
		cleanup();

		install({ read_agent_profiles: () => httpError(403, { error: "mfa_required" }) });
		renderEditor();
		expect(await screen.findByRole("link", { name: "Verify with authenticator" })).toHaveAttribute(
			"href",
			`/auth/dlp-step-up?tenant=${TENANT}`,
		);
	});

	it("diffs and rolls back a staged revision; viewers cannot edit", async () => {
		install({
			restore_agent_profiles: () => ({
				data: { ok: true, staged: true, version: 3, restored_from: 1 },
				error: null,
			}),
		});
		renderEditor();
		fireEvent.click(await screen.findByRole("button", { name: "Compare revision 1 with current" }));
		expect(await screen.findByText("Revision 1 → current staged revision 2")).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Roll back profiles to revision 1" }));
		expect(await screen.findByText(/Revision 1 restored as revision 3/)).toBeInTheDocument();
		expect(bodies("restore_agent_profiles")).toEqual([
			{ action: "restore_agent_profiles", tenant_id: TENANT, version: 1, expected_version: 2 },
		]);
		cleanup();

		install();
		renderEditor(false);
		const editor = await screen.findByLabelText("Agent profile document (JSON or YAML)");
		expect(editor).toHaveAttribute("readonly");
		expect(screen.queryByRole("button", { name: "Stage for publication" })).toBeNull();
		expect(screen.queryByRole("button", { name: /Roll back/ })).toBeNull();
	});

	it("builds template documents and commands the engine accepts", () => {
		const document = JSON.parse(templateDocument("read-only-reviewer"));
		expect(document).toMatchObject({ version: 1, default_profile: "read-only-reviewer" });
		expect(publishCommand(TENANT, 7)).toContain(`--tenant ${TENANT} --revision 7`);
		expect(
			parseProfileRevision({
				version: 1,
				policy_sha256: "x",
				profile_count: 1,
				created_at: "2026-09-28T10:00:00Z",
			}),
		).toBeNull();
	});
});
