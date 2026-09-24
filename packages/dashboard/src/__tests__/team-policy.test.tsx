// @vitest-environment jsdom

// Regression guards for AIDR-009 (team policy editor unreachable) and for the
// two defects that wiring it up exposed:
//
//   1. The load effect depended on component-local functions, so it re-ran after
//      every render and re-issued the query forever.
//   2. The hand-rolled YAML reader never handled a nested mapping inside a
//      sequence item, so `condition:` under a rule became the key "condition:"
//      with an empty value and the preview crashed reading `rule.condition.mcp_tool`.
//
// Saves submit exact bytes and the loaded revision to the server action. No
// browser mutation or save-time read may bypass compilation or hide stale edits;
// rejected and unconfirmed responses must never be reported as success.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
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
	},
	supabaseEnvError: null,
}));

import { AppLayout } from "../ui/AppLayout";
import { PolicyPage } from "../ui/pages/PolicyPage";
import {
	installDashboardMocks,
	POLICY_ROW_ID,
	policySourceHash,
	TEAM_ID,
} from "./helpers/dashboard-mocks";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const MAIN_TSX = readFileSync(resolve(REPO_ROOT, "packages/dashboard/src/main.tsx"), "utf8");

const STORED_POLICY = `version: "1.0"
description: Team policy
default_action: deny
unknown_action: ask
risky_action: deny
rules:
  - name: Block shell execution
    condition:
      mcp_tool: shell.execute
    action: deny
    priority: 100
`;

function renderPolicyRoute() {
	return render(
		<MemoryRouter initialEntries={["/policies"]}>
			<Routes>
				<Route path="/*" element={<AppLayout />}>
					<Route path="policies" element={<PolicyPage />} />
				</Route>
			</Routes>
		</MemoryRouter>,
	);
}

function saveButton(): HTMLElement {
	return screen.getByRole("button", { name: /Save Policy|Saving/ });
}

describe("Team policy editor is reachable (AIDR-009)", () => {
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("registers /policies through the console shell behind the session loader", () => {
		const start = MAIN_TSX.indexOf('path: "/policies"');
		expect(start, 'main.tsx does not register path: "/policies"').toBeGreaterThan(-1);
		const block = MAIN_TSX.slice(start, start + 320);
		expect(block).toContain("lazy: loadAppLayout");
		expect(block).toContain("loader: requireSessionLoader");
		expect(block).toContain('import("./ui/pages/PolicyPage")');
	});

	it("exposes the policy surface from the console navigation", () => {
		const layout = readFileSync(
			resolve(REPO_ROOT, "packages/dashboard/src/ui/AppLayout.tsx"),
			"utf8",
		);
		expect(layout).toContain('<NavLink to="/policies">Policies</NavLink>');
	});

	it("renders the editor and the default policy for a team with no stored policy", async () => {
		installDashboardMocks({ role: "admin" });

		renderPolicyRoute();

		await waitFor(() =>
			expect(screen.getByRole("heading", { name: "Security Policy Editor" })).toBeInTheDocument(),
		);
		expect(screen.getByRole("heading", { name: "Team policy", level: 1 })).toBeInTheDocument();
		expect(screen.getByText("✓ Valid policy")).toBeInTheDocument();
		const editor = screen.getByRole("textbox", { name: /Policy \(YAML\)/ }) as HTMLTextAreaElement;
		expect(editor.value).toContain("default_action: ask");
		expect(screen.getByText("Rules (2):")).toBeInTheDocument();
		expect(screen.getByText("Block repository deletion")).toBeInTheDocument();
	});

	it("reads the stored policy once and previews a nested rule condition", async () => {
		const mocks = installDashboardMocks({
			role: "admin",
			policyRow: {
				id: POLICY_ROW_ID,
				content: STORED_POLICY,
				updated_at: "2026-01-02T00:00:00.000Z",
			},
		});

		renderPolicyRoute();

		await waitFor(() => expect(screen.getByText("Block shell execution")).toBeInTheDocument());
		// The nested `condition:` mapping must survive the parse; the previous
		// reader produced the key "condition:" and crashed here.
		expect(screen.getByText(/MCP tool: shell.execute/)).toBeInTheDocument();
		expect(screen.getByText("Rules (1):")).toBeInTheDocument();
		// Default, risky-MCP and the rule's own action pills.
		expect(screen.getAllByText("deny")).toHaveLength(3);
		expect(screen.getByRole("textbox", { name: /Policy \(YAML\)/ })).toHaveValue(STORED_POLICY);

		// One load, not a render loop: the effect used to re-run on every render
		// because its dependencies were recreated each time.
		expect(mocks.teamPolicies.select).toHaveBeenCalledTimes(1);
	});

	it("blocks the write when the document is not a valid policy", async () => {
		const mocks = installDashboardMocks({ role: "admin" });

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.change(screen.getByRole("textbox", { name: /Policy \(YAML\)/ }), {
			target: { value: 'version: "1.0"\ndefault_action: maybe\nrules: []\n' },
		});

		expect(screen.getByText("✗ Invalid policy")).toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent(/default_action/);
		expect(saveButton()).toBeDisabled();

		fireEvent.click(saveButton());

		expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
		expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
	});

	it.each(["owner", "admin", "member"])(
		"saves a first draft as %s through the tenant-scoped server action",
		async (role) => {
			const mocks = installDashboardMocks({ role });

			renderPolicyRoute();
			await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

			fireEvent.click(saveButton());

			await waitFor(() =>
				expect(screen.getByText("Policy saved successfully")).toBeInTheDocument(),
			);
			expect(mocks.invoke).toHaveBeenCalledWith("policy-management", {
				body: {
					action: "save_document_draft",
					tenant_id: TEAM_ID,
					content: (screen.getByRole("textbox", { name: /Policy \(YAML\)/ }) as HTMLTextAreaElement)
						.value,
					expected_document: null,
					simulation: {
						kind: "mcp",
						server: "unregistered-preview",
						tool: "call",
						inventory: "unknown",
					},
				},
			});
			expect(mocks.teamPolicies.select).toHaveBeenCalledTimes(1);
			expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
			expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
			expect(mocks.teamPolicies.delete).not.toHaveBeenCalled();
		},
	);

	it("updates with the initially loaded revision without a save-time refresh", async () => {
		const mocks = installDashboardMocks({
			role: "admin",
			policyRow: {
				id: POLICY_ROW_ID,
				content: STORED_POLICY,
				updated_at: "2026-01-02T00:00:00.000Z",
			},
		});

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("Block shell execution")).toBeInTheDocument());

		fireEvent.click(saveButton());

		await waitFor(() => expect(screen.getByText("Policy saved successfully")).toBeInTheDocument());
		expect(mocks.invoke).toHaveBeenCalledWith("policy-management", {
			body: expect.objectContaining({
				action: "save_document_draft",
				tenant_id: TEAM_ID,
				content: STORED_POLICY,
				expected_document: {
					id: POLICY_ROW_ID,
					version: 1,
					source_sha256: policySourceHash(STORED_POLICY),
				},
			}),
		});
		expect(mocks.teamPolicies.select).toHaveBeenCalledTimes(1);
		expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
		expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
		expect(mocks.teamPolicies.delete).not.toHaveBeenCalled();
	});

	it("reports a rejected write instead of a successful save", async () => {
		installDashboardMocks({
			role: "admin",
			policySaveResponse: { data: { error: "policy_document_save_failed" }, error: null },
		});

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/Policy was not saved:.*policy_document_save_failed/,
			),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
	});

	it("does not claim a save when the server returns no source row", async () => {
		installDashboardMocks({
			role: "admin",
			policySaveResponse: { data: { ok: true }, error: null },
		});

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/Policy was not saved:.*policy_document_save_unconfirmed/,
			),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
	});

	it("keeps the loaded revision and draft after a 409 conflict", async () => {
		const mocks = installDashboardMocks({
			policyRow: {
				id: POLICY_ROW_ID,
				content: STORED_POLICY,
				updated_at: "2026-01-02T00:00:00.000Z",
			},
			policySaveResponse: {
				data: null,
				error: { context: { json: async () => ({ error: "policy_document_conflict" }) } },
			},
		});
		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("Block shell execution")).toBeInTheDocument());
		const draft = `${STORED_POLICY}# Unsaved UTF-8: güvenli 🔒\n`;
		fireEvent.change(screen.getByRole("textbox", { name: /Policy \(YAML\)/ }), {
			target: { value: draft },
		});
		fireEvent.click(saveButton());
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/stored policy changed.*reload/),
		);
		expect(screen.getByRole("textbox", { name: /Policy \(YAML\)/ })).toHaveValue(draft);
		fireEvent.click(saveButton());
		await waitFor(() => expect(saveButton()).toBeEnabled());
		const saves = mocks.invoke.mock.calls.filter(
			([, request]) => request?.body?.action === "save_document_draft",
		);
		expect(saves).toHaveLength(2);
		for (const [, request] of saves) {
			expect(request.body.content).toBe(draft);
			expect(request.body.expected_document).toEqual({
				id: POLICY_ROW_ID,
				version: 1,
				source_sha256: policySourceHash(STORED_POLICY),
			});
		}
		expect(mocks.teamPolicies.select).toHaveBeenCalledTimes(1);
		for (const method of [
			mocks.teamPolicies.insert,
			mocks.teamPolicies.update,
			mocks.teamPolicies.delete,
		])
			expect(method).not.toHaveBeenCalled();
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
	});

	it.each([
		{ label: "wrong content hash", source: { source_sha256: "a".repeat(64) } },
		{
			label: "uppercase hash",
			source: { source_sha256: policySourceHash(STORED_POLICY).toUpperCase() },
		},
		{ label: "fractional version", source: { version: 1.5 } },
		{ label: "zero version", source: { version: 0 } },
		{ label: "string version", source: { version: "2" } },
		{ label: "unchanged version", source: { version: 1 } },
		{ label: "wrong row id", source: { id: "66666666-6666-4666-8666-666666666666" } },
		{ label: "malformed row id", source: { id: "different-row" } },
		{ label: "invalid update timestamp", source: { updated_at: "not-a-date" } },
	])("rejects an unconfirmed save with $label", async ({ source }) => {
		const mocks = installDashboardMocks({
			policyRow: {
				id: POLICY_ROW_ID,
				content: STORED_POLICY,
				updated_at: "2026-01-02T00:00:00.000Z",
			},
			policySaveResponse: {
				data: {
					ok: true,
					source: {
						id: POLICY_ROW_ID,
						version: 2,
						source_sha256: policySourceHash(STORED_POLICY),
						updated_at: "2026-01-03T00:00:00.000Z",
						...source,
					},
				},
				error: null,
			},
		});
		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("Block shell execution")).toBeInTheDocument());
		fireEvent.click(saveButton());
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/policy_document_save_unconfirmed/),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
		for (const method of [
			mocks.teamPolicies.insert,
			mocks.teamPolicies.update,
			mocks.teamPolicies.delete,
		])
			expect(method).not.toHaveBeenCalled();
	});

	it("rejects an invocation error even when its data claims success", async () => {
		installDashboardMocks({
			policySaveResponse: { data: { ok: true }, error: new Error("policy_document_save_failed") },
		});
		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());
		fireEvent.click(saveButton());
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/policy_document_save_failed/),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
	});

	it("refuses to overwrite a stored policy it could not read", async () => {
		const mocks = installDashboardMocks({
			role: "admin",
			policyReadError: { message: "permission denied for table team_policies" },
		});

		renderPolicyRoute();

		await waitFor(() =>
			expect(screen.getByText("Stored policy could not be loaded.")).toBeInTheDocument(),
		);
		expect(screen.getByRole("alert")).toHaveTextContent("Failed to load policy");
		expect(screen.getByRole("alert")).not.toHaveTextContent("team_policies");
		expect(
			screen.getByText(/Saving is disabled until the stored policy can be read/),
		).toBeInTheDocument();
		expect(saveButton()).toBeDisabled();

		fireEvent.click(saveButton());

		expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
		expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
	});

	it("does not turn a loaded row with missing revision metadata into a first draft", async () => {
		const mocks = installDashboardMocks({
			policyRow: {
				id: POLICY_ROW_ID,
				content: STORED_POLICY,
				version: undefined,
				source_sha256: undefined,
			},
		});
		renderPolicyRoute();
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/Stored policy revision is invalid/),
		);
		expect(saveButton()).toBeDisabled();
		fireEvent.click(saveButton());
		expect(
			mocks.invoke.mock.calls.some(
				([, request]) => request?.body?.action === "save_document_draft",
			),
		).toBe(false);
		for (const method of [
			mocks.teamPolicies.insert,
			mocks.teamPolicies.update,
			mocks.teamPolicies.delete,
		])
			expect(method).not.toHaveBeenCalled();
	});

	it("does not issue a save when exact-byte hash verification is unavailable", async () => {
		const mocks = installDashboardMocks();
		vi.stubGlobal("crypto", {});
		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());
		fireEvent.click(saveButton());
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/Policy was not saved/),
		);
		expect(
			mocks.invoke.mock.calls.some(
				([, request]) => request?.body?.action === "save_document_draft",
			),
		).toBe(false);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
	});

	it("shows a viewer the permission boundary instead of the editor", async () => {
		const mocks = installDashboardMocks({ role: "viewer" });

		renderPolicyRoute();

		await waitFor(() =>
			expect(screen.getByText(/don't have permission to edit team policies/)).toBeInTheDocument(),
		);
		expect(screen.queryByRole("textbox", { name: /Policy \(YAML\)/ })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: /Save Policy/ })).not.toBeInTheDocument();
		expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
		expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
	});

	it("shows a user without a team why there is nothing to author", async () => {
		installDashboardMocks({ role: null, members: [] });

		renderPolicyRoute();

		await waitFor(() => expect(screen.getByText(/no team policy to author/)).toBeInTheDocument());
		expect(screen.queryByRole("textbox", { name: /Policy \(YAML\)/ })).not.toBeInTheDocument();
	});

	it("renders the enforcement-consumption boundary rather than implying the policy is live", async () => {
		installDashboardMocks({ role: "admin" });

		renderPolicyRoute();

		await waitFor(() =>
			expect(
				screen.getByText("Saved YAML is compiled before it can become runtime policy."),
			).toBeInTheDocument(),
		);
		expect(screen.getByText(/Publication alone does not confirm every agent/)).toBeInTheDocument();
	});

	it("asks for a saved YAML draft when the dry run has no source", async () => {
		const mocks = installDashboardMocks({ role: "admin" });
		renderPolicyRoute();
		const compile = await screen.findByRole("button", { name: "Compile saved YAML (dry run)" });
		await waitFor(() => expect(compile).toBeEnabled());
		mocks.invoke.mockResolvedValueOnce({
			data: null,
			error: {
				context: new Response(JSON.stringify({ error: "policy_document_not_found" }), {
					status: 404,
					headers: { "content-type": "application/json" },
				}),
			},
		});

		fireEvent.click(compile);
		await waitFor(() =>
			expect(
				screen.getByText(
					"Save a YAML draft in the Security Policy Editor first, then run the dry run.",
				),
			).toBeInTheDocument(),
		);
		expect(screen.getByRole("button", { name: "Compile and publish saved YAML" })).toBeDisabled();
	});

	it("loads a server-compiled dry run and exposes the unknown-MCP simulation", async () => {
		const mocks = installDashboardMocks({ role: "admin" });
		renderPolicyRoute();
		const compile = await screen.findByRole("button", { name: "Compile saved YAML (dry run)" });
		await waitFor(() => expect(compile).toBeEnabled());
		const publish = screen.getByRole("button", { name: "Compile and publish saved YAML" });
		expect(publish).toBeDisabled();
		const reviewedSource = {
			id: POLICY_ROW_ID,
			version: 4,
			source_sha256: policySourceHash(STORED_POLICY),
		};
		mocks.invoke.mockResolvedValueOnce({
			data: {
				ok: true,
				dry_run: true,
				source: { ...reviewedSource, updated_at: "2026-01-02T00:00:00.000Z" },
				runtime_policy: { command_default: "deny", mcp_unknown: "ask" },
				semantics: { precedence: ["deny", "ask", "allow"] },
				diagnostics: [],
				simulation: { action: "ask", source: "mcp_unknown", matched: null },
			},
			error: null,
		});

		fireEvent.click(compile);

		await waitFor(() =>
			expect(screen.getByText(/Unknown MCP simulation: ask \(mcp_unknown\)/)).toBeInTheDocument(),
		);
		expect(
			(screen.getByRole("textbox", { name: "Runtime controls (JSON)" }) as HTMLTextAreaElement)
				.value,
		).toContain('"command_default": "deny"');
		await waitFor(() => expect(publish).toBeEnabled());
		expect(mocks.invoke).toHaveBeenCalledWith("policy-management", {
			body: expect.objectContaining({
				action: "compile_document",
				tenant_id: TEAM_ID,
				simulation: {
					kind: "mcp",
					server: "unregistered-preview",
					tool: "call",
					inventory: "unknown",
				},
			}),
		});

		mocks.invoke.mockResolvedValueOnce({
			data: {
				ok: true,
				version: 1,
				policy: { command_default: "deny", mcp_unknown: "ask" },
				compiled_from: { ...reviewedSource, updated_at: "2026-01-02T00:00:00.000Z" },
			},
			error: null,
		});
		fireEvent.click(publish);
		await waitFor(() =>
			expect(
				screen.getByText(/Saved YAML compiled and published as version 1/),
			).toBeInTheDocument(),
		);
		expect(mocks.invoke).toHaveBeenCalledWith("policy-management", {
			body: expect.objectContaining({
				action: "publish_document",
				tenant_id: TEAM_ID,
				expected_document: reviewedSource,
			}),
		});
	});
});

describe("Policy editor wire contract", () => {
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("never directly mutates team_policies from the browser", () => {
		const source = readFileSync(
			resolve(REPO_ROOT, "packages/dashboard/src/enterprise/policy-editor.tsx"),
			"utf8",
		);
		// Browser policy writes and compensating rollbacks must never return.
		const code = source
			.split("\n")
			.filter((line) => !line.trim().startsWith("//"))
			.map((line) => line.replace(/\s\/\/.*$/, ""))
			.join("\n");
		expect(code).not.toContain('onConflict: "team_id"');
		for (const mutation of [".upsert(", ".insert(", ".update(", ".delete("]) {
			expect(code).not.toContain(mutation);
		}
		expect(code).toContain('action: "save_document_draft"');
	});
});
