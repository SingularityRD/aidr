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
// It also pins the honest save contract: the write must match the schema that
// actually exists (no `onConflict: "team_id"` — public.team_policies has no
// unique constraint on team_id) and a rejected or unconfirmed write must never
// be reported as "Policy saved successfully".

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
	ADMIN_USER_ID,
	installDashboardMocks,
	POLICY_ROW_ID,
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
	afterEach(cleanup);

	it("registers /policies through the console shell behind the session loader", () => {
		const start = MAIN_TSX.indexOf('path: "/policies"');
		expect(start, 'main.tsx does not register path: "/policies"').toBeGreaterThan(-1);
		const block = MAIN_TSX.slice(start, start + 320);
		expect(block).toContain("<AppLayout />");
		expect(block).toContain("loader: requireSessionLoader");
		expect(block).toContain("<PolicyPage />");
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
			expect(
				screen.getByRole("heading", { name: "Security Policy Editor" }),
			).toBeInTheDocument(),
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
			policyRow: { id: POLICY_ROW_ID, content: STORED_POLICY, updated_at: "2026-01-02T00:00:00.000Z" },
		});

		renderPolicyRoute();

		await waitFor(() =>
			expect(screen.getByText("Block shell execution")).toBeInTheDocument(),
		);
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

	it("saves a new policy row with the tenant and author the schema requires", async () => {
		const mocks = installDashboardMocks({ role: "admin" });

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByText("Policy saved successfully")).toBeInTheDocument(),
		);
		expect(mocks.teamPolicies.insert).toHaveBeenCalledTimes(1);
		expect(mocks.teamPolicies.insert).toHaveBeenCalledWith(
			expect.objectContaining({
				team_id: TEAM_ID,
				tenant_id: TEAM_ID,
				updated_by: ADMIN_USER_ID,
				content: expect.stringContaining("default_action"),
			}),
		);
		expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
	});

	it("updates the existing policy row instead of upserting on a non-unique column", async () => {
		const mocks = installDashboardMocks({
			role: "admin",
			policyRow: { id: POLICY_ROW_ID, content: STORED_POLICY, updated_at: "2026-01-02T00:00:00.000Z" },
		});

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("Block shell execution")).toBeInTheDocument());

		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByText("Policy saved successfully")).toBeInTheDocument(),
		);
		// public.team_policies has no unique constraint on team_id, so an upsert
		// with onConflict: "team_id" fails with 42P10 on every save.
		expect(mocks.teamPolicies.update).toHaveBeenCalledWith(
			expect.objectContaining({ tenant_id: TEAM_ID, updated_by: ADMIN_USER_ID }),
		);
		expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
	});

	it("reports a rejected write instead of a successful save", async () => {
		installDashboardMocks({
			role: "admin",
			policyWriteError: { message: "new row violates row-level security policy" },
		});

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/Policy was not saved: new row violates row-level security policy/,
			),
		);
		expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
	});

	it("does not claim a save when the database stored no row", async () => {
		installDashboardMocks({ role: "admin", policyWriteRows: null });

		renderPolicyRoute();
		await waitFor(() => expect(screen.getByText("✓ Valid policy")).toBeInTheDocument());

		fireEvent.click(saveButton());

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/Policy was not saved: the database did not store any policy row/,
			),
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
		expect(screen.getByRole("alert")).toHaveTextContent(
			"permission denied for table team_policies",
		);
		expect(screen.getByText(/Saving is disabled until the stored policy can be read/)).toBeInTheDocument();
		expect(saveButton()).toBeDisabled();

		fireEvent.click(saveButton());

		expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
		expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
	});

	it("shows a viewer the permission boundary instead of the editor", async () => {
		const mocks = installDashboardMocks({ role: "viewer" });

		renderPolicyRoute();

		await waitFor(() =>
			expect(
				screen.getByText(/don't have permission to edit team policies/),
			).toBeInTheDocument(),
		);
		expect(screen.queryByRole("textbox", { name: /Policy \(YAML\)/ })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: /Save Policy/ })).not.toBeInTheDocument();
		expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
		expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
	});

	it("shows a user without a team why there is nothing to author", async () => {
		installDashboardMocks({ role: null, members: [] });

		renderPolicyRoute();

		await waitFor(() =>
			expect(screen.getByText(/no team policy to author/)).toBeInTheDocument(),
		);
		expect(screen.queryByRole("textbox", { name: /Policy \(YAML\)/ })).not.toBeInTheDocument();
	});

	it("renders the enforcement-consumption boundary rather than implying the policy is live", async () => {
		installDashboardMocks({ role: "admin" });

		renderPolicyRoute();

		await waitFor(() =>
				expect(screen.getByText("Saved YAML is compiled before it can become runtime policy.")).toBeInTheDocument(),
		);
		expect(screen.getByText(/Publication alone does not confirm every agent/)).toBeInTheDocument();
	});

	it("loads a server-compiled dry run and exposes the unknown-MCP simulation", async () => {
		const mocks = installDashboardMocks({ role: "admin" });
		renderPolicyRoute();
		const compile = await screen.findByRole("button", { name: "Compile saved YAML (dry run)" });
		await waitFor(() => expect(compile).toBeEnabled());
		mocks.invoke.mockResolvedValueOnce({
			data: {
				ok: true,
				dry_run: true,
				runtime_policy: { command_default: "deny", mcp_unknown: "ask" },
				semantics: { precedence: ["deny", "ask", "allow"] },
				diagnostics: [],
				simulation: { action: "ask", source: "mcp_unknown", matched: null },
			},
			error: null,
		});

		fireEvent.click(compile);

		await waitFor(() => expect(screen.getByText(/Unknown MCP simulation: ask \(mcp_unknown\)/)).toBeInTheDocument());
		expect((screen.getByRole("textbox", { name: "Runtime controls (JSON)" }) as HTMLTextAreaElement).value).toContain('"command_default": "deny"');
		expect(mocks.invoke).toHaveBeenCalledWith("policy-management", {
			body: expect.objectContaining({ action: "compile_document", tenant_id: TEAM_ID, simulation: { kind: "mcp", server: "unregistered-preview", tool: "call", inventory: "unknown" } }),
		});
	});
});

describe("Policy editor wire contract", () => {
	afterEach(cleanup);

	it("does not use an upsert on team_id, which public.team_policies cannot satisfy", () => {
		const source = readFileSync(
			resolve(REPO_ROOT, "packages/dashboard/src/enterprise/policy-editor.tsx"),
			"utf8",
		);
		// Comments explaining the removal are fine; executable code must not
		// reintroduce the upsert.
		const code = source
			.split("\n")
			.filter((line) => !line.trim().startsWith("//"))
			.map((line) => line.replace(/\s\/\/.*$/, ""))
			.join("\n");
		expect(code).not.toContain('onConflict: "team_id"');
		expect(code).not.toContain(".upsert(");
	});
});
