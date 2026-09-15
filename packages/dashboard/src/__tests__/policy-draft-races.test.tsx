// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const { useTeam } = vi.hoisted(() => ({ useTeam: vi.fn() }));

vi.mock("../enterprise/team-provider", () => ({ useTeam }));
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

import { PolicyEditor } from "../enterprise/policy-editor";
import {
	installDashboardMocks,
	POLICY_ROW_ID,
	policySourceHash,
	TEAM_ID,
} from "./helpers/dashboard-mocks";

const TEAM_B_ID = "66666666-6666-4666-8666-666666666666";
const TEAM_B_POLICY_ID = "77777777-7777-4777-8777-777777777777";
const STORED_AT = "2026-01-02T00:00:00.000Z";

function document(description: string): string {
	return [
		'version: "1.0"',
		`description: ${description}`,
		"default_action: ask",
		"unknown_action: deny",
		"rules:",
		"  - name: Block deletion",
		"    condition:",
		"      mcp_tool: github.delete_repository",
		"    action: deny",
		"    priority: 1",
		"",
	].join("\n");
}

function revision(content: string, version: number, id = POLICY_ROW_ID) {
	return { id, version, source_sha256: policySourceHash(content) };
}

function storedRow(content: string, version = 1) {
	return { ...revision(content, version), content, updated_at: STORED_AT };
}

function savedResponse(content: string, version: number, id = POLICY_ROW_ID) {
	return {
		data: {
			ok: true,
			source: { ...revision(content, version, id), updated_at: STORED_AT },
			diagnostics: [],
			semantics: { precedence: ["deny", "ask", "allow"] },
			simulation: { action: "deny", source: "mcp_unknown", matched: null },
		},
		error: null,
	};
}

function deferred<T>() {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((complete) => {
		resolve = complete;
	});
	return { promise, resolve };
}

function selectTeam(id: string) {
	// Return one stable object until the test deliberately switches teams.
	useTeam.mockReturnValue({
		currentTeam: { id, name: id === TEAM_ID ? "Team A" : "Team B" },
		canEditPolicy: true,
		isLoading: false,
		error: null,
	});
}

function editorView() {
	return (
		<MemoryRouter>
			<PolicyEditor />
		</MemoryRouter>
	);
}

function textarea(): HTMLTextAreaElement {
	return screen.getByRole("textbox", { name: /Policy \(YAML\)/ }) as HTMLTextAreaElement;
}

function saveButton() {
	return screen.getByRole("button", { name: /Save Policy|Saving/ });
}

function expectNoSavedVerdict() {
	expect(screen.queryByText("Policy saved successfully")).not.toBeInTheDocument();
	expect(screen.queryByText("Unsupported fields: none.")).not.toBeInTheDocument();
	expect(screen.queryByText(/Conflict precedence: deny > ask > allow/)).not.toBeInTheDocument();
	expect(screen.queryByText(/Simulated unknown MCP call:/)).not.toBeInTheDocument();
}

function expectSaveRequest(
	mocks: ReturnType<typeof installDashboardMocks>,
	call: number,
	teamId: string,
	content: string,
	expected: ReturnType<typeof revision> | null,
) {
	expect(mocks.invoke).toHaveBeenNthCalledWith(call, "policy-management", {
		body: {
			action: "save_document_draft",
			tenant_id: teamId,
			content,
			expected_document: expected,
			simulation: {
				kind: "mcp",
				server: "unregistered-preview",
				tool: "call",
				inventory: "unknown",
			},
		},
	});
	expect(mocks.teamPolicies.insert).not.toHaveBeenCalled();
	expect(mocks.teamPolicies.update).not.toHaveBeenCalled();
	expect(mocks.teamPolicies.delete).not.toHaveBeenCalled();
}

afterEach(() => {
	cleanup();
	vi.resetAllMocks();
	vi.unstubAllGlobals();
});

describe("Policy draft save races", () => {
	it("preserves newer typing without publishing an old verdict and advances the next precondition", async () => {
		const stored = document("Stored policy");
		const submitted = document("Submitted draft");
		const newer = document("Newer unsaved draft");
		const pending = deferred<ReturnType<typeof savedResponse>>();
		const mocks = installDashboardMocks({ policyRow: storedRow(stored) });
		mocks.invoke.mockReturnValueOnce(pending.promise);
		selectTeam(TEAM_ID);
		render(editorView());
		await waitFor(() => expect(textarea()).toHaveValue(stored));

		fireEvent.change(textarea(), { target: { value: submitted } });
		fireEvent.click(saveButton());
		await waitFor(() => expect(mocks.invoke).toHaveBeenCalledTimes(1));
		expectSaveRequest(mocks, 1, TEAM_ID, submitted, revision(stored, 1));
		expect(saveButton()).toBeDisabled();

		fireEvent.change(textarea(), { target: { value: newer } });
		await act(async () => {
			pending.resolve(savedResponse(submitted, 2));
			await pending.promise;
		});

		expect(textarea()).toHaveValue(newer);
		expectNoSavedVerdict();
		expect(saveButton()).toBeEnabled();

		mocks.invoke.mockResolvedValueOnce(savedResponse(newer, 3));
		fireEvent.click(saveButton());
		await waitFor(() => expect(screen.getByText("Policy saved successfully")).toBeInTheDocument());
		expect(mocks.invoke).toHaveBeenCalledTimes(2);
		expectSaveRequest(mocks, 2, TEAM_ID, newer, revision(submitted, 2));
		expect(textarea()).toHaveValue(newer);
	});

	it("ignores a late Team A save after switching to Team B and keeps B's first-save precondition null", async () => {
		const stored = document("Team A stored policy");
		const submitted = document("Team A submitted draft");
		const teamBDraft = document("Team B unsaved draft");
		const pending = deferred<ReturnType<typeof savedResponse>>();
		const mocks = installDashboardMocks({ policyRow: storedRow(stored) });
		mocks.invoke.mockReturnValueOnce(pending.promise);
		selectTeam(TEAM_ID);
		const view = render(editorView());
		await waitFor(() => expect(textarea()).toHaveValue(stored));

		fireEvent.change(textarea(), { target: { value: submitted } });
		fireEvent.click(saveButton());
		await waitFor(() => expect(mocks.invoke).toHaveBeenCalledTimes(1));
		expectSaveRequest(mocks, 1, TEAM_ID, submitted, revision(stored, 1));

		mocks.teamPolicies.select.mockReturnValueOnce(mocks.teamPolicies);
		mocks.teamPolicies.maybeSingle.mockResolvedValueOnce({ data: null, error: null });
		selectTeam(TEAM_B_ID);
		view.rerender(editorView());
		await waitFor(() => expect(saveButton()).toBeEnabled());
		fireEvent.change(textarea(), { target: { value: teamBDraft } });

		await act(async () => {
			pending.resolve(savedResponse(submitted, 2));
			await pending.promise;
		});

		expect(textarea()).toHaveValue(teamBDraft);
		expectNoSavedVerdict();
		expect(saveButton()).toBeEnabled();

		mocks.invoke.mockResolvedValueOnce(savedResponse(teamBDraft, 1, TEAM_B_POLICY_ID));
		fireEvent.click(saveButton());
		await waitFor(() => expect(screen.getByText("Policy saved successfully")).toBeInTheDocument());
		expect(mocks.invoke).toHaveBeenCalledTimes(2);
		expectSaveRequest(mocks, 2, TEAM_B_ID, teamBDraft, null);
		expect(textarea()).toHaveValue(teamBDraft);
	});

	it("ignores an old Team A save generation after switching A to B and back to A", async () => {
		const stored = document("Original Team A policy");
		const submitted = document("Old Team A submitted draft");
		const reloaded = document("Fresh Team A policy from another editor");
		const newer = document("New Team A unsaved draft");
		const pending = deferred<ReturnType<typeof savedResponse>>();
		const mocks = installDashboardMocks({ policyRow: storedRow(stored) });
		mocks.invoke.mockReturnValueOnce(pending.promise);
		selectTeam(TEAM_ID);
		const view = render(editorView());
		await waitFor(() => expect(textarea()).toHaveValue(stored));

		fireEvent.change(textarea(), { target: { value: submitted } });
		fireEvent.click(saveButton());
		await waitFor(() => expect(mocks.invoke).toHaveBeenCalledTimes(1));
		expectSaveRequest(mocks, 1, TEAM_ID, submitted, revision(stored, 1));

		mocks.teamPolicies.select.mockReturnValueOnce(mocks.teamPolicies);
		mocks.teamPolicies.maybeSingle.mockResolvedValueOnce({ data: null, error: null });
		selectTeam(TEAM_B_ID);
		view.rerender(editorView());
		await waitFor(() => expect(saveButton()).toBeEnabled());

		mocks.teamPolicies.select.mockReturnValueOnce(mocks.teamPolicies);
		mocks.teamPolicies.maybeSingle.mockResolvedValueOnce({ data: storedRow(reloaded, 4), error: null });
		selectTeam(TEAM_ID);
		view.rerender(editorView());
		await waitFor(() => expect(textarea()).toHaveValue(reloaded));

		// No further typing: only the team-load generation, not an edit counter,
		// can distinguish this request from the old save for the same team id.
		await act(async () => {
			pending.resolve(savedResponse(submitted, 2));
			await pending.promise;
		});

		expect(textarea()).toHaveValue(reloaded);
		expectNoSavedVerdict();
		expect(saveButton()).toBeEnabled();

		fireEvent.change(textarea(), { target: { value: newer } });
		mocks.invoke.mockResolvedValueOnce(savedResponse(newer, 5));
		fireEvent.click(saveButton());
		await waitFor(() => expect(screen.getByText("Policy saved successfully")).toBeInTheDocument());
		expect(mocks.invoke).toHaveBeenCalledTimes(2);
		expectSaveRequest(mocks, 2, TEAM_ID, newer, revision(reloaded, 4));
		expect(textarea()).toHaveValue(newer);
	});
});
