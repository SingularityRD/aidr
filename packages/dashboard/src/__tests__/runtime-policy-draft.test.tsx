// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RuntimePolicyEditor } from "../enterprise/runtime-policy-editor";
import { supabase } from "../lib/supabase";

vi.mock("../enterprise/team-provider", () => ({
	useTeam: () => ({ currentTeam: team, canManageTeam: true }),
}));
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: vi.fn() } } }));
const team = { id: "11111111-1111-4111-8111-111111111111" };
const invoke = vi.mocked(supabase.functions.invoke);
const published = { mcp_unknown: "ask" };
const draft = { mcp_unknown: "deny" };
const source = {
	id: "22222222-2222-4222-8222-222222222222",
	version: 1,
	source_sha256: "a".repeat(64),
};
const agent = {
	id: "33333333-3333-4333-8333-333333333333",
	iid: "canary",
	display_name: "Canary",
	target_version: 3,
	loaded_version: 3,
	received_at: "2026-10-05T10:00:00Z",
	state: "current",
};
let currentVersion: number;
let currentPolicy: Record<string, string>;

beforeEach(() => {
	vi.clearAllMocks();
	currentVersion = 3;
	currentPolicy = published;
	invoke.mockImplementation(async (_name, options) => {
		const action = (options?.body as { action?: string })?.action;
		if (action === "read")
			return { error: null, data: { ok: true, version: currentVersion, policy: currentPolicy } };
		if (action === "history")
			return {
				error: null,
				data: {
					ok: true,
					revisions: [{ version: 3, policy: published, created_at: "2026-10-05T10:00:00Z" }],
				},
			};
		if (action === "adoption") return { error: null, data: { ok: true, agents: [agent] } };
		if (action === "rollout_progress")
			return {
				error: null,
				data: {
					ok: true,
					status: "none",
					version: null,
					rollout_progress: { targeted: 0, current: 0, stale: 0, unknown: 0 },
				},
			};
		if (action === "compile_document")
			return { error: null, data: { ok: true, runtime_policy: draft, source } };
		if (action === "restore") {
			currentVersion = 4;
			currentPolicy = published;
		}
		return {
			error: null,
			data: {
				ok: true,
				version: 4,
				target_count: 1,
				rollout_id: "44444444-4444-4444-8444-444444444444",
			},
		};
	});
});
afterEach(cleanup);

function editor() {
	return screen.getByRole("textbox", { name: "Runtime controls (JSON)" });
}
function calls(action: string) {
	return invoke.mock.calls.filter(
		(call) => (call[1]?.body as { action?: string })?.action === action,
	);
}

describe("Runtime policy draft preservation", () => {
	it.each([
		["receipt refresh", "Refresh deployment status", false],
		["staging", "Stage current draft for 1 selected agents", true],
		["canary rollout", "Start ordered canary rollout for 1 selected agents", true],
	])("keeps a reviewed draft through %s", async (_label, button, select) => {
		render(<RuntimePolicyEditor />);
		await screen.findByText("Published version: 3");
		fireEvent.click(screen.getByRole("button", { name: "Compile saved YAML (dry run)" }));
		await screen.findByText(/Dry run compiled/);
		await screen.findByText("Canary");
		const receiptReads = calls("adoption").length;
		if (select) fireEvent.click(screen.getByRole("checkbox", { name: "Stage policy for Canary" }));
		fireEvent.click(screen.getByRole("button", { name: button }));
		await waitFor(() => expect(calls("adoption").length).toBeGreaterThan(receiptReads));
		expect(editor()).toHaveValue(JSON.stringify(draft, null, 2));
		expect(screen.getByRole("button", { name: "Compile and publish saved YAML" })).toBeEnabled();
		expect(calls("read")).toHaveLength(1);
	});

	it("preserves unsaved edits while refreshing receipts and reloads the policy after rollback", async () => {
		render(<RuntimePolicyEditor />);
		await screen.findByText("Published version: 3");
		fireEvent.change(editor(), { target: { value: JSON.stringify(draft) } });
		const receiptReads = calls("adoption").length;
		fireEvent.click(screen.getByRole("button", { name: "Refresh deployment status" }));
		await waitFor(() => expect(calls("adoption").length).toBeGreaterThan(receiptReads));
		expect(editor()).toHaveValue(JSON.stringify(draft));
		fireEvent.click(
			screen.getByRole("button", { name: "Publish version 3 to all enrolled agents" }),
		);
		await screen.findByText("Published version: 4");
		expect(editor()).toHaveValue(JSON.stringify(published, null, 2));
		expect(calls("read")).toHaveLength(2);
	});
});
