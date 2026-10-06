// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PolicyRollout } from "../enterprise/policy-rollout";
import { supabase } from "../lib/supabase";

const team = vi.hoisted(() => ({ currentTeam: { id: "team-a" }, canManageTeam: true }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: () => team }));
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: vi.fn() } } }));
const invoke = vi.mocked(supabase.functions.invoke);
const controls = { mcp_unknown: "deny" };
const agent = { id: "agent-a", iid: "workstation", display_name: "Finance laptop", target_version: 3, loaded_version: null, received_at: null, state: "unknown" };
const rolloutProgress = { ok: true, status: "none", version: null, rollout_progress: { targeted: 0, current: 0, stale: 0, unknown: 0 } };
const onChanged = vi.fn(), onReview = vi.fn();
function view() { return render(<PolicyRollout version={3} draft={JSON.stringify(controls)} onChanged={onChanged} onReview={onReview} />); }

beforeEach(() => {
  vi.clearAllMocks(); team.canManageTeam = true; team.currentTeam = { id: "team-a" };
  invoke.mockImplementation(async (_name, options) => {
    const action = (options?.body as { action?: string })?.action;
    return { error: null, data: action === "adoption" ? { ok: true, agents: [agent] } : action === "history" ? { ok: true, revisions: [{ version: 3, policy: controls, created_at: "2026-09-11T13:00:00Z" }, { version: 2, policy: controls, created_at: "2026-09-11T12:00:00Z" }] } : action === "rollout_progress" ? rolloutProgress : { ok: true, version: 4, target_count: 1 } };
  });
});
afterEach(cleanup);
describe("Policy rollout operator flow", () => {
  it("explains the ordered rollout request and selection limits", () => {
    view();
    expect(
      screen.getByText(/up to 1,667 agents per request and must fit within 64 KB/),
    ).toBeInTheDocument();
    expect(screen.getByText(/stages up to 200 selected agents at a time/)).toBeInTheDocument();
  });
  it("keeps missing receipts unknown and stages only selected agents with optimistic concurrency", async () => {
    view(); await screen.findByText("Finance laptop"); expect(screen.getByText("Unknown")).toBeInTheDocument();
    const stage = screen.getByRole("button", { name: /Stage current draft/ }); expect(stage).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox")); fireEvent.click(stage);
    await screen.findByText(/Version 4 assigned to 1 selected agents/);
    expect(invoke).toHaveBeenCalledWith("policy-management", { body: { action: "stage", tenant_id: "team-a", expected_version: 3, expected_revision_version: 3, agent_ids: ["agent-a"], policy: controls } });
    expect(onChanged).not.toHaveBeenCalled();
  });
  it("uses the newest staged revision rather than the tenant-wide version as its stage precondition", async () => {
    invoke.mockImplementation(async (_name, options) => {
      const action = (options?.body as { action?: string })?.action;
      return { error: null, data: action === "adoption" ? { ok: true, agents: [agent] } : action === "history" ? { ok: true, revisions: [{ version: 7, policy: controls, created_at: "2026-09-11T13:00:00Z" }] } : action === "rollout_progress" ? rolloutProgress : { ok: true, version: 8, target_count: 1 } };
    });
    view(); await screen.findByText("Finance laptop");
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: /Stage current draft/ }));
    await screen.findByText(/Version 8 assigned/);
    expect(invoke).toHaveBeenCalledWith("policy-management", { body: { action: "stage", tenant_id: "team-a", expected_version: 3, expected_revision_version: 7, agent_ids: ["agent-a"], policy: controls } });
  });
  it("keeps staging disabled when revision history is unavailable", async () => {
    invoke.mockImplementation(async (_name, options) => ({ error: null, data: (options?.body as { action?: string })?.action === "adoption" ? { ok: true, agents: [agent] } : (options?.body as { action?: string })?.action === "rollout_progress" ? rolloutProgress : { ok: true, revisions: [] } }));
    view(); await screen.findByText("Finance laptop");
    fireEvent.click(screen.getByRole("checkbox"));
    expect(screen.getByRole("button", { name: /Stage current draft/ })).toBeDisabled();
  });
  it("reviews a historical revision and republishes through the guarded restore API", async () => {
    view(); fireEvent.click(await screen.findByRole("button", { name: "Review version 2" })); expect(onReview).toHaveBeenCalledWith(controls);
    fireEvent.click(screen.getByRole("button", { name: "Publish version 2 to all enrolled agents" }));
    await screen.findByText(/Revision 2 republished as version 4/);
    expect(invoke).toHaveBeenCalledWith("policy-management", { body: { action: "restore", tenant_id: "team-a", expected_version: 3, target_version: 2 } });
    expect(onChanged).toHaveBeenCalledOnce();
  });
  it("prevents a viewer from staging or publishing", async () => {
    team.canManageTeam = false; view(); await screen.findByText("Finance laptop");
    expect(screen.getByRole("checkbox")).toBeDisabled();
    expect(screen.getByRole("button", { name: /Stage current draft/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Start ordered canary rollout/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Publish version 2 to all enrolled agents" })).toBeDisabled();
  });
  it("starts a canary before the rest and shows only reported-load progress", async () => {
    const canary = { ...agent, id: "11111111-1111-4111-8111-111111111111" };
    const follower = { ...agent, id: "22222222-2222-4222-8222-222222222222", iid: "runner", display_name: "Build runner" };
    invoke.mockImplementation(async (_name, options) => {
      const action = (options?.body as { action?: string })?.action;
      return { error: null, data: action === "adoption" ? { ok: true, agents: [canary, follower] }
        : action === "history" ? { ok: true, revisions: [{ version: 3, policy: controls, created_at: "2026-09-11T13:00:00Z" }] }
        : action === "rollout_progress" ? { ok: true, status: "running", version: 4, rollout_progress: { targeted: 2, current: 1, stale: 0, outdated: 0, unknown: 1 } }
        : { ok: true, version: 4, rollout_id: "33333333-3333-4333-8333-333333333333" } };
    });
    view(); await screen.findByText("Build runner");
    expect(screen.getByText(/agent-reported loads 1\/2 current/)).toBeInTheDocument();
    expect(screen.getByText(/not host-enforcement attestation/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("checkbox", { name: "Stage policy for Finance laptop" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Stage policy for Build runner" }));
    fireEvent.click(screen.getByRole("button", { name: /Start ordered canary rollout for 2/ }));
    await screen.findByText(/Ordered rollout version 4 started/);
    expect(invoke).toHaveBeenCalledWith("policy-management", { body: {
      action: "rollout", tenant_id: "team-a", expected_version: 3, expected_revision_version: 3, policy: controls,
      rings: [
        { ring_order: 1, batches: [{ batch_order: 1, agent_ids: [canary.id] }] },
        { ring_order: 2, batches: [{ batch_order: 1, agent_ids: [follower.id] }] },
      ],
    } });
  });
  it("does not hide unavailable ordered-rollout evidence behind a healthy fleet list", async () => {
    invoke.mockImplementation(async (_name, options) => {
      const action = (options?.body as { action?: string })?.action;
      if (action === "rollout_progress") return { error: new Error("offline"), data: null };
      return { error: null, data: action === "adoption" ? { ok: true, agents: [agent] } : { ok: true, revisions: [] } };
    });
    view();
    expect(await screen.findByRole("alert")).toHaveTextContent("Policy deployment status could not be loaded");
    expect(screen.queryByText("Finance laptop")).not.toBeInTheDocument();
  });
  it("does not claim success when the server rejects a concurrent update", async () => {
    view(); await screen.findByText("Finance laptop"); invoke.mockResolvedValueOnce({ data: null, error: new Error("conflict") });
    fireEvent.click(screen.getByRole("button", { name: "Publish version 2 to all enrolled agents" }));
    await screen.findByRole("alert"); expect(onChanged).not.toHaveBeenCalled();
    expect(screen.queryByText(/republished as/)).not.toBeInTheDocument();
  });
  it("clears old team receipts and ignores an in-flight response after a team switch", async () => {
    let complete!: (value: { data: unknown; error: null }) => void;
    invoke.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
    const rendered = view(); await waitFor(() => expect(invoke).toHaveBeenCalledTimes(3));
    team.currentTeam = { id: "team-b" };
    invoke.mockImplementation(async (_name, options) => ({ data: (options?.body as { action?: string })?.action === "adoption" ? { ok: true, agents: [] }
      : (options?.body as { action?: string })?.action === "rollout_progress" ? rolloutProgress : { ok: true, revisions: [] }, error: null }));
    rendered.rerender(<PolicyRollout version={3} draft="{}" onChanged={onChanged} onReview={onReview} />);
    await screen.findByText("No agent loading receipts available.");
    complete({ data: { ok: true, agents: [agent] }, error: null });
    await waitFor(() => expect(screen.queryByText("Finance laptop")).not.toBeInTheDocument());
  });
});
