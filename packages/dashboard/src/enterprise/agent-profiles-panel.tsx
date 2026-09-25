/**
 * Agent permission profiles — read-only view in the Policy area.
 *
 * Profiles are enforced by every connector from two sources: the operator's
 * local `agent-profiles.json` and, in managed mode, the Ed25519-signed tenant
 * detector bundle. The control plane does not store or sign profiles (the
 * signing key stays with the operator), so this panel does not edit them. It
 * shows the shipped templates, how to publish a signed profile, and the real
 * profile decisions agents have reported.
 */
import { useEffect, useMemo, useState } from "react";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import {
	PROFILE_CHECK_LABELS,
	PROFILE_TEMPLATE_SUMMARIES,
	PROFILE_TOOL_CLASSES,
} from "./agent-profile-templates";
import { useTeam } from "./team-provider";

const RECENT_LIMIT = 200;
const ACTION_LABELS = { allow: "Allow", ask: "Ask", deny: "Deny" } as const;
const DECISIONS_UNAVAILABLE = "Recent profile decisions are unavailable.";

export interface ProfileDecisionRow {
	id: string;
	createdAt: string;
	agentId: string | null;
	toolName: string;
	decision: "ask" | "deny";
	check: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}

/** Accept only rows the engine reports for a profile decision; drop anything else. */
export function parseProfileDecisionRow(row: unknown): ProfileDecisionRow | null {
	if (!isRecord(row) || !isRecord(row.payload)) return null;
	const payload = row.payload;
	const decision = payload.verdict;
	const check = payload.matched_threat_id;
	if (payload.source !== "agent_profile") return null;
	if (decision !== "ask" && decision !== "deny") return null;
	if (typeof check !== "string" || !/^AGENT-PROFILE-[A-Z]+$/.test(check)) return null;
	if (typeof row.id !== "string" && typeof row.id !== "number") return null;
	if (typeof row.created_at !== "string") return null;
	return {
		id: String(row.id),
		createdAt: row.created_at,
		agentId: typeof row.agent_id === "string" ? row.agent_id : null,
		toolName: typeof payload.tool_name === "string" ? payload.tool_name : "unknown",
		decision,
		check,
	};
}

type Load =
	| { state: "loading" }
	| { state: "error"; message: string }
	| { state: "ready"; rows: ProfileDecisionRow[]; agents: Map<string, string> };

async function loadDecisions(tenantId: string): Promise<Load> {
	try {
		const [events, agents] = await Promise.all([
			supabase
				.from("events")
				.select("id,created_at,agent_id,payload")
				.eq("tenant_id", tenantId)
				.eq("type", "runtime_verdict")
				.eq("payload->>source", "agent_profile")
				.order("created_at", { ascending: false })
				.limit(RECENT_LIMIT),
			supabase.from("agents").select("id,iid,display_name").eq("tenant_id", tenantId),
		]);
		if (events.error || !Array.isArray(events.data)) {
			return { state: "error", message: readErrorMessage(events.error, DECISIONS_UNAVAILABLE) };
		}
		const names = new Map<string, string>();
		if (!agents.error && Array.isArray(agents.data)) {
			for (const agent of agents.data as Array<Record<string, unknown>>) {
				if (typeof agent.id !== "string") continue;
				const label =
					(typeof agent.display_name === "string" && agent.display_name) ||
					(typeof agent.iid === "string" && agent.iid) ||
					agent.id;
				names.set(agent.id, label);
			}
		}
		const rows = events.data
			.map(parseProfileDecisionRow)
			.filter((row): row is ProfileDecisionRow => row !== null);
		return { state: "ready", rows, agents: names };
	} catch (cause) {
		return { state: "error", message: readErrorMessage(cause, DECISIONS_UNAVAILABLE) };
	}
}

const PUBLISH_COMMAND = `aidr profile validate agent-profiles.json
node scripts/provision-agent-profiles.mjs --tenant <tenant-id> --runtime <claude-code|cursor|vscode|openclaw|opencode|codex> \\
  --profiles agent-profiles.json --expires-at <UTC time within 24h> \\
  --private-key <publisher-ed25519.pem> --output-dir ~/.singularity-aidr/detectors`;

function DecisionSummary({ rows }: { rows: ProfileDecisionRow[] }) {
	const byCheck = useMemo(() => {
		const counts = new Map<string, { deny: number; ask: number }>();
		for (const row of rows) {
			const entry = counts.get(row.check) ?? { deny: 0, ask: 0 };
			entry[row.decision] += 1;
			counts.set(row.check, entry);
		}
		return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b));
	}, [rows]);
	return (
		<div className="table-wrap">
			<table className="table" aria-label="Profile decisions by rule family">
				<thead>
					<tr>
						<th>Rule family</th>
						<th>Denied</th>
						<th>Held for approval</th>
					</tr>
				</thead>
				<tbody>
					{byCheck.map(([check, counts]) => (
						<tr key={check}>
							<td>{PROFILE_CHECK_LABELS[check] ?? check}</td>
							<td>{counts.deny}</td>
							<td>{counts.ask}</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

export function AgentProfilesPanel() {
	const { currentTeam } = useTeam();
	const tenantId = currentTeam?.id ?? null;
	const [load, setLoad] = useState<Load>({ state: "loading" });

	useEffect(() => {
		if (!tenantId) return;
		let cancelled = false;
		setLoad({ state: "loading" });
		void loadDecisions(tenantId).then((result) => {
			if (!cancelled) setLoad(result);
		});
		return () => {
			cancelled = true;
		};
	}, [tenantId]);

	return (
		<section className="card stack" aria-labelledby="agent-profiles-heading">
			<div>
				<div className="pill" style={{ marginBottom: 8 }}>
					Least privilege
				</div>
				<h2 id="agent-profiles-heading">Agent permission profiles</h2>
				<p className="muted" style={{ maxWidth: 760 }}>
					A profile limits what one agent may do — which tools, command prefixes, file paths,
					network domains and MCP servers or tools — per connector and optionally per repository.
					Profiles only add restrictions: threat detection still runs, and a profile never overrides
					a threat block (deny &gt; ask &gt; allow).
				</p>
			</div>

			<div className="notice notice-warning" role="status">
				<b>Profiles are published as signed bundles, not from this page.</b>
				<div className="muted small" style={{ marginTop: 6 }}>
					The signing key stays with your policy administrator, so the dashboard only shows
					templates and what agents report. A managed profile overrides the agent's local profile
					file, which can only narrow it. A broken managed profile blocks every call on that
					connector until it is fixed.
				</div>
			</div>

			<div>
				<h3>Shipped templates</h3>
				<div className="table-wrap">
					<table className="table" aria-label="Agent permission profile templates">
						<thead>
							<tr>
								<th>Template</th>
								<th>Default</th>
								{PROFILE_TOOL_CLASSES.map((toolClass) => (
									<th key={toolClass}>{toolClass.replace("_", " ")}</th>
								))}
							</tr>
						</thead>
						<tbody>
							{PROFILE_TEMPLATE_SUMMARIES.map((template) => (
								<tr key={template.name}>
									<td>
										<code>{template.name}</code>
										<div className="muted small">{template.description}</div>
									</td>
									<td>{ACTION_LABELS[template.default]}</td>
									{PROFILE_TOOL_CLASSES.map((toolClass) => (
										<td key={toolClass}>{ACTION_LABELS[template.tools[toolClass]]}</td>
									))}
								</tr>
							))}
						</tbody>
					</table>
				</div>
				<p className="muted small">
					Print one with <code>aidr profile show &lt;template&gt; --template</code>, scope it with{" "}
					<code>applies_to</code>, and dry-run calls with <code>aidr profile test</code>.
				</p>
			</div>

			<div>
				<h3>Publish a signed profile</h3>
				<pre
					className="mono small"
					aria-label="Signed profile publishing commands"
					style={{ overflowX: "auto" }}
				>
					{PUBLISH_COMMAND}
				</pre>
				<p className="muted small">
					Run on the publishing host for each connector runtime. The bundle keeps any DLP policy
					already signed for the same tenant. Confirm adoption on the agent with{" "}
					<code>aidr doctor</code>.
				</p>
			</div>

			<div>
				<h3>Recent profile decisions</h3>
				{!tenantId ? (
					<p className="muted">Select a managed tenant to see reported profile decisions.</p>
				) : load.state === "loading" ? (
					<p role="status">Loading profile decisions…</p>
				) : load.state === "error" ? (
					<p role="alert">{load.message}</p>
				) : load.rows.length === 0 ? (
					<p className="muted">
						No agent has reported a profile decision yet. Decisions appear here once enrolled agents
						with a profile block or hold a call.
					</p>
				) : (
					<>
						<DecisionSummary rows={load.rows} />
						<div className="table-wrap">
							<table className="table" aria-label="Recent profile decisions">
								<thead>
									<tr>
										<th>Time</th>
										<th>Agent</th>
										<th>Tool</th>
										<th>Decision</th>
										<th>Rule family</th>
									</tr>
								</thead>
								<tbody>
									{load.rows.slice(0, 25).map((row) => (
										<tr key={row.id}>
											<td>{new Date(row.createdAt).toLocaleString()}</td>
											<td>{row.agentId ? (load.agents.get(row.agentId) ?? row.agentId) : "—"}</td>
											<td>
												<code>{row.toolName}</code>
											</td>
											<td>{row.decision === "deny" ? "Denied" : "Held for approval"}</td>
											<td>{PROFILE_CHECK_LABELS[row.check] ?? row.check}</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					</>
				)}
			</div>
		</section>
	);
}
