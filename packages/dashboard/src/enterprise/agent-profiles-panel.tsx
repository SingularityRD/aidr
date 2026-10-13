/**
 * Agent permission profiles in the Policy area.
 *
 * Profiles are enforced by every connector from two sources: the operator's
 * local `agent-profiles.json` and, in managed mode, the Ed25519-signed tenant
 * detector bundle. The control plane validates and stages profile documents
 * (see agent-profile-editor.tsx) but never signs them: the signing key stays
 * with the operator, who publishes a staged revision with one command. The
 * panel also shows the shipped templates and the profile decisions agents
 * have reported.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import type { DashboardMessageKey } from "../i18n/en";
import { englishT, type Translate, useRichT, useT } from "../i18n/I18nProvider";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { AgentProfileEditor } from "./agent-profile-editor";
import {
	PROFILE_CHECK_LABELS,
	PROFILE_TEMPLATE_DESCRIPTIONS,
	PROFILE_TEMPLATE_SUMMARIES,
	PROFILE_TOOL_CLASS_LABELS,
	PROFILE_TOOL_CLASSES,
} from "./agent-profile-templates";
import { useTeam } from "./team-provider";

const RECENT_LIMIT = 200;
const ACTION_LABELS = {
	allow: "ap.action.allow",
	ask: "ap.action.ask",
	deny: "ap.action.deny",
} as const satisfies Record<string, DashboardMessageKey>;

/** A rule family in the viewer's language; an unknown family is shown as reported. */
function checkLabel(check: string, t: Translate): string {
	const key = Object.hasOwn(PROFILE_CHECK_LABELS, check) ? PROFILE_CHECK_LABELS[check] : undefined;
	return key ? t(key) : check;
}

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

async function loadDecisions(tenantId: string, t: Translate = englishT): Promise<Load> {
	const unavailable = t("ap.decisionsUnavailable");
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
			return { state: "error", message: readErrorMessage(events.error, unavailable) };
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
		return { state: "error", message: readErrorMessage(cause, unavailable) };
	}
}

function DecisionSummary({ rows }: { rows: ProfileDecisionRow[] }) {
	const t = useT();
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
			<table className="table" aria-label={t("ap.byFamily")}>
				<thead>
					<tr>
						<th>{t("ap.col.family")}</th>
						<th>{t("ap.col.denied")}</th>
						<th>{t("ap.col.held")}</th>
					</tr>
				</thead>
				<tbody>
					{byCheck.map(([check, counts]) => (
						<tr key={check}>
							<td>{checkLabel(check, t)}</td>
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
	const t = useT();
	const richT = useRichT();
	// The loader reads the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
	const { currentTeam, canManageTeam } = useTeam();
	const tenantId = currentTeam?.id ?? null;
	const [load, setLoad] = useState<Load>({ state: "loading" });

	useEffect(() => {
		if (!tenantId) return;
		let cancelled = false;
		setLoad({ state: "loading" });
		void loadDecisions(tenantId, translator.current).then((result) => {
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
					{t("ap.eyebrow")}
				</div>
				<h2 id="agent-profiles-heading">{t("ap.title")}</h2>
				<p className="muted" style={{ maxWidth: 760 }}>
					{t("ap.lead")}
				</p>
			</div>

			<div className="notice notice-warning" role="status">
				<b>{t("ap.stagedTitle")}</b>
				<div className="muted small" style={{ marginTop: 6 }}>
					{t("ap.stagedBody")}
				</div>
			</div>

			<div>
				<h3>{t("ap.editTitle")}</h3>
				{tenantId ? (
					<AgentProfileEditor tenantId={tenantId} canManage={canManageTeam === true} />
				) : (
					<p className="muted">{t("ap.selectTenantEdit")}</p>
				)}
			</div>

			<div>
				<h3>{t("ap.templates")}</h3>
				<div className="table-wrap">
					<table className="table" aria-label={t("ap.templatesLabel")}>
						<thead>
							<tr>
								<th>{t("ap.col.template")}</th>
								<th>{t("ap.col.default")}</th>
								{PROFILE_TOOL_CLASSES.map((toolClass) => (
									<th key={toolClass}>{t(PROFILE_TOOL_CLASS_LABELS[toolClass])}</th>
								))}
							</tr>
						</thead>
						<tbody>
							{PROFILE_TEMPLATE_SUMMARIES.map((template) => (
								<tr key={template.name}>
									<td>
										<code>{template.name}</code>
										<div className="muted small">
											{Object.hasOwn(PROFILE_TEMPLATE_DESCRIPTIONS, template.name)
												? t(PROFILE_TEMPLATE_DESCRIPTIONS[template.name] as DashboardMessageKey)
												: template.description}
										</div>
									</td>
									<td>{t(ACTION_LABELS[template.default])}</td>
									{PROFILE_TOOL_CLASSES.map((toolClass) => (
										<td key={toolClass}>{t(ACTION_LABELS[template.tools[toolClass]])}</td>
									))}
								</tr>
							))}
						</tbody>
					</table>
				</div>
				<p className="muted small">
					{richT("ap.templatesHint", {
						show: <code>aidr profile show &lt;template&gt; --template</code>,
						applies: <code>applies_to</code>,
						test: <code>aidr profile test</code>,
					})}
				</p>
			</div>

			<div>
				<h3>{t("ap.recent")}</h3>
				{!tenantId ? (
					<p className="muted">{t("ap.selectTenantDecisions")}</p>
				) : load.state === "loading" ? (
					<p role="status">{t("ap.loadingDecisions")}</p>
				) : load.state === "error" ? (
					<p role="alert">{load.message}</p>
				) : load.rows.length === 0 ? (
					<p className="muted">{t("ap.noDecisions")}</p>
				) : (
					<>
						<DecisionSummary rows={load.rows} />
						<div className="table-wrap">
							<table className="table" aria-label={t("ap.recentLabel")}>
								<thead>
									<tr>
										<th>{t("ap.col.time")}</th>
										<th>{t("ap.col.agent")}</th>
										<th>{t("ap.col.tool")}</th>
										<th>{t("ap.col.decision")}</th>
										<th>{t("ap.col.family")}</th>
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
											<td>{row.decision === "deny" ? t("ap.col.denied") : t("ap.col.held")}</td>
											<td>{checkLabel(row.check, t)}</td>
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
