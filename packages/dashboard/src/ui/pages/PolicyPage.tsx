import { AgentProfilesPanel } from "../../enterprise/agent-profiles-panel";
import { DlpPolicyEditor } from "../../enterprise/dlp-editor";
import { PolicyEditor } from "../../enterprise/policy-editor";
import { RuntimePolicyEditor } from "../../enterprise/runtime-policy-editor";
import { useT } from "../../i18n/I18nProvider";

/**
 * Team policy authoring surface (AIDR-009).
 *
 * PolicyEditor already implemented load/validate/save against
 * public.team_policies but had no route. The editor gates itself on
 * canEditPolicy (owner/admin/member) and the database repeats that rule in
 * row-level security.
 *
 * policy-management reads the newest stored document, compiles only supported
 * controls and either returns an explainable dry run or publishes the compiled
 * runtime policy. Agent receipts remain the separate adoption signal.
 */
export function PolicyPage() {
	const t = useT();
	return (
		<div className="stack">
			<div className="card">
				<div className="pill" style={{ marginBottom: 8 }}>
					{t("policy.pill")}
				</div>
				<h1>{t("nav.policies")}</h1>
				<p className="muted" style={{ maxWidth: 760 }}>
					{t("policy.intro")}
				</p>
			</div>
			<div className="notice notice-warning" role="status">
				<b>{t("policy.compiledNotice")}</b>
				<div className="muted small" style={{ marginTop: 6 }}>
					{t("policy.compiledBody")}
				</div>
			</div>
			<PolicyEditor />
			<RuntimePolicyEditor />
			<DlpPolicyEditor />
			<AgentProfilesPanel />
		</div>
	);
}
