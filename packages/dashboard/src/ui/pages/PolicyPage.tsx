import { PolicyEditor } from "../../enterprise/policy-editor";
import { RuntimePolicyEditor } from "../../enterprise/runtime-policy-editor";

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
	return (
		<div className="stack">
			<div className="card">
				<div className="pill" style={{ marginBottom: 8 }}>
					Policy as code
				</div>
				<h1>Team policy</h1>
				<p className="muted" style={{ maxWidth: 760 }}>
					Write and validate strict team policy documents, run a dry-run compilation, then publish the compiled controls to enrolled agents.
				</p>
			</div>
			<div className="notice notice-warning" role="status">
				<b>Saved YAML is compiled before it can become runtime policy.</b>
				<div className="muted small" style={{ marginTop: 6 }}>
					Unsupported fields fail compilation. Use the dry-run or compile-and-publish action below; connected agents fetch the published controls on their next refresh.
					Publication alone does not confirm every agent has adopted the version.
				</div>
			</div>
			<PolicyEditor />
			<RuntimePolicyEditor />
		</div>
	);
}
