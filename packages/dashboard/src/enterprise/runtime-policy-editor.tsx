import { useEffect, useRef, useState } from "react";
import { supabase } from "../lib/supabase";
import { useTeam } from "./team-provider";
import { PolicyRollout } from "./policy-rollout";

const INITIAL_POLICY = {
	command_default: "allow",
	file_default: "allow",
	url_default: "allow",
	package_default: "allow",
	output_default: "ask",
	mcp_default: "ask",
	mcp_unknown: "ask",
	mcp_risky: "deny",
};

export function RuntimePolicyEditor() {
	const { currentTeam, canManageTeam } = useTeam();
	const [text, setText] = useState(JSON.stringify(INITIAL_POLICY, null, 2));
	const [version, setVersion] = useState<number | null>(null);
	const [message, setMessage] = useState("");
	const [busy, setBusy] = useState(false);
	const [refresh, setRefresh] = useState(0);
	const selectedTeamId = useRef(currentTeam?.id);
	selectedTeamId.current = currentTeam?.id;
	useEffect(() => {
		let cancelled = false;
		setVersion(null);
		setMessage("");
		setBusy(false);
		if (!currentTeam) return;
		void supabase.functions
			.invoke("policy-management", { body: { action: "read", tenant_id: currentTeam.id } })
			.then(({ data, error }) => {
				if (cancelled) return;
				if (error || data?.ok !== true || !Number.isSafeInteger(data.version)) {
					setMessage(
						"Published policy could not be loaded. Publishing is disabled until it can be read.",
					);
					return;
				}
				setVersion(data.version);
				setText(JSON.stringify(data.policy ?? INITIAL_POLICY, null, 2));
			})
			.catch(() => {
				if (!cancelled) setMessage("Published policy could not be loaded.");
			});
		return () => {
			cancelled = true;
		};
	}, [currentTeam?.id, currentTeam, refresh]);

	async function publish() {
		if (!currentTeam || !canManageTeam || version === null) return;
		const requestedTeam = currentTeam.id;
		setBusy(true);
		setMessage("");
		try {
			const policy: unknown = JSON.parse(text);
			const { data, error } = await supabase.functions.invoke("policy-management", {
				body: { action: "publish", tenant_id: currentTeam.id, expected_version: version, policy },
			});
			if (selectedTeamId.current !== requestedTeam) return;
			if (error || data?.ok !== true || !Number.isSafeInteger(data.version))
				throw new Error(
					"Publication failed. Reload the page if another administrator changed the policy.",
				);
			setVersion(data.version);
			setMessage(
				`Version ${data.version} published. Agents fetch it on their next policy refresh. Required-policy endpoints retain cached controls within their offline grace, then block until policy is available. Check loading receipts below.`,
			);
		} catch (error) {
			if (selectedTeamId.current === requestedTeam)
				setMessage(error instanceof Error ? error.message : "Publication failed.");
		} finally {
			if (selectedTeamId.current === requestedTeam) setBusy(false);
		}
	}

	async function compileSavedDocument(publishNow: boolean) {
		if (!currentTeam || !canManageTeam || (publishNow && version === null)) return;
		const requestedTeam = currentTeam.id;
		setBusy(true);
		setMessage("");
		try {
			const { data, error } = await supabase.functions.invoke("policy-management", {
				body: {
					action: publishNow ? "publish_document" : "compile_document",
					tenant_id: currentTeam.id,
					...(publishNow ? { expected_version: version } : {}),
					...(!publishNow ? { simulation: { kind: "mcp", server: "unregistered-preview", tool: "call", inventory: "unknown" } } : {}),
				},
			});
			if (selectedTeamId.current !== requestedTeam) return;
			if (error || data?.ok !== true || (!data.policy && !data.runtime_policy)) throw new Error("Saved YAML could not be compiled. Review unsupported fields in the policy editor.");
			const compiled = data.runtime_policy ?? data.policy;
			setText(JSON.stringify(compiled, null, 2));
			if (publishNow) {
				if (!Number.isSafeInteger(data.version)) throw new Error("The compiled policy was not published.");
				setVersion(data.version);
				setMessage(`Saved YAML compiled and published as version ${data.version}. Check agent loading receipts below.`);
			} else {
				const precedence = Array.isArray(data.semantics?.precedence) ? data.semantics.precedence.join(" > ") : "deny > ask > allow";
				const simulation = data.simulation ? ` Unknown MCP simulation: ${data.simulation.action} (${data.simulation.source}).` : "";
				const warnings = Array.isArray(data.diagnostics) && data.diagnostics.length > 0 ? ` ${data.diagnostics.length} shadowed rule warning(s).` : "";
				setMessage(`Dry run compiled. Conflict precedence: ${precedence}.${simulation}${warnings}`);
			}
		} catch (error) {
			if (selectedTeamId.current === requestedTeam) setMessage(error instanceof Error ? error.message : "Saved YAML could not be compiled.");
		} finally {
			if (selectedTeamId.current === requestedTeam) setBusy(false);
		}
	}

	if (!currentTeam) return null;
	return (
		<>
			<section className="card stack">
				<h2>Runtime policy</h2>
				<p className="muted">
					Publish controls for agents enrolled in this team. Detection rules still apply when an
					action defaults to allow. Use ask to require operator approval, or deny to block.
				</p>
				<p>
					{version === null
						? "Published version unavailable"
						: version === 0
							? "No policy published"
							: `Published version: ${version}`}
				</p>
				<label htmlFor="runtime-policy">Runtime controls (JSON)</label>
				<textarea
					id="runtime-policy"
					className="input mono"
					rows={14}
					value={text}
					onChange={(event) => setText(event.target.value)}
					disabled={!canManageTeam || busy}
				/>
				<p className="muted small">
					Actions: command_default, file_default, url_default, package_default, output_default,
					mcp_default, mcp_unknown, mcp_risky. MCP lists: mcp_allow_servers, mcp_require_approval_servers,
					mcp_deny_servers and the corresponding *_tools lists. Unsupported fields are rejected.
				</p>
				<div className="row">
					<button type="button" className="btn" disabled={!canManageTeam || busy} onClick={() => void compileSavedDocument(false)}>
						Compile saved YAML (dry run)
					</button>
					<button type="button" className="btn" disabled={!canManageTeam || version === null || busy} onClick={() => void compileSavedDocument(true)}>
						Compile and publish saved YAML
					</button>
					<button
						type="button"
						className="btn btn-primary"
						disabled={!canManageTeam || version === null || busy}
						onClick={() => void publish()}
					>
						{busy ? "Working…" : "Publish runtime policy JSON"}
					</button>
				</div>
				{message && <p role="status">{message}</p>}
			</section>
			<PolicyRollout
				version={version}
				draft={text}
				onChanged={() => setRefresh((value) => value + 1)}
				onReview={(policy) => setText(JSON.stringify(policy, null, 2))}
			/>
		</>
	);
}
