/**
 * Agent permission profile editor (Policy → Agent permission profiles).
 *
 * The dashboard validates a profile document with the engine's own schema (on
 * the server, `validate_agent_profiles`) and STAGES it as a versioned, audited
 * revision (`stage_agent_profiles`, four-eyes when enabled). Staging is not
 * enforcement: connectors trust only the Ed25519 tenant detector bundle signed
 * with the operator-held key, so an operator publishes the staged revision
 * with one command that pulls exactly that revision. History, diff and
 * rollback work like the runtime and DLP policies.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { pendingPolicyChangeNotice } from "../lib/ai-governance";
import { diffDocuments } from "../lib/json-diff";
import { invokePolicyManagement, policyManagementMessage } from "../lib/policy-management";
import { DiffView } from "../ui/governance/common";
import { PROFILE_TEMPLATE_SUMMARIES } from "./agent-profile-templates";

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export interface StagedProfiles {
	version: number;
	policy: Record<string, unknown> | null;
	sha256: string | null;
	updatedAt: string | null;
}

export interface ProfileRevision {
	version: number;
	sha256: string;
	profileCount: number;
	restoredFrom: number | null;
	createdAt: string;
}

/** Strict projection of one `agent_profile_history` row; null when malformed. */
export function parseProfileRevision(value: unknown): ProfileRevision | null {
	if (
		!isRecord(value) ||
		!Number.isSafeInteger(value.version) ||
		Number(value.version) < 1 ||
		typeof value.policy_sha256 !== "string" ||
		!/^[0-9a-f]{64}$/.test(value.policy_sha256) ||
		!Number.isSafeInteger(value.profile_count) ||
		typeof value.created_at !== "string" ||
		!Number.isFinite(Date.parse(value.created_at))
	)
		return null;
	return {
		version: value.version as number,
		sha256: value.policy_sha256,
		profileCount: value.profile_count as number,
		restoredFrom: Number.isSafeInteger(value.restored_from)
			? (value.restored_from as number)
			: null,
		createdAt: value.created_at,
	};
}

/** A one-profile starter document built from a shipped template summary. */
export function templateDocument(name: string): string {
	const template = PROFILE_TEMPLATE_SUMMARIES.find((entry) => entry.name === name);
	const profile = template
		? {
				name: template.name,
				description: template.description,
				default: template.default,
				tools: template.tools,
			}
		: { name: "default", default: "ask" };
	return `${JSON.stringify({ version: 1, default_profile: profile.name, profiles: [profile] }, null, 2)}\n`;
}

/** The operator's one publication command for a staged revision. */
export function publishCommand(tenantId: string, version: number): string {
	return `node scripts/provision-agent-profiles.mjs \\
  --endpoint https://<project>/functions/v1/policy-management --token-file <aal2-access-token-file> \\
  --tenant ${tenantId} --revision ${version} \\
  --runtime <claude-code|cursor|vscode|openclaw|opencode|codex> --expires-at <UTC time within 24h> \\
  --private-key <publisher-ed25519.pem> --output-dir ~/.singularity-aidr/detectors`;
}

type Load =
	| { kind: "loading" }
	| { kind: "mfa_required" }
	| { kind: "error"; message: string }
	| { kind: "ready"; staged: StagedProfiles };

type Validation =
	| { kind: "idle" }
	| { kind: "valid"; profiles: string[]; diagnostics: string[] }
	| { kind: "invalid"; errors: string[] };

function stringList(value: unknown, max = 20): string[] {
	return Array.isArray(value)
		? value
				.filter((item): item is string => typeof item === "string")
				.slice(0, max)
				.map((item) => item.slice(0, 300))
		: [];
}

function diagnosticsList(value: unknown): string[] {
	return Array.isArray(value)
		? value
				.filter(isRecord)
				.slice(0, 20)
				.map((item) => `${String(item.profile ?? "")}: ${String(item.message ?? "")}`.slice(0, 300))
		: [];
}

export function AgentProfileEditor({
	tenantId,
	canManage,
}: {
	tenantId: string;
	canManage: boolean;
}) {
	const [load, setLoad] = useState<Load>({ kind: "loading" });
	const [source, setSource] = useState("");
	const [validation, setValidation] = useState<Validation>({ kind: "idle" });
	const [busy, setBusy] = useState(false);
	const [notice, setNotice] = useState<{ tone: "success" | "error"; message: string } | null>(null);
	const [revisions, setRevisions] = useState<ProfileRevision[] | null>(null);
	const [diff, setDiff] = useState<{
		title: string;
		lines: ReturnType<typeof diffDocuments>;
	} | null>(null);

	const refresh = useCallback(async () => {
		const [current, history] = await Promise.all([
			invokePolicyManagement(
				{ action: "read_agent_profiles", tenant_id: tenantId },
				"agent_profiles_unavailable",
			),
			invokePolicyManagement(
				{ action: "agent_profile_history", tenant_id: tenantId },
				"agent_profile_history_unavailable",
			),
		]);
		if (!current.ok) {
			setLoad(
				current.code === "mfa_required"
					? { kind: "mfa_required" }
					: { kind: "error", message: policyManagementMessage(current.code) },
			);
			return;
		}
		const data = current.data;
		if (!Number.isSafeInteger(data.version) || (data.policy !== null && !isRecord(data.policy))) {
			setLoad({ kind: "error", message: "The staged profiles could not be verified." });
			return;
		}
		const staged: StagedProfiles = {
			version: data.version as number,
			policy: (data.policy as Record<string, unknown> | null) ?? null,
			sha256: typeof data.policy_sha256 === "string" ? data.policy_sha256 : null,
			updatedAt: typeof data.updated_at === "string" ? data.updated_at : null,
		};
		setLoad({ kind: "ready", staged });
		setSource(
			staged.policy
				? `${JSON.stringify(staged.policy, null, 2)}\n`
				: templateDocument("standard-developer"),
		);
		setValidation({ kind: "idle" });
		const rows =
			history.ok && Array.isArray(history.data.revisions)
				? history.data.revisions.map(parseProfileRevision)
				: null;
		setRevisions(rows && rows.every((row) => row !== null) ? (rows as ProfileRevision[]) : null);
	}, [tenantId]);

	useEffect(() => {
		setLoad({ kind: "loading" });
		setNotice(null);
		setDiff(null);
		void refresh();
	}, [refresh]);

	async function validate(): Promise<boolean> {
		const result = await invokePolicyManagement(
			{ action: "validate_agent_profiles", tenant_id: tenantId, source },
			"agent_profiles_unavailable",
		);
		if (!result.ok) {
			setValidation({ kind: "invalid", errors: [policyManagementMessage(result.code)] });
			return false;
		}
		if (result.data.valid === true) {
			setValidation({
				kind: "valid",
				profiles: stringList(result.data.profiles),
				diagnostics: diagnosticsList(result.data.diagnostics),
			});
			return true;
		}
		setValidation({ kind: "invalid", errors: stringList(result.data.errors) });
		return false;
	}

	async function stage() {
		if (load.kind !== "ready" || !canManage) return;
		setBusy(true);
		setNotice(null);
		const result = await invokePolicyManagement(
			{
				action: "stage_agent_profiles",
				tenant_id: tenantId,
				source,
				expected_version: load.staged.version,
			},
			"agent_profiles_stage_failed",
		);
		setBusy(false);
		if (!result.ok) {
			const errors = stringList(result.body?.errors, 8);
			if (errors.length > 0) setValidation({ kind: "invalid", errors });
			setNotice({ tone: "error", message: policyManagementMessage(result.code) });
			return;
		}
		const pending = pendingPolicyChangeNotice(result.data);
		if (pending) {
			setNotice({ tone: "success", message: `Profiles filed for approval. ${pending}` });
			return;
		}
		if (result.data.staged !== true || result.data.version !== load.staged.version + 1) {
			setNotice({ tone: "error", message: "Staging was not confirmed." });
			return;
		}
		setNotice({
			tone: "success",
			message: `Profiles staged as revision ${result.data.version}. Not enforced until an operator publishes that revision.`,
		});
		await refresh();
	}

	async function showDiff(version: number) {
		if (load.kind !== "ready") return;
		const read = async (target: number) => {
			const result = await invokePolicyManagement(
				{ action: "read_agent_profile_revision", tenant_id: tenantId, version: target },
				"agent_profile_history_unavailable",
			);
			return result.ok && isRecord(result.data.revision) && result.data.revision.version === target
				? result.data.revision.policy
				: undefined;
		};
		const before = await read(version);
		if (before === undefined) {
			setNotice({ tone: "error", message: "That revision could not be read." });
			return;
		}
		setDiff({
			title: `Revision ${version} → current staged revision ${load.staged.version}`,
			lines: diffDocuments(before, load.staged.policy),
		});
	}

	async function restore(version: number) {
		if (load.kind !== "ready" || !canManage) return;
		setBusy(true);
		setNotice(null);
		const result = await invokePolicyManagement(
			{
				action: "restore_agent_profiles",
				tenant_id: tenantId,
				version,
				expected_version: load.staged.version,
			},
			"agent_profiles_stage_failed",
		);
		setBusy(false);
		if (!result.ok) {
			setNotice({ tone: "error", message: policyManagementMessage(result.code) });
			return;
		}
		const pending = pendingPolicyChangeNotice(result.data);
		if (pending) {
			setNotice({
				tone: "success",
				message: `Rollback to revision ${version} filed for approval. ${pending}`,
			});
			return;
		}
		setNotice({
			tone: "success",
			message: `Revision ${version} restored as revision ${String(result.data.version)}. Publish it to enforce it.`,
		});
		await refresh();
	}

	const stagedCommand = useMemo(
		() =>
			load.kind === "ready" && load.staged.version > 0
				? publishCommand(tenantId, load.staged.version)
				: null,
		[load, tenantId],
	);

	if (load.kind === "loading") return <p role="status">Loading staged profiles…</p>;
	if (load.kind === "mfa_required") {
		return (
			<div className="notice notice-warning" role="alert">
				Profiles describe the commands, paths and hosts your agents may use, so reading and staging
				them requires multi-factor verification.{" "}
				<Link to={`/auth/dlp-step-up?tenant=${encodeURIComponent(tenantId)}`}>
					Verify with authenticator
				</Link>
			</div>
		);
	}
	if (load.kind === "error") return <p role="alert">{load.message}</p>;

	return (
		<div className="stack">
			<div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
				<span className="muted small">
					{load.staged.version > 0
						? `Staged revision ${load.staged.version}${load.staged.sha256 ? ` · sha256 ${load.staged.sha256.slice(0, 12)}…` : ""}`
						: "Nothing staged yet."}
				</span>
				<label className="row small" style={{ gap: 6 }}>
					<span>Start from template</span>
					<select
						className="input"
						aria-label="Profile template"
						style={{ width: "auto" }}
						defaultValue=""
						disabled={!canManage}
						onChange={(event) => {
							if (!event.target.value) return;
							setSource(templateDocument(event.target.value));
							setValidation({ kind: "idle" });
							event.target.value = "";
						}}
					>
						<option value="">Choose…</option>
						{PROFILE_TEMPLATE_SUMMARIES.map((template) => (
							<option key={template.name} value={template.name}>
								{template.name}
							</option>
						))}
					</select>
				</label>
			</div>
			<textarea
				className="input mono small"
				aria-label="Agent profile document (JSON or YAML)"
				rows={18}
				spellCheck={false}
				value={source}
				readOnly={!canManage}
				onChange={(event) => {
					setSource(event.target.value);
					setValidation({ kind: "idle" });
				}}
			/>
			<div className="row" style={{ gap: 8 }}>
				<button
					type="button"
					className="btn btn-secondary"
					disabled={busy || source.trim() === ""}
					onClick={() => void validate()}
				>
					Validate
				</button>
				{canManage ? (
					<button
						type="button"
						className="btn btn-primary"
						disabled={busy || source.trim() === ""}
						onClick={() => void stage()}
					>
						Stage for publication
					</button>
				) : null}
			</div>
			{validation.kind === "valid" ? (
				<div className="notice notice-success" role="status">
					Valid: {validation.profiles.join(", ")}.
					{validation.diagnostics.length > 0 ? (
						<ul className="small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>
							{validation.diagnostics.map((item) => (
								<li key={item}>{item}</li>
							))}
						</ul>
					) : null}
				</div>
			) : validation.kind === "invalid" ? (
				<div className="notice notice-danger" role="alert">
					<b>The profile document is not valid.</b>
					<ul className="small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>
						{validation.errors.map((item) => (
							<li key={item}>{item}</li>
						))}
					</ul>
				</div>
			) : null}
			{notice ? (
				<div
					className={`notice ${notice.tone === "error" ? "notice-danger" : "notice-success"}`}
					role={notice.tone === "error" ? "alert" : "status"}
				>
					{notice.message}
				</div>
			) : null}

			<div>
				<h3>Publish the staged revision</h3>
				{stagedCommand ? (
					<>
						<pre
							className="mono small"
							aria-label="Signed profile publishing commands"
							style={{ overflowX: "auto" }}
						>
							{stagedCommand}
						</pre>
						<p className="muted small">
							Run on the publishing host for each connector runtime, with an owner or administrator
							access token verified at AAL2. The command refuses anything but the current staged
							revision and checks its digest before signing; the bundle keeps any DLP policy already
							signed for this tenant. Confirm adoption on the agent with <code>aidr doctor</code>.
						</p>
					</>
				) : (
					<p className="muted small" aria-label="Signed profile publishing commands">
						Stage a document first; the operator then signs that exact revision with
						provision-agent-profiles.mjs and the publisher key.
					</p>
				)}
			</div>

			<div>
				<h3>Staged revisions</h3>
				{revisions === null ? (
					<p className="muted small">The revision history is unavailable.</p>
				) : revisions.length === 0 ? (
					<p className="muted small">No revision has been staged yet.</p>
				) : (
					<div className="table-wrap">
						<table className="table" aria-label="Staged agent profile revisions">
							<thead>
								<tr>
									<th>Revision</th>
									<th>Staged</th>
									<th>Profiles</th>
									<th>Digest</th>
									<th>Actions</th>
								</tr>
							</thead>
							<tbody>
								{revisions.map((revision) => {
									const current = revision.version === load.staged.version;
									return (
										<tr key={revision.version}>
											<td>
												r{revision.version}
												{current ? (
													<span className="pill" style={{ marginLeft: 6 }}>
														current
													</span>
												) : null}
												{revision.restoredFrom ? (
													<div className="muted small">restored from r{revision.restoredFrom}</div>
												) : null}
											</td>
											<td className="small">{new Date(revision.createdAt).toLocaleString()}</td>
											<td>{revision.profileCount}</td>
											<td className="mono small">{revision.sha256.slice(0, 12)}…</td>
											<td>
												{!current ? (
													<div className="row" style={{ gap: 6 }}>
														<button
															type="button"
															className="btn btn-secondary btn-sm"
															aria-label={`Compare revision ${revision.version} with current`}
															onClick={() => void showDiff(revision.version)}
														>
															Diff vs current
														</button>
														{canManage ? (
															<button
																type="button"
																className="btn btn-secondary btn-sm"
																disabled={busy}
																aria-label={`Roll back profiles to revision ${revision.version}`}
																onClick={() => void restore(revision.version)}
															>
																Roll back
															</button>
														) : null}
													</div>
												) : null}
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				)}
				{diff ? (
					<div className="stack" style={{ gap: 6 }}>
						<b>{diff.title}</b>
						<DiffView lines={diff.lines} label={diff.title} />
					</div>
				) : null}
			</div>
		</div>
	);
}
