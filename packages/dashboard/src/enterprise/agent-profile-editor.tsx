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
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useRichT, useT } from "../i18n/I18nProvider";
import { pendingPolicyChangeNotice } from "../lib/ai-governance";
import { diffDocuments } from "../lib/json-diff";
import { invokePolicyManagement, policyManagementMessage } from "../lib/policy-management";
import { DiffView } from "../ui/governance/common";
import { PROFILE_TEMPLATE_SUMMARIES } from "./agent-profile-templates";

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

interface StagedProfiles {
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

/** The `read_agent_profiles` answer, or null when it does not verify. */
function parseStagedProfiles(data: Record<string, unknown>): StagedProfiles | null {
	if (!Number.isSafeInteger(data.version) || (data.policy !== null && !isRecord(data.policy))) {
		return null;
	}
	return {
		version: data.version as number,
		policy: (data.policy as Record<string, unknown> | null) ?? null,
		sha256: typeof data.policy_sha256 === "string" ? data.policy_sha256 : null,
		updatedAt: typeof data.updated_at === "string" ? data.updated_at : null,
	};
}

/** Every revision of an `agent_profile_history` answer, or null when any row is malformed. */
function parseRevisionList(revisions: unknown): ProfileRevision[] | null {
	if (!Array.isArray(revisions)) return null;
	const rows = revisions.map(parseProfileRevision);
	return rows.every((row) => row !== null) ? (rows as ProfileRevision[]) : null;
}

function ValidationResult({ validation }: { validation: Validation }) {
	const t = useT();
	if (validation.kind === "valid") {
		return (
			<div className="notice notice-success" role="status">
				{t("ap.valid", { profiles: validation.profiles.join(", ") })}
				{validation.diagnostics.length > 0 ? (
					<ul className="small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>
						{validation.diagnostics.map((item) => (
							<li key={item}>{item}</li>
						))}
					</ul>
				) : null}
			</div>
		);
	}
	if (validation.kind === "invalid") {
		return (
			<div className="notice notice-danger" role="alert">
				<b>{t("ap.invalid")}</b>
				<ul className="small" style={{ margin: "6px 0 0", paddingLeft: 18 }}>
					{validation.errors.map((item) => (
						<li key={item}>{item}</li>
					))}
				</ul>
			</div>
		);
	}
	return null;
}

interface RevisionActions {
	canManage: boolean;
	busy: boolean;
	onDiff: (version: number) => void;
	onRestore: (version: number) => void;
}

function RevisionTable({
	revisions,
	currentVersion,
	...actions
}: RevisionActions & { revisions: ProfileRevision[] | null; currentVersion: number }) {
	const t = useT();
	if (revisions === null) return <p className="muted small">{t("ap.historyUnavailable")}</p>;
	if (revisions.length === 0) return <p className="muted small">{t("ap.noRevision")}</p>;
	return (
		<div className="table-wrap">
			<table className="table" aria-label={t("ap.revisionsLabel")}>
				<thead>
					<tr>
						<th>{t("ap.col.revision")}</th>
						<th>{t("ap.col.staged")}</th>
						<th>{t("ap.col.profiles")}</th>
						<th>{t("ap.col.digest")}</th>
						<th>{t("ap.col.actions")}</th>
					</tr>
				</thead>
				<tbody>
					{revisions.map((revision) => (
						<RevisionRow
							key={revision.version}
							revision={revision}
							current={revision.version === currentVersion}
							{...actions}
						/>
					))}
				</tbody>
			</table>
		</div>
	);
}

function PublishInstructions({ command }: { command: string | null }) {
	const t = useT();
	const richT = useRichT();
	if (!command) {
		return (
			<p className="muted small" aria-label={t("ap.publishLabel")}>
				{t("ap.stageFirst")}
			</p>
		);
	}
	return (
		<>
			<pre className="mono small" aria-label={t("ap.publishLabel")} style={{ overflowX: "auto" }}>
				{command}
			</pre>
			<p className="muted small">{richT("ap.publishHint", { doctor: <code>aidr doctor</code> })}</p>
		</>
	);
}

function RevisionRow({
	revision,
	current,
	canManage,
	busy,
	onDiff,
	onRestore,
}: RevisionActions & { revision: ProfileRevision; current: boolean }) {
	const t = useT();
	return (
		<tr>
			<td>
				r{revision.version}
				{current ? (
					<span className="pill" style={{ marginLeft: 6 }}>
						{t("ap.current")}
					</span>
				) : null}
				{revision.restoredFrom ? (
					<div className="muted small">
						{t("ap.restoredFrom", { version: revision.restoredFrom })}
					</div>
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
							aria-label={t("ap.compareLabel", { version: revision.version })}
							onClick={() => onDiff(revision.version)}
						>
							{t("ap.diffCurrent")}
						</button>
						{canManage ? (
							<button
								type="button"
								className="btn btn-secondary btn-sm"
								disabled={busy}
								aria-label={t("ap.rollBackLabel", { version: revision.version })}
								onClick={() => onRestore(revision.version)}
							>
								{t("ap.rollBack")}
							</button>
						) : null}
					</div>
				) : null}
			</td>
		</tr>
	);
}

export function AgentProfileEditor({
	tenantId,
	canManage,
}: {
	tenantId: string;
	canManage: boolean;
}) {
	const t = useT();
	// The loader reads the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
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
		const t = translator.current;
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
					: { kind: "error", message: policyManagementMessage(current.code, t) },
			);
			return;
		}
		const staged = parseStagedProfiles(current.data);
		if (!staged) {
			setLoad({ kind: "error", message: t("ap.stagedUnverified") });
			return;
		}
		setLoad({ kind: "ready", staged });
		setSource(
			staged.policy
				? `${JSON.stringify(staged.policy, null, 2)}\n`
				: templateDocument("standard-developer"),
		);
		setValidation({ kind: "idle" });
		setRevisions(history.ok ? parseRevisionList(history.data.revisions) : null);
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
			setValidation({ kind: "invalid", errors: [policyManagementMessage(result.code, t)] });
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
			setNotice({ tone: "error", message: policyManagementMessage(result.code, t) });
			return;
		}
		const pending = pendingPolicyChangeNotice(result.data, t);
		if (pending) {
			setNotice({ tone: "success", message: t("ap.filed", { pending }) });
			return;
		}
		if (result.data.staged !== true || result.data.version !== load.staged.version + 1) {
			setNotice({ tone: "error", message: t("ap.stagingUnconfirmed") });
			return;
		}
		setNotice({
			tone: "success",
			message: t("ap.staged", { version: String(result.data.version) }),
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
			setNotice({ tone: "error", message: t("ap.readFailed") });
			return;
		}
		setDiff({
			title: t("ap.diffTitle", { version, current: load.staged.version }),
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
			setNotice({ tone: "error", message: policyManagementMessage(result.code, t) });
			return;
		}
		const pending = pendingPolicyChangeNotice(result.data, t);
		if (pending) {
			setNotice({ tone: "success", message: t("ap.rollbackFiled", { version, pending }) });
			return;
		}
		setNotice({
			tone: "success",
			message: t("ap.restored", { version, next: String(result.data.version) }),
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

	if (load.kind === "loading") return <p role="status">{t("ap.loading")}</p>;
	if (load.kind === "mfa_required") {
		return (
			<div className="notice notice-warning" role="alert">
				{t("ap.mfa")}{" "}
				<Link to={`/auth/dlp-step-up?tenant=${encodeURIComponent(tenantId)}`}>
					{t("common.verifyMfa")}
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
						? `${t("ap.stagedRevision", { version: load.staged.version })}${load.staged.sha256 ? ` · sha256 ${load.staged.sha256.slice(0, 12)}…` : ""}`
						: t("ap.nothingStaged")}
				</span>
				<label className="row small" style={{ gap: 6 }}>
					<span>{t("ap.startTemplate")}</span>
					<select
						className="input"
						aria-label={t("ap.templateLabel")}
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
						<option value="">{t("ap.choose")}</option>
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
				aria-label={t("ap.documentLabel")}
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
					{t("ap.validate")}
				</button>
				{canManage ? (
					<button
						type="button"
						className="btn btn-primary"
						disabled={busy || source.trim() === ""}
						onClick={() => void stage()}
					>
						{t("ap.stage")}
					</button>
				) : null}
			</div>
			<ValidationResult validation={validation} />
			{notice ? (
				<div
					className={`notice ${notice.tone === "error" ? "notice-danger" : "notice-success"}`}
					role={notice.tone === "error" ? "alert" : "status"}
				>
					{notice.message}
				</div>
			) : null}

			<div>
				<h3>{t("ap.publishTitle")}</h3>
				<PublishInstructions command={stagedCommand} />
			</div>

			<div>
				<h3>{t("ap.revisions")}</h3>

				<RevisionTable
					revisions={revisions}
					currentVersion={load.staged.version}
					canManage={canManage}
					busy={busy}
					onDiff={(version) => void showDiff(version)}
					onRestore={(version) => void restore(version)}
				/>
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
