import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabaseEnvError } from "../../lib/supabase";
import {
	closeWorkspace,
	loadSessionAssurance,
	loadWorkspaceSettings,
	type SessionAssurance,
	updateWorkspaceSettings,
	type WorkspaceClosure,
	type WorkspaceSettings,
} from "../../lib/workspace-settings";
import { NotificationSettings } from "../NotificationSettings";
import { getSession, signOut } from "../session";
import { useTheme } from "../ThemeProvider";

const ROLE_LABELS: Record<string, string> = {
	owner: "Owner",
	admin: "Administrator",
	member: "Member",
	viewer: "Viewer",
};

const STATUS_LABELS: Record<string, string> = {
	active: "Active",
	suspended: "Suspended",
	closing: "Closing (offboarding in progress)",
	closed: "Closed",
};

/** Operator copy for the service's machine-readable workspace errors. */
function workspaceErrorMessage(code: string): string {
	switch (code) {
		case "mfa_required":
			return "Multi-factor verification is required for workspace changes. Verify with your authenticator, then try again.";
		case "workspace_role_insufficient":
			return "Your role cannot make this workspace change.";
		case "workspace_forbidden":
			return "You no longer have access to this workspace's settings.";
		case "workspace_not_active":
			return "This workspace is not active, so its settings can no longer be changed.";
		case "retention_reduction_unconfirmed":
			return "Confirm the shorter retention period before saving.";
		case "confirmation_mismatch":
			return "The name you typed does not match the workspace name. Nothing was closed.";
		case "invalid_workspace_name":
			return "Enter a workspace name of 1 to 200 characters without control characters.";
		case "invalid_retention_days":
			return "Enter a whole number of retention days within the allowed range.";
		case "rate_limited":
			return "Too many workspace changes. Wait a minute and try again.";
		case "session_revoked":
		case "invalid_access_token":
			return "Your session is no longer valid. Sign in again.";
		default:
			return "The workspace service did not confirm the request.";
	}
}

function stepUpPath(tenantId: string): string {
	return `/auth/dlp-step-up?tenant=${encodeURIComponent(tenantId)}&return=settings`;
}

interface Notice {
	tone: "success" | "error";
	message: string;
	code?: string;
}

function MfaStatus({
	tenantId,
	assurance,
	failed,
}: {
	tenantId: string | null;
	assurance: SessionAssurance | null;
	failed: boolean;
}) {
	if (!tenantId)
		return <p className="muted">Select a workspace to check this session's MFA status.</p>;
	if (failed) {
		return (
			<p className="muted" role="status">
				MFA status could not be confirmed by the control plane.
			</p>
		);
	}
	if (!assurance) return <p className="muted">Checking MFA status…</p>;
	if (assurance.currentLevel === "aal2") {
		return <p data-testid="mfa-status">Verified for this session (AAL2).</p>;
	}
	return (
		<div data-testid="mfa-status">
			<p>
				Not verified for this session (AAL1).{" "}
				{assurance.requireMfa
					? "This workspace requires MFA."
					: "Workspace changes still require MFA."}
			</p>
			<Link className="button button-secondary button-sm" to={stepUpPath(tenantId)}>
				Set up or verify MFA
			</Link>
		</div>
	);
}

function ProfileSection({
	email,
	tenantId,
	onSignOut,
}: {
	email: string | null;
	tenantId: string | null;
	onSignOut: () => void;
}) {
	const [assurance, setAssurance] = useState<SessionAssurance | null>(null);
	const [assuranceError, setAssuranceError] = useState(false);

	useEffect(() => {
		let cancelled = false;
		setAssurance(null);
		setAssuranceError(false);
		if (!tenantId) return;
		void loadSessionAssurance(tenantId).then((result) => {
			if (cancelled) return;
			if (result.ok) setAssurance(result.value);
			else setAssuranceError(true);
		});
		return () => {
			cancelled = true;
		};
	}, [tenantId]);

	return (
		<div className="card">
			<h2>Profile</h2>
			<div className="session-box" style={{ marginTop: 10, maxWidth: 420 }}>
				<div className="muted small">Signed in as</div>
				<div className="mono" style={{ marginTop: 2, overflowWrap: "anywhere" }}>
					{email ?? "unknown"}
				</div>
			</div>
			<div style={{ marginTop: 12 }}>
				<div className="muted small">Multi-factor authentication</div>
				<MfaStatus tenantId={tenantId} assurance={assurance} failed={assuranceError} />
			</div>
			<div className="row" style={{ marginTop: 12 }}>
				<button className="button button-secondary" type="button" onClick={onSignOut}>
					Sign out of this session
				</button>
			</div>
		</div>
	);
}

type Workspace = WorkspaceSettings["workspace"];

/** Client-side mirror of the service's validation; the service stays authoritative. */
function draftChanges(
	workspace: Workspace,
	bounds: WorkspaceSettings["retentionBounds"],
	name: string,
	retention: string,
) {
	const trimmedName = name.trim();
	const days = Number(retention);
	const retentionValid = /^\d+$/.test(retention.trim()) && days >= bounds.min && days <= bounds.max;
	const nameValid = trimmedName.length > 0 && trimmedName.length <= 200;
	const nameChanged = trimmedName !== workspace.name;
	const retentionChanged = retentionValid && days !== workspace.retentionDays;
	return {
		trimmedName,
		days,
		valid: nameValid && retentionValid,
		nameChanged,
		retentionChanged,
		reducing: retentionChanged && days < workspace.retentionDays,
	};
}

function WorkspaceEditForm({
	tenantId,
	workspace,
	bounds,
	onSaved,
	onError,
}: {
	tenantId: string;
	workspace: Workspace;
	bounds: WorkspaceSettings["retentionBounds"];
	onSaved: (workspace: Workspace) => void;
	onError: (code: string) => void;
}) {
	const [name, setName] = useState(workspace.name);
	const [retention, setRetention] = useState(String(workspace.retentionDays));
	const [confirmReduction, setConfirmReduction] = useState(false);
	const [busy, setBusy] = useState(false);
	const draft = draftChanges(workspace, bounds, name, retention);
	const canSave =
		!busy &&
		draft.valid &&
		(draft.nameChanged || draft.retentionChanged) &&
		(!draft.reducing || confirmReduction);

	async function save(event: React.FormEvent) {
		event.preventDefault();
		if (!canSave) return;
		setBusy(true);
		const result = await updateWorkspaceSettings(tenantId, {
			...(draft.nameChanged ? { name: draft.trimmedName } : {}),
			...(draft.retentionChanged ? { retentionDays: draft.days } : {}),
			...(draft.reducing ? { confirmRetentionReduction: true } : {}),
		});
		setBusy(false);
		if (!result.ok) {
			onError(result.error);
			return;
		}
		setName(result.value.name);
		setRetention(String(result.value.retentionDays));
		setConfirmReduction(false);
		onSaved(result.value);
	}

	return (
		<form onSubmit={save} className="stack" style={{ marginTop: 16, maxWidth: 480 }}>
			<label className="label">
				Workspace name
				<input
					className="input"
					value={name}
					maxLength={200}
					onChange={(event) => setName(event.target.value)}
					required
				/>
			</label>
			<label className="label">
				Telemetry retention (days)
				<input
					className="input"
					type="number"
					inputMode="numeric"
					min={bounds.min}
					max={bounds.max}
					step={1}
					value={retention}
					onChange={(event) => {
						setRetention(event.target.value);
						setConfirmReduction(false);
					}}
					required
				/>
			</label>
			<p className="muted small">
				Allowed range: {bounds.min}–{bounds.max} days. Commercial and security audit records keep
				their own minimum retention.
			</p>
			{draft.reducing ? (
				<label className="row" style={{ gap: 8, alignItems: "flex-start" }}>
					<input
						type="checkbox"
						checked={confirmReduction}
						onChange={(event) => setConfirmReduction(event.target.checked)}
					/>
					<span>
						I understand that shortening retention from {workspace.retentionDays} to {draft.days}{" "}
						days makes older telemetry eligible for permanent deletion.
					</span>
				</label>
			) : null}
			<div className="row">
				<button className="button" type="submit" disabled={!canSave}>
					{busy ? "Saving…" : "Save workspace settings"}
				</button>
			</div>
			<p className="muted small">
				Changes require multi-factor verification (AAL2) and are recorded in the audit log.
			</p>
		</form>
	);
}

function CloseWorkspaceForm({
	tenantId,
	workspaceName,
	onClosed,
	onError,
}: {
	tenantId: string;
	workspaceName: string;
	onClosed: (closure: WorkspaceClosure) => void;
	onError: (code: string) => void;
}) {
	const [confirmName, setConfirmName] = useState("");
	const [busy, setBusy] = useState(false);
	const matches = confirmName.trim() === workspaceName;

	async function close(event: React.FormEvent) {
		event.preventDefault();
		if (busy || !matches) return;
		setBusy(true);
		const result = await closeWorkspace(tenantId, confirmName);
		setBusy(false);
		if (!result.ok) {
			onError(result.error);
			return;
		}
		setConfirmName("");
		onClosed(result.value);
	}

	return (
		<form
			onSubmit={close}
			className="stack"
			style={{ marginTop: 24, paddingTop: 16, borderTop: "1px solid var(--border)", maxWidth: 480 }}
		>
			<h3>Close workspace</h3>
			<p className="muted small">
				Closing starts offboarding: API keys, SCIM tokens and delegated credentials are revoked
				immediately, members lose access, and workspace data is deleted as each retention period
				ends. Active legal holds pause deletion. This cannot be undone from the console.
			</p>
			<label className="label">
				Type <b>{workspaceName}</b> to confirm
				<input
					className="input"
					value={confirmName}
					onChange={(event) => setConfirmName(event.target.value)}
					autoComplete="off"
				/>
			</label>
			<div className="row">
				<button className="button button-danger" type="submit" disabled={busy || !matches}>
					Close workspace
				</button>
			</div>
		</form>
	);
}

function NoticeBanner({ notice, tenantId }: { notice: Notice; tenantId: string }) {
	const error = notice.tone === "error";
	return (
		<div
			className={`notice ${error ? "notice-danger" : "notice-success"}`}
			role={error ? "alert" : "status"}
			style={{ marginTop: 12 }}
		>
			{notice.message}
			{notice.code === "mfa_required" ? (
				<div style={{ marginTop: 8 }}>
					<Link className="button button-sm" to={stepUpPath(tenantId)}>
						Verify with authenticator
					</Link>
				</div>
			) : null}
		</div>
	);
}

function WorkspaceSection({ tenantId }: { tenantId: string }) {
	const { applyWorkspaceName } = useTeam();
	const [settings, setSettings] = useState<WorkspaceSettings | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [notice, setNotice] = useState<Notice | null>(null);
	const request = useRef(0);

	const load = useCallback(async () => {
		const id = ++request.current;
		setLoadError(null);
		const result = await loadWorkspaceSettings(tenantId);
		if (id !== request.current) return;
		setSettings(result.ok ? result.value : null);
		setLoadError(result.ok ? null : workspaceErrorMessage(result.error));
	}, [tenantId]);

	useEffect(() => {
		void load();
		return () => {
			request.current++;
		};
	}, [load]);

	if (loadError || !settings) {
		return (
			<div className="card">
				<h2>Workspace</h2>
				{loadError ? (
					<>
						<div className="notice notice-danger" role="alert">
							{loadError}
						</div>
						<button className="button button-secondary" type="button" onClick={() => void load()}>
							Retry
						</button>
					</>
				) : (
					<p className="muted">Loading workspace settings…</p>
				)}
			</div>
		);
	}

	const { workspace } = settings;
	const showError = (code: string) =>
		setNotice({ tone: "error", message: workspaceErrorMessage(code), code });

	function saved(updated: Workspace) {
		setSettings((prev) => (prev ? { ...prev, workspace: updated } : prev));
		if (updated.name !== workspace.name) applyWorkspaceName(tenantId, updated.name);
		setNotice({ tone: "success", message: "Workspace settings saved." });
	}

	function closed(closure: WorkspaceClosure) {
		setSettings((prev) =>
			prev
				? {
						...prev,
						workspace: { ...prev.workspace, status: "closing" },
						canEdit: false,
						canClose: false,
					}
				: prev,
		);
		const backup = closure.backupException ? ` ${closure.backupException}` : "";
		setNotice({
			tone: "success",
			message: `Workspace closure requested (offboarding status: ${closure.status}). Credentials are revoked and data is deleted as each retention period ends.${backup}`,
		});
	}

	return (
		<div className="card">
			<h2>Workspace</h2>
			<dl className="stack" style={{ marginTop: 10, gap: 6 }}>
				<div>
					<dt className="muted small">Name</dt>
					<dd data-testid="workspace-name">{workspace.name}</dd>
				</div>
				<div>
					<dt className="muted small">Status</dt>
					<dd>{STATUS_LABELS[workspace.status] ?? workspace.status}</dd>
				</div>
				<div>
					<dt className="muted small">Telemetry retention</dt>
					<dd>{workspace.retentionDays} days</dd>
				</div>
				<div>
					<dt className="muted small">Your role</dt>
					<dd>{ROLE_LABELS[settings.role] ?? settings.role}</dd>
				</div>
			</dl>

			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}

			{settings.canEdit ? (
				<WorkspaceEditForm
					tenantId={tenantId}
					workspace={workspace}
					bounds={settings.retentionBounds}
					onSaved={saved}
					onError={showError}
				/>
			) : (
				<p className="muted" style={{ marginTop: 12 }}>
					{workspace.status === "active"
						? "Only an owner or administrator can change workspace settings."
						: "This workspace is read-only."}
				</p>
			)}

			{settings.canClose ? (
				<CloseWorkspaceForm
					tenantId={tenantId}
					workspaceName={workspace.name}
					onClosed={closed}
					onError={showError}
				/>
			) : null}
		</div>
	);
}

export function SettingsPage() {
	const navigate = useNavigate();
	const { theme, toggleTheme } = useTheme();
	const { currentTeam } = useTeam();
	const [email, setEmail] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [endingSession, setEndingSession] = useState(false);
	const tenantId = currentTeam?.id ?? null;

	useEffect(() => {
		let cancelled = false;
		async function load() {
			try {
				const session = await getSession();
				if (!cancelled) setEmail(session?.user?.email ?? null);
			} catch (cause) {
				if (!cancelled) {
					setError(readErrorMessage(cause, "Unable to load your session."));
				}
			}
		}
		load();
		return () => {
			cancelled = true;
		};
	}, []);

	if (endingSession) return <div role="status">Ending this browser session…</div>;

	async function endSession() {
		setEndingSession(true);
		try {
			const result = await signOut();
			navigate(result.serverRevoked ? "/login" : "/login?signout=revocation-unconfirmed", {
				replace: true,
			});
		} catch {
			navigate("/login?signout=local-failed", { replace: true });
		}
	}

	return (
		<div className="stack">
			<div className="card">
				<h1>Settings</h1>
				<p className="muted">
					Workspace, notifications, profile, appearance, and privacy controls for this console.
				</p>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</div>

			{tenantId ? <WorkspaceSection key={tenantId} tenantId={tenantId} /> : null}

			{tenantId ? (
				<NotificationSettings key={`notifications-${tenantId}`} tenantId={tenantId} />
			) : null}

			<ProfileSection email={email} tenantId={tenantId} onSignOut={() => void endSession()} />

			<div className="card">
				<h2>Appearance</h2>
				<p className="muted">The console follows your stored preference, then your OS setting.</p>
				<div className="row" style={{ marginTop: 12 }}>
					<button
						className={`button ${theme === "light" ? "" : "button-secondary"}`}
						type="button"
						aria-pressed={theme === "light"}
						onClick={() => {
							if (theme !== "light") toggleTheme();
						}}
					>
						Light
					</button>
					<button
						className={`button ${theme === "dark" ? "" : "button-secondary"}`}
						type="button"
						aria-pressed={theme === "dark"}
						onClick={() => {
							if (theme !== "dark") toggleTheme();
						}}
					>
						Dark
					</button>
				</div>
			</div>

			<div className="card">
				<h2>Privacy &amp; data</h2>
				<p className="muted">
					Supported connectors evaluate intercepted actions locally against the effective policy.
					Connector coverage, optional checks, and data sent to configured providers vary by
					deployment; review the canonical documents for the exact scope and retention terms.
				</p>
				<div className="row" style={{ marginTop: 12, flexWrap: "wrap" }}>
					<Link className="button button-secondary button-sm" to="/privacy">
						Privacy notice
					</Link>
					<Link className="button button-secondary button-sm" to="/security">
						Security
					</Link>
					<Link className="button button-secondary button-sm" to="/terms">
						Terms
					</Link>
					<Link className="button button-secondary button-sm" to="/support">
						Support
					</Link>
				</div>
			</div>

			{supabaseEnvError ? (
				<div className="notice notice-danger" role="alert">
					<b>Environment is incomplete.</b>
					<div className="muted small" style={{ marginTop: 6 }}>
						{supabaseEnvError}
					</div>
				</div>
			) : null}
		</div>
	);
}
