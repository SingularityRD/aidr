import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { englishT, type Translate, useRichT, useT } from "../../i18n/I18nProvider";
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
import { LicenseSection } from "../LicenseSection";
import { NotificationSettings } from "../NotificationSettings";
import { getSession, signOut } from "../session";
import { useTheme } from "../ThemeProvider";

const ROLE_LABELS: Record<string, DashboardMessageKey> = {
	owner: "common.role.owner",
	admin: "common.role.admin",
	member: "common.role.member",
	viewer: "common.role.viewer",
};

const STATUS_LABELS: Record<string, DashboardMessageKey> = {
	active: "settings.status.active",
	suspended: "settings.status.suspended",
	closing: "settings.status.closing",
	closed: "settings.status.closed",
};

/** Operator copy for the service's machine-readable workspace errors. */
function workspaceErrorMessage(code: string, t: Translate = englishT): string {
	switch (code) {
		case "mfa_required":
			return t("settings.error.mfaRequired");
		case "workspace_role_insufficient":
			return t("settings.error.role");
		case "workspace_forbidden":
			return t("settings.error.forbidden");
		case "workspace_not_active":
			return t("settings.error.notActive");
		case "retention_reduction_unconfirmed":
			return t("settings.error.retentionUnconfirmed");
		case "confirmation_mismatch":
			return t("settings.error.confirmationMismatch");
		case "invalid_workspace_name":
			return t("settings.error.invalidName");
		case "invalid_retention_days":
			return t("settings.error.invalidRetention");
		case "rate_limited":
			return t("settings.error.rateLimited");
		case "session_revoked":
		case "invalid_access_token":
			return t("common.sessionInvalid");
		default:
			return t("settings.error.generic");
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
	const t = useT();
	if (!tenantId) return <p className="muted">{t("settings.mfa.noTeam")}</p>;
	if (failed) {
		return (
			<p className="muted" role="status">
				{t("settings.mfa.failed")}
			</p>
		);
	}
	if (!assurance) return <p className="muted">{t("settings.mfa.checking")}</p>;
	if (assurance.currentLevel === "aal2") {
		return <p data-testid="mfa-status">{t("settings.mfa.verified")}</p>;
	}
	return (
		<div data-testid="mfa-status">
			<p>
				{t("settings.mfa.notVerified")}{" "}
				{assurance.requireMfa
					? t("settings.mfa.workspaceRequires")
					: t("settings.mfa.changesRequire")}
			</p>
			<Link className="button button-secondary button-sm" to={stepUpPath(tenantId)}>
				{t("settings.mfa.setUp")}
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
	const t = useT();
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
			<h2>{t("settings.profile.title")}</h2>
			<div className="session-box" style={{ marginTop: 10, maxWidth: 420 }}>
				<div className="muted small">{t("settings.profile.signedInAs")}</div>
				<div className="mono" style={{ marginTop: 2, overflowWrap: "anywhere" }}>
					{email ?? t("common.unknown")}
				</div>
			</div>
			<div style={{ marginTop: 12 }}>
				<div className="muted small">{t("settings.profile.mfa")}</div>
				<MfaStatus tenantId={tenantId} assurance={assurance} failed={assuranceError} />
			</div>
			<div className="row" style={{ marginTop: 12 }}>
				<button className="button button-secondary" type="button" onClick={onSignOut}>
					{t("settings.profile.signOut")}
				</button>
			</div>
		</div>
	);
}

type Workspace = WorkspaceSettings["workspace"];

/**
 * Client-side mirror of the service's validation; the service stays authoritative.
 * Without retention rights the stored value is never part of a change.
 */
function draftChanges(
	workspace: Workspace,
	bounds: WorkspaceSettings["retentionBounds"],
	name: string,
	retention: string,
	canEditRetention: boolean,
) {
	const trimmedName = name.trim();
	const days = canEditRetention ? Number(retention) : workspace.retentionDays;
	const retentionValid =
		!canEditRetention ||
		(/^\d+$/.test(retention.trim()) && days >= bounds.min && days <= bounds.max);
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
	canEditRetention,
	onSaved,
	onError,
}: {
	tenantId: string;
	workspace: Workspace;
	bounds: WorkspaceSettings["retentionBounds"];
	canEditRetention: boolean;
	onSaved: (workspace: Workspace) => void;
	onError: (code: string) => void;
}) {
	const t = useT();
	const [name, setName] = useState(workspace.name);
	const [retention, setRetention] = useState(String(workspace.retentionDays));
	const [confirmReduction, setConfirmReduction] = useState(false);
	const [busy, setBusy] = useState(false);
	const draft = draftChanges(workspace, bounds, name, retention, canEditRetention);
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
				{t("settings.form.name")}
				<input
					className="input"
					value={name}
					maxLength={200}
					onChange={(event) => setName(event.target.value)}
					required
				/>
			</label>
			{canEditRetention ? (
				<>
					<label className="label">
						{t("settings.form.retention")}
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
						{t("settings.form.range", { min: bounds.min, max: bounds.max })}
					</p>
				</>
			) : (
				<p className="muted small" data-testid="retention-owner-only">
					{t("settings.form.ownerOnly", { days: workspace.retentionDays })}
				</p>
			)}
			{draft.reducing ? (
				<label className="row" style={{ gap: 8, alignItems: "flex-start" }}>
					<input
						type="checkbox"
						checked={confirmReduction}
						onChange={(event) => setConfirmReduction(event.target.checked)}
					/>
					<span>
						{t("settings.form.confirmReduction", {
							from: workspace.retentionDays,
							to: draft.days,
						})}
					</span>
				</label>
			) : null}
			<div className="row">
				<button className="button" type="submit" disabled={!canSave}>
					{busy ? t("common.saving") : t("settings.form.save")}
				</button>
			</div>
			<p className="muted small">{t("settings.form.note")}</p>
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
	const t = useT();
	const richT = useRichT();
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
			<h3>{t("settings.close.title")}</h3>
			<p className="muted small">{t("settings.close.body")}</p>
			<label className="label">
				{richT("settings.close.confirm", { name: <b>{workspaceName}</b> })}
				<input
					className="input"
					value={confirmName}
					onChange={(event) => setConfirmName(event.target.value)}
					autoComplete="off"
				/>
			</label>
			<div className="row">
				<button className="button button-danger" type="submit" disabled={busy || !matches}>
					{t("settings.close.title")}
				</button>
			</div>
		</form>
	);
}

function NoticeBanner({ notice, tenantId }: { notice: Notice; tenantId: string }) {
	const t = useT();
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
						{t("common.verifyMfa")}
					</Link>
				</div>
			) : null}
		</div>
	);
}

function WorkspaceSection({ tenantId }: { tenantId: string }) {
	const { applyWorkspaceName } = useTeam();
	const t = useT();
	const [settings, setSettings] = useState<WorkspaceSettings | null>(null);
	// The error code; its text is chosen at render time in the current language.
	const [loadError, setLoadError] = useState<string | null>(null);
	const [notice, setNotice] = useState<Notice | null>(null);
	const request = useRef(0);

	const load = useCallback(async () => {
		const id = ++request.current;
		setLoadError(null);
		const result = await loadWorkspaceSettings(tenantId);
		if (id !== request.current) return;
		setSettings(result.ok ? result.value : null);
		setLoadError(result.ok ? null : result.error);
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
				<h2>{t("settings.workspace.title")}</h2>
				{loadError ? (
					<>
						<div className="notice notice-danger" role="alert">
							{workspaceErrorMessage(loadError, t)}
						</div>
						<button className="button button-secondary" type="button" onClick={() => void load()}>
							{t("common.retry")}
						</button>
					</>
				) : (
					<p className="muted">{t("settings.workspace.loading")}</p>
				)}
			</div>
		);
	}

	const { workspace } = settings;
	const label = (labels: Record<string, DashboardMessageKey>, value: string) => {
		const key = labels[value];
		return key ? t(key) : value;
	};
	const showError = (code: string) =>
		setNotice({ tone: "error", message: workspaceErrorMessage(code, t), code });

	function saved(updated: Workspace) {
		setSettings((prev) => (prev ? { ...prev, workspace: updated } : prev));
		if (updated.name !== workspace.name) applyWorkspaceName(tenantId, updated.name);
		setNotice({ tone: "success", message: t("settings.workspace.saved") });
	}

	function closed(closure: WorkspaceClosure) {
		setSettings((prev) =>
			prev
				? {
						...prev,
						workspace: { ...prev.workspace, status: "closing" },
						canEdit: false,
						canEditRetention: false,
						canClose: false,
					}
				: prev,
		);
		const backup = closure.backupException ? ` ${closure.backupException}` : "";
		setNotice({
			tone: "success",
			message: `${t("settings.workspace.closed", { status: closure.status })}${backup}`,
		});
	}

	return (
		<div className="card">
			<h2>{t("settings.workspace.title")}</h2>
			<dl className="stack" style={{ marginTop: 10, gap: 6 }}>
				<div>
					<dt className="muted small">{t("common.name")}</dt>
					<dd data-testid="workspace-name">{workspace.name}</dd>
				</div>
				<div>
					<dt className="muted small">{t("common.status")}</dt>
					<dd>{label(STATUS_LABELS, workspace.status)}</dd>
				</div>
				<div>
					<dt className="muted small">{t("settings.workspace.retention")}</dt>
					<dd>{t("common.days", { count: workspace.retentionDays })}</dd>
				</div>
				<div>
					<dt className="muted small">{t("settings.workspace.role")}</dt>
					<dd>{label(ROLE_LABELS, settings.role)}</dd>
				</div>
			</dl>

			{notice ? <NoticeBanner notice={notice} tenantId={tenantId} /> : null}

			{settings.canEdit ? (
				<WorkspaceEditForm
					tenantId={tenantId}
					workspace={workspace}
					bounds={settings.retentionBounds}
					canEditRetention={settings.canEditRetention}
					onSaved={saved}
					onError={showError}
				/>
			) : (
				<p className="muted" style={{ marginTop: 12 }}>
					{workspace.status === "active"
						? t("settings.workspace.adminOnly")
						: t("settings.workspace.readOnly")}
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
	const t = useT();
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
					setError(readErrorMessage(cause, t("settings.sessionLoadFailed")));
				}
			}
		}
		load();
		return () => {
			cancelled = true;
		};
	}, []);

	if (endingSession) return <div role="status">{t("layout.signingOut")}</div>;

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
				<h1>{t("nav.settings")}</h1>
				<p className="muted">{t("settings.intro")}</p>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</div>

			{tenantId ? <WorkspaceSection key={tenantId} tenantId={tenantId} /> : null}

			{tenantId ? <LicenseSection key={`license-${tenantId}`} tenantId={tenantId} /> : null}

			{tenantId ? (
				<NotificationSettings key={`notifications-${tenantId}`} tenantId={tenantId} />
			) : null}

			<ProfileSection email={email} tenantId={tenantId} onSignOut={() => void endSession()} />

			<div className="card">
				<h2>{t("settings.appearance.title")}</h2>
				<p className="muted">{t("settings.appearance.body")}</p>
				<div className="row" style={{ marginTop: 12 }}>
					<button
						className={`button ${theme === "light" ? "" : "button-secondary"}`}
						type="button"
						aria-pressed={theme === "light"}
						onClick={() => {
							if (theme !== "light") toggleTheme();
						}}
					>
						{t("settings.appearance.light")}
					</button>
					<button
						className={`button ${theme === "dark" ? "" : "button-secondary"}`}
						type="button"
						aria-pressed={theme === "dark"}
						onClick={() => {
							if (theme !== "dark") toggleTheme();
						}}
					>
						{t("settings.appearance.dark")}
					</button>
				</div>
			</div>

			<div className="card">
				<h2>{t("settings.privacy.title")}</h2>
				<p className="muted">{t("settings.privacy.body")}</p>
				<div className="row" style={{ marginTop: 12, flexWrap: "wrap" }}>
					<Link className="button button-secondary button-sm" to="/privacy">
						{t("settings.privacy.notice")}
					</Link>
					<Link className="button button-secondary button-sm" to="/security">
						{t("public.security")}
					</Link>
					<Link className="button button-secondary button-sm" to="/terms">
						{t("public.terms")}
					</Link>
					<Link className="button button-secondary button-sm" to="/support">
						{t("public.support")}
					</Link>
				</div>
			</div>

			{supabaseEnvError ? (
				<div className="notice notice-danger" role="alert">
					<b>{t("settings.envIncomplete")}</b>
					<div className="muted small" style={{ marginTop: 6 }}>
						{supabaseEnvError}
					</div>
				</div>
			) : null}
		</div>
	);
}
