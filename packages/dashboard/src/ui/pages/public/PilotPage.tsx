import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getSalesContactHref } from "../../../billing/commercial";
import type { DashboardMessageKey } from "../../../i18n/en";
import { englishT, type Translate, useRichT, useT } from "../../../i18n/I18nProvider";
import { readErrorMessage } from "../../../lib/errors";
import { supabase } from "../../../lib/supabase";
import { getSession } from "../../session";
import {
	type GaLegal,
	readGaLegal,
	readTenantAdmission,
	type TenantAdmission,
} from "../../tenant-admission";
import { safeExternalUrl } from "./external-url";

type PilotStatus =
	| { status: "none" }
	| { status: "pending"; cohort?: string | null }
	| { status: "approved"; cohort?: string | null }
	| { status: "denied"; cohort?: string | null };

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

interface PilotWorkspace {
	tenantId: string;
	teamId: string | null;
}

const PILOT_STATUS_LABEL: Record<PilotStatus["status"], DashboardMessageKey> = {
	none: "pl.status.none",
	pending: "pl.status.pending",
	approved: "pl.status.approved",
	denied: "pl.status.denied",
};

async function loadWorkspaces(t: Translate = englishT): Promise<PilotWorkspace[]> {
	const { data, error } = await supabase.functions.invoke("identity-security", {
		body: { action: "bootstrap" },
	});
	if (error || data?.ok !== true || !Array.isArray(data.memberships)) {
		throw new Error(readErrorMessage(error, t("pl.workspaceUnverified")));
	}
	const memberships = data.memberships as unknown[];
	if (
		memberships.some(
			(entry) =>
				!entry ||
				typeof entry !== "object" ||
				Array.isArray(entry) ||
				!UUID.test(String((entry as Record<string, unknown>).tenant_id ?? "")) ||
				((entry as Record<string, unknown>).team_id !== undefined &&
					(entry as Record<string, unknown>).team_id !== null &&
					!UUID.test(String((entry as Record<string, unknown>).team_id))),
		)
	) {
		throw new Error(t("pl.workspaceInvalid"));
	}
	return memberships.map((entry) => {
		const membership = entry as Record<string, unknown>;
		return {
			tenantId: membership.tenant_id as string,
			teamId: typeof membership.team_id === "string" ? membership.team_id : null,
		};
	});
}

function pilotStatusFrom(data: Record<string, unknown>, t: Translate = englishT): PilotStatus {
	const status = data.status;
	if (status !== "none" && status !== "pending" && status !== "approved" && status !== "denied") {
		throw new Error(t("pl.statusInvalid"));
	}
	return {
		status,
		...((typeof data.cohort === "string" || data.cohort === null) && status !== "none"
			? { cohort: data.cohort }
			: {}),
	} as PilotStatus;
}

// Apply for the selected tenant's pilot access.
async function applyForPilot(
	email: string,
	_org: string,
	useCase: string,
	tenantId: string,
	t: Translate = englishT,
): Promise<PilotStatus> {
	const res = await supabase.functions.invoke("pilot-apply", {
		method: "POST",
		headers: { "X-AIDR-Tenant-ID": tenantId },
		body: { email, org: _org, useCase },
	});
	if (res.error || res.data?.ok !== true) {
		throw new Error(readErrorMessage(res.error, t("pl.notConfirmed")));
	}
	return pilotStatusFrom(res.data as Record<string, unknown>, t);
}

export function PilotPage() {
	const t = useT();
	const richT = useRichT();
	// Loaders read the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
	const navigate = useNavigate();
	const [sessionReady, setSessionReady] = useState(false);
	const [hasSession, setHasSession] = useState(false);
	const [status, setStatus] = useState<PilotStatus>({ status: "none" });
	const [admission, setAdmission] = useState<TenantAdmission | null>(null);
	const [legal, setLegal] = useState<GaLegal | null>(null);
	const [workspaces, setWorkspaces] = useState<PilotWorkspace[]>([]);
	const [pilotTenantId, setPilotTenantId] = useState<string | null>(null);
	const [useCase, setUseCase] = useState("");
	const [email, setEmail] = useState("");
	const [reviewedLegalDocs, setReviewedLegalDocs] = useState(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const statusRequest = useRef(0);
	const salesContactHref = getSalesContactHref();
	const privacyUrl = safeExternalUrl(import.meta.env.VITE_PRIVACY_URL);
	const termsUrl = safeExternalUrl(import.meta.env.VITE_TERMS_URL);
	const legalDocsReady = Boolean(privacyUrl && termsUrl);
	const canSubmit =
		!busy &&
		admission?.mode === "pilot" &&
		Boolean(pilotTenantId) &&
		Boolean(useCase.trim()) &&
		legalDocsReady &&
		reviewedLegalDocs;
	const selectedWorkspace = workspaces.find((workspace) => workspace.tenantId === pilotTenantId);

	useEffect(() => {
		let cancelled = false;
		const t = translator.current;
		async function load() {
			try {
				const sess = await getSession();
				if (cancelled) return;
				setHasSession(Boolean(sess));
				setSessionReady(true);
				if (!sess) return;

				// Get user email from session
				const userEmail = sess.user?.email || "";
				setEmail(userEmail);

				const availableWorkspaces = await loadWorkspaces(t);
				if (cancelled) return;
				const firstWorkspace = availableWorkspaces[0];
				if (!firstWorkspace) throw new Error(t("pl.noWorkspace"));
				setWorkspaces(availableWorkspaces);
				setPilotTenantId(firstWorkspace.tenantId);
			} catch (cause) {
				if (!cancelled) {
					setError(readErrorMessage(cause, t("pl.loadFailed")));
					setSessionReady(true);
				}
			}
		}
		load();
		return () => {
			cancelled = true;
		};
	}, []);

	useEffect(() => {
		const tenantId = pilotTenantId;
		if (!hasSession || !tenantId) return;
		let cancelled = false;
		const t = translator.current;
		const request = ++statusRequest.current;
		setStatus({ status: "none" });
		setAdmission(null);
		setLegal(null);
		setError(null);
		async function loadStatus(tenantId: string) {
			try {
				const res = await supabase.functions.invoke("pilot-status", {
					method: "GET",
					headers: { "X-AIDR-Tenant-ID": tenantId },
				});
				if (cancelled || request !== statusRequest.current) return;
				if (res.error || res.data?.ok !== true) {
					setError(readErrorMessage(res.error, t("pl.statusInvalid")));
					return;
				}
				const nextAdmission = readTenantAdmission(res.data.admission);
				if (!nextAdmission) throw new Error(t("pl.accessInvalid"));
				setAdmission(nextAdmission);
				setLegal(readGaLegal(res.data.legal));
				setStatus(pilotStatusFrom(res.data as Record<string, unknown>, t));
			} catch (cause) {
				if (!cancelled && request === statusRequest.current)
					setError(readErrorMessage(cause, t("pl.statusInvalid")));
			}
		}
		void loadStatus(tenantId);
		return () => {
			cancelled = true;
		};
	}, [hasSession, pilotTenantId]);

	if (!sessionReady) {
		return (
			<div className="card">
				<div className="muted">{t("common.loading")}</div>
			</div>
		);
	}

	return (
		<div className="stack">
			<div className="card">
				<h1>{admission?.mode === "pilot" ? t("pl.titlePilot") : t("pl.titleAccess")}</h1>
				{admission?.mode === "pilot" ? (
					<p className="muted">{t("pl.leadPilot")}</p>
				) : (
					<p className="muted">{t("pl.leadAccess")}</p>
				)}

				{!hasSession ? (
					<>
						<div className="row" style={{ marginTop: 12 }}>
							<Link className="button" to="/login?returnTo=/pilot">
								{t("pl.signIn")}
							</Link>
							{salesContactHref ? (
								<a className="button" href={salesContactHref}>
									{t("pl.contactSales")}
								</a>
							) : null}
						</div>
						{!salesContactHref ? (
							<div className="notice" role="status">
								{t("pl.noSales")}
							</div>
						) : null}
					</>
				) : (
					<div className="notice">
						{workspaces.length > 1 ? (
							<label className="label">
								{t("pl.workspace")}
								<select
									className="input"
									value={pilotTenantId ?? ""}
									disabled={busy}
									onChange={(event) => setPilotTenantId(event.target.value)}
								>
									{workspaces.map((workspace) => (
										<option key={workspace.tenantId} value={workspace.tenantId}>
											{workspace.teamId
												? t("pl.teamWorkspace", { id: workspace.tenantId.slice(0, 8) })
												: t("pl.personalWorkspace", { id: workspace.tenantId.slice(0, 8) })}
										</option>
									))}
								</select>
							</label>
						) : null}
						<div className="muted small">{t("pl.yourStatus")}</div>
						<div className="mono">
							{admission?.mode === "pilot"
								? t(PILOT_STATUS_LABEL[status.status])
								: (admission?.status ?? t("pl.checking"))}
							{admission?.mode === "pilot" && status.status === "approved" && status.cohort
								? ` (${status.cohort})`
								: ""}
						</div>
						{(admission?.status === "active" ||
							(admission?.mode === "cloud" && admission.trial_available && legal?.configured)) &&
						selectedWorkspace?.teamId &&
						pilotTenantId ? (
							<div className="row" style={{ marginTop: 10 }}>
								<button
									className="button"
									type="button"
									onClick={() =>
										navigate(`/onboarding?tenant=${encodeURIComponent(pilotTenantId)}`)
									}
								>
									{admission?.mode === "cloud" && admission.trial_available
										? t("pl.setUpTrial")
										: t("pl.startOnboarding")}
								</button>
							</div>
						) : null}
						{admission?.status === "active" && selectedWorkspace && !selectedWorkspace.teamId ? (
							<div className="notice notice-warning" role="status">
								{t("pl.needTeam")}
							</div>
						) : null}
						{admission?.mode === "cloud" && admission.access_kind === "trial" ? (
							<p className="muted small">
								{t("pl.trial", {
									count: admission.allowed_agents,
									time: admission.expires_at
										? new Date(admission.expires_at).toLocaleString()
										: t("common.unknown"),
								})}
							</p>
						) : null}
						{admission?.mode === "cloud" &&
						admission.status !== "active" &&
						(!admission.trial_available || !legal?.configured) ? (
							<div className="notice notice-warning" role="status">
								{legal?.configured === false ? t("pl.legalPending") : t("pl.noTrial")}
							</div>
						) : null}
						{admission &&
						(admission.mode === "onprem" || admission.mode === "unconfigured") &&
						admission.status !== "active" ? (
							<div className="notice notice-warning" role="status">
								{t("pl.inactive")}
							</div>
						) : null}
					</div>
				)}
				{error ? (
					<div className="notice notice-danger" role="alert">
						{error}
					</div>
				) : null}
			</div>

			{hasSession && admission?.mode === "pilot" ? (
				<div className="card">
					<h2>{t("pl.apply")}</h2>
					<p className="muted">{t("pl.applyLead")}</p>
					<label className="label">
						{t("pl.useCase")}
						<textarea
							className="input"
							style={{ minHeight: 140, resize: "vertical" }}
							value={useCase}
							onChange={(e) => setUseCase(e.target.value)}
							// i18n-exempt: example list of product names
							placeholder="Claude Code/Cursor/OpenClaw/OpenCode, tools, constraints, risks…"
						/>
					</label>

					{privacyUrl && termsUrl ? (
						<label className="label">
							<input
								type="checkbox"
								checked={reviewedLegalDocs}
								onChange={(event) => setReviewedLegalDocs(event.target.checked)}
							/>{" "}
							{richT("pl.reviewed", {
								privacy: <a href={privacyUrl}>{t("pl.privacy")}</a>,
								terms: <a href={termsUrl}>{t("pl.terms")}</a>,
							})}
						</label>
					) : (
						<div className="notice notice-danger" role="alert">
							{t("pl.legalMissing")}
						</div>
					)}

					<div className="row">
						<button
							type="submit"
							className="button"
							disabled={!canSubmit}
							onClick={async () => {
								if (!canSubmit) return;
								setBusy(true);
								setError(null);
								++statusRequest.current;
								try {
									if (!pilotTenantId) throw new Error(t("pl.noWorkspace"));
									setStatus(await applyForPilot(email, "", useCase, pilotTenantId, t));
								} catch (e) {
									setError(readErrorMessage(e, t("pl.submitFailed")));
								} finally {
									setBusy(false);
								}
							}}
						>
							{t("pl.submit")}
						</button>
					</div>
				</div>
			) : null}
		</div>
	);
}
