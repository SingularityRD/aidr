import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getSalesContactHref } from "../../../billing/commercial";
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

async function loadWorkspaces(): Promise<PilotWorkspace[]> {
	const { data, error } = await supabase.functions.invoke("identity-security", {
		body: { action: "bootstrap" },
	});
	if (error || data?.ok !== true || !Array.isArray(data.memberships)) {
		throw new Error(readErrorMessage(error, "Unable to verify an active workspace."));
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
		throw new Error("The active workspace response is invalid.");
	}
	return memberships.map((entry) => {
		const membership = entry as Record<string, unknown>;
		return {
			tenantId: membership.tenant_id as string,
			teamId: typeof membership.team_id === "string" ? membership.team_id : null,
		};
	});
}

function pilotStatusFrom(data: Record<string, unknown>): PilotStatus {
	const status = data.status;
	if (status !== "none" && status !== "pending" && status !== "approved" && status !== "denied") {
		throw new Error("Pilot status response is invalid.");
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
): Promise<PilotStatus> {
	const res = await supabase.functions.invoke("pilot-apply", {
		method: "POST",
		headers: { "X-AIDR-Tenant-ID": tenantId },
		body: { email, org: _org, useCase },
	});
	if (res.error || res.data?.ok !== true) {
		throw new Error(
			readErrorMessage(res.error, "The pilot service did not confirm the application."),
		);
	}
	return pilotStatusFrom(res.data as Record<string, unknown>);
}

export function PilotPage() {
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

				const availableWorkspaces = await loadWorkspaces();
				if (cancelled) return;
				const firstWorkspace = availableWorkspaces[0];
				if (!firstWorkspace) throw new Error("No active workspace is available for this account.");
				setWorkspaces(availableWorkspaces);
				setPilotTenantId(firstWorkspace.tenantId);
			} catch (cause) {
				if (!cancelled) {
					setError(readErrorMessage(cause, "Unable to load pilot status."));
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
					setError(readErrorMessage(res.error, "Pilot status response is invalid."));
					return;
				}
				const nextAdmission = readTenantAdmission(res.data.admission);
				if (!nextAdmission) throw new Error("Workspace access response is invalid.");
				setAdmission(nextAdmission);
				setLegal(readGaLegal(res.data.legal));
				setStatus(pilotStatusFrom(res.data as Record<string, unknown>));
			} catch (cause) {
				if (!cancelled && request === statusRequest.current)
					setError(readErrorMessage(cause, "Pilot status response is invalid."));
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
				<div className="muted">Loading…</div>
			</div>
		);
	}

	return (
		<div className="stack">
			<div className="card">
				<h1>{admission?.mode === "pilot" ? "Pilot program" : "Workspace access"}</h1>
				{admission?.mode === "pilot" ? (
					<p className="muted">
						Pilot access is approval-gated. Scope, pricing, support, and data-retention terms are
						confirmed in writing before enrollment. An application requests review; it does not
						grant access or authorize production use.
					</p>
				) : (
					<p className="muted">
						Sign in to check your workspace access and available setup options.
					</p>
				)}

				{!hasSession ? (
					<>
						<div className="row" style={{ marginTop: 12 }}>
							<Link className="button" to="/login?returnTo=/pilot">
								Sign in to check access
							</Link>
							{salesContactHref ? (
								<a className="button" href={salesContactHref}>
									Contact sales
								</a>
							) : null}
						</div>
						{!salesContactHref ? (
							<div className="notice" role="status">
								A sales contact route is not configured.
							</div>
						) : null}
					</>
				) : (
					<div className="notice">
						{workspaces.length > 1 ? (
							<label className="label">
								Workspace
								<select
									className="input"
									value={pilotTenantId ?? ""}
									disabled={busy}
									onChange={(event) => setPilotTenantId(event.target.value)}
								>
									{workspaces.map((workspace) => (
										<option key={workspace.tenantId} value={workspace.tenantId}>
											{workspace.teamId ? "Team" : "Personal"} workspace ·{" "}
											{workspace.tenantId.slice(0, 8)}
										</option>
									))}
								</select>
							</label>
						) : null}
						<div className="muted small">Your status</div>
						<div className="mono">
							{admission?.mode === "pilot" ? status.status : (admission?.status ?? "checking")}
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
										? "Set up 14-day trial"
										: "Start onboarding"}
								</button>
							</div>
						) : null}
						{admission?.status === "active" && selectedWorkspace && !selectedWorkspace.teamId ? (
							<div className="notice notice-warning" role="status">
								Agent enrollment requires a team workspace. Select an approved team workspace above.
							</div>
						) : null}
						{admission?.mode === "cloud" && admission.access_kind === "trial" ? (
							<p className="muted small">
								Trial: {admission.allowed_agents} agent; ends{" "}
								{admission.expires_at ? new Date(admission.expires_at).toLocaleString() : "unknown"}
								.
							</p>
						) : null}
						{admission?.mode === "cloud" &&
						admission.status !== "active" &&
						(!admission.trial_available || !legal?.configured) ? (
							<div className="notice notice-warning" role="status">
								{legal?.configured === false
									? "Trial setup awaits published Terms and Privacy. Contact your administrator."
									: "No self-service trial is available for this workspace. Contact your administrator or sales."}
							</div>
						) : null}
						{admission &&
						(admission.mode === "onprem" || admission.mode === "unconfigured") &&
						admission.status !== "active" ? (
							<div className="notice notice-warning" role="status">
								Workspace access is not active. Contact your deployment administrator.
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
					<h2>Apply</h2>
					<p className="muted">
						Describe the runtime and tools you want to protect. Do not include credentials, tokens,
						customer content, or other sensitive data.
					</p>
					<label className="label">
						Use case
						<textarea
							className="input"
							style={{ minHeight: 140, resize: "vertical" }}
							value={useCase}
							onChange={(e) => setUseCase(e.target.value)}
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
							I have reviewed the <a href={privacyUrl}>privacy notice</a> and{" "}
							<a href={termsUrl}>pilot terms</a>.
						</label>
					) : (
						<div className="notice notice-danger" role="alert">
							Pilot applications are disabled until safe HTTPS privacy and terms documents are
							configured.
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
									if (!pilotTenantId)
										throw new Error("No active workspace is available for this account.");
									setStatus(await applyForPilot(email, "", useCase, pilotTenantId));
								} catch (e) {
									setError(readErrorMessage(e, "Failed to submit"));
								} finally {
									setBusy(false);
								}
							}}
						>
							Submit application
						</button>
					</div>
				</div>
			) : null}
		</div>
	);
}
