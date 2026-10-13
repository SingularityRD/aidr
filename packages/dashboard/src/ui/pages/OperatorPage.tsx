import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { type Translate, useRichT, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
import {
	callOperatorAdmin,
	type GrantLicenseInput,
	isUuid,
	MAX_SEATS,
	OPERATOR_PAGE_SIZE,
	type OperatorTenant,
	operatorErrorMessage,
	PLAN_ID,
	parseTenantPage,
	parseTenantUsage,
	type TenantUsage,
	validReference,
} from "../../lib/operator-admin";
import { supabase } from "../../lib/supabase";
import { ThemeToggle } from "../ThemeToggle";
import { useSessionSnapshot } from "../use-session";

/**
 * Platform-operator console: tenant licences, usage and seats.
 *
 * This route deliberately sits outside the tenant-scoped AppLayout. Platform
 * operators are not members of the tenants they license (separation of duty),
 * so the tenant identity bootstrap would refuse them. Access is decided only by
 * the `operator-admin` Edge Function on every call: an active platform-operator
 * row (otherwise 403 `forbidden`) and an AAL2 session (otherwise 403
 * `mfa_required`). No client flag opens this screen.
 */
export function OperatorPage() {
	const t = useT();
	const { snapshot, generation, refresh } = useSessionSnapshot();
	const session = snapshot?.session ?? null;
	return (
		<div className="app">
			<a className="skip-link" href="#page-content">
				{t("op.skip")}
			</a>
			<header className="console-topbar">
				<Link to="/dashboard" className="brand-link">
					<span className="brand-word" aria-hidden="true">
						AIDR
					</span>
					<span className="brand-sub" aria-hidden="true">
						{t("op.brand")}
					</span>
					<span className="sr-only">{t("op.brandSr")}</span>
				</Link>
				<div className="header-actions">
					<ThemeToggle />
				</div>
			</header>
			<main className="main" id="page-content" tabIndex={-1}>
				{!snapshot ? (
					<div className="card" role="status" aria-live="polite">
						<h1>{t("op.verifying")}</h1>
						<p className="muted">{t("op.verifyingLead")}</p>
					</div>
				) : !session ? (
					<div className="card">
						<h1>{t("op.signInRequired")}</h1>
						<p className="muted">{t("op.signInLead")}</p>
						<Link className="button" to="/login?returnTo=%2Foperator">
							{t("op.signIn")}
						</Link>
					</div>
				) : (
					// A token or user change discards every loaded row, form and secret.
					<OperatorConsole
						key={JSON.stringify([session.user.id, session.access_token, generation])}
						accessToken={session.access_token}
						refreshSession={refresh}
					/>
				)}
			</main>
		</div>
	);
}

type Gate =
	| { kind: "checking" }
	| { kind: "ready" }
	| { kind: "forbidden" }
	| { kind: "mfa_required" }
	| { kind: "signed_out" }
	| { kind: "unavailable"; message: string };

type Notice = { tone: "success" | "error"; message: string };

const formatDate = (value: string | null) => (value ? new Date(value).toLocaleString() : "—");

/** The gate outcomes the server can force on any call, independent of the action. */
function gateFor(status: number | null, code: string | null): Gate | null {
	if (code === "forbidden") return { kind: "forbidden" };
	if (code === "mfa_required") return { kind: "mfa_required" };
	if (status === 401) return { kind: "signed_out" };
	return null;
}

function licenceLabel(tenant: OperatorTenant, t: Translate): { text: string; badge: string } {
	const admission = tenant.admission;
	if (!admission) return { text: t("op.noAdmission"), badge: "badge-neutral" };
	if (admission.active) return { text: t("op.active"), badge: "badge-success" };
	return { text: t("op.inactive"), badge: "badge-warning" };
}

function OperatorConsole({
	accessToken,
	refreshSession,
}: {
	accessToken: string;
	refreshSession: () => Promise<void>;
}) {
	const t = useT();
	// The loader reads the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
	const [gate, setGate] = useState<Gate>({ kind: "checking" });
	const [tenants, setTenants] = useState<OperatorTenant[]>([]);
	const [nextCursor, setNextCursor] = useState<string | null>(null);
	// Keyset paging: the cursor that produced each page, so Previous is exact.
	const [cursors, setCursors] = useState<(string | null)[]>([null]);
	const [loading, setLoading] = useState(false);
	const [listError, setListError] = useState<string | null>(null);
	const [selected, setSelected] = useState<OperatorTenant | null>(null);
	const live = useRef(true);
	useEffect(
		() => () => {
			live.current = false;
		},
		[],
	);

	const loadPage = useCallback(
		async (after: string | null) => {
			const t = translator.current;
			setLoading(true);
			setListError(null);
			const response = await callOperatorAdmin(accessToken, {
				action: "list_tenants",
				limit: OPERATOR_PAGE_SIZE,
				...(after ? { after } : {}),
			});
			if (!live.current) return false;
			setLoading(false);
			if (!response.ok) {
				const forced = gateFor(response.status, response.code);
				const message = operatorErrorMessage(response.code, t("op.listUnavailable"), t);
				if (forced) setGate(forced);
				else
					setGate((current) =>
						current.kind === "ready" ? current : { kind: "unavailable", message },
					);
				if (!forced) setListError(message);
				return false;
			}
			const page = parseTenantPage(response.result);
			if (!page) {
				const message = t("op.listUnexpected");
				setGate((current) =>
					current.kind === "ready" ? current : { kind: "unavailable", message },
				);
				setListError(message);
				return false;
			}
			setTenants(page.tenants);
			setNextCursor(page.nextCursor);
			setGate({ kind: "ready" });
			return true;
		},
		[accessToken],
	);

	useEffect(() => {
		void loadPage(null);
	}, [loadPage]);

	const currentCursor = cursors[cursors.length - 1] ?? null;

	async function goNext() {
		if (!nextCursor) return;
		const cursor = nextCursor;
		if (await loadPage(cursor)) setCursors((stack) => [...stack, cursor]);
	}

	async function goPrevious() {
		if (cursors.length < 2) return;
		const previous = cursors[cursors.length - 2] ?? null;
		if (await loadPage(previous)) setCursors((stack) => stack.slice(0, -1));
	}

	const refreshList = useCallback(() => loadPage(currentCursor), [loadPage, currentCursor]);

	switch (gate.kind) {
		case "checking":
			return (
				<div className="card" role="status" aria-live="polite">
					<h1>{t("op.checking")}</h1>
					<p className="muted">{t("op.checkingLead")}</p>
				</div>
			);
		case "forbidden":
			return (
				<div className="card" role="alert">
					<p className="eyebrow">{t("op.forbidden")}</p>
					<h1>{t("op.accessRequired")}</h1>
					<p className="muted">{t("op.accessRequiredLead")}</p>
					<Link className="button button-secondary" to="/dashboard">
						{t("op.returnDashboard")}
					</Link>
				</div>
			);
		case "mfa_required":
			return <OperatorStepUp onVerified={refreshSession} />;
		case "signed_out":
			return (
				<div className="card" role="alert">
					<h1>{t("op.sessionInvalid")}</h1>
					<p className="muted">{t("op.sessionInvalidLead")}</p>
					<Link className="button" to="/login?returnTo=%2Foperator">
						{t("op.signIn")}
					</Link>
				</div>
			);
		case "unavailable":
			return (
				<div className="card" role="alert">
					<h1>{t("op.unavailable")}</h1>
					<p className="muted">{gate.message}</p>
					<button
						className="button button-secondary"
						type="button"
						disabled={loading}
						onClick={() => {
							setGate({ kind: "checking" });
							void loadPage(null);
						}}
					>
						{t("common.retry")}
					</button>
				</div>
			);
		case "ready":
			break;
	}

	return (
		<div className="stack">
			<header className="card">
				<p className="eyebrow">{t("op.eyebrow")}</p>
				<h1>{t("op.title")}</h1>
				<p className="muted">{t("op.lead")}</p>
			</header>

			<section className="card" aria-labelledby="tenants-heading">
				<div className="row space-between">
					<h2 id="tenants-heading">{t("op.tenants")}</h2>
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={loading}
						onClick={() => void refreshList()}
					>
						{t("common.refresh")}
					</button>
				</div>
				{listError ? (
					<div className="notice notice-danger" role="alert">
						{listError}
					</div>
				) : null}
				{loading ? <p role="status">{t("common.loading")}</p> : null}
				{!loading && tenants.length === 0 ? <p className="muted">{t("op.noTenants")}</p> : null}
				{tenants.length > 0 ? (
					<div className="table-wrap">
						<table className="table">
							<caption className="sr-only">{t("op.tenantsCaption")}</caption>
							<thead>
								<tr>
									<th scope="col">{t("op.col.tenant")}</th>
									<th scope="col">{t("op.col.kind")}</th>
									<th scope="col">{t("common.status")}</th>
									<th scope="col">{t("op.col.licence")}</th>
									<th scope="col">{t("op.col.plan")}</th>
									<th scope="col">{t("op.col.seats")}</th>
									<th scope="col">{t("op.col.expires")}</th>
									<th scope="col">{t("op.col.actions")}</th>
								</tr>
							</thead>
							<tbody>
								{tenants.map((tenant) => {
									const licence = licenceLabel(tenant, t);
									return (
										<tr key={tenant.id} aria-selected={selected?.id === tenant.id}>
											<td>
												<div>
													{tenant.name ?? <span className="muted">{t("op.personalWithheld")}</span>}
												</div>
												<code className="mono small">{tenant.id}</code>
											</td>
											<td>{tenant.kind}</td>
											<td>{tenant.status}</td>
											<td>
												<span className={`badge ${licence.badge}`}>{licence.text}</span>
												{tenant.admission ? (
													<div className="muted small">{tenant.admission.kind}</div>
												) : null}
											</td>
											<td>{tenant.admission?.planId ?? "—"}</td>
											<td>{tenant.admission?.seats ?? "—"}</td>
											<td>{formatDate(tenant.admission?.expiresAt ?? null)}</td>
											<td>
												<button
													className="button button-secondary button-sm"
													type="button"
													aria-label={t("op.manageLabel", { name: tenant.name ?? tenant.id })}
													onClick={() => setSelected(tenant)}
												>
													{t("op.manage")}
												</button>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				) : null}
				<div className="row" style={{ marginTop: 10 }}>
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={loading || cursors.length < 2}
						onClick={() => void goPrevious()}
					>
						{t("op.previous")}
					</button>
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={loading || !nextCursor}
						onClick={() => void goNext()}
					>
						{t("op.next")}
					</button>
					<span className="muted small">{t("op.page", { page: cursors.length })}</span>
				</div>
			</section>

			{selected ? (
				<TenantPanel
					key={selected.id}
					tenant={selected}
					accessToken={accessToken}
					onGate={setGate}
					onChanged={refreshList}
					onClose={() => setSelected(null)}
				/>
			) : null}
		</div>
	);
}

function TenantPanel({
	tenant,
	accessToken,
	onGate,
	onChanged,
	onClose,
}: {
	tenant: OperatorTenant;
	accessToken: string;
	onGate: (gate: Gate) => void;
	onChanged: () => Promise<boolean>;
	onClose: () => void;
}) {
	const t = useT();
	const richT = useRichT();
	// The usage loader reads the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
	const [usage, setUsage] = useState<TenantUsage | null>(null);
	const [usageError, setUsageError] = useState<string | null>(null);
	const [usageLoading, setUsageLoading] = useState(true);
	const [notice, setNotice] = useState<Notice | null>(null);
	const [busy, setBusy] = useState(false);

	const admission = tenant.admission;
	const [planId, setPlanId] = useState(admission?.planId ?? "");
	const [seats, setSeats] = useState(admission?.seats ? String(admission.seats) : "");
	const [expiryDate, setExpiryDate] = useState("");
	const [reference, setReference] = useState("");
	const [owner, setOwner] = useState("");
	const [grantReview, setGrantReview] = useState<GrantLicenseInput | null>(null);

	const [reason, setReason] = useState("");
	const [confirmRevoke, setConfirmRevoke] = useState(false);

	const live = useRef(true);
	useEffect(
		() => () => {
			live.current = false;
		},
		[],
	);

	const loadUsage = useCallback(async () => {
		const t = translator.current;
		setUsageLoading(true);
		setUsageError(null);
		const response = await callOperatorAdmin(accessToken, {
			action: "tenant_usage",
			tenant_id: tenant.id,
		});
		if (!live.current) return;
		setUsageLoading(false);
		if (!response.ok) {
			const forced = gateFor(response.status, response.code);
			if (forced) return onGate(forced);
			setUsage(null);
			setUsageError(operatorErrorMessage(response.code, t("op.usageUnavailable"), t));
			return;
		}
		const parsed = parseTenantUsage(response.result, tenant.id);
		if (!parsed) {
			setUsage(null);
			setUsageError(t("op.usageUnexpected"));
			return;
		}
		setUsage(parsed);
	}, [accessToken, tenant.id, onGate]);

	useEffect(() => {
		void loadUsage();
	}, [loadUsage]);

	function reviewGrant(event: FormEvent) {
		event.preventDefault();
		setNotice(null);
		const seatCount = Number(seats);
		const ownerId = owner.trim();
		const expiry = /^\d{4}-\d{2}-\d{2}$/.test(expiryDate) ? `${expiryDate}T23:59:59.000Z` : "";
		let problem: string | null = null;
		if (!PLAN_ID.test(planId)) problem = t("op.badPlan");
		else if (!Number.isInteger(seatCount) || seatCount < 1 || seatCount > MAX_SEATS)
			problem = operatorErrorMessage("invalid_seats", "", t);
		else if (!expiry || !(Date.parse(expiry) > Date.now()))
			problem = operatorErrorMessage("invalid_expiry", "", t);
		else if (!validReference(reference)) problem = t("op.badReference");
		else if (ownerId && !isUuid(ownerId)) problem = operatorErrorMessage("invalid_owner", "", t);
		if (problem) {
			setNotice({ tone: "error", message: problem });
			return;
		}
		setGrantReview({
			tenant_id: tenant.id,
			plan_id: planId,
			seats: seatCount,
			expires_at: expiry,
			reference: reference.trim(),
			...(ownerId ? { owner_user_id: ownerId.toLowerCase() } : {}),
		});
	}

	async function submitGrant() {
		if (!grantReview || busy) return;
		setBusy(true);
		setNotice(null);
		try {
			const response = await callOperatorAdmin(accessToken, {
				action: "grant_license",
				...grantReview,
			});
			if (!live.current) return;
			if (!response.ok) {
				const forced = gateFor(response.status, response.code);
				if (forced) return onGate(forced);
				setNotice({
					tone: "error",
					message: operatorErrorMessage(response.code, t("op.grantUnconfirmed"), t),
				});
				return;
			}
			setGrantReview(null);
			setReference("");
			setNotice({
				tone: "success",
				message: t("op.granted", {
					plan: grantReview.plan_id,
					seats: grantReview.seats,
					time: formatDate(grantReview.expires_at),
				}),
			});
			await Promise.all([onChanged(), loadUsage()]);
		} catch (cause) {
			setNotice({
				tone: "error",
				message: readErrorMessage(cause, t("op.grantNotConfirmed")),
			});
		} finally {
			if (live.current) setBusy(false);
		}
	}

	function reviewRevoke() {
		setNotice(null);
		if (!validReference(reason)) {
			setNotice({ tone: "error", message: operatorErrorMessage("invalid_reason", "", t) });
			return;
		}
		setConfirmRevoke(true);
	}

	async function submitRevoke() {
		if (busy) return;
		setBusy(true);
		setNotice(null);
		try {
			const response = await callOperatorAdmin(accessToken, {
				action: "revoke_license",
				tenant_id: tenant.id,
				reason: reason.trim(),
			});
			if (!live.current) return;
			setConfirmRevoke(false);
			if (!response.ok) {
				const forced = gateFor(response.status, response.code);
				if (forced) return onGate(forced);
				setNotice({
					tone: "error",
					message: operatorErrorMessage(response.code, t("op.revokeUnconfirmed"), t),
				});
				return;
			}
			setReason("");
			setNotice(
				response.result.status === "not_active"
					? { tone: "success", message: t("op.nothingToRevoke") }
					: { tone: "success", message: t("op.revoked") },
			);
			await Promise.all([onChanged(), loadUsage()]);
		} catch (cause) {
			setNotice({
				tone: "error",
				message: readErrorMessage(cause, t("op.revokeNotConfirmed")),
			});
		} finally {
			if (live.current) setBusy(false);
		}
	}

	const title = tenant.name ?? t("op.personal");
	return (
		<section className="card" aria-labelledby="tenant-panel-heading">
			<div className="row space-between">
				<h2 id="tenant-panel-heading">{title}</h2>
				<button className="button button-ghost button-sm" type="button" onClick={onClose}>
					{t("op.close")}
				</button>
			</div>
			<code className="mono small">{tenant.id}</code>

			{notice ? (
				<div
					className={`notice ${notice.tone === "error" ? "notice-danger" : "notice-success"}`}
					role={notice.tone === "error" ? "alert" : "status"}
					style={{ marginTop: 12 }}
				>
					{notice.message}
				</div>
			) : null}

			<h3>{t("op.usage")}</h3>
			{usageLoading ? (
				<p role="status">{t("op.loadingUsage")}</p>
			) : usageError ? (
				<div className="notice notice-danger" role="alert">
					{usageError}{" "}
					<button
						className="button button-secondary button-sm"
						type="button"
						onClick={() => void loadUsage()}
					>
						{t("common.retry")}
					</button>
				</div>
			) : usage ? (
				<dl className="kv" aria-label={t("op.usageLabel")}>
					<dt>{t("op.admissionMode")}</dt>
					<dd>{usage.admissionMode}</dd>
					<dt>{t("op.col.licence")}</dt>
					<dd>
						{usage.admission
							? `${usage.admission.kind} · ${usage.admission.planId ?? t("op.noPlan")} · ${
									usage.admission.active
										? t("op.activeLower")
										: usage.admission.revokedAt
											? t("op.revokedAt", { time: formatDate(usage.admission.revokedAt) })
											: t("op.inactiveLower")
								}`
							: t("op.noAdmissionRecorded")}
					</dd>
					<dt>{t("op.licensedSeats")}</dt>
					<dd>{usage.admission?.seats ?? "—"}</dd>
					<dt>{t("op.period")}</dt>
					<dd>
						{usage.admission
							? `${formatDate(usage.admission.startsAt)} → ${formatDate(usage.admission.expiresAt)}`
							: "—"}
					</dd>
					<dt>{t("op.capacity")}</dt>
					<dd>{usage.allowedAgents ?? t("op.notReported")}</dd>
					<dt>{t("op.enrolled")}</dt>
					<dd>{usage.agents.enrolled}</dd>
					<dt>{t("op.active7d")}</dt>
					<dd>{usage.agents.active7d}</dd>
					<dt>{t("op.members")}</dt>
					<dd>{usage.members}</dd>
				</dl>
			) : null}

			<h3>{admission ? t("op.renew") : t("op.grant")}</h3>
			<p className="muted small">{t("op.grantLead")}</p>
			<form onSubmit={reviewGrant} aria-label={t("op.grant")} noValidate>
				<label className="label" htmlFor="grant-plan">
					{t("op.planId")}
				</label>
				<input
					id="grant-plan"
					className="input mono"
					maxLength={32}
					value={planId}
					onChange={(event) => {
						setPlanId(event.target.value);
						setGrantReview(null);
					}}
					autoComplete="off"
				/>
				<label className="label" htmlFor="grant-seats">
					{t("op.col.seats")}
				</label>
				<input
					id="grant-seats"
					className="input"
					type="number"
					min={1}
					max={MAX_SEATS}
					value={seats}
					onChange={(event) => {
						setSeats(event.target.value);
						setGrantReview(null);
					}}
				/>
				<label className="label" htmlFor="grant-expiry">
					{t("op.expiry")}
				</label>
				<input
					id="grant-expiry"
					className="input"
					type="date"
					value={expiryDate}
					onChange={(event) => {
						setExpiryDate(event.target.value);
						setGrantReview(null);
					}}
				/>
				<label className="label" htmlFor="grant-reference">
					{t("op.contract")}
				</label>
				<input
					id="grant-reference"
					className="input"
					maxLength={200}
					value={reference}
					onChange={(event) => {
						setReference(event.target.value);
						setGrantReview(null);
					}}
					// i18n-exempt: sample reference
					placeholder="PO-2026-001"
					autoComplete="off"
				/>
				<label className="label" htmlFor="grant-owner">
					{t("op.ownerOptional")}
				</label>
				<input
					id="grant-owner"
					className="input mono"
					maxLength={36}
					value={owner}
					onChange={(event) => {
						setOwner(event.target.value);
						setGrantReview(null);
					}}
					placeholder={t("op.ownerPlaceholder")}
					autoComplete="off"
				/>
				{grantReview ? (
					<div
						className="notice notice-warning"
						role="region"
						aria-label={t("op.reviewLabel")}
						style={{ marginTop: 12 }}
					>
						<p>
							{richT("op.reviewLine", {
								plan: <strong>{grantReview.plan_id}</strong>,
								seats: <strong>{grantReview.seats}</strong>,
								tenant: title,
								time: formatDate(grantReview.expires_at),
								reference: grantReview.reference,
							})}
						</p>
						<div className="row">
							<button
								className="button"
								type="button"
								disabled={busy}
								onClick={() => void submitGrant()}
							>
								{busy ? t("op.granting") : t("op.confirmGrant")}
							</button>
							<button
								className="button button-secondary"
								type="button"
								disabled={busy}
								onClick={() => setGrantReview(null)}
							>
								{t("common.cancel")}
							</button>
						</div>
					</div>
				) : (
					<div className="row" style={{ marginTop: 12 }}>
						<button className="button" type="submit" disabled={busy}>
							{t("op.reviewGrant")}
						</button>
					</div>
				)}
			</form>

			{admission?.kind === "licensed" ? (
				<>
					<h3>{t("op.revoke")}</h3>
					<p className="muted small">{t("op.revokeLead")}</p>
					<label className="label" htmlFor="revoke-reason">
						{t("op.revokeReason")}
					</label>
					<input
						id="revoke-reason"
						className="input"
						maxLength={200}
						value={reason}
						onChange={(event) => {
							setReason(event.target.value);
							setConfirmRevoke(false);
						}}
						autoComplete="off"
					/>
					<div className="row" style={{ marginTop: 12 }}>
						{confirmRevoke ? (
							<>
								<button
									className="button button-danger"
									type="button"
									disabled={busy}
									onClick={() => void submitRevoke()}
								>
									{busy ? t("op.revoking") : t("op.confirmRevoke", { tenant: title })}
								</button>
								<button
									className="button button-secondary"
									type="button"
									disabled={busy}
									onClick={() => setConfirmRevoke(false)}
								>
									{t("common.cancel")}
								</button>
							</>
						) : (
							<button
								className="button button-secondary"
								type="button"
								disabled={busy || reason.trim() === ""}
								onClick={reviewRevoke}
							>
								{t("op.revoke")}
							</button>
						)}
					</div>
				</>
			) : null}
		</section>
	);
}

/**
 * TOTP step-up for operators. Uses the same Supabase Auth MFA calls as the
 * tenant step-up in `enterprise/auth.tsx`, but not its `identity-security`
 * probe: that probe is tenant-scoped and operators are not tenant members. The
 * client verify result never opens the console — a successful verify rotates
 * the token, the session binding remounts the console, and the operator
 * service re-checks AAL2 itself.
 */
function OperatorStepUp({ onVerified }: { onVerified: () => Promise<void> }) {
	const t = useT();
	const [factorId, setFactorId] = useState<string | null>(null);
	const [factorState, setFactorState] = useState<"loading" | "ready" | "none" | "error">("loading");
	const [enrollment, setEnrollment] = useState<{
		factorId: string;
		secret: string | null;
		uri: string | null;
	} | null>(null);
	const [code, setCode] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		void (async () => {
			try {
				const { data, error: listError } = await supabase.auth.mfa.listFactors();
				if (cancelled) return;
				if (listError) throw listError;
				const verified =
					(data?.totp ?? []).find((factor) => factor.status === "verified") ??
					(data?.all ?? []).find(
						(factor) => factor.factor_type === "totp" && factor.status === "verified",
					);
				setFactorId(verified?.id ?? null);
				setFactorState(verified ? "ready" : "none");
			} catch {
				if (!cancelled) setFactorState("error");
			}
		})();
		return () => {
			cancelled = true;
		};
	}, []);

	async function startEnrollment() {
		setBusy(true);
		setError(null);
		try {
			const { data, error: enrollError } = await supabase.auth.mfa.enroll({
				factorType: "totp",
				friendlyName: "AIDR operator console",
			});
			if (enrollError) throw enrollError;
			if (!data || data.type !== "totp")
				throw new Error("The authentication service did not start a TOTP enrollment.");
			setEnrollment({ factorId: data.id, secret: data.totp.secret, uri: data.totp.uri });
		} catch (cause) {
			setError(readErrorMessage(cause, t("ea.enrollFailed")));
		} finally {
			setBusy(false);
		}
	}

	async function verify(event: FormEvent) {
		event.preventDefault();
		const target = enrollment?.factorId ?? factorId;
		if (busy || !target || !code.trim()) return;
		setBusy(true);
		setError(null);
		try {
			const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({
				factorId: target,
			});
			if (challengeError) throw challengeError;
			if (!challenge?.id)
				throw new Error("The authentication service returned no challenge identifier.");
			const { error: verifyError } = await supabase.auth.mfa.verify({
				factorId: target,
				challengeId: challenge.id,
				code: code.trim(),
			});
			if (verifyError) throw verifyError;
			setCode("");
			await onVerified();
		} catch (cause) {
			setCode("");
			setError(readErrorMessage(cause, t("op.codeRejected")));
		} finally {
			setBusy(false);
		}
	}

	const canVerify = Boolean(enrollment) || factorState === "ready";
	return (
		<div className="card">
			<p className="eyebrow">{t("op.stepUp")}</p>
			<h1>{t("ea.mfaRequired")}</h1>
			<p className="muted">{t("op.stepUpLead")}</p>
			{factorState === "loading" ? <p role="status">{t("op.readingFactors")}</p> : null}
			{factorState === "error" ? (
				<div className="notice notice-danger" role="alert">
					{t("op.factorsFailed")}
				</div>
			) : null}
			{factorState === "none" && !enrollment ? (
				<div style={{ marginTop: 12 }}>
					<p className="muted">{t("op.noFactor")}</p>
					<button
						className="button"
						type="button"
						disabled={busy}
						onClick={() => void startEnrollment()}
					>
						{busy ? t("ea.starting") : t("ea.setUp")}
					</button>
				</div>
			) : null}
			{enrollment ? (
				<div style={{ marginTop: 12 }}>
					<p className="muted">{t("ea.addThisSecret")}</p>
					<code className="mono" style={{ display: "block", wordBreak: "break-all" }}>
						{enrollment.secret ?? t("ea.noSecret")}
					</code>
					{enrollment.uri ? (
						<p className="muted" style={{ wordBreak: "break-all" }}>
							{enrollment.uri}
						</p>
					) : null}
				</div>
			) : null}
			{canVerify ? (
				<form onSubmit={verify} style={{ marginTop: 12 }}>
					<label className="label" htmlFor="operator-mfa-code">
						{t("ea.code")}
					</label>
					<input
						id="operator-mfa-code"
						className="input mono"
						type="text"
						inputMode="numeric"
						autoComplete="one-time-code"
						maxLength={10}
						value={code}
						onChange={(event) => setCode(event.target.value)}
					/>
					<button
						className="button"
						type="submit"
						disabled={busy || !code.trim()}
						style={{ marginTop: 12 }}
					>
						{busy ? t("ea.verifying") : t("ea.verify")}
					</button>
				</form>
			) : null}
			{error ? (
				<div className="notice notice-danger" role="alert" style={{ marginTop: 12 }}>
					{error}
				</div>
			) : null}
		</div>
	);
}
