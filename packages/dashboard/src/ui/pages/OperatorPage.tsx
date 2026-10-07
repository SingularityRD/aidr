import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
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
	const { snapshot, generation, refresh } = useSessionSnapshot();
	const session = snapshot?.session ?? null;
	return (
		<div className="app">
			<a className="skip-link" href="#page-content">
				Skip to content
			</a>
			<header className="console-topbar">
				<Link to="/dashboard" className="brand-link">
					<span className="brand-word" aria-hidden="true">
						AIDR
					</span>
					<span className="brand-sub" aria-hidden="true">
						Operator console
					</span>
					<span className="sr-only">Singularity AIDR operator console</span>
				</Link>
				<div className="header-actions">
					<ThemeToggle />
				</div>
			</header>
			<main className="main" id="page-content" tabIndex={-1}>
				{!snapshot ? (
					<div className="card" role="status" aria-live="polite">
						<h1>Verifying session</h1>
						<p className="muted">
							Reading the signed-in session before contacting the operator service.
						</p>
					</div>
				) : !session ? (
					<div className="card">
						<h1>Sign in required</h1>
						<p className="muted">The operator console needs a signed-in session.</p>
						<Link className="button" to="/login?returnTo=%2Foperator">
							Sign in
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

function licenceLabel(tenant: OperatorTenant): { text: string; badge: string } {
	const admission = tenant.admission;
	if (!admission) return { text: "No admission", badge: "badge-neutral" };
	if (admission.active) return { text: "Active", badge: "badge-success" };
	return { text: "Inactive", badge: "badge-warning" };
}

function OperatorConsole({
	accessToken,
	refreshSession,
}: {
	accessToken: string;
	refreshSession: () => Promise<void>;
}) {
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
				const message = operatorErrorMessage(
					response.code,
					"The operator service is unavailable. No tenant data is shown.",
				);
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
				const message =
					"The operator service returned an unexpected tenant list. No tenant data is shown.";
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
					<h1>Checking operator access</h1>
					<p className="muted">
						The operator service decides access. Nothing is shown until it answers.
					</p>
				</div>
			);
		case "forbidden":
			return (
				<div className="card" role="alert">
					<p className="eyebrow">403 · Forbidden</p>
					<h1>Operator access required</h1>
					<p className="muted">
						This account has no active platform-operator grant, so the operator service refused the
						request. Platform-operator access is provisioned by a database administrator through
						change control; it cannot be requested from this page.
					</p>
					<Link className="button button-secondary" to="/dashboard">
						Return to dashboard
					</Link>
				</div>
			);
		case "mfa_required":
			return <OperatorStepUp onVerified={refreshSession} />;
		case "signed_out":
			return (
				<div className="card" role="alert">
					<h1>Session no longer valid</h1>
					<p className="muted">The operator service rejected this session. Sign in again.</p>
					<Link className="button" to="/login?returnTo=%2Foperator">
						Sign in
					</Link>
				</div>
			);
		case "unavailable":
			return (
				<div className="card" role="alert">
					<h1>Operator service unavailable</h1>
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
						Retry
					</button>
				</div>
			);
		case "ready":
			break;
	}

	return (
		<div className="stack">
			<header className="card">
				<p className="eyebrow">Platform operator</p>
				<h1>Tenant licences and usage</h1>
				<p className="muted">
					Grant, renew and revoke tenant licences and read seat and agent usage. Every call is
					re-authorized by the operator service at AAL2 and recorded in the administrative audit log
					with your user id — including reads.
				</p>
			</header>

			<section className="card" aria-labelledby="tenants-heading">
				<div className="row space-between">
					<h2 id="tenants-heading">Tenants</h2>
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={loading}
						onClick={() => void refreshList()}
					>
						Refresh
					</button>
				</div>
				{listError ? (
					<div className="notice notice-danger" role="alert">
						{listError}
					</div>
				) : null}
				{loading ? <p role="status">Loading…</p> : null}
				{!loading && tenants.length === 0 ? (
					<p className="muted">No tenants exist on this control plane yet.</p>
				) : null}
				{tenants.length > 0 ? (
					<div className="table-wrap">
						<table className="table">
							<caption className="sr-only">Tenants and licence status</caption>
							<thead>
								<tr>
									<th scope="col">Tenant</th>
									<th scope="col">Kind</th>
									<th scope="col">Status</th>
									<th scope="col">Licence</th>
									<th scope="col">Plan</th>
									<th scope="col">Seats</th>
									<th scope="col">Expires</th>
									<th scope="col">Actions</th>
								</tr>
							</thead>
							<tbody>
								{tenants.map((tenant) => {
									const licence = licenceLabel(tenant);
									return (
										<tr key={tenant.id} aria-selected={selected?.id === tenant.id}>
											<td>
												<div>
													{tenant.name ?? (
														<span className="muted">Personal workspace (name withheld)</span>
													)}
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
													aria-label={`Manage ${tenant.name ?? tenant.id}`}
													onClick={() => setSelected(tenant)}
												>
													Manage
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
						Previous page
					</button>
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={loading || !nextCursor}
						onClick={() => void goNext()}
					>
						Next page
					</button>
					<span className="muted small">Page {cursors.length}</span>
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
			setUsageError(
				operatorErrorMessage(
					response.code,
					"Usage is unavailable for this tenant. No figures are shown.",
				),
			);
			return;
		}
		const parsed = parseTenantUsage(response.result, tenant.id);
		if (!parsed) {
			setUsage(null);
			setUsageError("The operator service returned unexpected usage data. No figures are shown.");
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
		if (!PLAN_ID.test(planId)) problem = "Enter a plan id (lowercase letters, digits, - or _).";
		else if (!Number.isInteger(seatCount) || seatCount < 1 || seatCount > MAX_SEATS)
			problem = operatorErrorMessage("invalid_seats", "");
		else if (!expiry || !(Date.parse(expiry) > Date.now()))
			problem = operatorErrorMessage("invalid_expiry", "");
		else if (!validReference(reference))
			problem =
				"Enter the contract or purchase-order reference (single line, up to 200 characters).";
		else if (ownerId && !isUuid(ownerId)) problem = operatorErrorMessage("invalid_owner", "");
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
					message: operatorErrorMessage(
						response.code,
						"The licence grant was not confirmed. Refresh before retrying.",
					),
				});
				return;
			}
			setGrantReview(null);
			setReference("");
			setNotice({
				tone: "success",
				message: `Licence granted: ${grantReview.plan_id}, ${grantReview.seats} seats, expires ${formatDate(grantReview.expires_at)}.`,
			});
			await Promise.all([onChanged(), loadUsage()]);
		} catch (cause) {
			setNotice({
				tone: "error",
				message: readErrorMessage(cause, "The licence grant was not confirmed."),
			});
		} finally {
			if (live.current) setBusy(false);
		}
	}

	function reviewRevoke() {
		setNotice(null);
		if (!validReference(reason)) {
			setNotice({ tone: "error", message: operatorErrorMessage("invalid_reason", "") });
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
					message: operatorErrorMessage(
						response.code,
						"The revocation was not confirmed. Refresh before retrying.",
					),
				});
				return;
			}
			setReason("");
			setNotice(
				response.result.status === "not_active"
					? { tone: "success", message: "This tenant had no active licence. Nothing was revoked." }
					: { tone: "success", message: "Licence revoked." },
			);
			await Promise.all([onChanged(), loadUsage()]);
		} catch (cause) {
			setNotice({
				tone: "error",
				message: readErrorMessage(cause, "The revocation was not confirmed."),
			});
		} finally {
			if (live.current) setBusy(false);
		}
	}

	const title = tenant.name ?? "Personal workspace";
	return (
		<section className="card" aria-labelledby="tenant-panel-heading">
			<div className="row space-between">
				<h2 id="tenant-panel-heading">{title}</h2>
				<button className="button button-ghost button-sm" type="button" onClick={onClose}>
					Close
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

			<h3>Usage and seats</h3>
			{usageLoading ? (
				<p role="status">Loading usage…</p>
			) : usageError ? (
				<div className="notice notice-danger" role="alert">
					{usageError}{" "}
					<button
						className="button button-secondary button-sm"
						type="button"
						onClick={() => void loadUsage()}
					>
						Retry
					</button>
				</div>
			) : usage ? (
				<dl className="kv" aria-label="Tenant usage">
					<dt>Deployment admission mode</dt>
					<dd>{usage.admissionMode}</dd>
					<dt>Licence</dt>
					<dd>
						{usage.admission
							? `${usage.admission.kind} · ${usage.admission.planId ?? "no plan"} · ${usage.admission.active ? "active" : usage.admission.revokedAt ? `revoked ${formatDate(usage.admission.revokedAt)}` : "inactive"}`
							: "No admission recorded"}
					</dd>
					<dt>Licensed seats</dt>
					<dd>{usage.admission?.seats ?? "—"}</dd>
					<dt>Licence period</dt>
					<dd>
						{usage.admission
							? `${formatDate(usage.admission.startsAt)} → ${formatDate(usage.admission.expiresAt)}`
							: "—"}
					</dd>
					<dt>Agent capacity</dt>
					<dd>{usage.allowedAgents ?? "Not reported"}</dd>
					<dt>Agents enrolled</dt>
					<dd>{usage.agents.enrolled}</dd>
					<dt>Agents active (7 days)</dt>
					<dd>{usage.agents.active7d}</dd>
					<dt>Current members</dt>
					<dd>{usage.members}</dd>
				</dl>
			) : null}

			<h3>{admission ? "Renew or change licence" : "Grant licence"}</h3>
			<p className="muted small">
				A grant replaces the tenant's current licence terms. It also requires a separate, unexpired
				admission-operator grant for this tenant, and you must not be a member of it.
			</p>
			<form onSubmit={reviewGrant} aria-label="Grant licence" noValidate>
				<label className="label" htmlFor="grant-plan">
					Plan id
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
					Seats
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
					Expiry date (ends 23:59:59 UTC)
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
					Contract reference
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
					placeholder="PO-2026-001"
					autoComplete="off"
				/>
				<label className="label" htmlFor="grant-owner">
					Owner user id (optional)
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
					placeholder="Inferred when the tenant has exactly one owner"
					autoComplete="off"
				/>
				{grantReview ? (
					<div
						className="notice notice-warning"
						role="region"
						aria-label="Review licence grant"
						style={{ marginTop: 12 }}
					>
						<p>
							Grant <strong>{grantReview.plan_id}</strong> with <strong>{grantReview.seats}</strong>{" "}
							seats to {title}, expiring {formatDate(grantReview.expires_at)} (reference{" "}
							{grantReview.reference}).
						</p>
						<div className="row">
							<button
								className="button"
								type="button"
								disabled={busy}
								onClick={() => void submitGrant()}
							>
								{busy ? "Granting…" : "Confirm grant"}
							</button>
							<button
								className="button button-secondary"
								type="button"
								disabled={busy}
								onClick={() => setGrantReview(null)}
							>
								Cancel
							</button>
						</div>
					</div>
				) : (
					<div className="row" style={{ marginTop: 12 }}>
						<button className="button" type="submit" disabled={busy}>
							Review grant
						</button>
					</div>
				)}
			</form>

			{admission?.kind === "licensed" ? (
				<>
					<h3>Revoke licence</h3>
					<p className="muted small">
						Revocation ends the licensed admission and increments the tenant's entitlement
						revocation epoch. It takes effect immediately and is recorded in the audit log.
					</p>
					<label className="label" htmlFor="revoke-reason">
						Revocation reason
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
									{busy ? "Revoking…" : `Confirm: revoke licence for ${title}`}
								</button>
								<button
									className="button button-secondary"
									type="button"
									disabled={busy}
									onClick={() => setConfirmRevoke(false)}
								>
									Cancel
								</button>
							</>
						) : (
							<button
								className="button button-secondary"
								type="button"
								disabled={busy || reason.trim() === ""}
								onClick={reviewRevoke}
							>
								Revoke licence
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
			setError(readErrorMessage(cause, "Authenticator enrollment could not be started."));
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
			setError(
				readErrorMessage(cause, "The verification code was rejected. The console was not opened."),
			);
		} finally {
			setBusy(false);
		}
	}

	const canVerify = Boolean(enrollment) || factorState === "ready";
	return (
		<div className="card">
			<p className="eyebrow">Step-up required</p>
			<h1>Multi-factor authentication required</h1>
			<p className="muted">
				The operator service confirmed operator access but reports this session below AAL2. Verify
				with your authenticator app to continue. Platform administration always requires a second
				factor.
			</p>
			{factorState === "loading" ? <p role="status">Reading enrolled factors…</p> : null}
			{factorState === "error" ? (
				<div className="notice notice-danger" role="alert">
					Enrolled factors could not be read. Reload the page to try again.
				</div>
			) : null}
			{factorState === "none" && !enrollment ? (
				<div style={{ marginTop: 12 }}>
					<p className="muted">No verified authenticator factor is enrolled for this account.</p>
					<button
						className="button"
						type="button"
						disabled={busy}
						onClick={() => void startEnrollment()}
					>
						{busy ? "Starting…" : "Set up authenticator app"}
					</button>
				</div>
			) : null}
			{enrollment ? (
				<div style={{ marginTop: 12 }}>
					<p className="muted">Add this secret to your authenticator app:</p>
					<code className="mono" style={{ display: "block", wordBreak: "break-all" }}>
						{enrollment.secret ?? "The Auth service returned no secret; use the enrollment URI."}
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
						Authenticator code
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
						{busy ? "Verifying…" : "Verify and continue"}
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
