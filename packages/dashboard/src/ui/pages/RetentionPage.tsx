import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";

type Hold = {
	id: string;
	hold_reference: string;
	case_id: string | null;
	hold_owner: string | null;
	reason: string;
	placed_at: string;
	released_at: string | null;
	release_reason: string | null;
};
type Policy = {
	data_class: string;
	retention_days: number;
	min_days: number | null;
	max_days: number | null;
	configurable: boolean;
	updated_at: string | null;
};
type HoldCursor = { placed_at: string; id: string };
type Snapshot = { holds: Hold[]; policies: Policy[]; next: HoldCursor | null };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CASE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/ #-]*$/;
const CLASS_LABELS: Record<string, string> = {
	telemetry: "Agent telemetry and incidents",
	endpoint_identity: "Endpoint and agent identity",
	security_intelligence: "Tenant reputation records",
	policy_configuration: "Policy configuration",
	identity_membership: "Membership and invitations",
	commercial_records: "Commercial and billing records",
	security_audit: "Security and administrative audit",
	temporary_exports: "Temporary exports",
	access_credentials: "Access credentials",
	operational_ephemera: "Operational ephemera",
};
const SAFE_ERRORS: Record<string, string> = {
	owner_required: "Only an active tenant owner can change legal holds or retention periods.",
	admin_required:
		"Only an active tenant owner or admin can view legal hold and retention settings.",
	hold_already_active:
		"This tenant already has an active legal hold. Release it before placing another.",
	hold_refused_pending_deletion:
		"Hold NOT placed: a Storage deletion is already in flight for this tenant. Escalate to your AIDR operator now; the tenant is unprotected.",
	hold_not_found_or_released:
		"That hold no longer exists or was already released. Refresh the list.",
	retention_days_out_of_bounds:
		"That retention period is outside the allowed range for this data class.",
	retention_class_not_configurable:
		"That data class is controlled by the platform and cannot be changed.",
	retention_change_refused_offboarding:
		"Retention cannot change while tenant offboarding is in progress.",
	invalid_request: "The request was rejected. Check each field.",
	retention_management_unavailable:
		"Retention management is temporarily unavailable. No change was confirmed.",
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
const str = (value: unknown): string | null => (typeof value === "string" ? value : null);
const validDate = (value: string | null) => value === null || Number.isFinite(Date.parse(value));

function parseHold(value: unknown): Hold | null {
	if (!isRecord(value) || typeof value.id !== "string" || !UUID.test(value.id)) return null;
	const placedAt = str(value.placed_at);
	const releasedAt = str(value.released_at);
	if (
		!placedAt ||
		!validDate(placedAt) ||
		!validDate(releasedAt) ||
		typeof value.reason !== "string"
	)
		return null;
	return {
		id: value.id,
		hold_reference: str(value.hold_reference) ?? "",
		case_id: str(value.case_id),
		hold_owner: str(value.hold_owner),
		reason: value.reason,
		placed_at: placedAt,
		released_at: releasedAt,
		release_reason: str(value.release_reason),
	};
}

function parsePolicy(value: unknown): Policy | null {
	if (!isRecord(value) || typeof value.data_class !== "string") return null;
	if (typeof value.retention_days !== "number" || !Number.isSafeInteger(value.retention_days))
		return null;
	return {
		data_class: value.data_class,
		retention_days: value.retention_days,
		min_days: typeof value.min_days === "number" ? value.min_days : null,
		max_days: typeof value.max_days === "number" ? value.max_days : null,
		configurable: value.configurable === true,
		updated_at: str(value.updated_at),
	};
}

function parseSnapshot(value: unknown): Snapshot {
	if (
		!isRecord(value) ||
		value.ok !== true ||
		!Array.isArray(value.holds) ||
		!Array.isArray(value.retention_policies)
	)
		throw new Error("Retention management returned an invalid response.");
	const holds = value.holds.map(parseHold);
	const policies = value.retention_policies.map(parsePolicy);
	if (holds.some((row) => row === null) || policies.some((row) => row === null))
		throw new Error("Retention management returned an invalid record.");
	let next: HoldCursor | null = null;
	if (value.next_hold_cursor !== null && value.next_hold_cursor !== undefined) {
		const cursor = value.next_hold_cursor;
		if (
			!isRecord(cursor) ||
			typeof cursor.id !== "string" ||
			!UUID.test(cursor.id) ||
			typeof cursor.placed_at !== "string" ||
			!validDate(cursor.placed_at)
		)
			throw new Error("Retention management returned an invalid pagination cursor.");
		next = { id: cursor.id, placed_at: cursor.placed_at };
	}
	return { holds: holds as Hold[], policies: policies as Policy[], next };
}

async function responseError(error: unknown, data: unknown, fallback: string): Promise<string> {
	const safe = (value: unknown) =>
		isRecord(value) && typeof value.error === "string" ? SAFE_ERRORS[value.error] : undefined;
	const direct = safe(data);
	if (direct) return direct;
	if (isRecord(error) && error.context instanceof Response) {
		try {
			const code = safe(await error.context.clone().json());
			if (code) return code;
		} catch {
			// Fixed fallback only; never surface raw function/server details.
		}
	}
	return readErrorMessage(error, fallback);
}

const formatDate = (value: string | null) => (value ? new Date(value).toLocaleString() : "—");
const clean = (value: string, max: number) =>
	value.length >= 1 &&
	value.length <= max &&
	value === value.trim() &&
	!/[\u0000-\u001f\u007f]/.test(value);

export function RetentionPage() {
	const { currentTeam, currentRole } = useTeam();
	if (!currentTeam)
		return <div className="card">Select a tenant to manage legal holds and retention.</div>;
	if (currentRole !== "owner" && currentRole !== "admin")
		return (
			<div className="card">
				<h1>Legal holds and retention</h1>
				<p className="muted">
					Legal holds and retention periods are available to tenant owners and admins only.
				</p>
			</div>
		);
	return (
		<TenantRetention
			key={currentTeam.tenant_id}
			tenantId={currentTeam.tenant_id}
			teamName={currentTeam.name}
			isOwner={currentRole === "owner"}
		/>
	);
}

function TenantRetention({
	tenantId,
	teamName,
	isOwner,
}: {
	tenantId: string;
	teamName: string;
	isOwner: boolean;
}) {
	const [holds, setHolds] = useState<Hold[]>([]);
	const [policies, setPolicies] = useState<Policy[]>([]);
	const [next, setNext] = useState<HoldCursor | null>(null);
	const cursor = useRef<HoldCursor | null>(null);
	const [loading, setLoading] = useState(true);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [notice, setNotice] = useState<string | null>(null);
	const [caseId, setCaseId] = useState("");
	const [holdOwner, setHoldOwner] = useState("");
	const [reason, setReason] = useState("");
	const [reference, setReference] = useState("");
	const [confirmPlace, setConfirmPlace] = useState(false);
	const [releaseReason, setReleaseReason] = useState("");
	const [confirmRelease, setConfirmRelease] = useState(false);
	const [edit, setEdit] = useState<{ dataClass: string; days: string; reason: string } | null>(
		null,
	);

	const activeHold = holds.find((hold) => hold.released_at === null) ?? null;

	const load = useCallback(
		async (append = false) => {
			setLoading(!append);
			setError(null);
			try {
				const params = new URLSearchParams();
				if (append && cursor.current) {
					params.set("hold_after_placed_at", cursor.current.placed_at);
					params.set("hold_after_id", cursor.current.id);
				}
				const query = params.toString();
				const { data, error: invokeError } = await supabase.functions.invoke<unknown>(
					query ? `retention-admin?${query}` : "retention-admin",
					{ method: "GET", headers: { "X-AIDR-Tenant-ID": tenantId } },
				);
				if (invokeError)
					throw new Error(
						await responseError(invokeError, data, "Unable to load retention settings."),
					);
				const snapshot = parseSnapshot(data);
				setHolds((previous) => {
					if (!append) return snapshot.holds;
					const rows = new Map(previous.map((row) => [row.id, row]));
					for (const row of snapshot.holds) rows.set(row.id, row);
					return [...rows.values()];
				});
				if (!append) setPolicies(snapshot.policies);
				cursor.current = snapshot.next;
				setNext(snapshot.next);
			} catch (cause) {
				setError(readErrorMessage(cause, "Unable to load retention settings."));
			} finally {
				setLoading(false);
			}
		},
		[tenantId],
	);

	useEffect(() => {
		void load();
	}, [load]);

	async function write(
		body: Record<string, unknown>,
		fallback: string,
	): Promise<Record<string, unknown>> {
		const { data, error: invokeError } = await supabase.functions.invoke<unknown>(
			"retention-admin",
			{
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": tenantId },
				body: { ...body, tenant_id: tenantId },
			},
		);
		if (invokeError) throw new Error(await responseError(invokeError, data, fallback));
		if (!isRecord(data) || data.ok !== true)
			throw new Error(await responseError(null, data, fallback));
		return data;
	}

	async function placeHold(event: FormEvent) {
		event.preventDefault();
		if (!clean(caseId, 100) || !CASE_ID.test(caseId)) {
			setError("Enter the case ID (letters, digits and . _ : / # - only, up to 100 characters).");
			return;
		}
		if (
			!clean(holdOwner, 200) ||
			!clean(reason, 2000) ||
			(reference !== "" && !clean(reference, 200))
		) {
			setError(
				"Owner, reason and the optional reference must be non-empty, trimmed text without control characters.",
			);
			return;
		}
		if (!confirmPlace) {
			setConfirmPlace(true);
			return;
		}
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			await write(
				{
					action: "place_hold",
					case_id: caseId,
					owner: holdOwner,
					reason,
					...(reference ? { reference } : {}),
				},
				"The legal hold was not confirmed.",
			);
			setCaseId("");
			setHoldOwner("");
			setReason("");
			setReference("");
			setConfirmPlace(false);
			setNotice(
				"Legal hold placed. Retention and offboarding will not delete this tenant's data until it is released.",
			);
			await load();
		} catch (cause) {
			setConfirmPlace(false);
			// Refresh first: a failed placement may still have committed, and the
			// refresh clears any previous message.
			await load();
			setError(readErrorMessage(cause, "The legal hold was not confirmed."));
		} finally {
			setBusy(false);
		}
	}

	async function releaseHold(hold: Hold) {
		if (!clean(releaseReason, 2000)) {
			setError("Enter a release reason (non-empty, trimmed text).");
			return;
		}
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			await write(
				{ action: "release_hold", hold_id: hold.id, reason: releaseReason },
				"The release was not confirmed.",
			);
			setReleaseReason("");
			setConfirmRelease(false);
			setNotice(
				"Legal hold released. Data past its retention period becomes eligible for deletion on the next scheduled run.",
			);
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, "The release was not confirmed."));
		} finally {
			setBusy(false);
		}
	}

	async function saveRetention(policy: Policy) {
		if (!edit) return;
		const days = Number(edit.days);
		if (
			!Number.isSafeInteger(days) ||
			days < (policy.min_days ?? 0) ||
			days > (policy.max_days ?? 3650)
		) {
			setError(`Enter a whole number of days between ${policy.min_days} and ${policy.max_days}.`);
			return;
		}
		if (!clean(edit.reason, 500)) {
			setError("Enter a reason for this change (non-empty, trimmed text, up to 500 characters).");
			return;
		}
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			const result = await write(
				{
					action: "set_retention",
					data_class: policy.data_class,
					retention_days: days,
					reason: edit.reason,
				},
				"The retention change was not confirmed.",
			);
			setEdit(null);
			setNotice(
				result.changed === true
					? "Retention period saved and audited."
					: "That is already the configured retention period; nothing changed.",
			);
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, "The retention change was not confirmed."));
		} finally {
			setBusy(false);
		}
	}

	return (
		<div className="stack">
			<header className="card">
				<h1>Legal holds and retention</h1>
				<p className="muted">
					Manage legal holds and data retention periods for <strong>{teamName}</strong>. Every
					change is recorded in the administrative audit log.
				</p>
				{!isOwner ? (
					<p className="muted small">
						Admins can view these settings. Only a tenant owner can change them.
					</p>
				) : null}
			</header>

			{error ? (
				<div className="notice notice-danger" role="alert" aria-live="assertive">
					{error}
				</div>
			) : null}
			{notice ? (
				<div className="notice notice-success" role="status" aria-live="polite">
					{notice}
				</div>
			) : null}

			<section className="card" aria-labelledby="hold-heading">
				<h2 id="hold-heading">Legal hold</h2>
				{loading ? (
					<p role="status">Loading…</p>
				) : activeHold ? (
					<div className="notice notice-warning" role="region" aria-label="Active legal hold">
						<p>
							<strong>Active hold</strong> — case {activeHold.case_id ?? activeHold.hold_reference},
							owner {activeHold.hold_owner ?? "not recorded"}, placed{" "}
							{formatDate(activeHold.placed_at)}.
						</p>
						<p className="small">{activeHold.reason}</p>
						{isOwner ? (
							<>
								<label className="label" htmlFor="release-reason">
									Release reason
								</label>
								<input
									id="release-reason"
									className="input"
									maxLength={2000}
									value={releaseReason}
									onChange={(event) => setReleaseReason(event.target.value)}
									autoComplete="off"
								/>
								<div className="row" style={{ marginTop: 10 }}>
									{confirmRelease ? (
										<>
											<button
												className="button button-danger"
												type="button"
												disabled={busy}
												onClick={() => void releaseHold(activeHold)}
											>
												Confirm release
											</button>
											<button
												className="button button-secondary"
												type="button"
												onClick={() => setConfirmRelease(false)}
											>
												Cancel
											</button>
										</>
									) : (
										<button
											className="button button-secondary"
											type="button"
											disabled={busy || releaseReason.trim() === ""}
											onClick={() => setConfirmRelease(true)}
										>
											Release hold
										</button>
									)}
								</div>
							</>
						) : null}
					</div>
				) : (
					<p className="muted">
						No active legal hold. Retention and offboarding follow the periods below.
					</p>
				)}

				{isOwner && !activeHold && !loading ? (
					<form onSubmit={placeHold} style={{ marginTop: 14 }} aria-label="Place legal hold">
						<h3>Place a hold</h3>
						<label className="label" htmlFor="hold-case">
							Case ID
						</label>
						<input
							id="hold-case"
							className="input"
							maxLength={100}
							value={caseId}
							onChange={(e) => setCaseId(e.target.value)}
							placeholder="CASE-2026-001"
							autoComplete="off"
						/>
						<label className="label" htmlFor="hold-owner">
							Hold owner
						</label>
						<input
							id="hold-owner"
							className="input"
							maxLength={200}
							value={holdOwner}
							onChange={(e) => setHoldOwner(e.target.value)}
							placeholder="Responsible counsel or custodian"
							autoComplete="off"
						/>
						<label className="label" htmlFor="hold-reason">
							Reason
						</label>
						<input
							id="hold-reason"
							className="input"
							maxLength={2000}
							value={reason}
							onChange={(e) => setReason(e.target.value)}
							autoComplete="off"
						/>
						<label className="label" htmlFor="hold-reference">
							Reference (optional)
						</label>
						<input
							id="hold-reference"
							className="input"
							maxLength={200}
							value={reference}
							onChange={(e) => setReference(e.target.value)}
							autoComplete="off"
						/>
						<p className="muted small">
							While a hold is active, routine retention, audit export deletion and offboarding do
							not delete this tenant's data.
						</p>
						<div className="row" style={{ marginTop: 10 }}>
							<button
								className={confirmPlace ? "button button-danger" : "button"}
								type="submit"
								disabled={busy}
							>
								{confirmPlace ? "Confirm: place legal hold" : "Place legal hold"}
							</button>
							{confirmPlace ? (
								<button
									className="button button-secondary"
									type="button"
									onClick={() => setConfirmPlace(false)}
								>
									Cancel
								</button>
							) : null}
						</div>
					</form>
				) : null}
			</section>

			<section className="card" aria-labelledby="retention-heading">
				<h2 id="retention-heading">Retention periods</h2>
				<p className="muted">
					Periods are bounded per data class. Shortening a period lets the next scheduled run delete
					data already older than the new period unless a legal hold is active. Backup copies follow
					separate backup retention.
				</p>
				{loading ? (
					<p role="status">Loading…</p>
				) : (
					<div className="table-wrap">
						<table className="table">
							<caption className="sr-only">Retention periods by data class</caption>
							<thead>
								<tr>
									<th scope="col">Data class</th>
									<th scope="col">Days</th>
									<th scope="col">Allowed</th>
									<th scope="col">Actions</th>
								</tr>
							</thead>
							<tbody>
								{policies.map((policy) => (
									<tr key={policy.data_class}>
										<td>{CLASS_LABELS[policy.data_class] ?? policy.data_class}</td>
										<td>{policy.retention_days}</td>
										<td>
											{policy.configurable
												? `${policy.min_days}–${policy.max_days}`
												: "Platform controlled"}
										</td>
										<td>
											{isOwner && policy.configurable ? (
												edit?.dataClass === policy.data_class ? (
													<div className="row">
														<input
															className="input"
															type="number"
															aria-label={`Retention days for ${CLASS_LABELS[policy.data_class] ?? policy.data_class}`}
															min={policy.min_days ?? 0}
															max={policy.max_days ?? 3650}
															value={edit.days}
															onChange={(e) => setEdit({ ...edit, days: e.target.value })}
															style={{ width: 110 }}
														/>
														<input
															className="input"
															aria-label="Reason for change"
															maxLength={500}
															placeholder="Reason"
															value={edit.reason}
															onChange={(e) => setEdit({ ...edit, reason: e.target.value })}
														/>
														<button
															className="button"
															type="button"
															disabled={busy}
															onClick={() => void saveRetention(policy)}
														>
															Save
														</button>
														<button
															className="button button-secondary"
															type="button"
															onClick={() => setEdit(null)}
														>
															Cancel
														</button>
													</div>
												) : (
													<button
														className="button button-secondary button-sm"
														type="button"
														disabled={busy}
														onClick={() =>
															setEdit({
																dataClass: policy.data_class,
																days: String(policy.retention_days),
																reason: "",
															})
														}
													>
														Change
													</button>
												)
											) : null}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</section>

			<section className="card" aria-labelledby="history-heading">
				<h2 id="history-heading">Hold history</h2>
				{loading ? null : holds.length === 0 ? (
					<p className="muted">No legal holds have been recorded for this tenant.</p>
				) : (
					<div className="table-wrap">
						<table className="table">
							<caption className="sr-only">Legal hold history</caption>
							<thead>
								<tr>
									<th scope="col">Case</th>
									<th scope="col">Owner</th>
									<th scope="col">Placed</th>
									<th scope="col">Released</th>
									<th scope="col">Release reason</th>
								</tr>
							</thead>
							<tbody>
								{holds.map((hold) => (
									<tr key={hold.id}>
										<td>{hold.case_id ?? hold.hold_reference}</td>
										<td>{hold.hold_owner ?? "—"}</td>
										<td>{formatDate(hold.placed_at)}</td>
										<td>{hold.released_at ? formatDate(hold.released_at) : "Active"}</td>
										<td>{hold.release_reason ?? "—"}</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
				<div className="row" style={{ marginTop: 10 }}>
					{next ? (
						<button
							className="button button-secondary"
							type="button"
							disabled={busy}
							onClick={() => void load(true)}
						>
							Load more
						</button>
					) : null}
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={() => void load()}
					>
						Refresh
					</button>
				</div>
			</section>
		</div>
	);
}
