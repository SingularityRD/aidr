import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useRichT, useT } from "../../i18n/I18nProvider";
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
	/** Period the reaper applies: the setting capped by the plan term (telemetry only). */
	effective_retention_days: number;
	/** Plan maximum for this class; null = not plan-bound or contractual. */
	plan_max_days: number | null;
};
type HoldCursor = { placed_at: string; id: string };
type Snapshot = { holds: Hold[]; policies: Policy[]; next: HoldCursor | null };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CASE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/ #-]*$/;
const CLASS_LABELS: Record<string, DashboardMessageKey> = {
	telemetry: "ret.class.telemetry",
	endpoint_identity: "ret.class.endpointIdentity",
	security_intelligence: "ret.class.securityIntelligence",
	policy_configuration: "ret.class.policyConfiguration",
	identity_membership: "ret.class.identityMembership",
	commercial_records: "ret.class.commercialRecords",
	security_audit: "ret.class.securityAudit",
	temporary_exports: "ret.class.temporaryExports",
	access_credentials: "ret.class.accessCredentials",
	operational_ephemera: "ret.class.operationalEphemera",
};
const SAFE_ERRORS: Record<string, DashboardMessageKey> = {
	owner_required: "ret.err.ownerRequired",
	admin_required: "ret.err.adminRequired",
	hold_already_active: "ret.err.holdActive",
	hold_refused_pending_deletion: "ret.err.pendingDeletion",
	hold_not_found_or_released: "ret.err.holdGone",
	retention_days_out_of_bounds: "ret.err.outOfBounds",
	retention_days_exceeds_plan: "ret.err.exceedsPlan",
	retention_class_not_configurable: "ret.err.notConfigurable",
	retention_change_refused_offboarding: "ret.err.offboarding",
	invalid_request: "ret.err.invalid",
	retention_management_unavailable: "ret.err.unavailable",
};

/** A data class in the viewer's language; an unknown class is shown as stored. */
function classLabel(dataClass: string, t: Translate): string {
	const key = Object.hasOwn(CLASS_LABELS, dataClass) ? CLASS_LABELS[dataClass] : undefined;
	return key ? t(key) : dataClass;
}

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
		effective_retention_days:
			typeof value.effective_retention_days === "number" &&
			Number.isSafeInteger(value.effective_retention_days)
				? value.effective_retention_days
				: value.retention_days,
		plan_max_days: typeof value.plan_max_days === "number" ? value.plan_max_days : null,
	};
}

function parseSnapshot(value: unknown, t: Translate): Snapshot {
	if (
		!isRecord(value) ||
		value.ok !== true ||
		!Array.isArray(value.holds) ||
		!Array.isArray(value.retention_policies)
	)
		throw new Error(t("ret.err.invalidResponse"));
	const holds = value.holds.map(parseHold);
	const policies = value.retention_policies.map(parsePolicy);
	if (holds.some((row) => row === null) || policies.some((row) => row === null))
		throw new Error(t("ret.err.invalidRecord"));
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
			throw new Error(t("ret.err.invalidCursor"));
		next = { id: cursor.id, placed_at: cursor.placed_at };
	}
	return { holds: holds as Hold[], policies: policies as Policy[], next };
}

async function responseError(
	error: unknown,
	data: unknown,
	fallback: string,
	t: Translate,
): Promise<string> {
	const safe = (value: unknown) => {
		const key =
			isRecord(value) && typeof value.error === "string" && Object.hasOwn(SAFE_ERRORS, value.error)
				? SAFE_ERRORS[value.error]
				: undefined;
		return key ? t(key) : undefined;
	};
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
	const t = useT();
	const { currentTeam, currentRole } = useTeam();
	if (!currentTeam) return <div className="card">{t("ret.selectTenant")}</div>;
	if (currentRole !== "owner" && currentRole !== "admin")
		return (
			<div className="card">
				<h1>{t("ret.title")}</h1>
				<p className="muted">{t("ret.ownersOnly")}</p>
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
	const t = useT();
	const richT = useRichT();
	// Read the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
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
			const t = translator.current;
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
					throw new Error(await responseError(invokeError, data, t("ret.loadFailed"), t));
				const snapshot = parseSnapshot(data, t);
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
				setError(readErrorMessage(cause, t("ret.loadFailed")));
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
		if (invokeError) throw new Error(await responseError(invokeError, data, fallback, t));
		if (!isRecord(data) || data.ok !== true)
			throw new Error(await responseError(null, data, fallback, t));
		return data;
	}

	async function placeHold(event: FormEvent) {
		event.preventDefault();
		if (!clean(caseId, 100) || !CASE_ID.test(caseId)) {
			setError(t("ret.badCase"));
			return;
		}
		if (
			!clean(holdOwner, 200) ||
			!clean(reason, 2000) ||
			(reference !== "" && !clean(reference, 200))
		) {
			setError(t("ret.badText"));
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
				t("ret.holdUnconfirmed"),
			);
			setCaseId("");
			setHoldOwner("");
			setReason("");
			setReference("");
			setConfirmPlace(false);
			setNotice(t("ret.holdPlaced"));
			await load();
		} catch (cause) {
			setConfirmPlace(false);
			// Refresh first: a failed placement may still have committed, and the
			// refresh clears any previous message.
			await load();
			setError(readErrorMessage(cause, t("ret.holdUnconfirmed")));
		} finally {
			setBusy(false);
		}
	}

	async function releaseHold(hold: Hold) {
		if (!clean(releaseReason, 2000)) {
			setError(t("ret.badRelease"));
			return;
		}
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			await write(
				{ action: "release_hold", hold_id: hold.id, reason: releaseReason },
				t("ret.releaseUnconfirmed"),
			);
			setReleaseReason("");
			setConfirmRelease(false);
			setNotice(t("ret.released"));
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, t("ret.releaseUnconfirmed")));
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
			setError(t("ret.badDays", { min: String(policy.min_days), max: String(policy.max_days) }));
			return;
		}
		if (!clean(edit.reason, 500)) {
			setError(t("ret.badChangeReason"));
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
				t("ret.changeUnconfirmed"),
			);
			setEdit(null);
			setNotice(result.changed === true ? t("ret.saved") : t("ret.unchanged"));
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, t("ret.changeUnconfirmed")));
		} finally {
			setBusy(false);
		}
	}

	return (
		<div className="stack">
			<header className="card">
				<h1>{t("ret.title")}</h1>
				<p className="muted">{richT("ret.lead", { team: <strong>{teamName}</strong> })}</p>
				{!isOwner ? <p className="muted small">{t("ret.adminView")}</p> : null}
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
				<h2 id="hold-heading">{t("ret.hold")}</h2>
				{loading ? (
					<p role="status">{t("common.loading")}</p>
				) : activeHold ? (
					<div
						className="notice notice-warning"
						role="region"
						aria-label={t("ret.activeHoldLabel")}
					>
						<p>
							<strong>{t("ret.activeHold")}</strong>
							{t("ret.activeHoldLine", {
								case: activeHold.case_id ?? activeHold.hold_reference,
								owner: activeHold.hold_owner ?? t("ret.notRecorded"),
								time: formatDate(activeHold.placed_at),
							})}
						</p>
						<p className="small">{activeHold.reason}</p>
						{isOwner ? (
							<>
								<label className="label" htmlFor="release-reason">
									{t("ret.releaseReason")}
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
												{t("ret.confirmRelease")}
											</button>
											<button
												className="button button-secondary"
												type="button"
												onClick={() => setConfirmRelease(false)}
											>
												{t("common.cancel")}
											</button>
										</>
									) : (
										<button
											className="button button-secondary"
											type="button"
											disabled={busy || releaseReason.trim() === ""}
											onClick={() => setConfirmRelease(true)}
										>
											{t("ret.release")}
										</button>
									)}
								</div>
							</>
						) : null}
					</div>
				) : (
					<p className="muted">{t("ret.noHold")}</p>
				)}

				{isOwner && !activeHold && !loading ? (
					<form onSubmit={placeHold} style={{ marginTop: 14 }} aria-label={t("ret.placeLabel")}>
						<h3>{t("ret.placeTitle")}</h3>
						<label className="label" htmlFor="hold-case">
							{t("ret.caseId")}
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
							{t("ret.holdOwner")}
						</label>
						<input
							id="hold-owner"
							className="input"
							maxLength={200}
							value={holdOwner}
							onChange={(e) => setHoldOwner(e.target.value)}
							placeholder={t("ret.holdOwnerPlaceholder")}
							autoComplete="off"
						/>
						<label className="label" htmlFor="hold-reason">
							{t("ret.reason")}
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
							{t("ret.reference")}
						</label>
						<input
							id="hold-reference"
							className="input"
							maxLength={200}
							value={reference}
							onChange={(e) => setReference(e.target.value)}
							autoComplete="off"
						/>
						<p className="muted small">{t("ret.holdEffect")}</p>
						<div className="row" style={{ marginTop: 10 }}>
							<button
								className={confirmPlace ? "button button-danger" : "button"}
								type="submit"
								disabled={busy}
							>
								{confirmPlace ? t("ret.confirmPlace") : t("ret.placeLabel")}
							</button>
							{confirmPlace ? (
								<button
									className="button button-secondary"
									type="button"
									onClick={() => setConfirmPlace(false)}
								>
									{t("common.cancel")}
								</button>
							) : null}
						</div>
					</form>
				) : null}
			</section>

			<section className="card" aria-labelledby="retention-heading">
				<h2 id="retention-heading">{t("ret.periods")}</h2>
				<p className="muted">{t("ret.periodsLead")}</p>
				{loading ? (
					<p role="status">{t("common.loading")}</p>
				) : (
					<div className="table-wrap">
						<table className="table">
							<caption className="sr-only">{t("ret.periodsCaption")}</caption>
							<thead>
								<tr>
									<th scope="col">{t("ret.col.class")}</th>
									<th scope="col">{t("ret.col.days")}</th>
									<th scope="col">{t("ret.col.effective")}</th>
									<th scope="col">{t("ret.col.allowed")}</th>
									<th scope="col">{t("ret.col.actions")}</th>
								</tr>
							</thead>
							<tbody>
								{policies.map((policy) => (
									<tr key={policy.data_class}>
										<td>{classLabel(policy.data_class, t)}</td>
										<td>{policy.retention_days}</td>
										<td>
											{policy.effective_retention_days}
											{policy.plan_max_days !== null ? (
												<span className="muted">
													{t("ret.planMax", { days: policy.plan_max_days })}
												</span>
											) : null}
										</td>
										<td>
											{policy.configurable
												? `${policy.min_days}–${policy.max_days}`
												: t("ret.platform")}
										</td>
										<td>
											{isOwner && policy.configurable ? (
												edit?.dataClass === policy.data_class ? (
													<div className="row">
														<input
															className="input"
															type="number"
															aria-label={t("ret.daysFor", {
																class: classLabel(policy.data_class, t),
															})}
															min={policy.min_days ?? 0}
															max={policy.max_days ?? 3650}
															value={edit.days}
															onChange={(e) => setEdit({ ...edit, days: e.target.value })}
															style={{ width: 110 }}
														/>
														<input
															className="input"
															aria-label={t("ret.changeReason")}
															maxLength={500}
															placeholder={t("ret.reason")}
															value={edit.reason}
															onChange={(e) => setEdit({ ...edit, reason: e.target.value })}
														/>
														<button
															className="button"
															type="button"
															disabled={busy}
															onClick={() => void saveRetention(policy)}
														>
															{t("ret.save")}
														</button>
														<button
															className="button button-secondary"
															type="button"
															onClick={() => setEdit(null)}
														>
															{t("common.cancel")}
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
														{t("ret.change")}
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
				<h2 id="history-heading">{t("ret.history")}</h2>
				{loading ? null : holds.length === 0 ? (
					<p className="muted">{t("ret.noHistory")}</p>
				) : (
					<div className="table-wrap">
						<table className="table">
							<caption className="sr-only">{t("ret.historyCaption")}</caption>
							<thead>
								<tr>
									<th scope="col">{t("ret.col.case")}</th>
									<th scope="col">{t("ret.col.owner")}</th>
									<th scope="col">{t("ret.col.placed")}</th>
									<th scope="col">{t("ret.col.released")}</th>
									<th scope="col">{t("ret.releaseReason")}</th>
								</tr>
							</thead>
							<tbody>
								{holds.map((hold) => (
									<tr key={hold.id}>
										<td>{hold.case_id ?? hold.hold_reference}</td>
										<td>{hold.hold_owner ?? "—"}</td>
										<td>{formatDate(hold.placed_at)}</td>
										<td>{hold.released_at ? formatDate(hold.released_at) : t("ret.active")}</td>
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
							{t("ret.loadMore")}
						</button>
					) : null}
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={() => void load()}
					>
						{t("common.refresh")}
					</button>
				</div>
			</section>
		</div>
	);
}
