import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { readFunctionError } from "../../auth/oidc-sso";
import { EnterpriseAuth } from "../../enterprise/auth";
import type { DashboardMessageKey } from "../../i18n/en";
import { englishT, type Translate, useRichT, useT } from "../../i18n/I18nProvider";
import { supabase } from "../../lib/supabase";

type SamlChange = {
	request_id: string;
	tenant_id: string;
	requested_by: string;
	old_provider_id: string | null;
	new_provider_id: string | null;
	reason: string;
	change_ref: string;
	created_at: string;
	expires_at: string;
	approved_by: string | null;
	approved_at: string | null;
};
type Props = { tenantId: string; currentUserId: string };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_ERRORS: Record<string, DashboardMessageKey> = {
	owner_required: "saml.err.owner",
	mfa_required: "saml.err.mfa",
	sso_required: "saml.err.sso",
	saml_policy_owner_required: "saml.err.owner",
	saml_policy_aal2_required: "saml.err.mfa",
	saml_policy_session_invalid: "saml.err.sessionInvalid",
	saml_policy_session_revoked: "saml.err.sessionRevoked",
	saml_policy_provider_session_required: "saml.err.providerSession",
	saml_policy_provider_unavailable: "saml.err.providerUnavailable",
	saml_policy_owners_not_verified: "saml.err.ownersNotVerified",
	saml_policy_scim_identity_conflict: "saml.err.scimConflict",
	saml_policy_unsupported_transition: "saml.err.transition",
	saml_policy_policy_conflict: "saml.err.policyConflict",
	saml_policy_request_expired: "saml.err.expired",
	saml_policy_request_consumed: "saml.err.consumed",
	saml_policy_distinct_owner_required: "saml.err.distinctOwner",
	saml_policy_request_not_found: "saml.err.notFound",
	saml_policy_request_pending_limit: "saml.err.pendingLimit",
	saml_policy_invalid_request: "saml.err.invalid",
	invalid_request: "saml.err.invalid",
	rate_limited: "saml.err.rateLimited",
};

function record(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
function nullableUuid(value: unknown): value is string | null {
	return value === null || (typeof value === "string" && UUID.test(value));
}
function auditText(value: unknown, min: number, max: number): value is string {
	return (
		typeof value === "string" &&
		value.length >= min &&
		value.length <= max &&
		value.trim() === value &&
		!/[\u0000-\u001f\u007f]/.test(value)
	);
}
function parseChange(value: unknown, tenantId: string, t: Translate = englishT): SamlChange {
	if (
		!record(value) ||
		value.tenant_id !== tenantId ||
		typeof value.request_id !== "string" ||
		!UUID.test(value.request_id) ||
		typeof value.requested_by !== "string" ||
		!UUID.test(value.requested_by) ||
		!nullableUuid(value.old_provider_id) ||
		!nullableUuid(value.new_provider_id) ||
		(value.old_provider_id === null) === (value.new_provider_id === null) ||
		!auditText(value.reason, 12, 500) ||
		!auditText(value.change_ref, 1, 200) ||
		typeof value.created_at !== "string" ||
		!Number.isFinite(Date.parse(value.created_at)) ||
		typeof value.expires_at !== "string" ||
		!Number.isFinite(Date.parse(value.expires_at)) ||
		Date.parse(value.expires_at) <= Date.parse(value.created_at) ||
		Date.parse(value.expires_at) - Date.parse(value.created_at) > 5 * 60_000 ||
		!nullableUuid(value.approved_by) ||
		(value.approved_at !== null &&
			(typeof value.approved_at !== "string" ||
				!Number.isFinite(Date.parse(value.approved_at)) ||
				Date.parse(value.approved_at) < Date.parse(value.created_at) ||
				Date.parse(value.approved_at) >= Date.parse(value.expires_at))) ||
		(value.approved_by === null) !== (value.approved_at === null) ||
		value.approved_by === value.requested_by
	) {
		throw new Error(t("saml.err.invalidChange"));
	}
	return value as SamlChange;
}

export function SamlPolicyPanel(props: Props) {
	return (
		<EnterpriseAuth tenantId={props.tenantId} forceMfa>
			<SamlPolicyControls {...props} />
		</EnterpriseAuth>
	);
}

function SamlPolicyControls({ tenantId, currentUserId }: Props) {
	const t = useT();
	const richT = useRichT();
	// Loaders read the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
	const [policy, setPolicy] = useState<{ providerId: string | null } | null>(null);
	const [providerId, setProviderId] = useState("");
	const [reason, setReason] = useState("");
	const [changeRef, setChangeRef] = useState("");
	const [reviewId, setReviewId] = useState("");
	const [change, setChange] = useState<SamlChange | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [notice, setNotice] = useState<string | null>(null);
	const [now, setNow] = useState(Date.now);
	const active = useRef(true);
	const loadGeneration = useRef(0);

	useEffect(() => {
		active.current = true;
		return () => {
			active.current = false;
			++loadGeneration.current;
		};
	}, []);

	const invoke = useCallback(
		async (body: Record<string, unknown>) => {
			const { data, error: invokeError } = await supabase.functions.invoke<unknown>(
				"identity-security",
				{
					method: "POST",
					body: { ...body, tenant_id: tenantId },
				},
			);
			if (invokeError || !record(data) || data.ok !== true) {
				const details = await readFunctionError(invokeError, data);
				const code = details.error ?? "";
				const key = Object.hasOwn(SAFE_ERRORS, code) ? SAFE_ERRORS[code] : undefined;
				throw new Error(translator.current(key ?? "saml.err.unavailable"));
			}
			return data;
		},
		[tenantId],
	);

	const loadPolicy = useCallback(async () => {
		const generation = ++loadGeneration.current;
		setPolicy(null);
		try {
			const data = await invoke({ action: "status" });
			if (!active.current || generation !== loadGeneration.current) return;
			if (
				data.tenant_id !== tenantId ||
				data.role !== "owner" ||
				data.current_assurance !== "aal2" ||
				data.access_allowed !== true ||
				!nullableUuid(data.required_saml_provider_id)
			) {
				throw new Error(translator.current("saml.err.statusDisabled"));
			}
			setPolicy({ providerId: data.required_saml_provider_id });
		} catch (cause) {
			if (active.current && generation === loadGeneration.current)
				setError(cause instanceof Error ? cause.message : translator.current("saml.err.status"));
		}
	}, [invoke, tenantId]);

	useEffect(() => {
		void loadPolicy();
	}, [loadPolicy]);
	useEffect(() => {
		setNow(Date.now());
		if (!change || change.approved_at) return;
		const remaining = Date.parse(change.expires_at) - Date.now();
		if (remaining <= 0) return;
		const timer = window.setTimeout(() => setNow(Date.now()), remaining + 1);
		return () => window.clearTimeout(timer);
	}, [change]);

	async function run(action: () => Promise<void>) {
		if (busy) return;
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			await action();
		} catch (cause) {
			if (active.current)
				setError(cause instanceof Error ? cause.message : t("saml.err.notConfirmed"));
		} finally {
			if (active.current) setBusy(false);
		}
	}
	function requestChange(event: FormEvent) {
		event.preventDefault();
		if (!policy) return;
		const nextProvider = policy.providerId ? null : providerId.trim().toLowerCase();
		if (
			!nullableUuid(nextProvider) ||
			!auditText(reason.trim(), 12, 500) ||
			!auditText(changeRef.trim(), 1, 200)
		) {
			setError(t("saml.err.form"));
			return;
		}
		void run(async () => {
			const data = await invoke({
				action: "request_saml_policy_change",
				new_provider_id: nextProvider,
				reason: reason.trim(),
				change_ref: changeRef.trim(),
			});
			const requested = parseChange(data.request, tenantId, t);
			if (
				requested.old_provider_id !== policy.providerId ||
				requested.new_provider_id !== nextProvider ||
				requested.requested_by !== currentUserId ||
				requested.approved_at !== null ||
				requested.reason !== reason.trim() ||
				requested.change_ref !== changeRef.trim()
			)
				throw new Error(t("saml.err.mismatch"));
			if (!active.current) return;
			setChange(requested);
			setReviewId(requested.request_id);
			setNotice(t("saml.requested"));
		});
	}
	function reviewChange(event: FormEvent) {
		event.preventDefault();
		const requestId = reviewId.trim().toLowerCase();
		if (!UUID.test(requestId)) {
			setError(t("saml.err.requestId"));
			return;
		}
		setChange(null);
		void run(async () => {
			const data = await invoke({ action: "get_saml_policy_change", request_id: requestId });
			const reviewed = parseChange(data.request, tenantId, t);
			if (reviewed.request_id !== requestId) throw new Error(t("saml.err.selectedMismatch"));
			if (active.current) setChange(reviewed);
		});
	}
	const expired = Boolean(change && Date.parse(change.expires_at) <= now);
	const selfRequested = change?.requested_by === currentUserId;
	const approved = Boolean(change?.approved_at);
	return (
		<section className="card" aria-labelledby="saml-policy-heading">
			<h2 id="saml-policy-heading">{t("saml.title")}</h2>
			<p className="muted">{t("saml.lead")}</p>
			<p className="muted small">{t("saml.replace")}</p>
			{error ? (
				<div className="notice notice-danger" role="alert">
					{error}
				</div>
			) : null}
			{notice ? (
				<div className="notice notice-success" role="status">
					{notice}
				</div>
			) : null}
			<p>
				{policy
					? richT("saml.current", {
							provider: <strong>{policy.providerId ?? t("saml.off")}</strong>,
						})
					: error
						? t("saml.statusUnavailable")
						: t("saml.verifying")}
			</p>
			<form onSubmit={requestChange}>
				{!policy?.providerId ? (
					<>
						<label className="label" htmlFor="saml-provider-id">
							{t("saml.providerId")}
						</label>
						<input
							id="saml-provider-id"
							className="input mono"
							value={providerId}
							onChange={(event) => setProviderId(event.target.value)}
							maxLength={36}
							disabled={busy}
							autoComplete="off"
						/>
					</>
				) : null}
				<label className="label" htmlFor="saml-change-reason">
					{t("saml.reason")}
				</label>
				<textarea
					id="saml-change-reason"
					className="input"
					value={reason}
					onChange={(event) => setReason(event.target.value)}
					minLength={12}
					maxLength={500}
					disabled={busy}
				/>
				<label className="label" htmlFor="saml-change-ref">
					{t("saml.ref")}
				</label>
				<input
					id="saml-change-ref"
					className="input"
					value={changeRef}
					onChange={(event) => setChangeRef(event.target.value)}
					maxLength={200}
					disabled={busy}
				/>
				<button className="button" type="submit" disabled={busy || !policy || !currentUserId}>
					{policy?.providerId ? t("saml.requestDisable") : t("saml.requestEnable")}
				</button>
			</form>
			<form onSubmit={reviewChange} style={{ marginTop: 16 }}>
				<label className="label" htmlFor="saml-review-id">
					{t("saml.requestId")}
				</label>
				<input
					id="saml-review-id"
					className="input mono"
					value={reviewId}
					onChange={(event) => {
						setReviewId(event.target.value);
						setChange(null);
					}}
					maxLength={36}
					disabled={busy}
					autoComplete="off"
				/>
				<p className="muted small">{t("saml.share")}</p>
				<button className="button button-secondary" type="submit" disabled={busy}>
					{t("saml.review")}
				</button>
			</form>
			{change ? (
				<div
					className="notice notice-warning"
					role="region"
					aria-label={t("saml.reviewLabel")}
					style={{ marginTop: 16 }}
				>
					<dl>
						<dt>{t("saml.requestedBy")}</dt>
						<dd>{change.requested_by}</dd>
						<dt>{t("saml.currentProvider")}</dt>
						<dd>{change.old_provider_id ?? t("saml.off")}</dd>
						<dt>{t("saml.requestedProvider")}</dt>
						<dd>{change.new_provider_id ?? t("saml.off")}</dd>
						<dt>{t("saml.reason")}</dt>
						<dd>{change.reason}</dd>
						<dt>{t("saml.ref")}</dt>
						<dd>{change.change_ref}</dd>
						<dt>{t("saml.expires")}</dt>
						<dd>{new Date(change.expires_at).toLocaleString()}</dd>
					</dl>
					{approved ? (
						<p role="status">{t("saml.approvedBy", { owner: change.approved_by ?? "" })}</p>
					) : expired ? (
						<p role="status">{t("saml.err.expired")}</p>
					) : selfRequested ? (
						<p role="status">{t("saml.self")}</p>
					) : (
						<p className="small">{t("saml.reviewHint")}</p>
					)}
					<button
						className="button"
						type="button"
						disabled={busy || approved || expired || selfRequested || !currentUserId}
						onClick={() => {
							if (Date.parse(change.expires_at) <= Date.now()) {
								setNow(Date.now());
								return;
							}
							void run(async () => {
								const data = await invoke({
									action: "approve_saml_policy_change",
									request_id: change.request_id,
								});
								const result = parseChange(data.request, tenantId, t);
								if (
									result.request_id !== change.request_id ||
									result.approved_by !== currentUserId ||
									!result.approved_at ||
									result.requested_by !== change.requested_by ||
									result.old_provider_id !== change.old_provider_id ||
									result.new_provider_id !== change.new_provider_id ||
									result.reason !== change.reason ||
									result.change_ref !== change.change_ref ||
									result.created_at !== change.created_at ||
									result.expires_at !== change.expires_at
								)
									throw new Error(t("saml.err.approvalMismatch"));
								if (!active.current) return;
								setChange(result);
								setNotice(t("saml.applied"));
								await loadPolicy();
							});
						}}
					>
						{t("saml.approve")}
					</button>
				</div>
			) : null}
			<button
				className="button button-secondary"
				type="button"
				disabled={busy}
				style={{ marginTop: 12 }}
				onClick={() => {
					setError(null);
					void loadPolicy();
				}}
			>
				{t("saml.refresh")}
			</button>
		</section>
	);
}
