import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { readFunctionError } from "../../auth/oidc-sso";
import { EnterpriseAuth } from "../../enterprise/auth";
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
const SAFE_ERRORS: Record<string, string> = {
	owner_required: "Only an active tenant owner can manage SAML enforcement.",
	mfa_required: "Complete multi-factor verification, then try again.",
	sso_required: "Sign in through this workspace's required identity provider, then try again.",
	saml_policy_owner_required: "Only an active tenant owner can manage SAML enforcement.",
	saml_policy_aal2_required: "Complete multi-factor verification, then try again.",
	saml_policy_session_invalid: "Sign in again before changing SAML enforcement.",
	saml_policy_session_revoked: "This session was revoked. Sign in again.",
	saml_policy_provider_session_required:
		"Sign in through the SAML provider being enabled or currently required, then try again.",
	saml_policy_provider_unavailable: "The selected SAML provider is unavailable.",
	saml_policy_owners_not_verified:
		"At least two active owners are required. Every active owner must first verify their account through this SAML provider.",
	saml_policy_scim_identity_conflict:
		"A provisioned identity conflicts with an owner account. Resolve the identity before retrying.",
	saml_policy_unsupported_transition:
		"Disable the current SAML provider with two-owner approval before enabling another provider.",
	saml_policy_policy_conflict: "The identity policy changed. Refresh and create a new request.",
	saml_policy_request_expired: "This request expired. Create a new request for review.",
	saml_policy_request_consumed: "This request was already approved. Refresh its status.",
	saml_policy_distinct_owner_required: "A different active owner must approve this request.",
	saml_policy_request_not_found: "This request was not found in the selected workspace.",
	saml_policy_request_pending_limit:
		"Too many requests are pending. Wait for them to expire before creating another.",
	saml_policy_invalid_request: "Check the provider ID, change reason, and change reference.",
	invalid_request: "Check the provider ID, change reason, and change reference.",
	rate_limited: "Too many attempts. Wait a moment before retrying.",
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
function parseChange(value: unknown, tenantId: string): SamlChange {
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
		throw new Error(
			"SAML enforcement returned an invalid change request. No change was confirmed.",
		);
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
				throw new Error(
					SAFE_ERRORS[details.error ?? ""] ??
						"SAML enforcement is unavailable. No change was confirmed.",
				);
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
				throw new Error("SAML enforcement status could not be verified. Changes are disabled.");
			}
			setPolicy({ providerId: data.required_saml_provider_id });
		} catch (cause) {
			if (active.current && generation === loadGeneration.current)
				setError(
					cause instanceof Error ? cause.message : "SAML enforcement status could not be verified.",
				);
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
				setError(
					cause instanceof Error ? cause.message : "The SAML policy change was not confirmed.",
				);
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
			setError(
				"Enter a valid provider ID, a change reason of 12–500 characters, and a change reference.",
			);
			return;
		}
		void run(async () => {
			const data = await invoke({
				action: "request_saml_policy_change",
				new_provider_id: nextProvider,
				reason: reason.trim(),
				change_ref: changeRef.trim(),
			});
			const requested = parseChange(data.request, tenantId);
			if (
				requested.old_provider_id !== policy.providerId ||
				requested.new_provider_id !== nextProvider ||
				requested.requested_by !== currentUserId ||
				requested.approved_at !== null ||
				requested.reason !== reason.trim() ||
				requested.change_ref !== changeRef.trim()
			)
				throw new Error(
					"The returned request does not match this change. No change was confirmed.",
				);
			if (!active.current) return;
			setChange(requested);
			setReviewId(requested.request_id);
			setNotice(
				"Request created. SAML enforcement is unchanged until another owner reviews and approves it.",
			);
		});
	}
	function reviewChange(event: FormEvent) {
		event.preventDefault();
		const requestId = reviewId.trim().toLowerCase();
		if (!UUID.test(requestId)) {
			setError("Enter the complete change request ID.");
			return;
		}
		setChange(null);
		void run(async () => {
			const data = await invoke({ action: "get_saml_policy_change", request_id: requestId });
			const reviewed = parseChange(data.request, tenantId);
			if (reviewed.request_id !== requestId)
				throw new Error("The returned request does not match the selected change.");
			if (active.current) setChange(reviewed);
		});
	}
	const expired = Boolean(change && Date.parse(change.expires_at) <= now);
	const selfRequested = change?.requested_by === currentUserId;
	const approved = Boolean(change?.approved_at);
	return (
		<section className="card" aria-labelledby="saml-policy-heading">
			<h2 id="saml-policy-heading">SAML sign-in enforcement</h2>
			<p className="muted">
				Enabling or disabling required SAML sign-in needs two active owners, each signed in through
				the relevant provider with multi-factor verification. Review requests expire after five
				minutes.
			</p>
			<p className="muted small">
				To replace a provider, first disable the current requirement with two-owner approval, then
				request the new provider. Recovery sessions cannot approve these changes.
			</p>
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
				{policy ? (
					<>
						Current requirement: <strong>{policy.providerId ?? "Off"}</strong>
					</>
				) : error ? (
					"SAML enforcement status is unavailable."
				) : (
					"Verifying SAML enforcement status…"
				)}
			</p>
			<form onSubmit={requestChange}>
				{!policy?.providerId ? (
					<>
						<label className="label" htmlFor="saml-provider-id">
							SAML provider ID
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
					Change reason
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
					Change reference
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
					{policy?.providerId ? "Request disabling SAML" : "Request enabling SAML"}
				</button>
			</form>
			<form onSubmit={reviewChange} style={{ marginTop: 16 }}>
				<label className="label" htmlFor="saml-review-id">
					Change request ID
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
				<p className="muted small">
					Share this ID with a different owner. That owner can paste it here to review the exact
					change.
				</p>
				<button className="button button-secondary" type="submit" disabled={busy}>
					Review request
				</button>
			</form>
			{change ? (
				<div
					className="notice notice-warning"
					role="region"
					aria-label="SAML change review"
					style={{ marginTop: 16 }}
				>
					<dl>
						<dt>Requested by</dt>
						<dd>{change.requested_by}</dd>
						<dt>Current provider</dt>
						<dd>{change.old_provider_id ?? "Off"}</dd>
						<dt>Requested provider</dt>
						<dd>{change.new_provider_id ?? "Off"}</dd>
						<dt>Reason</dt>
						<dd>{change.reason}</dd>
						<dt>Change reference</dt>
						<dd>{change.change_ref}</dd>
						<dt>Expires</dt>
						<dd>{new Date(change.expires_at).toLocaleString()}</dd>
					</dl>
					{approved ? (
						<p role="status">Approved by {change.approved_by}. The policy change was applied.</p>
					) : expired ? (
						<p role="status">This request expired. Create a new request for review.</p>
					) : selfRequested ? (
						<p role="status">A different owner must approve your request.</p>
					) : (
						<p className="small">
							Review the provider and change details before approving. Approval applies this exact
							change.
						</p>
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
								const result = parseChange(data.request, tenantId);
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
									throw new Error(
										"Approval was not confirmed for this exact request. Refresh its status before retrying.",
									);
								if (!active.current) return;
								setChange(result);
								setNotice("The second owner approved the change. SAML enforcement was updated.");
								await loadPolicy();
							});
						}}
					>
						Approve as a second owner
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
				Refresh SAML status
			</button>
		</section>
	);
}
