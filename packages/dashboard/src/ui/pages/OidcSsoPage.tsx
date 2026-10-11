import { type FormEvent, useCallback, useEffect, useState } from "react";
import { readFunctionError, redirectToIdp, startOidcFlow } from "../../auth/oidc-sso";
import { useTeam } from "../../enterprise/team-provider";
import { supabase } from "../../lib/supabase";

type Kind = "entra" | "okta" | "generic";
type ProviderView = {
	id: string;
	kind: Kind;
	display_name: string;
	issuer: string;
	client_id: string;
	token_auth_method: string;
	client_secret_configured: boolean | null;
	subject_claim: "sub" | "oid";
	groups_claim: string | null;
	groups_mode: "ignore" | "require_mapped";
	enabled: boolean;
	discovery_ready: boolean;
};
type DomainView = { domain: string; verified: boolean; txt_name: string; txt_value?: string };
type Snapshot = {
	redirect_uri: string;
	provider: ProviderView | null;
	domains: DomainView[];
	enforced: boolean;
	saml_enforced: boolean;
	break_glass_enabled: boolean;
};

const SAFE_ERRORS: Record<string, string> = {
	owner_required: "Only an active tenant owner can manage single sign-on.",
	mfa_required: "Complete multi-factor verification (AAL2) to change single sign-on settings.",
	invalid_provider: "The provider settings were rejected. Check each field.",
	discovery_failed: "The identity provider's discovery document could not be fetched or validated.",
	client_secret_not_configured:
		"The client secret is not configured in the Edge function secrets yet.",
	provider_locked_by_enforcement: "Disable enforcement before changing the provider.",
	provider_changed:
		"The provider was changed by someone else while discovery was refreshing. Reload and try again.",
	invalid_domain: "Enter a valid domain such as example.com.",
	dns_lookup_failed:
		"The verification record could not be looked up yet. DNS changes can take time.",
	verification_record_not_found: "The verification record was not found. Check the name and value.",
	domain_verified_by_another_tenant: "Another workspace has already verified this domain.",
	last_verified_domain_locked_by_enforcement:
		"Disable enforcement before removing the last verified domain.",
	oidc_verified_owners_required:
		"Every owner must link an identity first, and at least two owners are required.",
	oidc_actor_session_required:
		"Sign in through single sign-on first, so enforcement cannot lock you out.",
	oidc_existing_identity_conflict:
		"Some provisioned users are bound to other accounts. They must link their identity first.",
	oidc_saml_enforcement_active: "SAML enforcement is active; a tenant cannot enforce both.",
	oidc_provider_unavailable: "The provider must be enabled before it can be enforced.",
	invalid_request: "The request was rejected. Check the fields.",
	sso_unavailable:
		"Single sign-on administration is temporarily unavailable. No change was confirmed.",
};

const PRESETS: Record<Kind, { issuer: string; hint: string }> = {
	entra: {
		issuer: "https://login.microsoftonline.com/<directory-tenant-id>/v2.0",
		hint: "Use your directory (tenant) ID, never common or organizations.",
	},
	okta: {
		issuer: "https://<your-org>.okta.com/oauth2/default",
		hint: "The issuer of the authorization server that issues your ID tokens.",
	},
	generic: { issuer: "https://", hint: "Any OpenID Connect provider with a discovery document." },
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

export function OidcSsoPage() {
	const { currentTeam, currentRole } = useTeam();
	if (!currentTeam) return <div className="card">Select a tenant to manage single sign-on.</div>;
	if (currentRole !== "owner")
		return (
			<div className="card">
				<h1>Single sign-on</h1>
				<p className="muted">OIDC single sign-on is available to active tenant owners only.</p>
			</div>
		);
	return (
		<TenantSso
			key={currentTeam.tenant_id}
			tenantId={currentTeam.tenant_id}
			teamName={currentTeam.name}
		/>
	);
}

function TenantSso({ tenantId, teamName }: { tenantId: string; teamName: string }) {
	const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [notice, setNotice] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [form, setForm] = useState({
		kind: "entra" as Kind,
		display_name: "",
		issuer: "",
		client_id: "",
		client_secret_ref: "",
		token_auth_method: "client_secret_basic",
		groups_claim: "",
		groups_mode: "ignore",
		enabled: false,
	});
	const [domain, setDomain] = useState("");
	const [reason, setReason] = useState("");
	const [changeRef, setChangeRef] = useState("");

	const invoke = useCallback(
		async (body: Record<string, unknown>): Promise<Record<string, unknown>> => {
			const { data, error: invokeError } = await supabase.functions.invoke<unknown>("oidc-sso", {
				method: "POST",
				body: { ...body, tenant_id: tenantId },
			});
			if (invokeError || !isRecord(data) || data.ok !== true) {
				const details = await readFunctionError(invokeError, data);
				throw new Error(SAFE_ERRORS[details.error ?? ""] ?? "The request was not confirmed.");
			}
			return data;
		},
		[tenantId],
	);

	const load = useCallback(async () => {
		try {
			const data = await invoke({ action: "get_config" });
			setSnapshot(data as unknown as Snapshot);
			const provider = (data as unknown as Snapshot).provider;
			if (provider)
				setForm((current) => ({
					...current,
					kind: provider.kind,
					display_name: provider.display_name,
					issuer: provider.issuer,
					client_id: provider.client_id,
					token_auth_method: provider.token_auth_method,
					groups_claim: provider.groups_claim ?? "",
					groups_mode: provider.groups_mode,
					enabled: provider.enabled,
				}));
			setError(null);
		} catch (cause) {
			setError(cause instanceof Error ? cause.message : "Unable to load single sign-on settings.");
		}
	}, [invoke]);

	useEffect(() => {
		void load();
	}, [load]);

	async function run(action: () => Promise<string>) {
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			setNotice(await action());
			await load();
		} catch (cause) {
			setError(cause instanceof Error ? cause.message : "The request was not confirmed.");
		} finally {
			setBusy(false);
		}
	}

	function saveProvider(event: FormEvent) {
		event.preventDefault();
		void run(async () => {
			await invoke({
				action: "put_provider",
				kind: form.kind,
				display_name: form.display_name,
				issuer: form.issuer.trim(),
				client_id: form.client_id.trim(),
				client_secret_ref: form.token_auth_method === "none" ? null : form.client_secret_ref.trim(),
				token_auth_method: form.token_auth_method,
				groups_claim: form.groups_claim.trim() || null,
				groups_mode: form.groups_mode,
				enabled: form.enabled,
			});
			return "Provider saved and discovery validated.";
		});
	}

	const provider = snapshot?.provider ?? null;
	const verifiedDomains = snapshot?.domains.filter((entry) => entry.verified) ?? [];
	return (
		<div className="stack">
			<header className="card">
				<h1>Single sign-on (OIDC)</h1>
				<p className="muted">
					Configure OpenID Connect sign-in for <strong>{teamName}</strong> with Microsoft Entra ID,
					Okta or another provider. SCIM still provisions users and roles; this page controls how
					they sign in.
				</p>
				{snapshot ? (
					<p className="muted small">
						Register this redirect URI at your provider: <code>{snapshot.redirect_uri}</code>
					</p>
				) : null}
				{snapshot?.saml_enforced ? (
					<p className="notice notice-warning" role="note">
						SAML enforcement is active for this workspace; OIDC cannot be enforced at the same time.
					</p>
				) : null}
			</header>
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

			<form className="card" onSubmit={saveProvider} aria-labelledby="oidc-provider-heading">
				<h2 id="oidc-provider-heading">Provider</h2>
				<label className="label" htmlFor="oidc-kind">
					Provider type
				</label>
				<select
					id="oidc-kind"
					value={form.kind}
					onChange={(event) => setForm({ ...form, kind: event.target.value as Kind })}
				>
					<option value="entra">Microsoft Entra ID</option>
					<option value="okta">Okta</option>
					<option value="generic">Generic OpenID Connect</option>
				</select>
				<label className="label" htmlFor="oidc-name">
					Display name
				</label>
				<input
					id="oidc-name"
					value={form.display_name}
					maxLength={64}
					onChange={(event) => setForm({ ...form, display_name: event.target.value })}
				/>
				<label className="label" htmlFor="oidc-issuer">
					Issuer
				</label>
				<input
					id="oidc-issuer"
					value={form.issuer}
					placeholder={PRESETS[form.kind].issuer}
					onChange={(event) => setForm({ ...form, issuer: event.target.value })}
				/>
				<p className="muted small">{PRESETS[form.kind].hint}</p>
				<label className="label" htmlFor="oidc-client-id">
					Client (application) ID
				</label>
				<input
					id="oidc-client-id"
					value={form.client_id}
					onChange={(event) => setForm({ ...form, client_id: event.target.value })}
				/>
				<label className="label" htmlFor="oidc-auth-method">
					Client authentication
				</label>
				<select
					id="oidc-auth-method"
					value={form.token_auth_method}
					onChange={(event) => setForm({ ...form, token_auth_method: event.target.value })}
				>
					<option value="client_secret_basic">Client secret (HTTP Basic)</option>
					<option value="client_secret_post">Client secret (request body)</option>
					<option value="none">None (public client, PKCE only)</option>
				</select>
				{form.token_auth_method !== "none" ? (
					<>
						<label className="label" htmlFor="oidc-secret-ref">
							Client secret reference
						</label>
						<input
							id="oidc-secret-ref"
							value={form.client_secret_ref}
							placeholder="CONTOSO"
							onChange={(event) =>
								setForm({ ...form, client_secret_ref: event.target.value.toUpperCase() })
							}
						/>
						<p className="muted small">
							Store the secret as the Edge function secret{" "}
							<code>AIDR_OIDC_CLIENT_SECRET_{form.client_secret_ref || "REF"}</code>; it is never
							saved in the database or shown here.
							{provider?.client_secret_configured === false ? " It is not configured yet." : null}
						</p>
					</>
				) : null}
				<label className="label" htmlFor="oidc-groups-claim">
					Groups claim (optional)
				</label>
				<input
					id="oidc-groups-claim"
					value={form.groups_claim}
					placeholder="groups"
					onChange={(event) => setForm({ ...form, groups_claim: event.target.value })}
				/>
				<label className="label" htmlFor="oidc-groups-mode">
					Group requirement
				</label>
				<select
					id="oidc-groups-mode"
					value={form.groups_mode}
					onChange={(event) => setForm({ ...form, groups_mode: event.target.value })}
				>
					<option value="ignore">Ignore groups (SCIM decides access)</option>
					<option value="require_mapped">
						Require a mapped group (exact group IDs from SCIM mappings)
					</option>
				</select>
				<label className="label">
					<input
						type="checkbox"
						checked={form.enabled}
						onChange={(event) => setForm({ ...form, enabled: event.target.checked })}
					/>{" "}
					Enable sign-in
				</label>
				<button className="button" type="submit" disabled={busy}>
					Save and validate
				</button>
			</form>

			<section className="card" aria-labelledby="oidc-domains-heading">
				<h2 id="oidc-domains-heading">Verified email domains</h2>
				<p className="muted">
					Sign-in is accepted only for email addresses on a domain this workspace has verified with
					a DNS TXT record.
				</p>
				<ul>
					{snapshot?.domains.map((entry) => (
						<li key={entry.domain}>
							<strong>{entry.domain}</strong> — {entry.verified ? "verified" : "pending"}
							{!entry.verified && entry.txt_value ? (
								<div>
									<code>
										{entry.txt_name} TXT {entry.txt_value}
									</code>{" "}
									<button
										type="button"
										className="button button-secondary"
										disabled={busy}
										onClick={() =>
											void run(async () => {
												await invoke({ action: "verify_domain", domain: entry.domain });
												return `${entry.domain} verified.`;
											})
										}
									>
										Verify {entry.domain}
									</button>
								</div>
							) : null}
							<button
								type="button"
								className="button button-secondary"
								disabled={busy}
								onClick={() =>
									void run(async () => {
										await invoke({ action: "remove_domain", domain: entry.domain });
										return `${entry.domain} removed.`;
									})
								}
							>
								Remove {entry.domain}
							</button>
						</li>
					))}
				</ul>
				<label className="label" htmlFor="oidc-domain">
					Add a domain
				</label>
				<input
					id="oidc-domain"
					value={domain}
					placeholder="example.com"
					onChange={(event) => setDomain(event.target.value)}
				/>
				<button
					type="button"
					className="button"
					disabled={busy || !domain.trim()}
					onClick={() =>
						void run(async () => {
							await invoke({ action: "add_domain", domain: domain.trim() });
							setDomain("");
							return "Domain added. Publish the TXT record, then verify.";
						})
					}
				>
					Add domain
				</button>
			</section>

			<section className="card" aria-labelledby="oidc-enforce-heading">
				<h2 id="oidc-enforce-heading">Enforcement</h2>
				<p className="muted">
					Link your own account first, then have every other owner do the same. Enforcement requires
					you to be signed in through this provider, at least two linked owners and no unlinked
					owner. Email, password and other sessions are refused for this workspace once it is on.
				</p>
				<button
					type="button"
					className="button button-secondary"
					disabled={busy || !provider?.enabled}
					onClick={() =>
						void run(async () => {
							const started = await startOidcFlow({
								providerId: provider?.id,
								mode: "link",
								returnTo: "/sso",
							});
							if (!started.ok) throw new Error(started.message);
							redirectToIdp(started.url);
							return "Redirecting to your identity provider…";
						})
					}
				>
					Link my account
				</button>
				<label className="label" htmlFor="oidc-reason">
					Reason (recorded in the audit log)
				</label>
				<input
					id="oidc-reason"
					value={reason}
					onChange={(event) => setReason(event.target.value)}
				/>
				<label className="label" htmlFor="oidc-change-ref">
					Change reference
				</label>
				<input
					id="oidc-change-ref"
					value={changeRef}
					placeholder="CHG-1042"
					onChange={(event) => setChangeRef(event.target.value)}
				/>
				{snapshot?.enforced ? (
					<button
						type="button"
						className="button button-secondary"
						disabled={busy || reason.trim().length < 12 || !changeRef.trim()}
						onClick={() =>
							void run(async () => {
								await invoke({
									action: "set_enforcement",
									provider_id: null,
									reason,
									change_ref: changeRef,
								});
								return "Enforcement disabled.";
							})
						}
					>
						Disable enforcement
					</button>
				) : (
					<button
						type="button"
						className="button"
						disabled={
							busy ||
							!provider?.enabled ||
							verifiedDomains.length === 0 ||
							reason.trim().length < 12 ||
							!changeRef.trim()
						}
						onClick={() =>
							void run(async () => {
								await invoke({
									action: "set_enforcement",
									provider_id: provider?.id,
									reason,
									change_ref: changeRef,
								});
								return "Enforcement enabled.";
							})
						}
					>
						Enforce single sign-on
					</button>
				)}
				<p className="muted small">
					Break-glass:{" "}
					{snapshot?.break_glass_enabled
						? "enabled. An owner's single-use recovery code can suspend enforcement if the identity provider is unavailable."
						: "disabled. Enable break-glass recovery in identity policy before enforcing, so an identity provider outage is recoverable."}
				</p>
			</section>
		</div>
	);
}
