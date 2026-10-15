import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import {
	formatJitMappingLines,
	type JitMappingLine,
	parseJitMappingLines,
	readFunctionError,
	redirectToIdp,
	startOidcFlow,
} from "../../auth/oidc-sso";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { useRichT, useT } from "../../i18n/I18nProvider";
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
	extra_scopes?: string[];
	enabled: boolean;
	discovery_ready: boolean;
};
type DomainView = { domain: string; verified: boolean; txt_name: string; txt_value?: string };
type JitView = {
	enabled: boolean;
	issuer_matches: boolean;
	allowed_domains: string[];
	default_role: "member" | "viewer" | null;
	mappings: JitMappingLine[];
	directory_authoritative: boolean;
	active_members: number;
	removed_members: Array<{ user_id: string; email: string | null; removed_at: string }>;
};
type Snapshot = {
	redirect_uri: string;
	provider: ProviderView | null;
	domains: DomainView[];
	enforced: boolean;
	saml_enforced: boolean;
	break_glass_enabled: boolean;
	/** Absent when the server predates just-in-time provisioning. */
	jit?: JitView;
};

const SAFE_ERRORS: Record<string, DashboardMessageKey> = {
	owner_required: "sso.err.owner",
	mfa_required: "sso.err.mfa",
	invalid_provider: "sso.err.provider",
	discovery_failed: "sso.err.discovery",
	client_secret_not_configured: "sso.err.secret",
	provider_locked_by_enforcement: "sso.err.locked",
	provider_changed: "sso.err.changed",
	invalid_domain: "sso.err.domain",
	dns_lookup_failed: "sso.err.dns",
	verification_record_not_found: "sso.err.recordMissing",
	domain_verified_by_another_tenant: "sso.err.otherTenant",
	last_verified_domain_locked_by_enforcement: "sso.err.lastDomain",
	oidc_verified_owners_required: "sso.err.owners",
	oidc_actor_session_required: "sso.err.actorSession",
	oidc_existing_identity_conflict: "sso.err.identityConflict",
	oidc_saml_enforcement_active: "sso.err.saml",
	oidc_provider_unavailable: "sso.err.providerDisabled",
	invalid_jit_policy: "sso.err.jitPolicy",
	jit_domain_not_verified: "sso.err.jitDomain",
	jit_domain_required: "sso.err.jitDomainRequired",
	jit_directory_authoritative: "sso.err.jitDirectory",
	provider_not_found: "sso.err.providerMissing",
	jit_member_not_removed: "sso.err.notRemoved",
	invalid_request: "sso.err.invalid",
	sso_unavailable: "sso.err.unavailable",
};

const PRESETS: Record<Kind, { issuer: string; hint: DashboardMessageKey }> = {
	entra: {
		issuer: "https://login.microsoftonline.com/<directory-tenant-id>/v2.0",
		hint: "sso.hint.entra",
	},
	okta: {
		issuer: "https://<your-org>.okta.com/oauth2/default",
		hint: "sso.hint.okta",
	},
	generic: { issuer: "https://", hint: "sso.hint.generic" },
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

export function OidcSsoPage() {
	const t = useT();
	const { currentTeam, currentRole } = useTeam();
	if (!currentTeam) return <div className="card">{t("sso.selectTenant")}</div>;
	if (currentRole !== "owner")
		return (
			<div className="card">
				<h1>{t("nav.sso")}</h1>
				<p className="muted">{t("sso.ownersOnly")}</p>
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
	const t = useT();
	const richT = useRichT();
	// Loaders read the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
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
		extra_scopes: "",
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
				const code = details.error ?? "";
				const key = Object.hasOwn(SAFE_ERRORS, code) ? SAFE_ERRORS[code] : undefined;
				throw new Error(translator.current(key ?? "sso.err.notConfirmed"));
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
					extra_scopes: (provider.extra_scopes ?? []).join(" "),
					enabled: provider.enabled,
				}));
			setError(null);
		} catch (cause) {
			setError(cause instanceof Error ? cause.message : translator.current("sso.err.load"));
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
			setError(cause instanceof Error ? cause.message : t("sso.err.notConfirmed"));
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
				extra_scopes: form.extra_scopes.split(/[\s,]+/).filter(Boolean),
				enabled: form.enabled,
			});
			return t("sso.saved");
		});
	}

	const provider = snapshot?.provider ?? null;
	const verifiedDomains = snapshot?.domains.filter((entry) => entry.verified) ?? [];
	return (
		<div className="stack">
			<header className="card">
				<h1>{t("sso.title")}</h1>
				<p className="muted">{richT("sso.lead", { team: <strong>{teamName}</strong> })}</p>
				{snapshot ? (
					<p className="muted small">
						{richT("sso.redirect", { uri: <code>{snapshot.redirect_uri}</code> })}
					</p>
				) : null}
				{snapshot?.saml_enforced ? (
					<p className="notice notice-warning" role="note">
						{t("sso.samlActive")}
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
				<h2 id="oidc-provider-heading">{t("sso.provider")}</h2>
				<label className="label" htmlFor="oidc-kind">
					{t("sso.providerType")}
				</label>
				<select
					id="oidc-kind"
					value={form.kind}
					onChange={(event) => setForm({ ...form, kind: event.target.value as Kind })}
				>
					<option value="entra">Microsoft Entra ID</option>
					<option value="okta">Okta</option>
					<option value="generic">{t("sso.generic")}</option>
				</select>
				<label className="label" htmlFor="oidc-name">
					{t("sso.displayName")}
				</label>
				<input
					id="oidc-name"
					value={form.display_name}
					maxLength={64}
					onChange={(event) => setForm({ ...form, display_name: event.target.value })}
				/>
				<label className="label" htmlFor="oidc-issuer">
					{t("sso.issuer")}
				</label>
				<input
					id="oidc-issuer"
					value={form.issuer}
					placeholder={PRESETS[form.kind].issuer}
					onChange={(event) => setForm({ ...form, issuer: event.target.value })}
				/>
				<p className="muted small">{t(PRESETS[form.kind].hint)}</p>
				<label className="label" htmlFor="oidc-client-id">
					{t("sso.clientId")}
				</label>
				<input
					id="oidc-client-id"
					value={form.client_id}
					onChange={(event) => setForm({ ...form, client_id: event.target.value })}
				/>
				<label className="label" htmlFor="oidc-auth-method">
					{t("sso.clientAuth")}
				</label>
				<select
					id="oidc-auth-method"
					value={form.token_auth_method}
					onChange={(event) => setForm({ ...form, token_auth_method: event.target.value })}
				>
					<option value="client_secret_basic">{t("sso.basic")}</option>
					<option value="client_secret_post">{t("sso.post")}</option>
					<option value="none">{t("sso.none")}</option>
				</select>
				{form.token_auth_method !== "none" ? (
					<>
						<label className="label" htmlFor="oidc-secret-ref">
							{t("sso.secretRef")}
						</label>
						<input
							id="oidc-secret-ref"
							value={form.client_secret_ref}
							// i18n-exempt: sample secret reference
							placeholder="CONTOSO"
							onChange={(event) =>
								setForm({ ...form, client_secret_ref: event.target.value.toUpperCase() })
							}
						/>
						<p className="muted small">
							{richT("sso.secretHint", {
								name: <code>AIDR_OIDC_CLIENT_SECRET_{form.client_secret_ref || "REF"}</code>,
							})}
							{provider?.client_secret_configured === false ? t("sso.secretMissing") : null}
						</p>
					</>
				) : null}
				<label className="label" htmlFor="oidc-groups-claim">
					{t("sso.groupsClaim")}
				</label>
				<input
					id="oidc-groups-claim"
					value={form.groups_claim}
					// i18n-exempt: claim name
					placeholder="groups"
					onChange={(event) => setForm({ ...form, groups_claim: event.target.value })}
				/>
				<label className="label" htmlFor="oidc-groups-mode">
					{t("sso.groupRequirement")}
				</label>
				<select
					id="oidc-groups-mode"
					value={form.groups_mode}
					onChange={(event) => setForm({ ...form, groups_mode: event.target.value })}
				>
					<option value="ignore">{t("sso.ignoreGroups")}</option>
					<option value="require_mapped">{t("sso.requireGroup")}</option>
				</select>
				<label className="label" htmlFor="oidc-extra-scopes">
					{t("sso.extraScopes")}
				</label>
				<input
					id="oidc-extra-scopes"
					value={form.extra_scopes}
					// i18n-exempt: scope name
					placeholder="allatclaims"
					onChange={(event) => setForm({ ...form, extra_scopes: event.target.value })}
				/>
				<p className="muted small">{t("sso.extraScopesHint")}</p>
				<label className="label">
					<input
						type="checkbox"
						checked={form.enabled}
						onChange={(event) => setForm({ ...form, enabled: event.target.checked })}
					/>{" "}
					{t("sso.enable")}
				</label>
				<button className="button" type="submit" disabled={busy}>
					{t("sso.save")}
				</button>
			</form>

			<section className="card" aria-labelledby="oidc-domains-heading">
				<h2 id="oidc-domains-heading">{t("sso.domains")}</h2>
				<p className="muted">{t("sso.domainsLead")}</p>
				<ul>
					{snapshot?.domains.map((entry) => (
						<li key={entry.domain}>
							<strong>{entry.domain}</strong> —{" "}
							{entry.verified ? t("sso.verified") : t("sso.pending")}
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
												return t("sso.domainVerified", { domain: entry.domain });
											})
										}
									>
										{t("sso.verifyDomain", { domain: entry.domain })}
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
										return t("sso.domainRemoved", { domain: entry.domain });
									})
								}
							>
								{t("sso.removeDomain", { domain: entry.domain })}
							</button>
						</li>
					))}
				</ul>
				<label className="label" htmlFor="oidc-domain">
					{t("sso.addDomainLabel")}
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
							return t("sso.domainAdded");
						})
					}
				>
					{t("sso.addDomain")}
				</button>
			</section>

			<JitProvisioningCard
				jit={snapshot?.jit}
				busy={busy}
				hasProvider={provider !== null}
				requireMappedGroups={form.groups_mode === "require_mapped"}
				verifiedDomains={verifiedDomains.map((entry) => entry.domain)}
				invoke={invoke}
				run={run}
			/>

			<section className="card" aria-labelledby="oidc-enforce-heading">
				<h2 id="oidc-enforce-heading">{t("sso.enforcement")}</h2>
				<p className="muted">{t("sso.enforcementLead")}</p>
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
								t,
							});
							if (!started.ok) throw new Error(started.message);
							redirectToIdp(started.url);
							return t("sso.redirecting");
						})
					}
				>
					{t("sso.link")}
				</button>
				<label className="label" htmlFor="oidc-reason">
					{t("gov.reason")}
				</label>
				<input
					id="oidc-reason"
					value={reason}
					onChange={(event) => setReason(event.target.value)}
				/>
				<label className="label" htmlFor="oidc-change-ref">
					{t("sso.changeRef")}
				</label>
				<input
					id="oidc-change-ref"
					value={changeRef}
					// i18n-exempt: sample change reference
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
								return t("sso.disabled");
							})
						}
					>
						{t("sso.disable")}
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
								return t("sso.enabled");
							})
						}
					>
						{t("sso.enforce")}
					</button>
				)}
				<p className="muted small">
					{snapshot?.break_glass_enabled ? t("sso.breakGlassOn") : t("sso.breakGlassOff")}
				</p>
			</section>
		</div>
	);
}

type JitProps = {
	jit: JitView;
	busy: boolean;
	hasProvider: boolean;
	requireMappedGroups: boolean;
	verifiedDomains: string[];
	invoke: (body: Record<string, unknown>) => Promise<Record<string, unknown>>;
	run: (action: () => Promise<string>) => Promise<void>;
};

/** Hidden when the server predates just-in-time provisioning. */
function JitProvisioningCard({
	jit,
	...rest
}: Omit<JitProps, "jit"> & { jit: JitView | undefined }) {
	// Re-seed the form whenever the server state changes.
	return jit ? <JitProvisioning key={JSON.stringify(jit)} jit={jit} {...rest} /> : null;
}

function JitProvisioning({
	jit,
	busy,
	hasProvider,
	requireMappedGroups,
	verifiedDomains,
	invoke,
	run,
}: JitProps) {
	const t = useT();
	const [jitForm, setJitForm] = useState({
		enabled: jit.enabled,
		domains: jit.allowed_domains.join(", "),
		default_role: jit.default_role ?? "",
		mappings: formatJitMappingLines(jit.mappings),
	});

	function saveJit(event: FormEvent) {
		event.preventDefault();
		void run(async () => {
			const parsed = parseJitMappingLines(jitForm.mappings);
			if (!parsed.ok) throw new Error(t("sso.jit.invalidMapping", { line: parsed.line }));
			await invoke({
				action: "put_jit_policy",
				enabled: jitForm.enabled,
				allowed_domains: jitForm.domains
					.split(/[\s,]+/)
					.map((entry) => entry.trim().toLowerCase())
					.filter(Boolean),
				default_role: jitForm.default_role || null,
				mappings: parsed.mappings,
			});
			return t("sso.jit.saved");
		});
	}

	return (
		<form className="card" onSubmit={saveJit} aria-labelledby="oidc-jit-heading">
			<h2 id="oidc-jit-heading">{t("sso.jit.title")}</h2>
			<p className="muted">{t("sso.jit.lead")}</p>
			{jit.directory_authoritative ? (
				<p className="notice notice-warning" role="note">
					{t("sso.jit.directoryAuthoritative")}
				</p>
			) : null}
			{jit.enabled && !jit.issuer_matches ? (
				<p className="notice notice-warning" role="note">
					{t("sso.jit.issuerChanged")}
				</p>
			) : null}
			<label className="label">
				<input
					type="checkbox"
					checked={jitForm.enabled}
					onChange={(event) => setJitForm({ ...jitForm, enabled: event.target.checked })}
				/>{" "}
				{t("sso.jit.enable")}
			</label>
			<label className="label" htmlFor="oidc-jit-domains">
				{t("sso.jit.domains")}
			</label>
			<input
				id="oidc-jit-domains"
				value={jitForm.domains}
				placeholder={verifiedDomains.join(", ") || "example.com"}
				onChange={(event) => setJitForm({ ...jitForm, domains: event.target.value })}
			/>
			<p className="muted small">{t("sso.jit.domainsHint")}</p>
			<label className="label" htmlFor="oidc-jit-default-role">
				{t("sso.jit.defaultRole")}
			</label>
			<select
				id="oidc-jit-default-role"
				value={jitForm.default_role}
				onChange={(event) => setJitForm({ ...jitForm, default_role: event.target.value })}
			>
				<option value="">{t("sso.jit.noDefault")}</option>
				<option value="viewer">{t("sso.jit.viewer")}</option>
				<option value="member">{t("sso.jit.member")}</option>
			</select>
			<label className="label" htmlFor="oidc-jit-mappings">
				{t("sso.jit.mappings")}
			</label>
			<textarea
				id="oidc-jit-mappings"
				rows={5}
				value={jitForm.mappings}
				// i18n-exempt: sample group claim values
				placeholder={"/aidr/admins=admin\n/aidr/users=member"}
				onChange={(event) => setJitForm({ ...jitForm, mappings: event.target.value })}
			/>
			<p className="muted small">{t("sso.jit.mappingsHint")}</p>
			{requireMappedGroups ? <p className="muted small">{t("sso.jit.groupModeHint")}</p> : null}
			<p className="muted small">{t("sso.jit.activeMembers", { count: jit.active_members })}</p>
			<button className="button" type="submit" disabled={busy || !hasProvider}>
				{t("sso.jit.save")}
			</button>
			{jit.removed_members.length > 0 ? (
				<>
					<h3>{t("sso.jit.removed")}</h3>
					<p className="muted small">{t("sso.jit.removedLead")}</p>
					<ul>
						{jit.removed_members.map((member) => {
							const label = member.email ?? member.user_id;
							return (
								<li key={member.user_id}>
									{label}{" "}
									<button
										type="button"
										className="button button-secondary"
										disabled={busy}
										onClick={() =>
											void run(async () => {
												await invoke({ action: "jit_readmit", user_id: member.user_id });
												return t("sso.jit.readmitted");
											})
										}
									>
										{t("sso.jit.readmit", { user: label })}
									</button>
								</li>
							);
						})}
					</ul>
				</>
			) : null}
		</form>
	);
}
