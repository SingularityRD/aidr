import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";

type ScimRole = "admin" | "member" | "viewer";
type ScimToken = {
	id: string;
	label: string;
	rotated_from: string | null;
	created_at: string;
	expires_at: string | null;
	revoked_at: string | null;
	last_used_at: string | null;
};
type GroupMapping = {
	external_group_id: string;
	role: ScimRole;
	created_by: string | null;
	created_at: string;
};
type TokenCursor = { created_at: string; id: string };
type ScimSnapshot = {
	tokens: ScimToken[];
	group_role_mappings: GroupMapping[];
	next_token_cursor: TokenCursor | null;
	next_mapping_cursor: string | null;
};
type OneTimeSecret = { value: string; label: string; expiresAt: string };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ALLOWED_ROLES = new Set<ScimRole>(["admin", "member", "viewer"]);
const SAFE_SCIM_ERRORS: Record<string, string> = {
	owner_required: "Only an active tenant owner can view or manage directory provisioning.",
	mapping_conflicts_with_manual_membership:
		"This group would take over a manually assigned team membership. Resolve that membership explicitly, then retry.",
	token_not_found_or_inactive:
		"The selected credential is no longer active. Refresh the list and retry.",
	token_not_found_or_revoked: "The credential is already revoked or no longer exists.",
	group_mapping_not_found: "The group mapping no longer exists. Refresh the list and retry.",
	scim_resource_conflict:
		"A conflicting directory resource already exists. Refresh the list and review it before retrying.",
	invalid_request:
		"The request was rejected. Check the selected role, label, and exact group identifier.",
	scim_management_unavailable:
		"Directory management is temporarily unavailable. No change was confirmed.",
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function parseToken(value: unknown): ScimToken | null {
	if (
		!isRecord(value) ||
		typeof value.id !== "string" ||
		!UUID.test(value.id) ||
		typeof value.label !== "string" ||
		typeof value.created_at !== "string" ||
		!Number.isFinite(Date.parse(value.created_at))
	)
		return null;
	const nullableString = (input: unknown): string | null =>
		typeof input === "string" ? input : null;
	const expiresAt = nullableString(value.expires_at);
	const revokedAt = nullableString(value.revoked_at);
	const lastUsedAt = nullableString(value.last_used_at);
	if (
		(expiresAt && !Number.isFinite(Date.parse(expiresAt))) ||
		(revokedAt && !Number.isFinite(Date.parse(revokedAt))) ||
		(lastUsedAt && !Number.isFinite(Date.parse(lastUsedAt)))
	)
		return null;
	return {
		id: value.id,
		label: value.label,
		rotated_from: nullableString(value.rotated_from),
		created_at: value.created_at,
		expires_at: expiresAt,
		revoked_at: revokedAt,
		last_used_at: lastUsedAt,
	};
}

function parseMapping(value: unknown): GroupMapping | null {
	if (
		!isRecord(value) ||
		typeof value.external_group_id !== "string" ||
		value.external_group_id.length < 1 ||
		value.external_group_id.length > 255 ||
		typeof value.role !== "string" ||
		!ALLOWED_ROLES.has(value.role as ScimRole) ||
		typeof value.created_at !== "string" ||
		!Number.isFinite(Date.parse(value.created_at))
	)
		return null;
	return {
		external_group_id: value.external_group_id,
		role: value.role as ScimRole,
		created_by: typeof value.created_by === "string" ? value.created_by : null,
		created_at: value.created_at,
	};
}

function parseSnapshot(value: unknown): ScimSnapshot {
	if (
		!isRecord(value) ||
		value.ok !== true ||
		!Array.isArray(value.tokens) ||
		!Array.isArray(value.group_role_mappings)
	)
		throw new Error("Directory management returned an invalid response.");
	const tokens = value.tokens.map(parseToken);
	const mappings = value.group_role_mappings.map(parseMapping);
	if (tokens.some((row) => row === null) || mappings.some((row) => row === null))
		throw new Error("Directory management returned an invalid record.");
	const rawTokenCursor = value.next_token_cursor;
	let nextTokenCursor: TokenCursor | null = null;
	if (rawTokenCursor !== null && rawTokenCursor !== undefined) {
		if (
			!isRecord(rawTokenCursor) ||
			typeof rawTokenCursor.id !== "string" ||
			!UUID.test(rawTokenCursor.id) ||
			typeof rawTokenCursor.created_at !== "string" ||
			!Number.isFinite(Date.parse(rawTokenCursor.created_at))
		)
			throw new Error("Directory management returned an invalid pagination cursor.");
		nextTokenCursor = { id: rawTokenCursor.id, created_at: rawTokenCursor.created_at };
	}
	const nextMappingCursor = value.next_mapping_cursor;
	if (
		nextMappingCursor !== null &&
		nextMappingCursor !== undefined &&
		(typeof nextMappingCursor !== "string" ||
			nextMappingCursor.length < 1 ||
			nextMappingCursor.length > 255)
	)
		throw new Error("Directory management returned an invalid pagination cursor.");
	return {
		tokens: tokens as ScimToken[],
		group_role_mappings: mappings as GroupMapping[],
		next_token_cursor: nextTokenCursor,
		next_mapping_cursor: typeof nextMappingCursor === "string" ? nextMappingCursor : null,
	};
}

async function responseError(error: unknown, data: unknown, fallback: string): Promise<string> {
	const getSafeCode = (value: unknown) =>
		isRecord(value) && typeof value.error === "string" ? SAFE_SCIM_ERRORS[value.error] : undefined;
	const direct = getSafeCode(data);
	if (direct) return direct;
	if (isRecord(error) && error.context instanceof Response) {
		try {
			const code = getSafeCode(await error.context.clone().json());
			if (code) return code;
		} catch {
			// Use only the fixed fallback; never surface raw function/server details.
		}
	}
	return readErrorMessage(error, fallback);
}

function mutationMayHaveCommitted(error: unknown): boolean {
	if (isRecord(error) && typeof error.scimMutationMayHaveCommitted === "boolean")
		return error.scimMutationMayHaveCommitted;
	if (!isRecord(error) || !isRecord(error.context) || typeof error.context.status !== "number")
		return true;
	return error.context.status < 400 || error.context.status >= 500;
}

function functionQuery(cursor?: { token: TokenCursor | null; mapping: string | null }): string {
	if (!cursor) return "";
	const params = new URLSearchParams();
	if (cursor.token) {
		params.set("token_after_created_at", cursor.token.created_at);
		params.set("token_after_id", cursor.token.id);
	}
	if (cursor.mapping) params.set("mapping_after_external_group_id", cursor.mapping);
	return params.toString();
}

function mergeBy<T>(previous: T[], next: T[], key: (item: T) => string): T[] {
	const rows = new Map(previous.map((row) => [key(row), row]));
	for (const row of next) rows.set(key(row), row);
	return [...rows.values()];
}

function isActiveToken(token: ScimToken): boolean {
	return !token.revoked_at && (!token.expires_at || Date.parse(token.expires_at) > Date.now());
}

function formatDate(value: string | null): string {
	return value ? new Date(value).toLocaleString() : "Never";
}

function validGroupId(value: string): boolean {
	return (
		value.length >= 1 &&
		value.length <= 255 &&
		value.trim() === value &&
		!/[\u0000-\u001f\u007f]/.test(value)
	);
}

export function ScimPage() {
	const { currentTeam, currentRole } = useTeam();
	if (!currentTeam)
		return <div className="card">Select a tenant to manage directory provisioning.</div>;
	return (
		<TenantScimPage
			key={currentTeam.tenant_id}
			tenantId={currentTeam.tenant_id}
			teamName={currentTeam.name}
			isOwner={currentRole === "owner"}
		/>
	);
}

function TenantScimPage({
	tenantId,
	teamName,
	isOwner,
}: {
	tenantId: string;
	teamName: string;
	isOwner: boolean;
}) {
	const [tokens, setTokens] = useState<ScimToken[]>([]);
	const [mappings, setMappings] = useState<GroupMapping[]>([]);
	const [tokenCursor, setTokenCursor] = useState<TokenCursor | null>(null);
	const [mappingCursor, setMappingCursor] = useState<string | null>(null);
	const cursors = useRef<{ token: TokenCursor | null; mapping: string | null }>({
		token: null,
		mapping: null,
	});
	const [tokenLabel, setTokenLabel] = useState("");
	const [groupId, setGroupId] = useState("");
	const [groupRole, setGroupRole] = useState<ScimRole>("viewer");
	const [secret, setSecret] = useState<OneTimeSecret | null>(null);
	const [showSecret, setShowSecret] = useState(false);
	const [copied, setCopied] = useState(false);
	const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
	const [confirmMappingRemoval, setConfirmMappingRemoval] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [loading, setLoading] = useState(true);
	const [loadingMore, setLoadingMore] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [notice, setNotice] = useState<string | null>(null);

	useEffect(() => {
		if (isOwner) return;
		setTokens([]);
		setMappings([]);
		setTokenCursor(null);
		setMappingCursor(null);
		cursors.current = { token: null, mapping: null };
		setSecret(null);
		setShowSecret(false);
		setCopied(false);
		setConfirmRevoke(null);
		setConfirmMappingRemoval(null);
	}, [isOwner]);

	const load = useCallback(
		async (append = false) => {
			if (!isOwner) return;
			if (append) setLoadingMore(true);
			else setLoading(true);
			setError(null);
			try {
				const query = functionQuery(append ? cursors.current : undefined);
				const { data, error: invokeError } = await supabase.functions.invoke<unknown>(
					query ? `scim-admin?${query}` : "scim-admin",
					{ method: "GET", headers: { "X-AIDR-Tenant-ID": tenantId } },
				);
				if (invokeError)
					throw new Error(
						await responseError(invokeError, data, "Unable to load directory settings."),
					);
				const snapshot = parseSnapshot(data);
				setTokens((previous) =>
					append ? mergeBy(previous, snapshot.tokens, (item) => item.id) : snapshot.tokens,
				);
				setMappings((previous) =>
					append
						? mergeBy(previous, snapshot.group_role_mappings, (item) => item.external_group_id)
						: snapshot.group_role_mappings,
				);
				cursors.current = {
					token: snapshot.next_token_cursor,
					mapping: snapshot.next_mapping_cursor,
				};
				setTokenCursor(snapshot.next_token_cursor);
				setMappingCursor(snapshot.next_mapping_cursor);
			} catch (cause) {
				setError(readErrorMessage(cause, "Unable to load directory settings."));
			} finally {
				setLoading(false);
				setLoadingMore(false);
			}
		},
		[isOwner, tenantId],
	);

	useEffect(() => {
		void load();
	}, [load]);

	async function invokeWrite(
		body: Record<string, unknown>,
		fallback: string,
	): Promise<Record<string, unknown>> {
		const { data, error: invokeError } = await supabase.functions.invoke<unknown>("scim-admin", {
			method: "POST",
			headers: { "X-AIDR-Tenant-ID": tenantId },
			body: { ...body, tenant_id: tenantId },
		});
		if (invokeError) {
			const message = await responseError(invokeError, data, fallback);
			throw Object.assign(new Error(message), {
				scimMutationMayHaveCommitted: mutationMayHaveCommitted(invokeError),
			});
		}
		if (!isRecord(data) || data.ok !== true)
			throw new Error(await responseError(null, data, fallback));
		return data;
	}

	async function createToken(action: "create_token" | "rotate_token", token?: ScimToken) {
		const label = tokenLabel.trim() || (token ? `${token.label} rotation`.slice(0, 120) : "");
		if (!label) {
			setError("Enter a descriptive credential label.");
			return;
		}
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			const body =
				action === "rotate_token" ? { action, token_id: token?.id, label } : { action, label };
			const data = await invokeWrite(body, "Credential creation was not confirmed.");
			if (
				typeof data.scim_token !== "string" ||
				!/^aidr_scim_[A-Za-z0-9_-]{43}$/.test(data.scim_token) ||
				typeof data.expires_at !== "string" ||
				!Number.isFinite(Date.parse(data.expires_at))
			)
				throw new Error("The credential service returned an invalid one-time secret response.");
			setSecret({ value: data.scim_token, label, expiresAt: data.expires_at });
			setShowSecret(false);
			setCopied(false);
			setTokenLabel("");
			setNotice(
				action === "rotate_token"
					? "Replacement created. The previous credential remains valid; verify the new secret with your provider, then revoke the old credential."
					: "Credential created. Copy it into your approved secret manager now; it cannot be shown again.",
			);
			await load();
		} catch (cause) {
			const message = readErrorMessage(cause, "Credential creation was not confirmed.");
			if (mutationMayHaveCommitted(cause)) {
				await load();
				setTokenLabel("");
				setError(
					`${message} The request may have reached AIDR before the connection failed. If a new active credential is listed but its secret was not shown, revoke it before retrying.`,
				);
			} else setError(message);
		} finally {
			setBusy(false);
		}
	}

	async function revokeToken(token: ScimToken) {
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			await invokeWrite(
				{ action: "revoke_token", token_id: token.id },
				"Credential revocation was not confirmed.",
			);
			setConfirmRevoke(null);
			setNotice("Credential revoked. Its secret can no longer provision directory changes.");
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, "Credential revocation was not confirmed."));
		} finally {
			setBusy(false);
		}
	}

	async function saveMapping(event: FormEvent) {
		event.preventDefault();
		if (!validGroupId(groupId)) {
			setError(
				"Enter the exact immutable SCIM Group.externalId (1–255 characters, without surrounding whitespace or control characters).",
			);
			return;
		}
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			await invokeWrite(
				{ action: "set_group_mapping", external_group_id: groupId, role: groupRole },
				"Group-role mapping was not confirmed.",
			);
			setGroupId("");
			setGroupRole("viewer");
			setNotice(
				"Group-role mapping saved. Only the exact immutable external ID is used; SCIM cannot grant owner.",
			);
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, "Group-role mapping was not confirmed."));
		} finally {
			setBusy(false);
		}
	}

	async function removeMapping(mapping: GroupMapping) {
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			await invokeWrite(
				{ action: "remove_group_mapping", external_group_id: mapping.external_group_id },
				"Group-role mapping removal was not confirmed.",
			);
			setConfirmMappingRemoval(null);
			setNotice(
				"Group-role mapping removed. SCIM-managed memberships were reconciled by the service.",
			);
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, "Group-role mapping removal was not confirmed."));
		} finally {
			setBusy(false);
		}
	}

	if (!isOwner)
		return (
			<div className="card">
				<h1>Directory provisioning</h1>
				<p className="muted">
					SCIM credentials and group-role mappings are available to active tenant owners only.
				</p>
			</div>
		);

	return (
		<div className="stack">
			<header className="card">
				<h1>Directory provisioning</h1>
				<p className="muted">
					Configure inbound SCIM for <strong>{teamName}</strong>. The service verifies owner access
					on every request.
				</p>
				<p className="muted small">
					SCIM provisioning does not enable SSO enforcement. Keep required SAML provider policy off
					until the separately documented dual-owner cutover and rollback procedure is complete.
				</p>
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

			<section className="card" aria-labelledby="scim-credentials-heading">
				<h2 id="scim-credentials-heading">Provisioning credentials</h2>
				<p className="muted">
					New credentials expire after 90 days by default. Rotation keeps the previous credential
					active until you verify the replacement and revoke the old one.
				</p>
				<label className="label" htmlFor="scim-token-label">
					Credential label
				</label>
				<input
					id="scim-token-label"
					className="input"
					maxLength={120}
					value={tokenLabel}
					onChange={(event) => setTokenLabel(event.target.value)}
					placeholder="Entra production"
					autoComplete="off"
				/>
				<div className="row" style={{ marginTop: 10 }}>
					<button
						className="button"
						type="button"
						disabled={busy || loading || Boolean(secret)}
						onClick={() => void createToken("create_token")}
					>
						Create credential
					</button>
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={() => void load()}
					>
						Refresh
					</button>
				</div>
				{secret ? (
					<div
						className="notice notice-warning"
						role="region"
						aria-labelledby="scim-secret-heading"
						style={{ marginTop: 14 }}
					>
						<h3 id="scim-secret-heading">Copy this credential now</h3>
						<p className="small">
							Shown once. Store it only in your approved secret manager and configure the IdP with
							that value. Expires {formatDate(secret.expiresAt)}.
						</p>
						<div className="row">
							<input
								className="input mono"
								style={{ flex: "1 1 280px" }}
								readOnly
								type={showSecret ? "text" : "password"}
								value={showSecret ? secret.value : "•".repeat(32)}
								aria-label="New SCIM credential"
								autoComplete="off"
							/>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => setShowSecret((value) => !value)}
							>
								{showSecret ? "Hide" : "Reveal"}
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={async () => {
									try {
										await navigator.clipboard.writeText(secret.value);
										setCopied(true);
									} catch {
										setError(
											"Clipboard access was blocked. Reveal the credential and copy it manually.",
										);
									}
								}}
							>
								{copied ? "Copied" : "Copy"}
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => {
									setSecret(null);
									setShowSecret(false);
									setCopied(false);
								}}
							>
								Clear secret
							</button>
						</div>
					</div>
				) : null}
				{loading ? (
					<p role="status">Loading credentials…</p>
				) : tokens.length === 0 ? (
					<p className="muted">No SCIM credentials have been issued.</p>
				) : (
					<div className="table-wrap" style={{ marginTop: 14 }}>
						<table className="table">
							<caption className="sr-only">SCIM provisioning credentials</caption>
							<thead>
								<tr>
									<th scope="col">Label</th>
									<th scope="col">Status</th>
									<th scope="col">Expires</th>
									<th scope="col">Last used</th>
									<th scope="col">Actions</th>
								</tr>
							</thead>
							<tbody>
								{tokens.map((token) => {
									const active = isActiveToken(token);
									return (
										<tr key={token.id}>
											<td>{token.label}</td>
											<td>{token.revoked_at ? "Revoked" : active ? "Active" : "Expired"}</td>
											<td>{formatDate(token.expires_at)}</td>
											<td>{formatDate(token.last_used_at)}</td>
											<td>
												<div className="row">
													{active ? (
														<button
															className="button button-secondary button-sm"
															type="button"
															disabled={busy || Boolean(secret)}
															onClick={() => void createToken("rotate_token", token)}
														>
															Rotate
														</button>
													) : null}
													{!token.revoked_at && confirmRevoke !== token.id ? (
														<button
															className="button button-danger button-sm"
															type="button"
															disabled={busy}
															onClick={() => setConfirmRevoke(token.id)}
														>
															Revoke
														</button>
													) : null}
													{confirmRevoke === token.id ? (
														<>
															<span className="small" role="status">
																Revoke permanently?
															</span>
															<button
																className="button button-danger button-sm"
																type="button"
																disabled={busy}
																onClick={() => void revokeToken(token)}
															>
																Confirm revoke
															</button>
															<button
																className="button button-secondary button-sm"
																type="button"
																disabled={busy}
																onClick={() => setConfirmRevoke(null)}
															>
																Cancel
															</button>
														</>
													) : null}
												</div>
											</td>
										</tr>
									);
								})}
							</tbody>
						</table>
					</div>
				)}
			</section>

			<section className="card" aria-labelledby="scim-mappings-heading">
				<h2 id="scim-mappings-heading">Group-to-role mappings</h2>
				<p className="muted">
					Use the exact immutable SCIM <code>Group.externalId</code>; display names and user
					metadata never grant roles. SCIM cannot grant owner.
				</p>
				<form onSubmit={(event) => void saveMapping(event)}>
					<label className="label" htmlFor="scim-external-group-id">
						Exact external group ID
					</label>
					<input
						id="scim-external-group-id"
						className="input mono"
						maxLength={255}
						value={groupId}
						onChange={(event) => setGroupId(event.target.value)}
						autoComplete="off"
						placeholder="Immutable Group.externalId"
					/>
					<label className="label" htmlFor="scim-group-role" style={{ marginTop: 10 }}>
						AIDR role
					</label>
					<select
						id="scim-group-role"
						className="input"
						value={groupRole}
						onChange={(event) => setGroupRole(event.target.value as ScimRole)}
					>
						<option value="admin">Admin</option>
						<option value="member">Member</option>
						<option value="viewer">Viewer</option>
					</select>
					<div className="row" style={{ marginTop: 10 }}>
						<button className="button" type="submit" disabled={busy || loading}>
							Save mapping
						</button>
						<button
							className="button button-secondary"
							type="button"
							disabled={busy}
							onClick={() => {
								setGroupId("");
								setGroupRole("viewer");
							}}
						>
							Clear
						</button>
					</div>
				</form>
				{loading ? (
					<p role="status">Loading mappings…</p>
				) : mappings.length === 0 ? (
					<p className="muted">No group-role mappings have been configured.</p>
				) : (
					<div className="table-wrap" style={{ marginTop: 14 }}>
						<table className="table">
							<caption className="sr-only">SCIM group-role mappings</caption>
							<thead>
								<tr>
									<th scope="col">Exact external group ID</th>
									<th scope="col">AIDR role</th>
									<th scope="col">Actions</th>
								</tr>
							</thead>
							<tbody>
								{mappings.map((mapping) => (
									<tr key={mapping.external_group_id}>
										<td className="mono" style={{ overflowWrap: "anywhere" }}>
											{mapping.external_group_id}
										</td>
										<td>{mapping.role}</td>
										<td>
											<div className="row">
												<button
													className="button button-secondary button-sm"
													type="button"
													disabled={busy}
													onClick={() => {
														setGroupId(mapping.external_group_id);
														setGroupRole(mapping.role);
														document.getElementById("scim-external-group-id")?.focus();
													}}
												>
													Edit
												</button>
												{confirmMappingRemoval !== mapping.external_group_id ? (
													<button
														className="button button-danger button-sm"
														type="button"
														disabled={busy}
														onClick={() => setConfirmMappingRemoval(mapping.external_group_id)}
													>
														Remove
													</button>
												) : (
													<>
														<span className="small" role="status">
															Remove mapping?
														</span>
														<button
															className="button button-danger button-sm"
															type="button"
															disabled={busy}
															onClick={() => void removeMapping(mapping)}
														>
															Confirm remove
														</button>
														<button
															className="button button-secondary button-sm"
															type="button"
															disabled={busy}
															onClick={() => setConfirmMappingRemoval(null)}
														>
															Cancel
														</button>
													</>
												)}
											</div>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</section>

			{tokenCursor || mappingCursor ? (
				<div className="row">
					<button
						className="button button-secondary"
						type="button"
						disabled={busy || loadingMore}
						onClick={() => void load(true)}
					>
						{loadingMore ? "Loading…" : "Load more"}
					</button>
				</div>
			) : null}
		</div>
	);
}
