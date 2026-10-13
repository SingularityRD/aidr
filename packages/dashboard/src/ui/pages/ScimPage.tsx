import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useRichT, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
import {
	type DirectoryAuthority,
	DirectoryAuthorityPanel,
	type DirectoryAuthorityRequest,
} from "./DirectoryAuthorityPanel";
import { SamlPolicyPanel } from "./SamlPolicyPanel";

type ScimRole = "admin" | "member" | "viewer";
type ScimToken = {
	id: string;
	label: string;
	rotated_from: string | null;
	created_at: string;
	expires_at: string | null;
	revoked_at: string | null;
	last_used_at: string | null;
	/** NULL only for legacy credentials issued before directory binding. */
	directory_id: string | null;
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
	directory_authority: DirectoryAuthority;
};
type OneTimeSecret = { value: string; label: string; expiresAt: string };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
// Matches the scim_tokens.directory_id database check constraint.
const DIRECTORY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ALLOWED_ROLES = new Set<ScimRole>(["admin", "member", "viewer"]);
const AUTHORITY_OFF: DirectoryAuthority = {
	enabled: false,
	directory_id: null,
	break_glass_user_ids: [],
};
const SAFE_SCIM_ERRORS: Record<string, DashboardMessageKey> = {
	owner_required: "scim.err.owner",
	mfa_required: "saml.err.mfa",
	scim_admin_directory_required: "scim.err.directoryRequired",
	scim_admin_directory_mismatch: "scim.err.directoryMismatch",
	scim_admin_directory_not_authoritative: "scim.err.notAuthoritative",
	directory_authority_already_enabled: "scim.err.alreadyOn",
	directory_authority_directory_token_required: "scim.err.tokenRequired",
	directory_authority_foreign_token_active: "scim.err.foreignToken",
	directory_authority_adoption_ambiguous: "scim.err.adoptionAmbiguous",
	directory_authority_break_glass_mismatch: "scim.err.breakGlassMismatch",
	directory_authority_break_glass_invalid: "scim.err.breakGlassInvalid",
	directory_authority_would_remove_all_administrators: "scim.err.noAdmins",
	directory_authority_tenant_unsupported: "scim.err.unsupported",
	directory_authority_membership_required: "scim.err.membershipRequired",
	directory_authority_break_glass_owner_required: "scim.err.breakGlassOwner",
	assurance_unavailable: "scim.err.assurance",
	mapping_conflicts_with_manual_membership: "scim.err.manualConflict",
	token_not_found_or_inactive: "scim.err.tokenInactive",
	token_not_found_or_revoked: "scim.err.tokenRevoked",
	group_mapping_not_found: "scim.err.mappingMissing",
	scim_resource_conflict: "scim.err.conflict",
	invalid_request: "scim.err.invalid",
	scim_management_unavailable: "scim.err.unavailable",
};

const ROLE_LABELS: Record<ScimRole, DashboardMessageKey> = {
	admin: "common.role.admin",
	member: "common.role.member",
	viewer: "common.role.viewer",
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
		directory_id:
			typeof value.directory_id === "string" && DIRECTORY_ID.test(value.directory_id)
				? value.directory_id
				: null,
	};
}

function parseAuthority(value: unknown, t: Translate): DirectoryAuthority {
	// Older deployments omit the field; the mode does not exist there (off).
	if (value === undefined) return AUTHORITY_OFF;
	if (
		!isRecord(value) ||
		typeof value.enabled !== "boolean" ||
		!(
			value.directory_id === null ||
			(typeof value.directory_id === "string" && DIRECTORY_ID.test(value.directory_id))
		) ||
		!Array.isArray(value.break_glass_owners) ||
		(value.enabled && value.directory_id === null)
	)
		throw new Error(t("scim.err.invalidMode"));
	const owners = value.break_glass_owners.map((row) =>
		isRecord(row) && typeof row.user_id === "string" && UUID.test(row.user_id) ? row.user_id : null,
	);
	if (owners.some((id) => id === null)) throw new Error(t("scim.err.invalidMode"));
	return {
		enabled: value.enabled,
		directory_id: value.directory_id as string | null,
		break_glass_user_ids: owners as string[],
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

function parseSnapshot(value: unknown, t: Translate): ScimSnapshot {
	if (
		!isRecord(value) ||
		value.ok !== true ||
		!Array.isArray(value.tokens) ||
		!Array.isArray(value.group_role_mappings)
	)
		throw new Error(t("scim.err.invalidResponse"));
	const tokens = value.tokens.map(parseToken);
	const mappings = value.group_role_mappings.map(parseMapping);
	if (tokens.some((row) => row === null) || mappings.some((row) => row === null))
		throw new Error(t("scim.err.invalidRecord"));
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
			throw new Error(t("scim.err.invalidCursor"));
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
		throw new Error(t("scim.err.invalidCursor"));
	return {
		tokens: tokens as ScimToken[],
		group_role_mappings: mappings as GroupMapping[],
		next_token_cursor: nextTokenCursor,
		next_mapping_cursor: typeof nextMappingCursor === "string" ? nextMappingCursor : null,
		directory_authority: parseAuthority(value.directory_authority, t),
	};
}

async function responseError(
	error: unknown,
	data: unknown,
	fallback: string,
	t: Translate,
): Promise<string> {
	const getSafeCode = (value: unknown) => {
		if (!isRecord(value) || typeof value.error !== "string") return undefined;
		if (value.error === "directory_authority_unmanaged_members") {
			const count = value.unmanaged_member_count;
			if (typeof count !== "number" || !Number.isSafeInteger(count) || count <= 0)
				return t("scim.err.unmanagedSome");
			return count === 1 ? t("scim.err.unmanagedOne") : t("scim.err.unmanagedMany", { count });
		}
		const key = Object.hasOwn(SAFE_SCIM_ERRORS, value.error)
			? SAFE_SCIM_ERRORS[value.error]
			: undefined;
		return key ? t(key) : undefined;
	};
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

function formatDate(value: string | null, t: Translate): string {
	return value ? new Date(value).toLocaleString() : t("scim.never");
}

/**
 * The directory_id to send: a new credential always names its directory, a
 * rotation inherits it, and only an unbound legacy credential is bound by an
 * entered value. `null` = send none; `undefined` = the entered value is invalid.
 */
function tokenDirectory(
	action: "create_token" | "rotate_token",
	token: ScimToken | undefined,
	entered: string,
): string | null | undefined {
	const directory = entered.trim();
	const binds = action === "create_token" || (token?.directory_id === null && directory !== "");
	if (!binds) return null;
	return DIRECTORY_ID.test(directory) ? directory : undefined;
}

function tokenRequestBody(
	action: "create_token" | "rotate_token",
	token: ScimToken | undefined,
	label: string,
	directory: string | null,
): Record<string, unknown> {
	const base =
		action === "rotate_token" ? { action, token_id: token?.id, label } : { action, label };
	return directory === null ? base : { ...base, directory_id: directory };
}

function directoryLabel(token: ScimToken, t: Translate): string {
	return token.directory_id ?? t("scim.unbound");
}

function enabledNotice(directoryId: string, removedCount: unknown, t: Translate): string {
	const removed = typeof removedCount === "number" ? removedCount : 0;
	const removal =
		removed > 0
			? removed === 1
				? t("scim.removedOne")
				: t("scim.removedMany", { count: removed })
			: "";
	return t("scim.enabledNotice", { directory: directoryId, removal });
}

function activeDirectories(tokens: ScimToken[]): string[] {
	const ids = new Set<string>();
	for (const token of tokens)
		if (token.directory_id && isActiveToken(token)) ids.add(token.directory_id);
	return [...ids].sort();
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
	const t = useT();
	const { currentTeam, currentRole, currentUserId, members } = useTeam();
	if (!currentTeam) return <div className="card">{t("scim.selectTenant")}</div>;
	const owners = (members ?? [])
		.filter((member) => member.role === "owner")
		.map((member) => ({ userId: member.user_id, email: member.email }));
	return (
		<TenantScimPage
			key={currentTeam.tenant_id}
			tenantId={currentTeam.tenant_id}
			teamName={currentTeam.name}
			isOwner={currentRole === "owner"}
			currentUserId={currentUserId}
			owners={owners}
		/>
	);
}

function TenantScimPage({
	tenantId,
	teamName,
	isOwner,
	currentUserId,
	owners,
}: {
	tenantId: string;
	teamName: string;
	isOwner: boolean;
	currentUserId: string;
	owners: { userId: string; email: string }[];
}) {
	const t = useT();
	const richT = useRichT();
	// The loader reads the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
	const [tokens, setTokens] = useState<ScimToken[]>([]);
	const [mappings, setMappings] = useState<GroupMapping[]>([]);
	const [authority, setAuthority] = useState<DirectoryAuthority>(AUTHORITY_OFF);
	const [directoryId, setDirectoryId] = useState("");
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
		setAuthority(AUTHORITY_OFF);
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
			const t = translator.current;
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
					throw new Error(await responseError(invokeError, data, t("scim.loadFailed"), t));
				const snapshot = parseSnapshot(data, t);
				setTokens((previous) =>
					append ? mergeBy(previous, snapshot.tokens, (item) => item.id) : snapshot.tokens,
				);
				setMappings((previous) =>
					append
						? mergeBy(previous, snapshot.group_role_mappings, (item) => item.external_group_id)
						: snapshot.group_role_mappings,
				);
				setAuthority(snapshot.directory_authority);
				cursors.current = {
					token: snapshot.next_token_cursor,
					mapping: snapshot.next_mapping_cursor,
				};
				setTokenCursor(snapshot.next_token_cursor);
				setMappingCursor(snapshot.next_mapping_cursor);
			} catch (cause) {
				setError(readErrorMessage(cause, t("scim.loadFailed")));
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
			const message = await responseError(invokeError, data, fallback, t);
			throw Object.assign(new Error(message), {
				scimMutationMayHaveCommitted: mutationMayHaveCommitted(invokeError),
			});
		}
		if (!isRecord(data) || data.ok !== true)
			throw new Error(await responseError(null, data, fallback, t));
		return data;
	}

	async function createToken(action: "create_token" | "rotate_token", token?: ScimToken) {
		const label = tokenLabel.trim() || (token ? `${token.label} rotation`.slice(0, 120) : "");
		if (!label) {
			setError(t("scim.labelRequired"));
			return;
		}
		const directory = tokenDirectory(action, token, directoryId);
		if (directory === undefined) {
			setError(t("scim.invalidDirectory"));
			return;
		}
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			const data = await invokeWrite(
				tokenRequestBody(action, token, label, directory),
				t("scim.createUnconfirmed"),
			);
			if (
				typeof data.scim_token !== "string" ||
				!/^aidr_scim_[A-Za-z0-9_-]{43}$/.test(data.scim_token) ||
				typeof data.expires_at !== "string" ||
				!Number.isFinite(Date.parse(data.expires_at))
			)
				throw new Error(t("scim.invalidSecret"));
			setSecret({ value: data.scim_token, label, expiresAt: data.expires_at });
			setShowSecret(false);
			setCopied(false);
			setTokenLabel("");
			setNotice(action === "rotate_token" ? t("scim.rotated") : t("scim.created"));
			await load();
		} catch (cause) {
			const message = readErrorMessage(cause, t("scim.createUnconfirmed"));
			if (mutationMayHaveCommitted(cause)) {
				await load();
				setTokenLabel("");
				setError(t("scim.mayHaveCommitted", { message }));
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
				t("scim.revokeUnconfirmed"),
			);
			setConfirmRevoke(null);
			setNotice(t("scim.revoked"));
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, t("scim.revokeUnconfirmed")));
		} finally {
			setBusy(false);
		}
	}

	async function changeAuthority(request: DirectoryAuthorityRequest): Promise<boolean> {
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			if (request.action === "enable") {
				const data = await invokeWrite(
					{
						action: "enable_directory_authority",
						directory_id: request.directoryId,
						break_glass_user_ids: request.breakGlassUserIds,
						adopt_existing_memberships: request.adoptExisting,
						remove_unmanaged_members: request.removeUnmanaged,
					},
					t("scim.enableUnconfirmed"),
				);
				setNotice(enabledNotice(request.directoryId, data.removed_count, t));
			} else {
				await invokeWrite({ action: "disable_directory_authority" }, t("scim.disableUnconfirmed"));
				setNotice(t("scim.disabled"));
			}
			await load();
			return true;
		} catch (cause) {
			const message = readErrorMessage(cause, t("scim.modeUnconfirmed"));
			if (mutationMayHaveCommitted(cause)) {
				await load();
				setError(t("scim.modeMayHaveChanged", { message }));
			} else setError(message);
			return false;
		} finally {
			setBusy(false);
		}
	}

	async function saveMapping(event: FormEvent) {
		event.preventDefault();
		if (!validGroupId(groupId)) {
			setError(t("scim.badGroup"));
			return;
		}
		setBusy(true);
		setError(null);
		setNotice(null);
		try {
			await invokeWrite(
				{ action: "set_group_mapping", external_group_id: groupId, role: groupRole },
				t("scim.mappingUnconfirmed"),
			);
			setGroupId("");
			setGroupRole("viewer");
			setNotice(t("scim.mappingSaved"));
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, t("scim.mappingUnconfirmed")));
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
				t("scim.removeUnconfirmed"),
			);
			setConfirmMappingRemoval(null);
			setNotice(t("scim.mappingRemoved"));
			await load();
		} catch (cause) {
			setError(readErrorMessage(cause, t("scim.removeUnconfirmed")));
		} finally {
			setBusy(false);
		}
	}

	if (!isOwner)
		return (
			<div className="card">
				<h1>{t("scim.title")}</h1>
				<p className="muted">{t("scim.ownersOnly")}</p>
			</div>
		);

	return (
		<div className="stack">
			<header className="card">
				<h1>{t("scim.title")}</h1>
				<p className="muted">{richT("scim.lead", { team: <strong>{teamName}</strong> })}</p>
				<p className="muted small">{t("scim.leadSaml")}</p>
			</header>

			<SamlPolicyPanel key={currentUserId} tenantId={tenantId} currentUserId={currentUserId} />

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
				<h2 id="scim-credentials-heading">{t("scim.credentials")}</h2>
				<p className="muted">{t("scim.credentialsLead")}</p>
				<label className="label" htmlFor="scim-token-label">
					{t("scim.credentialLabel")}
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
				<label className="label" htmlFor="scim-directory-id" style={{ marginTop: 10 }}>
					{t("scim.directoryId")}
				</label>
				<input
					id="scim-directory-id"
					className="input mono"
					maxLength={128}
					value={directoryId}
					onChange={(event) => setDirectoryId(event.target.value)}
					placeholder="entra-production"
					autoComplete="off"
					aria-describedby="scim-directory-id-help"
				/>
				<p id="scim-directory-id-help" className="muted small">
					{t("scim.directoryHelp")}
				</p>
				<div className="row" style={{ marginTop: 10 }}>
					<button
						className="button"
						type="button"
						disabled={busy || loading || Boolean(secret)}
						onClick={() => void createToken("create_token")}
					>
						{t("scim.create")}
					</button>
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={() => void load()}
					>
						{t("common.refresh")}
					</button>
				</div>
				{secret ? (
					<div
						className="notice notice-warning"
						role="region"
						aria-labelledby="scim-secret-heading"
						style={{ marginTop: 14 }}
					>
						<h3 id="scim-secret-heading">{t("scim.copyNow")}</h3>
						<p className="small">
							{t("scim.shownOnce", { time: formatDate(secret.expiresAt, t) })}
						</p>
						<div className="row">
							<input
								className="input mono"
								style={{ flex: "1 1 280px" }}
								readOnly
								type={showSecret ? "text" : "password"}
								value={showSecret ? secret.value : "•".repeat(32)}
								aria-label={t("scim.newCredential")}
								autoComplete="off"
							/>
							<button
								className="button button-secondary"
								type="button"
								onClick={() => setShowSecret((value) => !value)}
							>
								{showSecret ? t("scim.hide") : t("scim.reveal")}
							</button>
							<button
								className="button button-secondary"
								type="button"
								onClick={async () => {
									try {
										await navigator.clipboard.writeText(secret.value);
										setCopied(true);
									} catch {
										setError(t("scim.clipboard"));
									}
								}}
							>
								{copied ? t("scim.copied") : t("scim.copy")}
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
								{t("scim.clearSecret")}
							</button>
						</div>
					</div>
				) : null}
				{loading ? (
					<p role="status">{t("scim.loadingCredentials")}</p>
				) : tokens.length === 0 ? (
					<p className="muted">{t("scim.noCredentials")}</p>
				) : (
					<div className="table-wrap" style={{ marginTop: 14 }}>
						<table className="table">
							<caption className="sr-only">{t("scim.credentialsCaption")}</caption>
							<thead>
								<tr>
									<th scope="col">{t("scim.col.label")}</th>
									<th scope="col">{t("common.status")}</th>
									<th scope="col">{t("scim.col.directory")}</th>
									<th scope="col">{t("scim.col.expires")}</th>
									<th scope="col">{t("scim.col.lastUsed")}</th>
									<th scope="col">{t("scim.col.actions")}</th>
								</tr>
							</thead>
							<tbody>
								{tokens.map((token) => {
									const active = isActiveToken(token);
									return (
										<tr key={token.id}>
											<td>{token.label}</td>
											<td>
												{token.revoked_at
													? t("scim.revokedState")
													: active
														? t("scim.activeState")
														: t("scim.expiredState")}
											</td>
											<td className="mono">{directoryLabel(token, t)}</td>
											<td>{formatDate(token.expires_at, t)}</td>
											<td>{formatDate(token.last_used_at, t)}</td>
											<td>
												<div className="row">
													{active ? (
														<button
															className="button button-secondary button-sm"
															type="button"
															disabled={busy || Boolean(secret)}
															onClick={() => void createToken("rotate_token", token)}
														>
															{t("scim.rotate")}
														</button>
													) : null}
													{!token.revoked_at && confirmRevoke !== token.id ? (
														<button
															className="button button-danger button-sm"
															type="button"
															disabled={busy}
															onClick={() => setConfirmRevoke(token.id)}
														>
															{t("scim.revoke")}
														</button>
													) : null}
													{confirmRevoke === token.id ? (
														<>
															<span className="small" role="status">
																{t("scim.revokeConfirm")}
															</span>
															<button
																className="button button-danger button-sm"
																type="button"
																disabled={busy}
																onClick={() => void revokeToken(token)}
															>
																{t("scim.confirmRevoke")}
															</button>
															<button
																className="button button-secondary button-sm"
																type="button"
																disabled={busy}
																onClick={() => setConfirmRevoke(null)}
															>
																{t("common.cancel")}
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
				<h2 id="scim-mappings-heading">{t("scim.mappings")}</h2>
				<p className="muted">
					{richT("scim.mappingsLead", { field: <code>Group.externalId</code> })}
				</p>
				<form onSubmit={(event) => void saveMapping(event)}>
					<label className="label" htmlFor="scim-external-group-id">
						{t("scim.groupId")}
					</label>
					<input
						id="scim-external-group-id"
						className="input mono"
						maxLength={255}
						value={groupId}
						onChange={(event) => setGroupId(event.target.value)}
						autoComplete="off"
						placeholder={t("scim.groupPlaceholder")}
					/>
					<label className="label" htmlFor="scim-group-role" style={{ marginTop: 10 }}>
						{t("scim.role")}
					</label>
					<select
						id="scim-group-role"
						className="input"
						value={groupRole}
						onChange={(event) => setGroupRole(event.target.value as ScimRole)}
					>
						<option value="admin">{t("common.role.admin")}</option>
						<option value="member">{t("common.role.member")}</option>
						<option value="viewer">{t("common.role.viewer")}</option>
					</select>
					<div className="row" style={{ marginTop: 10 }}>
						<button className="button" type="submit" disabled={busy || loading}>
							{t("scim.saveMapping")}
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
							{t("scim.clear")}
						</button>
					</div>
				</form>
				{loading ? (
					<p role="status">{t("scim.loadingMappings")}</p>
				) : mappings.length === 0 ? (
					<p className="muted">{t("scim.noMappings")}</p>
				) : (
					<div className="table-wrap" style={{ marginTop: 14 }}>
						<table className="table">
							<caption className="sr-only">{t("scim.mappingsCaption")}</caption>
							<thead>
								<tr>
									<th scope="col">{t("scim.groupId")}</th>
									<th scope="col">{t("scim.role")}</th>
									<th scope="col">{t("scim.col.actions")}</th>
								</tr>
							</thead>
							<tbody>
								{mappings.map((mapping) => (
									<tr key={mapping.external_group_id}>
										<td className="mono" style={{ overflowWrap: "anywhere" }}>
											{mapping.external_group_id}
										</td>
										<td>{t(ROLE_LABELS[mapping.role])}</td>
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
													{t("scim.edit")}
												</button>
												{confirmMappingRemoval !== mapping.external_group_id ? (
													<button
														className="button button-danger button-sm"
														type="button"
														disabled={busy}
														onClick={() => setConfirmMappingRemoval(mapping.external_group_id)}
													>
														{t("scim.remove")}
													</button>
												) : (
													<>
														<span className="small" role="status">
															{t("scim.removeConfirm")}
														</span>
														<button
															className="button button-danger button-sm"
															type="button"
															disabled={busy}
															onClick={() => void removeMapping(mapping)}
														>
															{t("scim.confirmRemove")}
														</button>
														<button
															className="button button-secondary button-sm"
															type="button"
															disabled={busy}
															onClick={() => setConfirmMappingRemoval(null)}
														>
															{t("common.cancel")}
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
						{loadingMore ? t("common.loading") : t("scim.loadMore")}
					</button>
				</div>
			) : null}

			<DirectoryAuthorityPanel
				authority={authority}
				directories={activeDirectories(tokens)}
				owners={owners}
				currentUserId={currentUserId}
				busy={busy || loading}
				onChange={changeAuthority}
			/>
		</div>
	);
}
