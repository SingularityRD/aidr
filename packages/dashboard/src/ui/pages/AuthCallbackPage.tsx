import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useRichT, useT } from "../../i18n/I18nProvider";
import { supabase } from "../../lib/supabase";
import { ShieldIcon } from "../icons";
import { bindInvitePending, clearInvitePending, markInvitePending } from "../invite-pending";
import { sanitizeReturnTo, takePostAuthReturnTo } from "../return-to";

/** Supabase `token_hash` values are URL-safe digests; anything else is never sent. */
const TOKEN_HASH = /^[A-Za-z0-9_-]{16,256}$/;

/** Fragment keys that carry (or claim to carry) an implicit-flow session. */
const FRAGMENT_SESSION_KEYS = ["access_token", "refresh_token", "provider_token", "type"];

const FRAGMENT_REJECTED = "fragment_session_rejected";

interface InviteMembership {
	workspace: string;
	role: string;
}

interface InviteConfirmation {
	email: string;
	memberships: InviteMembership[];
}

interface MembershipRow {
	role: string;
	teams: { name: string } | Array<{ name: string }> | null;
}

function scrubCallbackUrl() {
	const clean = new URL(window.location.href);
	clean.search = "";
	clean.hash = "";
	window.history.replaceState(window.history.state, "", clean.toString());
}

function missingCodeVerifier(error: unknown): boolean {
	return Boolean(
		error &&
			typeof error === "object" &&
			"code" in error &&
			error.code === "pkce_code_verifier_not_found",
	);
}

function callbackErrorKey(cause: unknown): DashboardMessageKey {
	if (missingCodeVerifier(cause)) return "cb.verifier";
	if (cause instanceof Error && cause.message === FRAGMENT_REJECTED) return "cb.fragment";
	return "cb.failed";
}

const ROLE_LABELS: Record<string, DashboardMessageKey> = {
	owner: "common.role.owner",
	admin: "common.role.admin",
	member: "common.role.member",
	viewer: "common.role.viewer",
	auditor: "common.role.auditor",
};

function roleLabel(role: string, t: Translate): string {
	const key = Object.hasOwn(ROLE_LABELS, role) ? ROLE_LABELS[role] : undefined;
	return key ? t(key) : role;
}

/** Sign out locally; the pending-invite gate is dropped only once that succeeded. */
async function discardInviteSession(): Promise<void> {
	try {
		const { error } = await supabase.auth.signOut({ scope: "local" });
		if (!error) clearInvitePending();
	} catch {
		// The gate stays armed, so readSession() keeps refusing this session.
	}
}

/**
 * Redeem a single-use invite `token_hash` server-side and describe what it grants.
 * The resulting session stays gated (see `invite-pending.ts`) until confirmed.
 */
async function verifyInvite(tokenHash: string): Promise<InviteConfirmation> {
	// Arm the gate before the session exists: until Continue is pressed,
	// readSession() treats the invite session as signed out.
	markInvitePending();
	const verified = await supabase.auth.verifyOtp({ type: "invite", token_hash: tokenHash });
	const session = verified.data.session;
	const user = verified.data.user ?? session?.user ?? null;
	if (verified.error || !session || !user || user.id !== session.user.id)
		throw new Error("invalid_invite");
	bindInvitePending(user.id);
	const memberships = await supabase
		.from("team_members")
		.select("role, teams!inner(name)")
		.eq("user_id", user.id)
		.order("joined_at", { ascending: false })
		.limit(20);
	if (memberships.error) throw new Error("invite_membership_unavailable");
	const rows = (memberships.data ?? []) as unknown as MembershipRow[];
	return {
		email: user.email ?? "",
		memberships: rows.flatMap((row) => {
			const team = Array.isArray(row.teams) ? row.teams[0] : row.teams;
			return team ? [{ workspace: team.name, role: row.role }] : [];
		}),
	};
}

export function AuthCallbackPage() {
	const t = useT();
	const richT = useRichT();
	const navigate = useNavigate();
	const [error, setError] = useState<DashboardMessageKey | null>(null);
	const [confirmation, setConfirmation] = useState<InviteConfirmation | null>(null);
	const [deciding, setDeciding] = useState(false);
	const started = useRef(false);
	const active = useRef(false);

	useEffect(() => {
		active.current = true;
		// StrictMode replays effects. The callback URL and its one-time code or
		// token hash must be consumed once, while the first exchange can still finish.
		if (started.current)
			return () => {
				active.current = false;
			};
		started.current = true;
		setError(null);

		function done() {
			const to = sanitizeReturnTo(takePostAuthReturnTo());
			if (active.current) navigate(to, { replace: true });
		}

		async function run() {
			let inviteAttempted = false;
			try {
				const callback = new URL(window.location.href);
				const code = callback.searchParams.get("code");
				const tokenHash = callback.searchParams.get("token_hash");
				const type = callback.searchParams.get("type");
				const fragment = new URLSearchParams(callback.hash.slice(1));
				scrubCallbackUrl();
				// Session tokens in the URL fragment are never accepted, for any
				// type: nothing binds them to this browser, so a link carrying
				// someone else's tokens would silently sign this browser into
				// their workspace (login CSRF / session fixation).
				if (FRAGMENT_SESSION_KEYS.some((key) => fragment.has(key))) {
					await supabase.auth.signOut({ scope: "local" });
					throw new Error(FRAGMENT_REJECTED);
				}
				if (tokenHash !== null || type !== null) {
					// Only invites use the server-verified, single-use token_hash flow.
					if (code || type !== "invite" || !tokenHash || !TOKEN_HASH.test(tokenHash)) {
						await supabase.auth.signOut({ scope: "local" });
						throw new Error("unsupported_callback");
					}
					inviteAttempted = true;
					const pending = await verifyInvite(tokenHash);
					if (active.current) setConfirmation(pending);
					return;
				}
				if (callback.hash.length > 1 || !code) {
					await supabase.auth.signOut({ scope: "local" });
					throw new Error("unsupported_callback");
				}
				const exchanged = await supabase.auth.exchangeCodeForSession(code);
				if (exchanged.error || !exchanged.data.session)
					throw exchanged.error ?? new Error("no_session");
				done();
			} catch (cause) {
				scrubCallbackUrl();
				if (inviteAttempted) await discardInviteSession();
				if (active.current) setError(callbackErrorKey(cause));
			}
		}

		void run();
		return () => {
			active.current = false;
		};
	}, [navigate]);

	function acceptInvite() {
		setDeciding(true);
		clearInvitePending();
		navigate(sanitizeReturnTo(takePostAuthReturnTo()), { replace: true });
	}

	async function cancelInvite() {
		setDeciding(true);
		await discardInviteSession();
		setConfirmation(null);
		if (active.current) navigate("/login", { replace: true });
	}

	if (confirmation) {
		return (
			<div className="auth-screen">
				<div className="auth-card" role="dialog" aria-labelledby="invite-confirm-title">
					<div className="auth-brand">
						<span className="brand-mark">
							<ShieldIcon size={26} />
						</span>
						<div>
							<h1 className="auth-title" id="invite-confirm-title">
								{t("cb.confirmTitle")}
							</h1>
							<p className="auth-subtitle">
								{richT("cb.signingInAs", {
									email: <strong>{confirmation.email || t("cb.thisAccount")}</strong>,
								})}
							</p>
						</div>
					</div>
					{confirmation.memberships.length > 0 ? (
						<ul className="notice" aria-label={t("cb.access")}>
							{confirmation.memberships.map((membership) => (
								<li key={`${membership.workspace}:${membership.role}`}>
									{richT("cb.joining", {
										workspace: <strong>{membership.workspace}</strong>,
										role: <strong>{roleLabel(membership.role, t)}</strong>,
									})}
								</li>
							))}
						</ul>
					) : (
						<div className="notice">{t("cb.noMembership")}</div>
					)}
					<p className="auth-subtitle">{t("cb.expected")}</p>
					<div
						className="row"
						style={{ marginTop: 14, flexWrap: "wrap", justifyContent: "center", gap: 8 }}
					>
						<button
							className="button button-secondary"
							type="button"
							disabled={deciding}
							onClick={() => void cancelInvite()}
						>
							{t("common.cancel")}
						</button>
						<button className="button" type="button" disabled={deciding} onClick={acceptInvite}>
							{t("cb.continue")}
						</button>
					</div>
				</div>
			</div>
		);
	}

	return (
		<div className="auth-screen">
			<div className="auth-card" role="status" aria-live="polite">
				<div className="auth-brand">
					<span className="brand-mark">
						<ShieldIcon size={26} />
					</span>
					<div>
						<h1 className="auth-title">{t("cb.signingIn")}</h1>
						<p className="auth-subtitle">{t("cb.completing")}</p>
					</div>
				</div>
				{error ? null : (
					<div className="row" style={{ justifyContent: "center" }}>
						<span className="spinner" aria-hidden="true" />
					</div>
				)}
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{t(error)}
					</div>
				) : null}
				{error ? (
					<div
						className="row"
						style={{ marginTop: 14, flexWrap: "wrap", justifyContent: "center" }}
					>
						<button
							className="button button-secondary"
							type="button"
							onClick={() => navigate("/login")}
						>
							{t("cb.return")}
						</button>
					</div>
				) : null}
			</div>
		</div>
	);
}
