import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
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

function callbackErrorMessage(cause: unknown): string {
	if (missingCodeVerifier(cause))
		return "Open the sign-in link in the browser where you requested it, or request a new link.";
	if (cause instanceof Error && cause.message === FRAGMENT_REJECTED)
		return "This sign-in link format is not accepted. Ask your administrator for a new invitation link.";
	return "Authentication could not be completed.";
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
		email: user.email ?? "this account",
		memberships: rows.flatMap((row) => {
			const team = Array.isArray(row.teams) ? row.teams[0] : row.teams;
			return team ? [{ workspace: team.name, role: row.role }] : [];
		}),
	};
}

export function AuthCallbackPage() {
	const navigate = useNavigate();
	const [error, setError] = useState<string | null>(null);
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
				if (active.current) setError(callbackErrorMessage(cause));
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
								Confirm invitation
							</h1>
							<p className="auth-subtitle">
								You are signing in as <strong>{confirmation.email}</strong>.
							</p>
						</div>
					</div>
					{confirmation.memberships.length > 0 ? (
						<ul className="notice" aria-label="Workspace access">
							{confirmation.memberships.map((membership) => (
								<li key={`${membership.workspace}:${membership.role}`}>
									You are joining workspace <strong>{membership.workspace}</strong> as role{" "}
									<strong>{membership.role}</strong>.
								</li>
							))}
						</ul>
					) : (
						<div className="notice">No workspace membership is attached to this account yet.</div>
					)}
					<p className="auth-subtitle">
						Continue only if you expected this invitation. If you did not, cancel and this browser
						will be signed out.
					</p>
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
							Cancel
						</button>
						<button className="button" type="button" disabled={deciding} onClick={acceptInvite}>
							Continue
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
						<h1 className="auth-title">Signing in…</h1>
						<p className="auth-subtitle">Completing Supabase authentication.</p>
					</div>
				</div>
				{error ? null : (
					<div className="row" style={{ justifyContent: "center" }}>
						<span className="spinner" aria-hidden="true" />
					</div>
				)}
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
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
							Return to sign in
						</button>
					</div>
				) : null}
			</div>
		</div>
	);
}
