import { useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { setPostAuthReturnTo } from "../ui/return-to";

/**
 * Outcome of the last action. Kept as a typed value rather than inferred from
 * the message text: the previous `status.includes("Failed") || status.includes("error")`
 * check styled any other failure — including a missing Edge Function — as a
 * neutral, success-looking notice.
 */
interface AuthStatus {
	tone: "success" | "error";
	message: string;
}

export function EnterpriseAuth() {
	const navigate = useNavigate();
	const routerLocation = useLocation();
	const [searchParams] = useSearchParams();
	const [status, setStatus] = useState<AuthStatus | null>(null);
	const [busy, setBusy] = useState(false);

	const returnTo = (searchParams.get("returnTo") ?? "/onboarding").trim();
	const inviteToken = (searchParams.get("invite") ?? "").trim();

	// A signed-out invitee has no session yet, so the invitation has to survive
	// the OAuth round trip. Without this the token was dropped on the way to the
	// provider and the "Accept Invitation" panel was gone when the user came
	// back — the invitation could never actually be accepted.
	const postAuthPath = inviteToken
		? `${routerLocation.pathname}?invite=${encodeURIComponent(inviteToken)}`
		: returnTo;

	async function signInWithProvider(provider: "github" | "gitlab") {
		setBusy(true);
		setStatus(null);

		try {
			if (postAuthPath) setPostAuthReturnTo(postAuthPath);

			const redirectTo = `${window.location.origin}/auth/callback`;
			const { error } = await supabase.auth.signInWithOAuth({
				provider,
				options: {
					redirectTo,
					scopes: provider === "github" ? "read:org" : "read_api",
				},
			});

			if (error) {
				setStatus({ tone: "error", message: error.message });
			}
		} catch (cause) {
			setStatus({
				tone: "error",
				message: readErrorMessage(cause, "Sign-in could not be started."),
			});
		} finally {
			setBusy(false);
		}
	}

	async function handleTeamInviteAccept(token: string) {
		setBusy(true);
		setStatus(null);

		try {
			const { data, error } = await supabase.functions.invoke("oauth-callback", {
				body: { invite_token: token },
			});

			if (error) {
				throw new Error(
					`the "oauth-callback" Edge Function is unavailable (${error.message}). The invitation was not accepted.`,
				);
			}

			const response = (data ?? null) as { ok?: unknown; error?: unknown } | null;
			if (response?.error) throw new Error(String(response.error));

			// Fail closed on an unconfirmed response: an empty 200 must not be
			// reported as an accepted invitation.
			if (response?.ok !== true) {
				throw new Error(
					'the "oauth-callback" Edge Function did not confirm the invitation (expected {"ok":true}). The invitation was not accepted.',
				);
			}

			setStatus({ tone: "success", message: "Team invitation accepted! Redirecting..." });
			setTimeout(() => navigate("/team"), 1500);
		} catch (err) {
			setStatus({ tone: "error", message: readErrorMessage(err, "Failed to accept invitation") });
		} finally {
			setBusy(false);
		}
	}

	return (
		<div className="card">
			<h1>Enterprise Sign In</h1>
			<p className="muted">
				Sign in with your GitHub or GitLab account to access team features. Organization sync is
				automatic.
			</p>

			<div className="row" style={{ flexDirection: "column", gap: "12px", marginTop: "20px" }}>
				<button
					className="button"
					type="button"
					disabled={busy}
					onClick={() => void signInWithProvider("github")}
					style={{
						background: "linear-gradient(180deg, #24292f, #1a1f24)",
						borderColor: "rgba(36, 41, 47, 0.5)",
					}}
				>
					<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor">
						<path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
					</svg>
					Continue with GitHub
				</button>

				<button
					className="button"
					type="button"
					disabled={busy}
					onClick={() => void signInWithProvider("gitlab")}
					style={{
						background: "linear-gradient(180deg, #fc6d26, #e24329)",
						borderColor: "rgba(252, 109, 38, 0.5)",
					}}
				>
					<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor">
						<path d="M15.97 9.058l-.895-2.756-.01-.024-1.8-5.552a.653.653 0 00-1.24 0l-1.8 5.552-.009.024-.895 2.756-.007.023-2.55 7.847a.653.653 0 001.043.74l3.045-2.344 3.044 2.344a.653.653 0 001.043-.74l-2.55-7.847-.007-.023zM11.9 6.303l1.115 3.434H10.77l1.13-3.434zm-3.8 0l1.13 3.434H6.97l1.13-3.434zm0-2.827l1.13 3.434H6.97l1.13-3.434zM5.052 9.737l.83-2.558.86 2.558H5.052zm3.111 4.713L5.527 11.42l2.636-2.03 2.636 2.03-2.636 2.03zm3.8-4.713l.86-2.558.83 2.558h-1.69z" />
					</svg>
					Continue with GitLab
				</button>
			</div>

			{/* Team invite acceptance */}
			{inviteToken && (
				<div
					style={{ marginTop: "24px", paddingTop: "20px", borderTop: "1px solid var(--border)" }}
				>
					<h3 style={{ marginTop: 0 }}>Team Invitation</h3>
					<p className="muted">
						You&apos;ve been invited to join a team. Accept the invitation to continue.
					</p>
					<button
						className="button"
						type="button"
						disabled={busy}
						onClick={() => void handleTeamInviteAccept(inviteToken)}
					>
						Accept Invitation
					</button>
				</div>
			)}

			{status && (
				<div
					className={`notice ${status.tone === "error" ? "notice-danger" : ""}`}
					role={status.tone === "error" ? "alert" : "status"}
					aria-live="assertive"
					style={{ marginTop: "16px" }}
				>
					{status.message}
				</div>
			)}

			<div style={{ marginTop: "20px", fontSize: "12px", color: "var(--muted)" }}>
				<p>
					By signing in, you agree to sync your organization membership. Only public organization
					data is accessed.
				</p>
			</div>
		</div>
	);
}
