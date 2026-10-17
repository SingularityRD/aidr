import { escapeHtml, type MailMessage } from "../_shared/mailer.ts";

const ROLE_LABELS: Record<string, string> = {
	admin: "Administrator",
	member: "Member",
	viewer: "Viewer",
	auditor: "Auditor (read-only)",
};

export interface InvitationEmailInput {
	to: string;
	workspaceName: string | null | undefined;
	role: string;
	inviteUrl: string;
	expiresAt: string;
	invitationId: string;
	/** SHA-256 of the invitation secret; used only to scope provider de-duplication. */
	tokenHash: string;
}

/** Collapse whitespace and drop control characters from display text. */
function displayText(value: string | null | undefined, fallback: string, max = 120): string {
	const cleaned = (value ?? "").replace(/\p{Cc}/gu, " ").replace(/\s+/g, " ").trim();
	if (cleaned === "") return fallback;
	return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

function expiryText(expiresAt: string): string {
	const parsed = Date.parse(expiresAt);
	return Number.isFinite(parsed) ? new Date(parsed).toUTCString() : "in 7 days";
}

/**
 * The invitation mail. The link is the only credential in the message; the
 * idempotency key is derived from the invitation id and a prefix of the
 * secret's DIGEST, so replaying the same send is de-duplicated while a resend
 * (new secret, new digest) is a new message.
 */
export function invitationEmail(input: InvitationEmailInput): MailMessage {
	const workspace = displayText(input.workspaceName, "an AIDR workspace");
	const role = ROLE_LABELS[input.role] ?? "Member";
	const expires = expiryText(input.expiresAt);
	const subject = `You're invited to join ${workspace} on Singularity AIDR`;
	const text = [
		`You have been invited to join ${workspace} on Singularity AIDR as ${role}.`,
		"",
		"Accept the invitation by opening this link and signing in with this email address:",
		input.inviteUrl,
		"",
		`The link works once and expires ${expires}.`,
		"If you did not expect this invitation, ignore this email; no account is created until the link is used.",
	].join("\n");
	const html = `<!doctype html>
<html lang="en">
<body style="margin:0;padding:24px;background:#f5f6f8;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1d2330">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:8px;border:1px solid #e3e6eb">
<tr><td style="padding:28px">
<h1 style="font-size:20px;margin:0 0 16px">Join ${escapeHtml(workspace)} on Singularity AIDR</h1>
<p style="margin:0 0 16px;line-height:1.5">You have been invited to join <strong>${escapeHtml(workspace)}</strong> as <strong>${escapeHtml(role)}</strong>.</p>
<p style="margin:0 0 24px"><a href="${escapeHtml(input.inviteUrl)}" style="display:inline-block;padding:10px 18px;background:#2d5bff;color:#ffffff;text-decoration:none;border-radius:6px">Accept invitation</a></p>
<p style="margin:0 0 8px;font-size:13px;color:#5b6475">Sign in with this email address. The link works once and expires ${escapeHtml(expires)}.</p>
<p style="margin:0 0 8px;font-size:13px;color:#5b6475;word-break:break-all">If the button does not work, open: ${escapeHtml(input.inviteUrl)}</p>
<p style="margin:16px 0 0;font-size:12px;color:#8a92a3">If you did not expect this invitation, ignore this email; no account is created until the link is used.</p>
</td></tr>
</table>
</body>
</html>`;
	return {
		to: input.to,
		subject,
		html,
		text,
		idempotencyKey: `team-invite/${input.invitationId}/${input.tokenHash.slice(0, 16)}`,
	};
}
