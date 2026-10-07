/**
 * Marker for an Auth invite that has been verified but not yet confirmed.
 *
 * `verifyOtp({ type: "invite" })` persists a session before the person has
 * seen which account and workspace the link belongs to. Until they press
 * Continue, that session must not be usable: `readSession()` signs out any
 * session whose user still carries this marker, so closing the tab on the
 * confirmation screen cannot leave the browser signed into someone else's
 * workspace.
 */
const KEY = "aidr.auth.invite.unconfirmed.v1";

/** Throws when the marker cannot be stored; the caller must then not verify. */
export function markInvitePending(): void {
	window.localStorage.setItem(KEY, "*");
}

/** Bind the marker to the verified user. Throws when storage is unavailable. */
export function bindInvitePending(userId: string): void {
	window.localStorage.setItem(KEY, userId);
}

export function clearInvitePending(): void {
	try {
		window.localStorage.removeItem(KEY);
	} catch {
		// Nothing was stored, so nothing can gate a later session.
	}
}

/** True when the session of `userId` came from an invite the person has not confirmed. */
export function isInvitePending(userId: string): boolean {
	try {
		const value = window.localStorage.getItem(KEY);
		return value === "*" || value === userId;
	} catch {
		return false;
	}
}
