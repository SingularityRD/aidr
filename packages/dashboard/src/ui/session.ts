import type { Session } from "@supabase/supabase-js";
import { supabase } from "../lib/supabase";
import { clearInvitePending, isInvitePending } from "./invite-pending";

/**
 * Client-side session lifetime.
 *
 * The dashboard previously configured nothing here: `getSession()` handed back
 * whatever the Supabase client had in storage, so a signed-in browser kept a
 * usable session until the deployment's JWT expired. This constant is the
 * dashboard's own idle bound. Expiry and explicit sign-out first arm the
 * server-side `identity_session_revocations` barrier, revoke refresh tokens,
 * then clear local state. Tenant RLS and the barrier stay authoritative.
 * Nothing in this repository proves the deployed Auth project has a short JWT
 * expiry, so the client must not rely on one.
 */
export const INACTIVITY_TIMEOUT_MS = 15 * 60_000;

/** How often an idle tab re-checks itself between user activity events. */
const WATCHDOG_INTERVAL_MS = 30_000;

const ACTIVITY_STORAGE_KEY = "aidr.session.activity.v1";

/**
 * Session state is a typed value, mirroring the `AuthStatus` convention in
 * `enterprise/auth.tsx`: callers switch on `state`, and no code decides "signed
 * out" or "still allowed" by matching on a message string.
 */
type SessionState = "active" | "signed_out" | "expired";

export interface SessionStatus {
	state: SessionState;
	/** Why the state is not "active"; `"none"` while the session is active. */
	reason: "none" | "no_session" | "inactivity";
	message: string;
}

export interface SessionSnapshot {
	status: SessionStatus;
	/** Null whenever `status.state` is not `"active"`. */
	session: Session | null;
}

const ACTIVE_STATUS: SessionStatus = {
	state: "active",
	reason: "none",
	message: "The session is active.",
};

function signedOutStatus(): SessionStatus {
	return {
		state: "signed_out",
		reason: "no_session",
		message: "No session is established. Sign in to continue.",
	};
}

function expiredStatus(): SessionStatus {
	return {
		state: "expired",
		reason: "inactivity",
		message: `The session ended after ${Math.round(INACTIVITY_TIMEOUT_MS / 60_000)} minutes of inactivity. Sign in again to continue.`,
	};
}

interface ActivityRecord {
	user_id: string;
	at: number;
}

let tabActivity: ActivityRecord | null = null;

function activityStorage(): Storage | null {
	try {
		return typeof window === "undefined" ? null : window.localStorage;
	} catch {
		// Storage can be blocked (private mode, disabled cookies): the idle
		// timeout then only survives for the lifetime of the tab.
		return null;
	}
}

function readActivity(): ActivityRecord | null {
	const storage = activityStorage();
	if (!storage) return tabActivity;
	try {
		const raw = storage.getItem(ACTIVITY_STORAGE_KEY);
		if (!raw) return tabActivity;
		const parsed: unknown = JSON.parse(raw);
		if (!parsed || typeof parsed !== "object") return null;
		const record = parsed as { user_id?: unknown; at?: unknown };
		if (typeof record.user_id !== "string" || typeof record.at !== "number") return null;
		if (!Number.isFinite(record.at)) return null;
		return { user_id: record.user_id, at: record.at };
	} catch {
		return tabActivity;
	}
}

function writeActivity(userId: string, at: number): void {
	tabActivity = { user_id: userId, at };
	const storage = activityStorage();
	if (!storage) return;
	try {
		storage.setItem(ACTIVITY_STORAGE_KEY, JSON.stringify({ user_id: userId, at }));
	} catch {
		// A full or unavailable store must not break sign-in.
	}
}

function clearActivity(): void {
	tabActivity = null;
	const storage = activityStorage();
	if (!storage) return;
	try {
		storage.removeItem(ACTIVITY_STORAGE_KEY);
	} catch {
		// Nothing to clear.
	}
}

async function revokeCurrentSession(): Promise<void> {
	const { data, error } = await supabase.functions.invoke("identity-security", {
		body: { action: "revoke_sessions", scope: "global" },
	});
	if (
		error ||
		!data ||
		typeof data !== "object" ||
		data.ok !== true ||
		data.scope !== "global" ||
		data.reauthentication_required !== true
	) {
		throw new Error("Session revocation could not be confirmed.");
	}
}

/** Keep the expired record until local sign-out succeeds, even during an outage. */
async function endIdleSession(): Promise<void> {
	try {
		await revokeCurrentSession();
	} catch {
		// The server barrier is best effort for an idle tab, but retaining the
		// browser credential would make the expired session usable again.
	} finally {
		try {
			const { error } = await supabase.auth.signOut({ scope: "local" });
			if (!error) clearActivity();
		} catch {
			// Retain the expired record until local credentials can be cleared.
		}
	}
}

/**
 * Read the session together with its typed state.
 *
 * A session whose recorded activity is older than the idle bound is ended here,
 * so reloading a page cannot resurrect it. `active` is the only state that ever
 * carries a session.
 */
export async function readSession(): Promise<SessionSnapshot> {
	const { data, error } = await supabase.auth.getSession();
	if (error) throw error;
	const session = data.session ?? null;
	const userId = session?.user?.id;
	if (!session || !userId) {
		clearActivity();
		return { status: signedOutStatus(), session: null };
	}
	if (isInvitePending(userId)) {
		// An invite link was verified but its workspace/role confirmation was
		// never accepted. That session must not reach a protected route.
		const { error: signOutError } = await supabase.auth.signOut({ scope: "local" });
		if (signOutError) throw signOutError;
		clearInvitePending();
		clearActivity();
		return { status: signedOutStatus(), session: null };
	}
	const record = readActivity();
	if (!record || record.user_id !== userId) {
		// First observation of this principal (fresh sign-in, or a different
		// account in the same browser): start the idle clock.
		writeActivity(userId, Date.now());
		return { status: ACTIVE_STATUS, session };
	}
	if (Date.now() - record.at > INACTIVITY_TIMEOUT_MS) {
		await endIdleSession();
		return { status: expiredStatus(), session: null };
	}
	return { status: ACTIVE_STATUS, session };
}

export async function getSession() {
	return (await readSession()).session;
}

export async function signOut(): Promise<{ serverRevoked: boolean }> {
	let serverRevoked = false;
	try {
		const current = await supabase.auth.getSession();
		if (current.error) throw new Error("Session revocation could not be confirmed.");
		if (current.data.session) await revokeCurrentSession();
		serverRevoked = true;
	} catch {
		// Local sign-out still proceeds. The caller reports unconfirmed server revocation.
	}

	let localError: unknown = null;
	try {
		const { error } = await supabase.auth.signOut({ scope: "local" });
		if (error) localError = error;
	} catch (error) {
		localError = error;
	} finally {
		clearActivity();
	}

	if (localError) throw localError;
	return { serverRevoked };
}

/**
 * Arm the idle watchdog for a signed-in tab.
 *
 * Returns a disposer. `onExpired` is called with the typed `expired` status
 * after the local session has been ended, so the caller can route back to
 * sign-in; it is never called for a session that is merely absent.
 */
export function installInactivityTimeout(onExpired: (status: SessionStatus) => void): () => void {
	if (typeof window === "undefined") return () => undefined;

	let currentUserId: string | null = null;
	let lastActivity = Date.now();
	let watching = true;
	let checking = false;

	const noteActivity = () => {
		if (!watching) return;
		const record = readActivity();
		const lastSeen = record && record.user_id === currentUserId ? record.at : lastActivity;
		// A suspended tab must expire before focus or input can extend its clock.
		if (currentUserId && Date.now() - lastSeen > INACTIVITY_TIMEOUT_MS) {
			void check();
			return;
		}
		lastActivity = Date.now();
		if (currentUserId) writeActivity(currentUserId, lastActivity);
	};

	const events: Array<keyof WindowEventMap> = [
		"pointerdown",
		"keydown",
		"wheel",
		"touchstart",
		"focus",
	];
	for (const event of events) window.addEventListener(event, noteActivity, { passive: true });

	const check = async () => {
		if (!watching || checking) return;
		checking = true;
		try {
			const { data, error } = await supabase.auth.getSession();
			if (error || !watching) return;
			const userId = data?.session?.user?.id ?? null;
			if (!userId) {
				currentUserId = null;
				return;
			}
			if (currentUserId !== userId) lastActivity = Date.now();
			currentUserId = userId;
			const record = readActivity();
			const lastSeen = record && record.user_id === userId ? record.at : lastActivity;
			if (!record || record.user_id !== userId) writeActivity(userId, lastSeen);
			if (Date.now() - lastSeen <= INACTIVITY_TIMEOUT_MS) return;
			await endIdleSession();
			currentUserId = null;
			if (watching) onExpired(expiredStatus());
		} catch {
			// A temporary Auth failure must not stop future idle checks.
		} finally {
			checking = false;
		}
	};

	// Resolve the current principal immediately so the very first user event is
	// recorded, and so a tab restored after the idle bound expires instead of
	// waiting a full watchdog interval.
	void check();
	const interval = window.setInterval(() => {
		void check();
	}, WATCHDOG_INTERVAL_MS);

	return () => {
		watching = false;
		window.clearInterval(interval);
		for (const event of events) window.removeEventListener(event, noteActivity);
	};
}
