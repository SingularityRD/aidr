import type { Session } from "@supabase/supabase-js";
import { supabase } from "../lib/supabase";

/**
 * Client-side session lifetime.
 *
 * The dashboard previously configured nothing here: `getSession()` handed back
 * whatever the Supabase client had in storage, so a signed-in browser kept a
 * usable session until the deployment's JWT expired. This constant is the
 * dashboard's own idle bound and only ends the local session; it complements —
 * and never replaces — the deployment's server-side JWT expiry, the
 * `identity_session_revocations` barrier and the tenant RLS policies, which stay
 * authoritative. Nothing in this repository proves the deployed Auth project has
 * a short JWT expiry, so the client must not rely on one.
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
export type SessionState = "active" | "signed_out" | "expired";

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
	if (!storage) return null;
	try {
		const raw = storage.getItem(ACTIVITY_STORAGE_KEY);
		if (!raw) return null;
		const parsed: unknown = JSON.parse(raw);
		if (!parsed || typeof parsed !== "object") return null;
		const record = parsed as { user_id?: unknown; at?: unknown };
		if (typeof record.user_id !== "string" || typeof record.at !== "number") return null;
		if (!Number.isFinite(record.at)) return null;
		return { user_id: record.user_id, at: record.at };
	} catch {
		return null;
	}
}

function writeActivity(userId: string, at: number): void {
	const storage = activityStorage();
	if (!storage) return;
	try {
		storage.setItem(ACTIVITY_STORAGE_KEY, JSON.stringify({ user_id: userId, at }));
	} catch {
		// A full or unavailable store must not break sign-in.
	}
}

function clearActivity(): void {
	const storage = activityStorage();
	if (!storage) return;
	try {
		storage.removeItem(ACTIVITY_STORAGE_KEY);
	} catch {
		// Nothing to clear.
	}
}

/**
 * End an idle session. The activity record is only cleared once the sign-out is
 * acknowledged: if the client cannot sign out, the stale record must survive so
 * the next read expires the session again instead of treating it as freshly
 * used and handing back a pre-idle session.
 */
async function endIdleSession(): Promise<void> {
	try {
		const { error } = await supabase.auth.signOut();
		if (!error) clearActivity();
	} catch {
		// The caller still returns no session, and the stale record stays armed.
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

export async function signOut() {
	const { error } = await supabase.auth.signOut();
	clearActivity();
	if (error) throw error;
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

	const noteActivity = () => {
		if (!watching) return;
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
		if (!watching) return;
		const { data, error } = await supabase.auth.getSession();
		if (error) return;
		const userId = data?.session?.user?.id ?? null;
		if (!userId) {
			currentUserId = null;
			return;
		}
		currentUserId = userId;
		const record = readActivity();
		const lastSeen = record && record.user_id === userId ? record.at : lastActivity;
		if (Date.now() - lastSeen <= INACTIVITY_TIMEOUT_MS) return;
		await endIdleSession();
		watching = false;
		onExpired(expiredStatus());
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
