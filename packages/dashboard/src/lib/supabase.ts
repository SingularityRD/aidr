import { createClient } from "@supabase/supabase-js";
import type { Database } from "./database.types";

declare global {
	interface Window {
		__AIDR_CONFIG__?: {
			supabaseUrl?: string;
			supabaseAnonKey?: string;
			authMethods?: string[];
			signupMode?: "closed" | "cloud";
			samlProviderId?: string;
			samlDomain?: string;
			samlProviders?: Array<{ providerId: string; label: string }>;
			sentryDsn?: string | null;
			sentryEnvironment?: string;
			sentryTracesSampleRate?: number;
			/** Download-center manifest: same-origin path or HTTPS URL; null when not published. */
			releaseManifestUrl?: string | null;
		};
	}
}
const runtime = typeof window !== "undefined" ? window.__AIDR_CONFIG__ : undefined;
const url = runtime?.supabaseUrl ?? (import.meta.env.VITE_SUPABASE_URL as string | undefined);
const anonKey =
	runtime?.supabaseAnonKey ?? (import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined);

/** Control-plane base URL (the Supabase project URL) shown in enrollment templates. */
export const supabaseProjectUrl: string | null = url ? url.replace(/\/+$/, "") : null;

export const supabaseEnvError =
	!url || !anonKey
		? "Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY. Set them in the deployment environment (or .env.local for local development)."
		: null;

type SupabaseClient = ReturnType<typeof createClient<Database>>;

/**
 * Storage key for the persisted session.
 *
 * Setting it explicitly (instead of accepting the client's generated
 * `sb-<project-ref>-auth-token`) keeps the dashboard's session under the
 * application's own namespace and makes the storage contract reviewable rather
 * than a function of the deployment URL. Sessions written under the previous
 * key are not migrated: every signed-in browser authenticates once more, which
 * is the fail-closed direction for a control-plane session.
 */
const AUTH_STORAGE_KEY = "aidr.dashboard.auth.session.v1";

export const DASHBOARD_AUTH_OPTIONS = {
	persistSession: true,
	autoRefreshToken: true,
	detectSessionInUrl: false,
	flowType: "pkce",
	storageKey: AUTH_STORAGE_KEY,
	throwOnError: false,
} as const;

const missingConfigResponse = () => ({
	data: null,
	error: new Error(supabaseEnvError ?? "Supabase is not configured"),
});

/**
 * Keep the dashboard renderable when a developer forgets local Supabase
 * credentials, but make every attempted operation fail with an actionable
 * response instead of a TypeError from a partially-shaped Proxy. The old
 * fallback returned a function for `supabase.auth`, so the first
 * `supabase.auth.getSession()` call crashed before the environment warning
 * could help the user.
 */
function createUnavailableClient(): SupabaseClient {
	const query = new Proxy({} as Record<string, unknown>, {
		get(_target, property) {
			if (property === "then") {
				return (resolve: (value: unknown) => unknown, reject: (reason: unknown) => unknown) =>
					Promise.resolve(missingConfigResponse()).then(resolve, reject);
			}
			return () => query;
		},
	});

	const authError = async () => missingConfigResponse();
	const auth = {
		getSession: authError,
		getUser: authError,
		signOut: authError,
		signInWithOAuth: authError,
		signInWithSSO: authError,
		signInWithOtp: authError,
		signInWithPassword: authError,
		signUp: authError,
		signInWithIdToken: authError,
		setSession: authError,
		exchangeCodeForSession: authError,
		verifyOtp: authError,
		onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => undefined } } }),
		// The step-up surface calls these before rendering a protected screen.
		// Answering with the configuration error keeps that surface fail-closed
		// and actionable instead of crashing on `undefined.enroll`.
		mfa: {
			enroll: authError,
			challenge: authError,
			verify: authError,
			listFactors: authError,
		},
	};

	return {
		auth,
		functions: { invoke: authError },
		from: () => query,
		removeChannel: () => undefined,
	} as unknown as SupabaseClient;
}

function createSupabaseClient(): SupabaseClient {
	if (supabaseEnvError) {
		return createUnavailableClient();
	}
	return createClient<Database, "public", "public">(url as string, anonKey as string, {
		auth: {
			// Session lifetime is an explicit control here, not an inherited
			// client default: the dashboard decides whether a session is
			// persisted at all, whether it is silently renewed in the
			// background, and whether an auth callback in the URL is trusted.
			// `ui/session.ts` adds the idle bound on top of these.
			...DASHBOARD_AUTH_OPTIONS,
			// Callers handle `{ data, error }`; auth failures must not become
			// unhandled rejections that a screen renders as a blank console.
		},
	});
}

export const supabase = createSupabaseClient();
