import { createClient } from "@supabase/supabase-js";
import type { Database } from "./database.types";

const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabaseEnvError =
	!url || !anonKey
		? "Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY. Set them in the deployment environment (or .env.local for local development)."
		: null;

type SupabaseClient = ReturnType<typeof createClient<Database>>;

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
		signInWithOtp: authError,
		signInWithIdToken: authError,
		exchangeCodeForSession: authError,
		onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => undefined } } }),
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
	return createClient<Database>(url as string, anonKey as string);
}

export const supabase = createSupabaseClient();

export type { Database } from "./database.types";
