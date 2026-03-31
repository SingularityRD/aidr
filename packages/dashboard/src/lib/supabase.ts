import { createClient } from "@supabase/supabase-js";

const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabaseEnvError =
	!url || !anonKey
		? "Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY. Create a .env.local file for the dashboard."
		: null;

type SupabaseLike = ReturnType<typeof createClient>;

function buildMissingEnvClient(message: string): SupabaseLike {
	const error = { message };
	const chain = {
		select() {
			return Promise.resolve({ data: null, error, count: 0 });
		},
		insert() {
			return Promise.resolve({ data: null, error });
		},
		update() {
			return chain;
		},
		delete() {
			return chain;
		},
		upsert() {
			return Promise.resolve({ data: null, error });
		},
		eq() {
			return chain;
		},
		order() {
			return chain;
		},
		limit() {
			return chain;
		},
		maybeSingle() {
			return Promise.resolve({ data: null, error });
		},
		single() {
			return Promise.resolve({ data: null, error });
		},
	};

	return {
		from() {
			return chain;
		},
		auth: {
			async getSession() {
				return { data: { session: null }, error: null };
			},
			async signOut() {
				return { error: null };
			},
			async signInWithOAuth() {
				return { data: { provider: "", url: null }, error };
			},
			async signInWithOtp() {
				return { data: { session: null, user: null }, error };
			},
			async exchangeCodeForSession() {
				return { data: { session: null, user: null }, error };
			},
			onAuthStateChange(cb: (event: string, session: unknown | null) => void) {
				void cb;
				return { data: { subscription: { unsubscribe() {} } } };
			},
		},
		functions: {
			async invoke() {
				return { data: null, error };
			},
		},
	} as unknown as SupabaseLike;
}

export const supabase: SupabaseLike = supabaseEnvError
	? buildMissingEnvClient(supabaseEnvError)
	: createClient(url as string, anonKey as string);
