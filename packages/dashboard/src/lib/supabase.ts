import { createClient } from "@supabase/supabase-js";
import type { Database } from "./database.types";

const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabaseEnvError =
	!url || !anonKey
		? "Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY. Create a .env.local file for the dashboard."
		: null;

type SupabaseClient = ReturnType<typeof createClient<Database>>;

function createSupabaseClient(): SupabaseClient {
	if (supabaseEnvError) {
		// Return a mock that will throw at runtime but satisfies types
		return new Proxy({} as SupabaseClient, {
			get() {
				return () => Promise.resolve({ data: null, error: new Error(supabaseEnvError) });
			},
		});
	}
	return createClient<Database>(url as string, anonKey as string);
}

export const supabase = createSupabaseClient();

export type { Database } from "./database.types";
