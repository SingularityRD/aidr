import { supabase } from "../lib/supabase";

export async function getSession() {
	const { data, error } = await supabase.auth.getSession();
	if (error) throw error;
	return data.session ?? null;
}

export async function signOut() {
	const { error } = await supabase.auth.signOut();
	if (error) throw error;
}
