import { useCallback, useEffect, useRef, useState } from "react";
import { supabase } from "../lib/supabase";
import { readSession, type SessionSnapshot } from "./session";

/** Invalidate synchronously on auth events; an older read cannot restore a token. */
export function useSessionSnapshot() {
	const [state, setState] = useState<{ snapshot: SessionSnapshot | null; generation: number }>({
		snapshot: null,
		generation: 0,
	});
	const generation = useRef(0);
	const mounted = useRef(false);
	const refresh = useCallback(async () => {
		const next = ++generation.current;
		setState({ snapshot: null, generation: next });
		try {
			const snapshot = await readSession();
			if (mounted.current && next === generation.current) setState({ snapshot, generation: next });
		} catch {
			// No readable session means no accepted assurance or protected children.
			if (mounted.current && next === generation.current) {
				setState({ snapshot: null, generation: next });
			}
		}
	}, []);
	useEffect(() => {
		mounted.current = true;
		const { data } = supabase.auth.onAuthStateChange(() => {
			// Supabase emits under its auth lock. Invalidate now, read outside it.
			const next = ++generation.current;
			setState({ snapshot: null, generation: next });
			queueMicrotask(() => {
				if (mounted.current && next === generation.current) void refresh();
			});
		});
		void refresh();
		return () => {
			mounted.current = false;
			++generation.current;
			data.subscription.unsubscribe();
		};
	}, [refresh]);
	const isCurrent = useCallback(
		() => mounted.current && generation.current === state.generation,
		[state.generation],
	);
	return { ...state, refresh, isCurrent };
}
