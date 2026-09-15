import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "../lib/supabase";
import { readErrorMessage } from "../lib/errors";
import { useSessionSnapshot } from "../ui/use-session";
import { EnterpriseAuth } from "./auth";

type MembershipIdentity = { team_id: string | null; tenant_id: string };
type BootstrapState =
	| { kind: "checking" }
	| { kind: "blocked"; message: string }
	| { kind: "ready"; memberships: MembershipIdentity[] };
// The render callback constructs elements only; data work belongs in gated effects.
type Props = {
	children: (
		teamId: string | null,
		switchTeam: (teamId: string) => void,
		refreshMemberships: (tenantId: string) => Promise<void>,
		isCurrent: () => boolean,
	) => ReactNode;
};

function parseBootstrap(data: unknown): MembershipIdentity[] {
	if (!data || typeof data !== "object")
		throw new Error("Invalid identity bootstrap. Access is withheld.");
	const payload = data as Record<string, unknown>;
	if (payload.ok !== true || !Array.isArray(payload.memberships))
		throw new Error("Invalid identity bootstrap. Access is withheld.");
	return payload.memberships.map((entry: unknown) => {
		if (!entry || typeof entry !== "object") throw new Error("Invalid membership identity.");
		const row = entry as Record<string, unknown>;
		if (
			typeof row.tenant_id !== "string" ||
			!row.tenant_id ||
			!(row.team_id === null || (typeof row.team_id === "string" && row.team_id)) ||
			typeof row.require_mfa !== "boolean" ||
			typeof row.access_allowed !== "boolean" ||
			![null, "aal1", "aal2"].includes(row.current_assurance as string | null) ||
			![null, "aal1", "aal2"].includes(row.next_assurance as string | null)
		) {
			throw new Error("Invalid membership identity. Access is withheld.");
		}
		return { team_id: row.team_id as string | null, tenant_id: row.tenant_id };
	});
}

/** Only identifiers cross this boundary. Protected table providers mount AFTER assurance. */
export function IdentityBootstrap({ children }: Props) {
	const { snapshot, generation, refresh, isCurrent } = useSessionSnapshot();
	const preference = useRef<{ userId: string; tenantId: string } | null>(null);
	const userId = snapshot?.session?.user.id;
	const remember = useCallback(
		(tenantId: string) => {
			if (userId) preference.current = { userId, tenantId };
		},
		[userId],
	);
	if (!snapshot) return <div role="status">Resolving the managed tenant…</div>;
	if (!snapshot.session)
		return (
			<EnterpriseAuth>
				<div />
			</EnterpriseAuth>
		);
	const session = snapshot.session;
	return (
		<BoundBootstrap
			key={JSON.stringify([session.user.id, session.access_token, generation])}
			session={session}
			isCurrent={isCurrent}
			preferredTenant={
				preference.current?.userId === session.user.id ? preference.current.tenantId : null
			}
			onSelect={remember}
			refreshMemberships={async (tenantId) => {
				remember(tenantId);
				await refresh();
			}}
		>
			{children}
		</BoundBootstrap>
	);
}

function BoundBootstrap({
	session,
	children,
	preferredTenant,
	onSelect,
	refreshMemberships,
	isCurrent,
}: Props & {
	session: Session;
	isCurrent: () => boolean;
	preferredTenant: string | null;
	onSelect: (tenantId: string) => void;
	refreshMemberships: (tenantId: string) => Promise<void>;
}) {
	const [state, setState] = useState<BootstrapState>({ kind: "checking" });
	const [selection, setSelection] = useState<MembershipIdentity | null>(null);
	useEffect(() => {
		let cancelled = false;
		void (async () => {
			try {
				const { data, error } = await supabase.functions.invoke("identity-security", {
					body: { action: "bootstrap" },
					headers: { Authorization: `Bearer ${session.access_token}` },
				});
				if (cancelled || !isCurrent()) return;
				if (error) throw error;
				const memberships = parseBootstrap(data);
				const selected =
					memberships.find((item) => item.tenant_id === preferredTenant) ?? memberships[0] ?? null;
				setSelection(selected);
				if (selected) onSelect(selected.tenant_id);
				setState({ kind: "ready", memberships });
			} catch (cause) {
				if (!cancelled)
					setState({
						kind: "blocked",
						message: readErrorMessage(
							cause,
							"Managed identity could not be verified. Access is withheld.",
						),
					});
			}
		})();
		return () => {
			cancelled = true;
		};
	}, [session, preferredTenant, onSelect, isCurrent]);
	if (state.kind === "checking") return <div role="status">Resolving the managed tenant…</div>;
	if (state.kind === "blocked") return <div role="alert">{state.message}</div>;
	if (!selection)
		return (
			<div role="alert">
				No active managed membership is available. No protected screen was opened.
			</div>
		);
	const switchTeam = (teamId: string) => {
		const next = state.memberships.find((item) => item.team_id === teamId);
		if (next) {
			onSelect(next.tenant_id);
			setSelection(next);
		}
	};
	return (
		<>
			{state.memberships.length > 1 && (
				<label>
					Managed tenant
					<select
						aria-label="Managed tenant"
						value={selection.tenant_id}
						onChange={(event) => {
							const next = state.memberships.find((item) => item.tenant_id === event.target.value);
							if (next) {
								onSelect(next.tenant_id);
								setSelection(next);
							}
						}}
					>
						{state.memberships.map((item) => (
							<option key={item.tenant_id} value={item.tenant_id}>
								{item.tenant_id}
							</option>
						))}
					</select>
				</label>
			)}
			<EnterpriseAuth tenantId={selection.tenant_id}>
				{children(selection.team_id, switchTeam, refreshMemberships, isCurrent)}
			</EnterpriseAuth>
		</>
	);
}
