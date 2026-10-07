import { type ReactNode, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
	type GatedPlanFeature,
	loadTenantEntitlements,
	requiredPlanName,
	type TenantEntitlements,
} from "../billing/entitlements";
import { PLAN_FEATURE_LABELS, planById } from "../billing/plans";
import { useTeam } from "../enterprise/team-provider";

type GateState =
	| { kind: "loading" }
	| { kind: "unavailable" }
	| { kind: "ready"; entitlements: TenantEntitlements };

/**
 * Renders `children` only when the current workspace's plan includes
 * `feature`; otherwise an upgrade notice. The server enforces the same
 * decision (402 `plan_feature_required`), so this is presentation only, and an
 * unreadable plan shows a notice instead of the page.
 */
export function PlanGate({
	feature,
	children,
}: {
	feature: GatedPlanFeature;
	children: ReactNode;
}) {
	const { currentTeam, isLoading } = useTeam();
	const tenantId = currentTeam?.tenant_id ?? null;
	const [state, setState] = useState<GateState>({ kind: "loading" });

	useEffect(() => {
		if (!tenantId) {
			setState({ kind: isLoading ? "loading" : "unavailable" });
			return;
		}
		let current = true;
		setState({ kind: "loading" });
		loadTenantEntitlements(tenantId).then(
			(entitlements) => {
				if (current) setState({ kind: "ready", entitlements });
			},
			() => {
				if (current) setState({ kind: "unavailable" });
			},
		);
		return () => {
			current = false;
		};
	}, [tenantId, isLoading]);

	if (state.kind === "loading") {
		return (
			<p className="muted" role="status">
				Checking your plan…
			</p>
		);
	}
	if (state.kind === "unavailable") {
		return (
			<section className="card" role="alert">
				<h1>{PLAN_FEATURE_LABELS[feature]}</h1>
				<p>Plan information is unavailable, so this page is not shown. Try again shortly.</p>
			</section>
		);
	}
	if (state.entitlements.features.has(feature)) return <>{children}</>;
	const current = planById(state.entitlements.planId)?.displayName ?? state.entitlements.planId;
	return (
		<section className="card" aria-labelledby="plan-gate-heading" data-plan-gate={feature}>
			<h1 id="plan-gate-heading">{PLAN_FEATURE_LABELS[feature]}</h1>
			<p>
				{PLAN_FEATURE_LABELS[feature]} is included from the{" "}
				<strong>{requiredPlanName(feature)}</strong> edition. This workspace is on{" "}
				<strong>{current}</strong>
				{state.entitlements.source === "admission_inactive"
					? " because its licence or admission is not active"
					: ""}
				.
			</p>
			<p>
				<Link to="/billing">View plans and upgrade</Link>
			</p>
		</section>
	);
}
