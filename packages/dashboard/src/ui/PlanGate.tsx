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
import { useRichT, useT } from "../i18n/I18nProvider";

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
	const t = useT();
	const richT = useRichT();

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
				{t("plan.checking")}
			</p>
		);
	}
	if (state.kind === "unavailable") {
		return (
			<section className="card" role="alert">
				<h1>{PLAN_FEATURE_LABELS[feature]}</h1>
				<p>{t("plan.unavailable")}</p>
			</section>
		);
	}
	if (state.entitlements.features.has(feature)) return <>{children}</>;
	const current = planById(state.entitlements.planId)?.displayName ?? state.entitlements.planId;
	return (
		<section className="card" aria-labelledby="plan-gate-heading" data-plan-gate={feature}>
			<h1 id="plan-gate-heading">{PLAN_FEATURE_LABELS[feature]}</h1>
			<p>
				{richT("plan.includedFrom", {
					feature: PLAN_FEATURE_LABELS[feature],
					plan: <strong>{requiredPlanName(feature)}</strong>,
					current: <strong>{current}</strong>,
					why: state.entitlements.source === "admission_inactive" ? t("plan.inactive") : "",
				})}
			</p>
			<p>
				<Link to="/billing">{t("plan.upgrade")}</Link>
			</p>
		</section>
	);
}
