import { Link } from "react-router-dom";
import {
	QUOTE_CONTACT_EMAIL,
	quoteRequestHref,
	selfServiceCheckoutEnabled,
} from "../../../billing/commercial";
import {
	DEPLOYMENT_LABELS,
	PLAN_FEATURE_LABELS,
	type PlanDefinition,
	retentionTerms,
	seatTerms,
} from "../../../billing/plans";
import { useDashboardLocale, useRichT, useT } from "../../../i18n/I18nProvider";
import { PUBLIC_PLANS } from "./product-facts";

/** Self-serve signup applies only when the build enables online checkout. */
function selfServePlan(plan: PlanDefinition): boolean {
	return plan.id !== "free" && plan.selfServe && selfServiceCheckoutEnabled;
}

function QuoteLink({ edition }: { edition?: string }) {
	const t = useT();
	return (
		<a
			className="button"
			href={quoteRequestHref(edition)}
			aria-label={edition ? t("pr.contactAbout", { edition }) : undefined}
		>
			{t("pr.contact")}
		</a>
	);
}

function PlanActions({ plan }: { plan: PlanDefinition }) {
	const t = useT();
	if (plan.id === "free") {
		return (
			<Link className="button button-secondary" to="/login?returnTo=%2Fonboarding">
				{t("pr.startFree")}
			</Link>
		);
	}
	return (
		<>
			<QuoteLink edition={plan.displayName} />
			{selfServePlan(plan) ? (
				<Link className="button button-secondary" to="/login?returnTo=%2Fbilling">
					{t("pr.choose", { plan: plan.displayName })}
				</Link>
			) : (
				<Link className="button button-secondary" to="/pilot">
					{t("pr.scopeReview")}
				</Link>
			)}
		</>
	);
}

/**
 * Public Editions page, served at /pricing because that route may be linked
 * externally. It compares the editions and routes every paid one to a quote:
 * prices are not published (product-owner decision), so no amount, currency or
 * per-seat figure is rendered here.
 */
export function PricingPage() {
	const t = useT();
	const richT = useRichT();
	// The English page keeps its Turkish cues for Turkish readers; the Turkish page needs none.
	const english = useDashboardLocale() === "en";
	return (
		<div className="stack">
			<div className="card">
				{english ? (
					<div className="muted small" lang="tr">
						{/* i18n-exempt: Turkish cue on the English page */}
						Paketler
					</div>
				) : null}
				<h1>{t("pr.title")}</h1>
				<p className="muted">
					{richT("pr.lead", {
						iid: <span className="mono">iid</span>,
						orders: selfServiceCheckoutEnabled ? t("pr.ordersCheckout") : t("pr.ordersQuote"),
					})}
				</p>
				<div className="notice" role="note" style={{ marginTop: 10 }}>
					{richT("pr.requestQuote", {
						note: t("plan.quoteNotice"),
						email: <a href={quoteRequestHref()}>{QUOTE_CONTACT_EMAIL}</a>,
					})}
				</div>
				<div className="row" style={{ marginTop: 12 }}>
					<QuoteLink />
					{english ? (
						<span className="muted small" lang="tr">
							{/* i18n-exempt: Turkish cue on the English page */}
							Teklif alın
						</span>
					) : null}
				</div>
			</div>

			<div className="plan-grid" aria-label={t("pr.editionsLabel")}>
				{PUBLIC_PLANS.map((plan) => (
					<section
						className={plan.id === "team" ? "card referral-card" : "card"}
						key={plan.id}
						aria-labelledby={`plan-${plan.id}`}
					>
						<div className="row space-between">
							<h2 id={`plan-${plan.id}`}>{plan.displayName}</h2>
							{plan.id === "free" ? null : selfServePlan(plan) ? (
								<span className="badge recommended">{t("pr.selfServe")}</span>
							) : (
								<span className="badge">{t("pr.salesAssisted")}</span>
							)}
						</div>
						<div className="muted small">
							{plan.id === "free" ? t("pr.freeNote") : t("pr.quoteBased")}
						</div>
						<ul className="list">
							<li>{seatTerms(plan, t)}</li>
							<li>
								{t("pr.deployment", {
									list: plan.deployment
										.map((deployment) => t(DEPLOYMENT_LABELS[deployment]))
										.join(t("pr.or")),
								})}
							</li>
							<li>{retentionTerms(plan, t)}</li>
							{plan.features.map((feature) => (
								<li key={feature}>{t(PLAN_FEATURE_LABELS[feature])}</li>
							))}
						</ul>
						<div className="row" style={{ marginTop: 12 }}>
							<PlanActions plan={plan} />
						</div>
					</section>
				))}
			</div>

			<div className="card referral-card">
				<div className="row space-between">
					<h2>{t("pr.pilot")}</h2>
					<span className="badge recommended">{t("pr.reviewRequired")}</span>
				</div>
				<ul className="list">
					<li>{t("pr.pilot1")}</li>
					<li>{t("pr.pilot2")}</li>
					<li>{t("pr.pilot3")}</li>
				</ul>
				<p className="muted">{t("pr.pilotNote")}</p>
				<div className="row" style={{ marginTop: 12 }}>
					<Link className="button" to="/pilot">
						{t("pr.pilotReview")}
					</Link>
				</div>
			</div>

			<div className="card">
				<h2>{t("pr.enterprise")}</h2>
				<p className="muted">{t("pr.enterpriseLead")}</p>
				<div className="row">
					<QuoteLink edition="Enterprise" />
					<Link className="button button-secondary" to="/pilot">
						{t("pr.scopeReview")}
					</Link>
				</div>
			</div>
		</div>
	);
}
