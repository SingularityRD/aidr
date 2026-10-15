import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider, redirect } from "react-router-dom";
import { I18nProvider, useT } from "./i18n/I18nProvider";
import { supabaseEnvError } from "./lib/supabase";
import { initSentry } from "./sentry";
import { NotFoundPage } from "./ui/NotFoundPage";
import { PublicLayout } from "./ui/PublicLayout";
import { LandingPage } from "./ui/pages/public/LandingPage";
import { PilotPage } from "./ui/pages/public/PilotPage";
import { PricingPage } from "./ui/pages/public/PricingPage";
import { PublicInfoPage } from "./ui/pages/public/PublicInfoPage";
import { VerifyPage } from "./ui/pages/public/VerifyPage";
import { RouteErrorPage } from "./ui/RouteErrorPage";
import { buildReturnToFromRequest, sanitizeReturnTo, setPostAuthReturnTo } from "./ui/return-to";
import { getSession, installInactivityTimeout } from "./ui/session";
import { ThemeProvider } from "./ui/ThemeProvider";
import "./styles.css";

// The Node deployment supplies its validated DSN at runtime; Vite-hosted builds
// still fall back to the build-time value inside initSentry.
initSentry();

async function requireSessionLoader({ request }: { request: Request }) {
	const session = await getSession();
	if (!session) {
		const returnTo = buildReturnToFromRequest(request);
		throw redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`);
	}
	return null;
}

const routeErrorElement = <RouteErrorPage />;
const loadAppLayout = async () => ({ Component: (await import("./ui/AppLayout")).AppLayout });

/**
 * A page behind a plan feature: the server refuses it with 402
 * plan_feature_required; the dashboard shows an upgrade notice instead.
 */
function gatedPage(
	feature: import("./billing/entitlements").GatedPlanFeature,
	load: () => Promise<React.ComponentType>,
) {
	return async () => {
		const [Page, { PlanGate }] = await Promise.all([load(), import("./ui/PlanGate")]);
		return {
			Component: () => (
				<PlanGate feature={feature}>
					<Page />
				</PlanGate>
			),
		};
	};
}

const router = createBrowserRouter([
	{
		path: "/",
		element: <PublicLayout />,
		errorElement: routeErrorElement,
		children: [
			{ index: true, element: <LandingPage /> },
			{ path: "demo", loader: () => redirect("/login?returnTo=%2Fonboarding") },
			{ path: "pilot", element: <PilotPage /> },
			{ path: "pricing", element: <PricingPage /> },
			{ path: "verify", element: <VerifyPage /> },
			{ path: "support", element: <PublicInfoPage kind="support" /> },
			{ path: "status", element: <PublicInfoPage kind="status" /> },
			{ path: "privacy", element: <PublicInfoPage kind="privacy" /> },
			{ path: "security", element: <PublicInfoPage kind="security" /> },
			{ path: "terms", element: <PublicInfoPage kind="terms" /> },
			{ path: "*", element: <NotFoundPage /> },
		],
	},
	{
		path: "/login",
		errorElement: routeErrorElement,
		loader: async ({ request }) => {
			// Persist returnTo across OAuth redirects (and magic-link flows).
			const url = new URL(request.url);
			const rt = url.searchParams.get("returnTo");
			if (rt) setPostAuthReturnTo(sanitizeReturnTo(rt));
			return null;
		},
		lazy: async () => ({ Component: (await import("./ui/pages/LoginPage")).LoginPage }),
	},
	{
		path: "/auth/callback",
		lazy: async () => ({
			Component: (await import("./ui/pages/AuthCallbackPage")).AuthCallbackPage,
		}),
		errorElement: routeErrorElement,
	},
	{
		path: "/auth/oidc/callback",
		lazy: async () => ({
			Component: (await import("./ui/pages/OidcCallbackPage")).OidcCallbackPage,
		}),
		errorElement: routeErrorElement,
	},
	{
		path: "/auth/sso-recovery",
		lazy: async () => ({
			Component: (await import("./ui/pages/OidcBreakGlassPage")).OidcBreakGlassPage,
		}),
		errorElement: routeErrorElement,
	},
	{
		path: "/auth/recover",
		lazy: async () => ({ Component: (await import("./ui/pages/RecoveryPage")).RecoveryPage }),
		errorElement: routeErrorElement,
	},
	{
		// Invite-acceptance entry point. EnterpriseAuth was implemented with no
		// route at all, and its success path navigated to "/team", which did not
		// exist. Both ends are now real: this route renders the invitation panel,
		// and /team is the rendered team administration page below.
		path: "/enterprise",
		lazy: async () => ({ Component: (await import("./enterprise/auth")).EnterpriseAuth }),
		errorElement: routeErrorElement,
	},
	{
		path: "/auth/dlp-step-up",
		lazy: async () => ({ Component: (await import("./enterprise/dlp-editor")).DlpStepUpPage }),
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
	},
	{
		// Platform-operator console. Outside AppLayout: operators are not tenant
		// members. The operator-admin function alone decides access (operator row + AAL2).
		path: "/operator",
		lazy: async () => ({ Component: (await import("./ui/pages/OperatorPage")).OperatorPage }),
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
	},
	{
		path: "/onboarding",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/OnboardingPage")).OnboardingPage,
				}),
			},
		],
	},
	{
		path: "/downloads",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/DownloadsPage")).DownloadsPage }),
			},
		],
	},
	{
		path: "/dashboard",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/DashboardPage")).DashboardPage }),
			},
		],
	},
	{
		path: "/events",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/EventsPage")).EventsPage }),
			},
		],
	},
	{
		path: "/discovery",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/DiscoveryPage")).DiscoveryPage }),
			},
		],
	},
	{
		path: "/posture",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: gatedPage(
					"ai_security_posture",
					async () => (await import("./ui/pages/PosturePage")).PosturePage,
				),
			},
		],
	},
	{
		path: "/approvals",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/ApprovalsPage")).ApprovalsPage }),
			},
		],
	},
	{
		path: "/settings",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/SettingsPage")).SettingsPage }),
			},
		],
	},
	{
		path: "/agents",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/AgentsPage")).AgentsPage }),
			},
		],
	},
	{
		path: "/autosecops",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/AutoSecOpsPage")).AutoSecOpsPage,
				}),
			},
		],
	},
	{
		path: "/agents/:agentId",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/AgentDetailPage")).AgentDetailPage,
				}),
			},
		],
	},
	{
		path: "/incidents",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/IncidentsPage")).IncidentsPage }),
			},
		],
	},
	{
		path: "/api-keys",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/ApiKeysPage")).ApiKeysPage }),
			},
		],
	},
	{
		path: "/billing",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/BillingPage")).BillingPage }),
			},
		],
	},
	{
		path: "/team",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/TeamPage")).TeamPage }),
			},
		],
	},
	{
		path: "/scim",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: gatedPage("scim", async () => (await import("./ui/pages/ScimPage")).ScimPage),
			},
		],
	},
	{
		path: "/privacy-guard",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: gatedPage(
					"browser_privacy_guard",
					async () => (await import("./ui/pages/PrivacyGuardPage")).PrivacyGuardPage,
				),
			},
		],
	},
	{
		path: "/compliance",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/CompliancePage")).CompliancePage,
				}),
			},
		],
	},
	{
		path: "/reports",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/ReportsPage")).ReportsPage,
				}),
			},
		],
	},
	{
		path: "/governance",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/GovernancePage")).GovernancePage,
				}),
			},
		],
	},
	{
		path: "/governance/register",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/GovernanceRegisterPage")).GovernanceRegisterPage,
				}),
			},
		],
	},
	{
		path: "/governance/requests",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/GovernanceRequestsPage")).GovernanceRequestsPage,
				}),
			},
		],
	},
	{
		path: "/governance/detection-exceptions",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/DetectionExceptionsPage")).DetectionExceptionsPage,
				}),
			},
		],
	},
	{
		path: "/governance/change-control",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({
					Component: (await import("./ui/pages/GovernanceChangeControlPage"))
						.GovernanceChangeControlPage,
				}),
			},
		],
	},
	{
		path: "/retention",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/RetentionPage")).RetentionPage }),
			},
		],
	},
	{
		path: "/sso",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: gatedPage(
					"entra_sso",
					async () => (await import("./ui/pages/OidcSsoPage")).OidcSsoPage,
				),
			},
		],
	},
	{
		path: "/siem",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: gatedPage("siem_export", async () => (await import("./ui/pages/SiemPage")).SiemPage),
			},
		],
	},
	{
		path: "/policies",
		lazy: loadAppLayout,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [
			{
				index: true,
				lazy: async () => ({ Component: (await import("./ui/pages/PolicyPage")).PolicyPage }),
			},
		],
	},
]);

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Missing #root element");

// End an idle session locally and send the operator back to sign-in. This is the
// dashboard's own lifetime bound; the deployment's JWT expiry and the identity
// revocation barrier stay authoritative, so this must never be treated as the
// control that makes a token unusable.
installInactivityTimeout((status) => {
	if (status.state !== "expired") return;
	const returnTo = sanitizeReturnTo(`${window.location.pathname}${window.location.search}`);
	void router.navigate(`/login?returnTo=${encodeURIComponent(returnTo)}`);
});

function DashboardConfigurationError() {
	const t = useT();
	return (
		<main className="main">
			<div
				className="card"
				role="alert"
				aria-live="assertive"
				style={{ maxWidth: 620, margin: "48px auto" }}
			>
				<p className="eyebrow">{t("config.eyebrow")}</p>
				<h1>{t("config.title")}</h1>
				<p className="muted">{t("config.body")}</p>
				<div className="notice notice-danger" style={{ marginTop: 16 }}>
					{supabaseEnvError}
				</div>
			</div>
		</main>
	);
}

// Never ship a production build that silently renders an unconfigured dashboard.
const productionConfigMissing = Boolean(supabaseEnvError) && import.meta.env.PROD;

ReactDOM.createRoot(rootEl).render(
	<React.StrictMode>
		<I18nProvider>
			<ThemeProvider>
				{productionConfigMissing ? (
					<DashboardConfigurationError />
				) : (
					<RouterProvider router={router} />
				)}
			</ThemeProvider>
		</I18nProvider>
	</React.StrictMode>,
);
