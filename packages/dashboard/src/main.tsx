import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider, redirect } from "react-router-dom";
import { EnterpriseAuth } from "./enterprise/auth";
import { supabaseEnvError } from "./lib/supabase";
import { initSentry } from "./sentry";
import { AppLayout } from "./ui/AppLayout";
import { NotFoundPage } from "./ui/NotFoundPage";
import { PublicLayout } from "./ui/PublicLayout";
import { AgentDetailPage } from "./ui/pages/AgentDetailPage";
import { AgentsPage } from "./ui/pages/AgentsPage";
import { ApiKeysPage } from "./ui/pages/ApiKeysPage";
import { AuthCallbackPage } from "./ui/pages/AuthCallbackPage";
import { AutoSecOpsPage } from "./ui/pages/AutoSecOpsPage";
import { BillingPage } from "./ui/pages/BillingPage";
import { DashboardPage } from "./ui/pages/DashboardPage";
import { EventsPage } from "./ui/pages/EventsPage";
import { IncidentsPage } from "./ui/pages/IncidentsPage";
import { LoginPage } from "./ui/pages/LoginPage";
import { OnboardingPage } from "./ui/pages/OnboardingPage";
import { PolicyPage } from "./ui/pages/PolicyPage";
import { DemoPage } from "./ui/pages/public/DemoPage";
import { LandingPage } from "./ui/pages/public/LandingPage";
import { PilotPage } from "./ui/pages/public/PilotPage";
import { PricingPage } from "./ui/pages/public/PricingPage";
import { PublicInfoPage } from "./ui/pages/public/PublicInfoPage";
import { VerifyPage } from "./ui/pages/public/VerifyPage";
import { RecoveryPage } from "./ui/pages/RecoveryPage";
import { SettingsPage } from "./ui/pages/SettingsPage";
import { TeamPage } from "./ui/pages/TeamPage";
import { RouteErrorPage } from "./ui/RouteErrorPage";
import { buildReturnToFromRequest, sanitizeReturnTo, setPostAuthReturnTo } from "./ui/return-to";
import { getSession } from "./ui/session";
import { ThemeProvider } from "./ui/ThemeProvider";
import "./styles.css";

// Initialize Sentry for the dashboard
if (import.meta.env.VITE_SENTRY_DSN) {
	initSentry();
}

async function requireSessionLoader({ request }: { request: Request }) {
	const session = await getSession();
	if (!session) {
		const returnTo = buildReturnToFromRequest(request);
		throw redirect(`/login?returnTo=${encodeURIComponent(returnTo)}`);
	}
	return null;
}

const routeErrorElement = <RouteErrorPage />;

const router = createBrowserRouter([
	{
		path: "/",
		element: <PublicLayout />,
		errorElement: routeErrorElement,
		children: [
			{ index: true, element: <LandingPage /> },
			{ path: "demo", element: <DemoPage /> },
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
		element: <LoginPage />,
	},
	{
		path: "/auth/callback",
		element: <AuthCallbackPage />,
		errorElement: routeErrorElement,
	},
	{
		path: "/auth/recover",
		element: <RecoveryPage />,
		errorElement: routeErrorElement,
	},
	{
		// Invite-acceptance entry point. EnterpriseAuth was implemented with no
		// route at all, and its success path navigated to "/team", which did not
		// exist. Both ends are now real: this route renders the invitation panel,
		// and /team is the rendered team administration page below.
		path: "/enterprise",
		element: <EnterpriseAuth />,
		errorElement: routeErrorElement,
	},
	{
		path: "/onboarding",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <OnboardingPage /> }],
	},
	{
		path: "/dashboard",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <DashboardPage /> }],
	},
	{
		path: "/events",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <EventsPage /> }],
	},
	{
		path: "/settings",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <SettingsPage /> }],
	},
	{
		path: "/agents",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <AgentsPage /> }],
	},
	{
		path: "/autosecops",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <AutoSecOpsPage /> }],
	},
	{
		path: "/agents/:agentId",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <AgentDetailPage /> }],
	},
	{
		path: "/incidents",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <IncidentsPage /> }],
	},
	{
		path: "/api-keys",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <ApiKeysPage /> }],
	},
	{
		path: "/billing",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <BillingPage /> }],
	},
	{
		path: "/team",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <TeamPage /> }],
	},
	{
		path: "/policies",
		element: <AppLayout />,
		errorElement: routeErrorElement,
		loader: requireSessionLoader,
		children: [{ index: true, element: <PolicyPage /> }],
	},
]);

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Missing #root element");

function DashboardConfigurationError() {
	return (
		<main className="main">
			<div
				className="card"
				role="alert"
				aria-live="assertive"
				style={{ maxWidth: 620, margin: "48px auto" }}
			>
				<p className="eyebrow">Configuration required</p>
				<h1>Dashboard configuration is incomplete</h1>
				<p className="muted">
					This production deployment is not connected to Supabase. Configure the required public
					environment variables and redeploy before inviting customers.
				</p>
				<div className="notice notice-danger" style={{ marginTop: 16 }}>
					{supabaseEnvError}
				</div>
			</div>
		</main>
	);
}

// Never ship a production build that silently renders an unconfigured
// dashboard. The isolated synthetic demo is intentionally allowed to render
// without Supabase so prospects can inspect the product boundary without
// accidentally creating a tenant or making a production request.
const productionConfigMissing = Boolean(supabaseEnvError) && import.meta.env.PROD;
const isControlledDemoRoute = window.location.pathname === "/demo";

ReactDOM.createRoot(rootEl).render(
	<React.StrictMode>
		<ThemeProvider>
			{productionConfigMissing && !isControlledDemoRoute ? (
				<DashboardConfigurationError />
			) : (
				<RouterProvider router={router} />
			)}
		</ThemeProvider>
	</React.StrictMode>,
);
