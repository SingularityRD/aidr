import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider, redirect } from "react-router-dom";
import { initSentry } from "./sentry";
import { AppLayout } from "./ui/AppLayout";
import { PublicLayout } from "./ui/PublicLayout";
import { AgentDetailPage } from "./ui/pages/AgentDetailPage";
import { AgentsPage } from "./ui/pages/AgentsPage";
import { ApiKeysPage } from "./ui/pages/ApiKeysPage";
import { AuthCallbackPage } from "./ui/pages/AuthCallbackPage";
import { BillingPage } from "./ui/pages/BillingPage";
import { IncidentsPage } from "./ui/pages/IncidentsPage";
import { LoginPage } from "./ui/pages/LoginPage";
import { OnboardingPage } from "./ui/pages/OnboardingPage";
import { LandingPage } from "./ui/pages/public/LandingPage";
import { VerifyPage } from "./ui/pages/public/VerifyPage";
import { buildReturnToFromRequest, setPostAuthReturnTo } from "./ui/return-to";
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

const router = createBrowserRouter([
	{
		path: "/",
		element: <PublicLayout />,
		children: [
			{ index: true, element: <LandingPage /> },
			{ path: "verify", element: <VerifyPage /> },
		],
	},
	{
		path: "/login",
		loader: async ({ request }) => {
			// Persist returnTo across OAuth redirects (and magic-link flows).
			const url = new URL(request.url);
			const rt = url.searchParams.get("returnTo");
			const trimmedReturnTo = rt?.trim();
			if (trimmedReturnTo) setPostAuthReturnTo(trimmedReturnTo);
			return null;
		},
		element: <LoginPage />,
	},
	{
		path: "/auth/callback",
		element: <AuthCallbackPage />,
	},
	{
		path: "/onboarding",
		element: <AppLayout />,
		loader: requireSessionLoader,
		children: [{ index: true, element: <OnboardingPage /> }],
	},
	{
		path: "/agents",
		element: <AppLayout />,
		loader: requireSessionLoader,
		children: [{ index: true, element: <AgentsPage /> }],
	},
	{
		path: "/agents/:agentId",
		element: <AppLayout />,
		loader: requireSessionLoader,
		children: [{ index: true, element: <AgentDetailPage /> }],
	},
	{
		path: "/incidents",
		element: <AppLayout />,
		loader: requireSessionLoader,
		children: [{ index: true, element: <IncidentsPage /> }],
	},
	{
		path: "/api-keys",
		element: <AppLayout />,
		loader: requireSessionLoader,
		children: [{ index: true, element: <ApiKeysPage /> }],
	},
	{
		path: "/billing",
		element: <AppLayout />,
		loader: requireSessionLoader,
		children: [{ index: true, element: <BillingPage /> }],
	},
]);

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Missing #root element");

ReactDOM.createRoot(rootEl).render(
	<React.StrictMode>
		<ThemeProvider>
			<RouterProvider router={router} />
		</ThemeProvider>
	</React.StrictMode>,
);
