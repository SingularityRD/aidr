import * as Sentry from "@sentry/browser";
import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider, redirect } from "react-router-dom";
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
import { DemoPage } from "./ui/pages/public/DemoPage";
import { LandingPage } from "./ui/pages/public/LandingPage";
import { PilotPage } from "./ui/pages/public/PilotPage";
import { PricingPage } from "./ui/pages/public/PricingPage";
import { VerifyPage } from "./ui/pages/public/VerifyPage";
import { WaitlistPage } from "./ui/pages/public/WaitlistPage";
import { buildReturnToFromRequest, setPostAuthReturnTo } from "./ui/return-to";
import { getSession } from "./ui/session";
import "./styles.css";

// Initialize Sentry for the dashboard
if (import.meta.env.VITE_SENTRY_DSN) {
	Sentry.init({
		dsn: import.meta.env.VITE_SENTRY_DSN,
		environment: import.meta.env.VITE_SENTRY_ENVIRONMENT || "development",
		release: import.meta.env.VITE_SENTRY_RELEASE || "dev",
		integrations: [Sentry.browserTracingIntegration(), Sentry.replayIntegration()],
		tracesSampleRate: 0.1,
		replaysSessionSampleRate: 0.1,
		replaysOnErrorSampleRate: 1.0,
		beforeSend(event) {
			// Redact sensitive data
			if (event.extra) {
				event.extra = redactSensitiveData(event.extra);
			}
			return event;
		},
	});
}

function redactSensitiveData(obj: Record<string, unknown>): Record<string, unknown> {
	const sensitiveKeys = [
		"apiKey",
		"api_key",
		"token",
		"password",
		"secret",
		"authorization",
		"x-api-key",
		"authToken",
		"dsn",
		"anthropic_api_key",
		"openclaw_gateway_token",
		"supabase_key",
	];

	const redacted: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(obj)) {
		const lowerKey = key.toLowerCase();
		if (sensitiveKeys.some((sk) => lowerKey.includes(sk))) {
			redacted[key] = "[Redacted]";
		} else if (typeof value === "object" && value !== null) {
			redacted[key] = redactSensitiveData(value as Record<string, unknown>);
		} else {
			redacted[key] = value;
		}
	}
	return redacted;
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
			{ path: "pricing", element: <PricingPage /> },
			{ path: "waitlist", element: <WaitlistPage /> },
			{ path: "demo", element: <DemoPage /> },
			{ path: "pilot", element: <PilotPage /> },
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
		<RouterProvider router={router} />
	</React.StrictMode>,
);
