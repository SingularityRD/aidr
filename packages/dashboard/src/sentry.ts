import * as Sentry from "@sentry/browser";

export function initSentry(): void {
	Sentry.init({
		dsn: import.meta.env.VITE_SENTRY_DSN,
		environment: import.meta.env.VITE_SENTRY_ENVIRONMENT || "development",
		integrations: [Sentry.browserTracingIntegration()],
	});
}
