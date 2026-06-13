import * as Sentry from "@sentry/browser";

export function initSentry(): void {
	Sentry.init({
		dsn: process.env.SENTRY_DSN,
		environment: process.env.SENTRY_ENVIRONMENT || "development",
		integrations: [Sentry.browserTracingIntegration()],
	});
}
