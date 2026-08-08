/**
 * Singularity AIDR Sentry Integration
 * Error tracking and performance monitoring for all packages
 */

import type { Span } from "@sentry/node";
import { getInstallationId } from "./installation-id.js";
import {
	REDACTED_TELEMETRY_VALUE,
	redactTelemetryData,
	redactTelemetryString,
} from "./telemetry-redaction.js";
import { getVersion } from "./version.js";

let initialized = false;
let sentryModule: typeof import("@sentry/node") | null = null;

async function loadSentry(): Promise<typeof import("@sentry/node")> {
	if (!sentryModule) {
		sentryModule = await import("@sentry/node");
	}
	return sentryModule;
}

export interface SentryConfig {
	dsn?: string;
	environment?: string;
	release?: string;
	sampleRate?: number;
	tracesSampleRate?: number;
	debug?: boolean;
	enabled?: boolean;
	name?: string;
}

function boundedSampleRate(value: string | undefined, fallback: number): number {
	const parsed = Number.parseFloat(value ?? "");
	return Number.isFinite(parsed) ? Math.max(0, Math.min(1, parsed)) : fallback;
}

function getSentryConfig(): SentryConfig {
	return {
		dsn: process.env.SENTRY_DSN,
		environment: process.env.NODE_ENV || "development",
		release: process.env.SENTRY_RELEASE || getVersion(),
		sampleRate: boundedSampleRate(process.env.SENTRY_SAMPLE_RATE, 1),
		tracesSampleRate: boundedSampleRate(process.env.SENTRY_TRACES_SAMPLE_RATE, 0.1),
		debug: process.env.SENTRY_DEBUG === "true" || process.env.SENTRY_DEBUG === "1",
		enabled:
			process.env.SENTRY_ENABLED !== "false" &&
			process.env.SENTRY_ENABLED !== "0" &&
			!!process.env.SENTRY_DSN,
	};
}

/**
 * Initialize Sentry with AIDR configuration
 * Safe to call multiple times - subsequent calls are no-ops
 */
export async function initSentry(config?: Partial<SentryConfig>): Promise<void> {
	if (initialized) return;

	const configured = { ...getSentryConfig(), ...config };
	const cfg = {
		...configured,
		sampleRate: Math.max(0, Math.min(1, configured.sampleRate ?? 1)),
		tracesSampleRate: Math.max(0, Math.min(1, configured.tracesSampleRate ?? 0.1)),
	};

	if (!cfg.enabled || !cfg.dsn) {
		initialized = true;
		return;
	}

	try {
		const Sentry = await loadSentry();
		const installationId = await getInstallationId();

		Sentry.init({
			dsn: cfg.dsn,
			environment: cfg.environment,
			release: cfg.release,
			sampleRate: cfg.sampleRate,
			tracesSampleRate: cfg.tracesSampleRate,
			sendDefaultPii: false,
			debug: cfg.debug,

			// Set user context with installation ID (anonymous)
			initialScope: {
				user: { id: installationId },
				tags: {
					package: cfg.name || process.env.AIDR_PACKAGE_NAME || "unknown",
					runtime: process.env.AIDR_RUNTIME || "unknown",
				},
			},

			// Never send raw request URLs, exception messages, breadcrumbs, or
			// arbitrary context to a third-party telemetry sink.
			beforeSend(event) {
				return redactSentryEvent(
					event as unknown as Record<string, unknown>,
				) as unknown as typeof event;
			},
			beforeSendTransaction(event) {
				return redactSentryEvent(
					event as unknown as Record<string, unknown>,
				) as unknown as typeof event;
			},
			beforeBreadcrumb(breadcrumb) {
				return redactTelemetryData(breadcrumb) as typeof breadcrumb;
			},
		});

		initialized = true;
	} catch {
		// Fail silently - Sentry is optional
		initialized = true;
	}
}

// Sync version for backward compatibility - queues async init
export function initSentrySync(config?: Partial<SentryConfig>): void {
	if (initialized) return;
	// Fire and forget - async init will handle actual setup
	void initSentry(config);
}

/**
 * Redact sensitive data from event context
 */
/** Recursively redact arbitrary Sentry context (exported for integration tests). */
export function redactSensitiveData(obj: Record<string, unknown>): Record<string, unknown> {
	return redactTelemetryData(obj);
}

/**
 * Sentry's default event serializer includes fields that are outside `extra`
 * (exception values, request URLs, breadcrumbs and tags).  Redacting only
 * `extra` is therefore insufficient for a production deployment.
 */
function redactSentryException(exception: unknown): unknown {
	if (!exception || typeof exception !== "object" || Array.isArray(exception)) return exception;
	const values = (exception as Record<string, unknown>).values;
	if (!Array.isArray(values)) return exception;
	for (const value of values) {
		if (!value || typeof value !== "object") continue;
		const record = value as Record<string, unknown>;
		if (typeof record.value === "string") record.value = redactTelemetryString(record.value);
		// Stack traces may include command-line arguments and query strings.
		if (record.stacktrace && typeof record.stacktrace === "object") {
			record.stacktrace = redactTelemetryData(record.stacktrace);
		}
	}
	return exception;
}

function redactSentryRequest(request: unknown): unknown {
	if (!request || typeof request !== "object" || Array.isArray(request)) return request;
	const record = request as Record<string, unknown>;
	if (typeof record.url === "string") record.url = redactTelemetryString(record.url);
	if (typeof record.query_string === "string") {
		record.query_string = redactTelemetryString(record.query_string);
	}
	return request;
}

function redactSentryUser(user: unknown): unknown {
	if (!user || typeof user !== "object" || Array.isArray(user)) return user;
	const record = user as Record<string, unknown>;
	// Explicitly replace values rather than dropping fields, keeping Sentry
	// grouping stable while preventing accidental PII collection.
	if (typeof record.email === "string") record.email = REDACTED_TELEMETRY_VALUE;
	if (typeof record.username === "string") record.username = REDACTED_TELEMETRY_VALUE;
	return user;
}

export function redactSentryEvent<T extends Record<string, unknown>>(event: T): T {
	const safe = redactTelemetryData(event) as T;
	const mutable = safe as Record<string, unknown>;
	if (typeof mutable.message === "string") mutable.message = redactTelemetryString(mutable.message);
	if (typeof mutable.transaction === "string") {
		mutable.transaction = redactTelemetryString(mutable.transaction, 200);
	}
	mutable.exception = redactSentryException(mutable.exception);
	mutable.request = redactSentryRequest(mutable.request);
	mutable.user = redactSentryUser(mutable.user);
	return safe;
}

/**
 * Capture an error to Sentry
 */
export async function captureException(
	error: Error,
	context?: Record<string, unknown>,
): Promise<string> {
	if (!initialized) await initSentry();

	const Sentry = await loadSentry().catch(() => null);
	if (!Sentry?.getClient()) {
		return "";
	}

	return Sentry.captureException(error, { extra: redactSensitiveData(context ?? {}) });
}

/**
 * Capture a message to Sentry
 */
export async function captureMessage(
	message: string,
	level: "fatal" | "error" | "warning" | "info" | "debug" = "info",
	context?: Record<string, unknown>,
): Promise<string> {
	if (!initialized) await initSentry();

	const Sentry = await loadSentry().catch(() => null);
	if (!Sentry?.getClient()) {
		return "";
	}

	return Sentry.captureMessage(redactTelemetryString(message), {
		level,
		extra: redactSensitiveData(context ?? {}),
	});
}

/**
 * Create a span for performance tracking
 */
export async function startSpan<T>(name: string, operation: (span: Span) => T): Promise<T> {
	if (!initialized) await initSentry();

	const Sentry = await loadSentry().catch(() => null);
	if (!Sentry) {
		// Fallback: run operation without span
		return operation({} as Span);
	}

	return Sentry.startSpan({ name: redactTelemetryString(name, 200), op: "aidr" }, operation);
}

/**
 * Wrap a function with Sentry error tracking
 */
export function withSentry<T extends (...args: unknown[]) => unknown>(
	fn: T,
	context?: Record<string, unknown>,
): (...args: Parameters<T>) => ReturnType<T> {
	return (...args: Parameters<T>): ReturnType<T> => {
		try {
			const result = fn(...args);
			if (result instanceof Promise) {
				return result.catch((error: unknown) => {
					void captureException(error as Error, { ...context, args });
					throw error;
				}) as ReturnType<T>;
			}
			return result as ReturnType<T>;
		} catch (error) {
			void captureException(error as Error, { ...context, args });
			throw error;
		}
	};
}

/**
 * Set user context
 */
export async function setUser(user: { id?: string; username?: string }): Promise<void> {
	const Sentry = await loadSentry().catch(() => null);
	if (!Sentry) return;
	// Usernames are commonly emails/PII.  The anonymous installation ID is
	// already attached by initSentry; do not send an additional identifier.
	Sentry.setUser(user.id ? { id: redactTelemetryString(user.id, 200) } : null);
}

/**
 * Set tags for the current scope
 */
export async function setTags(tags: Record<string, string>): Promise<void> {
	const Sentry = await loadSentry().catch(() => null);
	if (!Sentry) return;
	const safeTags: Record<string, string> = {};
	for (const [key, value] of Object.entries(tags)) {
		safeTags[key] = redactTelemetryString(value, 200);
	}
	Sentry.setTags(safeTags);
}

/**
 * Flush events to Sentry (useful before process exit)
 */
export async function flush(timeout?: number): Promise<boolean> {
	const Sentry = await loadSentry().catch(() => null);
	if (!Sentry) return false;
	return Sentry.flush(timeout);
}

/**
 * Close Sentry client
 */
export async function close(timeout?: number): Promise<void> {
	const Sentry = await loadSentry().catch(() => null);
	if (!Sentry) return;
	await Sentry.close(timeout);
}

/**
 * Check if Sentry is initialized
 */
export function isSentryInitialized(): boolean {
	return initialized;
}
