/**
 * Singularity AIDR Sentry Integration
 * Error tracking and performance monitoring for all packages
 */

import type { Span } from "@sentry/node";
import { getInstallationId } from "./installation-id.js";
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

function getSentryConfig(): SentryConfig {
	return {
		dsn: process.env.SENTRY_DSN,
		environment: process.env.NODE_ENV || "development",
		release: process.env.SENTRY_RELEASE || getVersion(),
		sampleRate: parseFloat(process.env.SENTRY_SAMPLE_RATE || "1.0"),
		tracesSampleRate: parseFloat(process.env.SENTRY_TRACES_SAMPLE_RATE || "0.1"),
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

	const cfg = { ...getSentryConfig(), ...config };

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
			debug: cfg.debug,

			// Set user context with installation ID (anonymous)
			initialScope: {
				user: { id: installationId },
				tags: {
					package: cfg.name || process.env.AIDR_PACKAGE_NAME || "unknown",
					runtime: process.env.AIDR_RUNTIME || "unknown",
				},
			},

			// Filter sensitive data
			beforeSend(event) {
				// Redact sensitive fields
				if (event.extra) {
					event.extra = redactSensitiveData(event.extra as Record<string, unknown>);
				}
				if (event.contexts) {
					// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
					event.contexts = redactSensitiveData(
						event.contexts as Record<string, unknown>,
					) as typeof event.contexts;
				}
				return event;
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
function redactSensitiveData(obj: Record<string, unknown>): Record<string, unknown> {
	const sensitiveKeyPatterns = [
		"apikey",
		"api_key",
		"token",
		"password",
		"secret",
		"authorization",
		"x-api-key",
		"authtoken",
		"dsn",
		"anthropic_api_key",
		"openclaw_gateway_token",
	];

	const redacted: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(obj)) {
		const lowerKey = key.toLowerCase();
		if (sensitiveKeyPatterns.some((pattern) => lowerKey.includes(pattern))) {
			redacted[key] = "[Redacted]";
		} else if (typeof value === "object" && value !== null) {
			redacted[key] = redactSensitiveData(value as Record<string, unknown>);
		} else {
			redacted[key] = value;
		}
	}
	return redacted;
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

	return Sentry.captureException(error, { extra: context });
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

	return Sentry.captureMessage(message, { level, extra: context });
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

	return Sentry.startSpan({ name, op: "aidr" }, operation);
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
	Sentry.setUser(user);
}

/**
 * Set tags for the current scope
 */
export async function setTags(tags: Record<string, string>): Promise<void> {
	const Sentry = await loadSentry().catch(() => null);
	if (!Sentry) return;
	Sentry.setTags(tags);
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
