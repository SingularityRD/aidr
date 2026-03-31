/**
 * Singularity AIDR Logger
 * Lightweight Pino-based logging with JSON output and redaction
 */

import { createWriteStream, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import pino from "pino";
import { AIDR_DIR } from "./config.js";

export type LogLevel = "error" | "warn" | "info" | "debug";

const SENSITIVE_FIELDS = [
	"api_key",
	"apiKey",
	"token",
	"access_token",
	"accessToken",
	"auth_token",
	"authToken",
	"password",
	"secret",
	"secret_key",
	"secretKey",
	"private_key",
	"privateKey",
	"anthropic_api_key",
	"openclaw_gateway_token",
	"sentry_dsn",
	"dsn",
];

function redactSensitivePaths(): string[] {
	const paths: string[] = [];
	for (const field of SENSITIVE_FIELDS) {
		paths.push(`*.${field}`);
		paths.push(`${field}`);
	}
	paths.push("headers.authorization", "headers.x-api-key", "config.apiKey", "config.token");
	return paths;
}

function getLogLevel(): LogLevel {
	const envLevel = process.env.AIDR_LOG_LEVEL?.toLowerCase();
	if (envLevel && ["error", "warn", "info", "debug"].includes(envLevel)) {
		return envLevel as LogLevel;
	}
	return "info";
}

function shouldLogToFile(): boolean {
	return process.env.AIDR_LOG_TO_FILE === "true" || process.env.AIDR_LOG_TO_FILE === "1";
}

function getLogFilePath(): string {
	return process.env.AIDR_LOG_FILE_PATH || `${AIDR_DIR}/logs/aidr.log`;
}

export function createLogger(options?: { name?: string; level?: LogLevel }): pino.Logger {
	const level = options?.level ?? getLogLevel();
	const name = options?.name ?? "aidr";

	const config: pino.LoggerOptions = {
		name,
		level,
		base: { pid: process.pid, env: process.env.NODE_ENV ?? "development" },
		redact: { paths: redactSensitivePaths(), remove: false, censor: "[Redacted]" },
		timestamp: pino.stdTimeFunctions.isoTime,
		formatters: { level: (l) => ({ level: l.toUpperCase() }) },
	};

	if (shouldLogToFile()) {
		const logPath = getLogFilePath();
		mkdirSync(dirname(logPath), { recursive: true });
		return pino(
			config,
			pino.multistream([
				{ level, stream: pino.destination(2) },
				{ level, stream: createWriteStream(logPath, { flags: "a" }) },
			]),
		);
	}

	return pino(config, pino.destination(2));
}

let defaultLogger: pino.Logger | null = null;

export function getLogger(): pino.Logger {
	if (!defaultLogger) defaultLogger = createLogger();
	return defaultLogger;
}

export function setLogger(logger: pino.Logger): void {
	defaultLogger = logger;
}

export function createChildLogger(
	parent: pino.Logger,
	component: string,
	meta?: Record<string, unknown>,
): pino.Logger {
	return parent.child({ component, ...meta });
}

export type { Logger } from "pino";
export { pino };
