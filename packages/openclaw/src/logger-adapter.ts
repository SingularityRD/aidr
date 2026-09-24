/**
 * Bridges OpenClaw's PluginLogger to the core Logger interface.
 */

import { type Logger, redactTelemetryData, redactTelemetryString } from "@singularityrd/aidr-core";

/** Mirrors OpenClaw's PluginLogger type without importing it. */
export interface PluginLogger {
	debug?(msg: string): void;
	info(msg: string): void;
	warn(msg: string): void;
	error(msg: string): void;
}

export function createLogger(pluginLogger: PluginLogger): Logger {
	function formatMessage(msg: string, data?: unknown): string {
		const safeMessage = redactTelemetryString(msg);
		return data ? `${safeMessage} ${JSON.stringify(redactTelemetryData(data))}` : safeMessage;
	}

	return {
		debug(msg, data?) {
			pluginLogger.debug?.(formatMessage(msg, data));
		},
		info(msg, data?) {
			pluginLogger.info(formatMessage(msg, data));
		},
		warn(msg, data?) {
			pluginLogger.warn(formatMessage(msg, data));
		},
		error(msg, data?) {
			pluginLogger.error(formatMessage(msg, data));
		},
	};
}
