import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as core from "../index.js";
import {
	addSpanEvent,
	ConfigSchema,
	type ControlPlaneConfig,
	ControlPlaneConfigSchema,
	endSpan,
	type FileCheckConfig,
	FileCheckConfigSchema,
	getCurrentSpan,
	getSpanContext,
	initTracing,
	isTracingEnabled,
	loadTracingConfig,
	recordDetectionPhase,
	recordException,
	redactTelemetryAttributes,
	sanitizeTelemetryEndpoint,
	setSecurityDecisionAttributes,
	setSpanAttribute,
	setSpanAttributes,
	shutdownTracing,
	startActiveSpan,
	startSpan,
	type UrlCheckConfig,
	UrlCheckConfigSchema,
} from "../index.js";
import { McpTransportError } from "../mcp-transport.js";
import { inspectConfiguredSiemDelivery } from "../siem-incident-producer.js";
import { extractTraceContext, injectTraceContext } from "../tracing.js";
import { type NvdConfig, NvdConfigSchema } from "../types.js";

const legacyControlPlaneConfig: ControlPlaneConfig = {
	enabled: true,
	endpoint: "https://control.example.test",
	timeout_seconds: 0.5,
	send_audit_logs: true,
	send_clean_verdicts: false,
	sync_incidents: false,
	grace_period_hours: 72,
	redact_mode: "hash",
	remote_policy_cache_path: "~/.singularity-aidr/remote-policy-cache",
	remote_policy_cache_enabled: true,
	remote_policy_required: false,
	response_worker_required: false,
	remote_policy_offline_grace_seconds: 3600,
};
const legacyUrlConfig: UrlCheckConfig = { enabled: true, timeout_seconds: 5 };
const legacyFileConfig: FileCheckConfig = { enabled: true, timeout_seconds: 5 };
const tracingEnvKeys = [
	"TRACE_ENABLED",
	"TRACE_SAMPLING",
	"TRACE_OTLP_ENDPOINT",
	"TRACE_CONSOLE_EXPORTER",
	"TRACE_PROPAGATE_W3C",
] as const;
const originalTracingEnv = new Map(tracingEnvKeys.map((key) => [key, process.env[key]]));

describe("public API compatibility", () => {
	beforeEach(async () => {
		await shutdownTracing();
		for (const key of tracingEnvKeys) delete process.env[key];
	});

	afterEach(async () => {
		await shutdownTracing();
		for (const key of tracingEnvKeys) {
			const value = originalTracingEnv.get(key);
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}
	});

	it("retains the deprecated tracing root exports", () => {
		for (const name of [
			"addSpanEvent",
			"endSpan",
			"getCurrentSpan",
			"getSpanContext",
			"getTracer",
			"initTracing",
			"isTracingEnabled",
			"loadTracingConfig",
			"recordDetectionPhase",
			"recordException",
			"setSecurityDecisionAttributes",
			"setSpanAttribute",
			"setSpanAttributes",
			"shutdownTracing",
			"startActiveSpan",
			"startSpan",
		] as const) {
			expect(core[name], name).toBeTypeOf("function");
		}
	});

	it("keeps config schemas composable and defaults loopback opt-ins", () => {
		expect(ControlPlaneConfigSchema.partial).toBeTypeOf("function");
		expect(ControlPlaneConfigSchema.parse(legacyControlPlaneConfig).allow_insecure_loopback).toBe(
			false,
		);
		expect(UrlCheckConfigSchema.parse(legacyUrlConfig).allow_insecure_loopback).toBe(false);
		expect(FileCheckConfigSchema.parse(legacyFileConfig).allow_insecure_loopback).toBe(false);
	});

	it("accepts deprecated NVD configuration without enabling a runtime", () => {
		const config = ConfigSchema.parse({ nvd_check: { enabled: false, api_key: "legacy" } });
		expect(config.nvd_check.enabled).toBe(false);
		expect(config.nvd_check.api_key).toBe("legacy");

		const directModuleConfig: NvdConfig = NvdConfigSchema.parse({ enabled: false });
		expect(directModuleConfig.enabled).toBe(false);
	});

	it("retains direct-module contracts used by shipped workers", () => {
		const transportError = new McpTransportError("compat", "compatibility check");
		expect(transportError.code).toBe("compat");
		expect(inspectConfiguredSiemDelivery).toBeTypeOf("function");

		expect(extractTraceContext({ traceparent: "00-legacy" })).toBeUndefined();
		const carrier: Record<string, string> = {};
		injectTraceContext(carrier);
		expect(carrier).toEqual({});
	});

	it("keeps dependency-free telemetry and tracing helpers callable", async () => {
		expect(
			sanitizeTelemetryEndpoint("https://user:secret@collector.test/v1/traces?token=secret"),
		).toBe("https://collector.test/v1/traces");
		expect(redactTelemetryAttributes({ authorization: "secret", count: 1 })).toEqual({
			authorization: "[Redacted]",
			count: 1,
		});

		initTracing({ enabled: true, samplingRate: 1 });
		const result = await startActiveSpan("compat", async (span) => {
			expect(span.isRecording()).toBe(true);
			span.end();
			expect(span.durationMs).toBeGreaterThanOrEqual(0);
			return "ok";
		});
		expect(result).toBe("ok");
	});

	it("parses tracing environment values and clamps the sampling rate", () => {
		process.env.TRACE_ENABLED = "true";
		process.env.TRACE_SAMPLING = "2.5";
		process.env.TRACE_OTLP_ENDPOINT = "https://collector.test/v1/traces?token=secret";
		process.env.TRACE_CONSOLE_EXPORTER = "false";
		process.env.TRACE_PROPAGATE_W3C = "0";

		expect(loadTracingConfig()).toEqual({
			enabled: true,
			samplingRate: 1,
			otlpEndpoint: "https://collector.test/v1/traces",
			consoleExporter: false,
			propagateW3c: false,
		});

		process.env.TRACE_SAMPLING = "-1";
		expect(loadTracingConfig().samplingRate).toBe(0);
		process.env.TRACE_SAMPLING = "not-a-number";
		expect(loadTracingConfig().samplingRate).toBe(1);
	});

	it("keeps disabled spans and helper calls safe", async () => {
		initTracing({ enabled: false, propagateW3c: false });

		expect(isTracingEnabled()).toBe(false);
		expect(startSpan("disabled")).toBeNull();
		const result = await startActiveSpan("disabled-active", async (span) => {
			expect(span.isRecording()).toBe(false);
			expect(span.spanContext()).toEqual({ traceId: "", spanId: "", traceFlags: 0 });
			expect(getCurrentSpan()).toBeUndefined();
			expect(getSpanContext()).toBeUndefined();

			expect(() => {
				endSpan(null);
				setSpanAttribute("aidr.key", "value");
				setSpanAttributes({ "aidr.bool": true });
				addSpanEvent("ignored");
				recordException(new Error("ignored"));
				recordDetectionPhase({ phase: "rules", durationMs: 5, cacheHit: false });
				setSecurityDecisionAttributes({
					toolName: "Bash",
					sessionId: "session",
					decision: "allow",
					category: "command",
					confidence: 0.9,
					severity: "low",
					artifactsCount: 1,
				});
			}).not.toThrow();
			return "ok";
		});

		expect(result).toBe("ok");
	});

	it("redacts values before forwarding span attributes and events", async () => {
		initTracing({ enabled: true, samplingRate: 1 });
		const directAttributes: Record<string, string | number | boolean> = {};
		const bulkAttributes: Record<string, string | number | boolean> = {};
		const events: Array<{
			name: string;
			attributes?: Record<string, string | number | boolean>;
		}> = [];

		await startActiveSpan("redaction", (span) => {
			span.setAttribute = (key, value) => {
				directAttributes[key] = value;
				return span;
			};
			span.setAttributes = (attributes) => {
				Object.assign(bulkAttributes, attributes);
				return span;
			};
			span.addEvent = (name, attributes) => {
				events.push({ name, attributes });
				return span;
			};

			setSpanAttribute("aidr.note", "tool input token=live-secret");
			setSpanAttributes({
				authorization: "Bearer bulk-secret",
				"http.url": "https://example.test/?api_key=url-secret",
				"aidr.count": 2,
			});
			addSpanEvent("tool input token=event-secret", {
				authorization: "Bearer event-secret",
			});
		});

		expect(directAttributes).toEqual({ "aidr.note": "tool input token=[Redacted]" });
		expect(bulkAttributes).toEqual({
			authorization: "[Redacted]",
			"http.url": "https://example.test/?api_key=[Redacted]",
			"aidr.count": 2,
		});
		expect(events).toEqual([
			{
				name: "tool input token=[Redacted]",
				attributes: { authorization: "[Redacted]" },
			},
		]);
	});
});
