import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	addSpanEvent,
	endSpan,
	extractTraceContext,
	getSpanContext,
	initTracing,
	injectTraceContext,
	isTracingEnabled,
	loadTracingConfig,
	recordDetectionPhase,
	recordException,
	setSecurityDecisionAttributes,
	setSpanAttribute,
	setSpanAttributes,
	shutdownTracing,
	startActiveSpan,
	startSpan,
} from "../tracing.js";

const ORIGINAL_ENV = { ...process.env };

describe("tracing", () => {
	beforeEach(async () => {
		await shutdownTracing();
		process.env = { ...ORIGINAL_ENV };
		delete process.env.TRACE_ENABLED;
		delete process.env.TRACE_SAMPLING;
		delete process.env.TRACE_OTLP_ENDPOINT;
		delete process.env.TRACE_CONSOLE_EXPORTER;
		delete process.env.TRACE_PROPAGATE_W3C;
		delete process.env.TRACE_DEBUG;
	});

	afterEach(async () => {
		await shutdownTracing();
		process.env = { ...ORIGINAL_ENV };
	});

	it("loads tracing configuration from bounded environment values", () => {
		process.env.TRACE_ENABLED = "true";
		process.env.TRACE_SAMPLING = "2.5";
		process.env.TRACE_OTLP_ENDPOINT = "https://collector.example.invalid/v1/traces";
		process.env.TRACE_CONSOLE_EXPORTER = "0";
		process.env.TRACE_PROPAGATE_W3C = "false";

		expect(loadTracingConfig()).toEqual({
			enabled: true,
			samplingRate: 1,
			otlpEndpoint: "https://collector.example.invalid/v1/traces",
			consoleExporter: false,
			propagateW3c: false,
		});

		process.env.TRACE_SAMPLING = "not-a-number";
		expect(loadTracingConfig().samplingRate).toBe(1);
		process.env.TRACE_SAMPLING = "-1";
		expect(loadTracingConfig().samplingRate).toBe(0);
	});

	it("runs span helpers safely when tracing is disabled", async () => {
		initTracing({ enabled: false, propagateW3c: false });

		expect(isTracingEnabled()).toBe(false);
		expect(startSpan("disabled")).toBeNull();
		let sawNullSpan = false;
		const result = await startActiveSpan("disabled-active", async (span) => {
			sawNullSpan = !span.isRecording() && span.spanContext().traceId === "";
			span
				.setAttribute("aidr.test", true)
				.setAttributes({ "aidr.count": 1 })
				.addEvent("event")
				.recordException(new Error("ignored"))
				.setStatus({ code: 1 })
				.updateName("renamed")
				.end();
			return "ok";
		});

		expect(result).toBe("ok");
		expect(sawNullSpan).toBe(true);
		expect(getSpanContext()).toBeUndefined();
		expect(extractTraceContext({ traceparent: "00-invalid" })).toBeUndefined();

		const carrier: Record<string, string> = {};
		injectTraceContext(carrier);
		expect(carrier).toEqual({});

		expect(() => {
			endSpan(null);
			setSpanAttribute("aidr.key", "value");
			setSpanAttributes({ "aidr.bool": true });
			addSpanEvent("ignored");
			recordException(new Error("ignored"), { "aidr.safe": true });
			recordDetectionPhase({ phase: "rules", durationMs: 5, cacheHit: false });
			setSecurityDecisionAttributes({
				toolName: "Bash",
				sessionId: "session",
				decision: "allow",
				category: "command",
				confidence: 0.9,
				severity: "low",
				artifactsCount: 1,
				matchedThreatId: null,
				reasons: ["clean"],
				durationMs: 12,
			});
		}).not.toThrow();
	});
});
