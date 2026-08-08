/**
 * OpenTelemetry tracing for Singularity AIDR.
 * Provides distributed tracing for security decisions with configurable sampling.
 */

import {
	context,
	DiagConsoleLogger,
	DiagLogLevel,
	diag,
	propagation,
	type Span,
	SpanKind,
	type SpanOptions,
	type TextMapGetter,
	type TextMapSetter,
	type TimeInput,
	type Tracer,
	trace,
} from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { type Resource, resourceFromAttributes } from "@opentelemetry/resources";
import {
	BatchSpanProcessor,
	ConsoleSpanExporter,
	SimpleSpanProcessor,
	type SpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from "@opentelemetry/semantic-conventions";
import {
	redactTelemetryAttributes,
	redactTelemetryString,
	sanitizeTelemetryEndpoint,
} from "./telemetry-redaction.js";
import { VERSION } from "./version.js";

// ── Configuration ───────────────────────────────────────────────────────

export interface TracingConfig {
	enabled: boolean;
	samplingRate: number;
	otlpEndpoint?: string;
	consoleExporter: boolean;
	propagateW3c: boolean;
}

function getEnvBoolean(name: string, defaultValue: boolean): boolean {
	const value = process.env[name];
	if (value === undefined) return defaultValue;
	return value === "1" || value.toLowerCase() === "true";
}

function getEnvNumber(name: string, defaultValue: number): number {
	const value = process.env[name];
	if (value === undefined) return defaultValue;
	const parsed = Number.parseFloat(value);
	return Number.isNaN(parsed) ? defaultValue : Math.max(0, Math.min(1, parsed));
}

function getEnvString(name: string, defaultValue?: string): string | undefined {
	return process.env[name] || defaultValue;
}

export function loadTracingConfig(): TracingConfig {
	const configuredEndpoint = getEnvString("TRACE_OTLP_ENDPOINT");
	return {
		enabled: getEnvBoolean("TRACE_ENABLED", false),
		samplingRate: getEnvNumber("TRACE_SAMPLING", 1.0),
		// Query strings and URL credentials are a common way of accidentally
		// putting collector API keys into process configuration.  The exporter
		// only needs the origin/path.
		otlpEndpoint: sanitizeTelemetryEndpoint(configuredEndpoint),
		consoleExporter: getEnvBoolean("TRACE_CONSOLE_EXPORTER", true),
		propagateW3c: getEnvBoolean("TRACE_PROPAGATE_W3C", true),
	};
}

// ── Tracer Provider ──────────────────────────────────────────────────────

let tracerProvider: NodeTracerProvider | null = null;
let tracer: Tracer | null = null;
let tracingConfig: TracingConfig | null = null;

function createResource(): Resource {
	return resourceFromAttributes({
		[ATTR_SERVICE_NAME]: "aidr",
		[ATTR_SERVICE_VERSION]: VERSION,
		"deployment.environment": getEnvString("NODE_ENV", "development"),
	});
}

function createSampler(config: TracingConfig) {
	// Parent-based sampler with trace ID ratio for root spans
	return {
		shouldSample: (
			ctx: unknown,
			traceId: string,
			_spanName: string,
			_spanKind: SpanKind,
			_attributes: Record<string, unknown>,
			_links: unknown[],
		) => {
			// Always sample if parent is sampled
			const parentSpan = trace.getSpan(ctx as Parameters<typeof trace.getSpan>[0]);
			if (parentSpan?.spanContext().isRemote === false) {
				return { decision: 1 }; // RECORD_AND_SAMPLED
			}
			// For root spans, use trace ID ratio sampling
			// Trace ID is a 32-char hex string; use the last 8 chars for a hash
			const traceIdSuffix = traceId.slice(-8);
			const traceIdNum = Number.parseInt(traceIdSuffix, 16);
			const threshold = config.samplingRate * 0xffffffff;
			if (traceIdNum <= threshold) {
				return { decision: 1 }; // RECORD_AND_SAMPLED
			}
			return { decision: 0 }; // DROP
		},
		toString: () => `TraceIdRatioBased{${config.samplingRate}}`,
	};
}

export function initTracing(config?: Partial<TracingConfig>): void {
	if (tracerProvider) return; // Already initialized

	tracingConfig = { ...loadTracingConfig(), ...config };

	if (!tracingConfig.enabled) {
		diag.info("[aidr:tracing] Tracing disabled via TRACE_ENABLED");
		return;
	}

	// Set up diagnostics
	if (getEnvBoolean("TRACE_DEBUG", false)) {
		diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.DEBUG);
	}

	const resource = createResource();

	// Create processors array
	const processors: SpanProcessor[] = [];

	// Console exporter (for local debugging)
	if (tracingConfig.consoleExporter) {
		processors.push(new SimpleSpanProcessor(new ConsoleSpanExporter()));
	}

	// OTLP exporter (for remote collection)
	if (tracingConfig.otlpEndpoint) {
		const otlpExporter = new OTLPTraceExporter({
			url: tracingConfig.otlpEndpoint,
		});
		processors.push(new BatchSpanProcessor(otlpExporter));
	}

	tracerProvider = new NodeTracerProvider({
		resource,
		sampler: createSampler(tracingConfig),
		spanProcessors: processors,
	});

	tracerProvider.register();

	tracer = trace.getTracer("aidr", VERSION);

	diag.info(`[aidr:tracing] Initialized (sampling=${tracingConfig.samplingRate})`);
}

export function shutdownTracing(): Promise<void> {
	if (!tracerProvider) return Promise.resolve();
	const provider = tracerProvider;
	tracerProvider = null;
	tracer = null;
	tracingConfig = null;
	return provider.shutdown();
}

export function getTracer(): Tracer | null {
	if (!tracer) {
		// Auto-initialize if not done yet and enabled
		initTracing();
	}
	return tracer;
}

export function isTracingEnabled(): boolean {
	return tracingConfig?.enabled ?? false;
}

// ── Span Helpers ────────────────────────────────────────────────────────

export interface SpanContext {
	traceId: string;
	spanId: string;
	traceFlags: number;
	traceState?: string;
}

export function startSpan(
	name: string,
	options?: SpanOptions,
	parentContext?: ReturnType<typeof context.active>,
): Span | null {
	const tr = getTracer();
	if (!tr) return null;
	return tr.startSpan(name, options, parentContext);
}

export function startActiveSpan<T>(
	name: string,
	fn: (span: Span) => T | Promise<T>,
	options?: SpanOptions,
	parentContext?: ReturnType<typeof context.active>,
): Promise<T> | T {
	const tr = getTracer();
	if (!tr) {
		// Tracing disabled - just run the function
		const nullSpan = {
			setAttribute() {
				return this;
			},
			setAttributes() {
				return this;
			},
			addEvent() {
				return this;
			},
			recordException() {
				return this;
			},
			setStatus() {
				return this;
			},
			updateName() {
				return this;
			},
			end() {},
			spanContext() {
				return { traceId: "", spanId: "", traceFlags: 0 };
			},
			isRecording() {
				return false;
			},
			kind: SpanKind.INTERNAL,
		} as unknown as Span;
		return fn(nullSpan);
	}

	if (parentContext) {
		return context.with(parentContext, () => tr.startActiveSpan(name, options ?? {}, fn));
	}
	return tr.startActiveSpan(name, options ?? {}, fn);
}

export function endSpan(span: Span | null | undefined, endTime?: TimeInput): void {
	if (span) {
		span.end(endTime);
	}
}

// ── Context Propagation ────────────────────────────────────────────────

export function extractTraceContext(
	carrier: Record<string, unknown>,
): ReturnType<typeof context.active> | undefined {
	if (!tracingConfig?.enabled || !tracingConfig?.propagateW3c) return undefined;

	const getter: TextMapGetter<Record<string, unknown>> = {
		get: (h, key) => h[key] as string | string[] | undefined,
		keys: (h) => Object.keys(h),
	};

	// Use trace API to extract context from W3C headers
	const extracted = propagation.extract(context.active(), carrier, getter);
	return extracted;
}

export function injectTraceContext(carrier: Record<string, string>): void {
	if (!tracingConfig?.enabled || !tracingConfig?.propagateW3c) return;

	const setter: TextMapSetter<Record<string, string>> = {
		set: (h, key, value) => {
			h[key] = value;
		},
	};

	propagation.inject(context.active(), carrier, setter);
}

export function getCurrentSpan(): Span | undefined {
	return trace.getSpan(context.active());
}

export function getSpanContext(): SpanContext | undefined {
	const span = getCurrentSpan();
	if (!span) return undefined;
	const sc = span.spanContext();
	if (!sc.traceId) return undefined;
	return {
		traceId: sc.traceId,
		spanId: sc.spanId,
		traceFlags: sc.traceFlags,
		traceState: sc.traceState?.serialize(),
	};
}

export function setSpanAttribute(key: string, value: string | number | boolean): void {
	const span = getCurrentSpan();
	if (span) {
		span.setAttribute(key, typeof value === "string" ? redactTelemetryString(value, 500) : value);
	}
}

export function setSpanAttributes(attributes: Record<string, string | number | boolean>): void {
	const span = getCurrentSpan();
	if (span) {
		span.setAttributes(redactTelemetryAttributes(attributes));
	}
}

export function addSpanEvent(
	name: string,
	attributes?: Record<string, string | number | boolean>,
): void {
	const span = getCurrentSpan();
	if (span) {
		span.addEvent(
			redactTelemetryString(name, 200),
			attributes && redactTelemetryAttributes(attributes),
		);
	}
}

export function recordException(
	error: Error,
	attributes?: Record<string, string | number | boolean>,
): void {
	const span = getCurrentSpan();
	if (span) {
		// Set attributes first, then record the exception
		if (attributes) {
			span.setAttributes(redactTelemetryAttributes(attributes));
		}
		// Do not attach the original stack/error object: it can contain the
		// command, prompt or URL that caused the failed decision.
		span.recordException({
			name: redactTelemetryString(error.name || "Error", 100),
			message: redactTelemetryString(error.message, 1000),
		});
	}
}

// ── Convenience Helpers for Security Decisions ─────────────────────────

export interface SecurityDecisionAttributes {
	toolName: string;
	sessionId: string;
	decision: string;
	category: string;
	confidence: number;
	severity: string;
	artifactsCount: number;
	matchedThreatId?: string | null;
	reasons?: string[];
	durationMs?: number;
}

export function setSecurityDecisionAttributes(attrs: SecurityDecisionAttributes): void {
	setSpanAttributes({
		"aidr.tool_name": redactTelemetryString(attrs.toolName, 100),
		"aidr.session_id": redactTelemetryString(attrs.sessionId, 200),
		"aidr.decision": redactTelemetryString(attrs.decision, 50),
		"aidr.category": redactTelemetryString(attrs.category, 100),
		"aidr.confidence": attrs.confidence,
		"aidr.severity": redactTelemetryString(attrs.severity, 50),
		"aidr.artifacts_count": attrs.artifactsCount,
		...(attrs.matchedThreatId
			? { "aidr.matched_threat_id": redactTelemetryString(attrs.matchedThreatId, 100) }
			: {}),
		...(attrs.durationMs ? { "aidr.duration_ms": attrs.durationMs } : {}),
	});

	if (attrs.reasons && attrs.reasons.length > 0) {
		addSpanEvent("security_decision_reasons", {
			// Keep enough context for grouping, but never attach arbitrary prompt
			// or command text to a remote span.
			"aidr.reasons": attrs.reasons.map((reason) => redactTelemetryString(reason, 300)).join("; "),
		});
	}
}

export interface DetectionPhaseAttributes {
	phase: string;
	artifactType?: string;
	artifactCount?: number;
	matchCount?: number;
	cacheHit?: boolean;
	durationMs: number;
}

export function recordDetectionPhase(attrs: DetectionPhaseAttributes): void {
	const eventAttributes: Record<string, string | number | boolean> = {
		"aidr.phase": attrs.phase,
		"aidr.duration_ms": attrs.durationMs,
	};
	if (attrs.artifactType) {
		eventAttributes["aidr.artifact_type"] = attrs.artifactType;
	}
	if (attrs.artifactCount !== undefined) {
		eventAttributes["aidr.artifact_count"] = attrs.artifactCount;
	}
	if (attrs.matchCount !== undefined) {
		eventAttributes["aidr.match_count"] = attrs.matchCount;
	}
	if (attrs.cacheHit !== undefined) {
		eventAttributes["aidr.cache_hit"] = attrs.cacheHit;
	}
	addSpanEvent(`detection_phase:${attrs.phase}`, eventAttributes);
}
