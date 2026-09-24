/**
 * @deprecated Distributed tracing was removed. This dependency-free shim keeps
 * the published API source-compatible and records only in-process timings.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import {
	redactTelemetryAttributes,
	redactTelemetryString,
	sanitizeTelemetryEndpoint,
} from "./telemetry-redaction.js";

export interface TracingConfig {
	enabled: boolean;
	samplingRate: number;
	otlpEndpoint?: string;
	consoleExporter: boolean;
	propagateW3c: boolean;
}

export interface SpanContext {
	traceId: string;
	spanId: string;
	traceFlags: number;
	traceState?: string;
}

export interface TracingSpan {
	readonly kind: number;
	readonly durationMs?: number;
	setAttribute(key: string, value: string | number | boolean): this;
	setAttributes(attributes: Record<string, string | number | boolean>): this;
	addEvent(name: string, attributes?: Record<string, string | number | boolean>): this;
	recordException(error: Error | { name?: string; message?: string }): this;
	setStatus(status: unknown): this;
	updateName(name: string): this;
	end(endTime?: number | Date | [number, number]): void;
	spanContext(): SpanContext;
	isRecording(): boolean;
}

export interface TracingSpanOptions {
	attributes?: Record<string, string | number | boolean>;
	[key: string]: unknown;
}

export interface TracingTracer {
	startSpan(name: string, options?: TracingSpanOptions, parentContext?: unknown): TracingSpan;
	startActiveSpan<T>(
		name: string,
		optionsOrFn: TracingSpanOptions | ((span: TracingSpan) => T | Promise<T>),
		contextOrFn?: unknown | ((span: TracingSpan) => T | Promise<T>),
		fn?: (span: TracingSpan) => T | Promise<T>,
	): T | Promise<T>;
}

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

export interface DetectionPhaseAttributes {
	phase: string;
	artifactType?: string;
	artifactCount?: number;
	matchCount?: number;
	cacheHit?: boolean;
	durationMs: number;
}

function envBoolean(name: string, fallback: boolean): boolean {
	const value = process.env[name];
	return value === undefined ? fallback : value === "1" || value.toLowerCase() === "true";
}

function envSamplingRate(): number {
	const value = Number.parseFloat(process.env.TRACE_SAMPLING ?? "1");
	return Number.isNaN(value) ? 1 : Math.max(0, Math.min(1, value));
}

export function loadTracingConfig(): TracingConfig {
	return {
		enabled: envBoolean("TRACE_ENABLED", false),
		samplingRate: envSamplingRate(),
		otlpEndpoint: sanitizeTelemetryEndpoint(process.env.TRACE_OTLP_ENDPOINT),
		consoleExporter: envBoolean("TRACE_CONSOLE_EXPORTER", true),
		propagateW3c: envBoolean("TRACE_PROPAGATE_W3C", true),
	};
}

class LocalSpan implements TracingSpan {
	readonly kind = 0;
	durationMs?: number;
	private readonly startedAt = performance.now();
	private readonly context: SpanContext;
	private ended = false;

	constructor(
		private name: string,
		private readonly recording: boolean,
		parent?: SpanContext,
	) {
		this.context = recording
			? {
					traceId: parent?.traceId ?? randomBytes(16).toString("hex"),
					spanId: randomBytes(8).toString("hex"),
					traceFlags: 1,
				}
			: { traceId: "", spanId: "", traceFlags: 0 };
	}

	setAttribute(_key: string, _value: string | number | boolean): this {
		return this;
	}

	setAttributes(_attributes: Record<string, string | number | boolean>): this {
		return this;
	}

	addEvent(_name: string, _attributes?: Record<string, string | number | boolean>): this {
		return this;
	}

	recordException(_error: Error | { name?: string; message?: string }): this {
		return this;
	}

	setStatus(_status: unknown): this {
		return this;
	}

	updateName(name: string): this {
		this.name = redactTelemetryString(name, 200);
		return this;
	}

	end(_endTime?: number | Date | [number, number]): void {
		if (this.ended) return;
		this.ended = true;
		this.durationMs = performance.now() - this.startedAt;
	}

	spanContext(): SpanContext {
		return this.context;
	}

	isRecording(): boolean {
		return this.recording && !this.ended;
	}
}

const activeSpans = new AsyncLocalStorage<TracingSpan>();
let config: TracingConfig | null = null;

const tracer: TracingTracer = {
	startSpan(name, options) {
		const parent = activeSpans.getStore()?.spanContext();
		const span = new LocalSpan(
			redactTelemetryString(name, 200),
			Boolean(config?.enabled) && Math.random() <= (config?.samplingRate ?? 0),
			parent,
		);
		if (options?.attributes) span.setAttributes(redactTelemetryAttributes(options.attributes));
		return span;
	},
	startActiveSpan(name, optionsOrFn, contextOrFn, fn) {
		const options = typeof optionsOrFn === "function" ? {} : optionsOrFn;
		const callback =
			typeof optionsOrFn === "function"
				? optionsOrFn
				: typeof contextOrFn === "function"
					? contextOrFn
					: fn;
		if (!callback) throw new TypeError("startActiveSpan requires a callback");
		const span = this.startSpan(name, options);
		return activeSpans.run(span, () => callback(span));
	},
};

export function initTracing(overrides?: Partial<TracingConfig>): void {
	if (config !== null) return;
	config = { ...loadTracingConfig(), ...overrides };
}

export function shutdownTracing(): Promise<void> {
	config = null;
	return Promise.resolve();
}

export function getTracer(): TracingTracer | null {
	if (config === null) initTracing();
	return config?.enabled ? tracer : null;
}

export function isTracingEnabled(): boolean {
	return config?.enabled ?? false;
}

export function startSpan(
	name: string,
	options?: TracingSpanOptions,
	_parentContext?: unknown,
): TracingSpan | null {
	return getTracer()?.startSpan(name, options) ?? null;
}

export function startActiveSpan<T>(
	name: string,
	fn: (span: TracingSpan) => T | Promise<T>,
	options: TracingSpanOptions = {},
	_parentContext?: unknown,
): Promise<T> | T {
	const activeTracer = getTracer();
	if (!activeTracer) return fn(new LocalSpan(name, false));
	return activeTracer.startActiveSpan(name, options, fn);
}

export function endSpan(
	span: TracingSpan | null | undefined,
	endTime?: number | Date | [number, number],
): void {
	span?.end(endTime);
}

/**
 * @deprecated Context propagation is no longer performed.
 * @public
 */
export function extractTraceContext(_carrier: Record<string, unknown>): undefined {
	return undefined;
}

/**
 * @deprecated Context propagation is no longer performed.
 * @public
 */
export function injectTraceContext(_carrier: Record<string, string>): void {}

export function getCurrentSpan(): TracingSpan | undefined {
	return activeSpans.getStore();
}

export function getSpanContext(): SpanContext | undefined {
	const context = getCurrentSpan()?.spanContext();
	return context?.traceId ? context : undefined;
}

export function setSpanAttribute(key: string, value: string | number | boolean): void {
	getCurrentSpan()?.setAttribute(
		key,
		typeof value === "string" ? redactTelemetryString(value, 500) : value,
	);
}

export function setSpanAttributes(attributes: Record<string, string | number | boolean>): void {
	getCurrentSpan()?.setAttributes(redactTelemetryAttributes(attributes));
}

export function addSpanEvent(
	name: string,
	attributes?: Record<string, string | number | boolean>,
): void {
	getCurrentSpan()?.addEvent(
		redactTelemetryString(name, 200),
		attributes && redactTelemetryAttributes(attributes),
	);
}

export function recordException(
	error: Error,
	attributes?: Record<string, string | number | boolean>,
): void {
	if (attributes) setSpanAttributes(attributes);
	getCurrentSpan()?.recordException({
		name: redactTelemetryString(error.name || "Error", 100),
		message: redactTelemetryString(error.message, 1000),
	});
}

export function setSecurityDecisionAttributes(attrs: SecurityDecisionAttributes): void {
	setSpanAttributes({
		"aidr.tool_name": attrs.toolName,
		"aidr.session_id": attrs.sessionId,
		"aidr.decision": attrs.decision,
		"aidr.category": attrs.category,
		"aidr.confidence": attrs.confidence,
		"aidr.severity": attrs.severity,
		"aidr.artifacts_count": attrs.artifactsCount,
		...(attrs.matchedThreatId ? { "aidr.matched_threat_id": attrs.matchedThreatId } : {}),
		...(attrs.durationMs === undefined ? {} : { "aidr.duration_ms": attrs.durationMs }),
	});
	if (attrs.reasons?.length) {
		addSpanEvent("security_decision_reasons", { "aidr.reasons": attrs.reasons.join("; ") });
	}
}

export function recordDetectionPhase(attrs: DetectionPhaseAttributes): void {
	addSpanEvent(`detection_phase:${attrs.phase}`, {
		"aidr.phase": attrs.phase,
		"aidr.duration_ms": attrs.durationMs,
		...(attrs.artifactType ? { "aidr.artifact_type": attrs.artifactType } : {}),
		...(attrs.artifactCount === undefined ? {} : { "aidr.artifact_count": attrs.artifactCount }),
		...(attrs.matchCount === undefined ? {} : { "aidr.match_count": attrs.matchCount }),
		...(attrs.cacheHit === undefined ? {} : { "aidr.cache_hit": attrs.cacheHit }),
	});
}
