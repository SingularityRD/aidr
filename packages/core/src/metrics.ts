/**
 * Singularity AIDR Metrics
 * Lightweight metrics collection with JSONL output and Prometheus format support
 * Zero external dependencies
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { AIDR_DIR } from "./config.js";

export interface MetricRecord {
	timestamp: string;
	name: string;
	value: number;
	labels?: Record<string, string>;
	type: "counter" | "gauge" | "histogram";
}

export interface MetricsSnapshot {
	detection_latency_ms: number;
	verdict_count: number;
	cache_hit_rate: number;
	error_rate: number;
	timestamp: string;
	[key: string]: string | number;
}

/**
 * Counter metric - monotonically increasing
 */
export class Counter {
	private value = 0;
	private labels: Record<string, string>;
	private _name: string;
	private _description: string;

	constructor(name: string, description: string, labels: Record<string, string> = {}) {
		this._name = name;
		this._description = description;
		this.labels = labels;
	}

	/** Metric name */
	get name(): string {
		return this._name;
	}

	/** Metric description */
	get description(): string {
		return this._description;
	}

	increment(amount = 1): void {
		this.value += amount;
	}

	getValue(): number {
		return this.value;
	}

	getLabels(): Record<string, string> {
		return this.labels;
	}

	getPrometheusFormat(): string {
		const lines: string[] = [];
		lines.push(`# HELP ${this._name} ${this._description}`);
		lines.push(`# TYPE ${this._name} counter`);
		const labelStr = Object.entries(this.labels)
			.map(([k, v]) => `${k}="${v}"`)
			.join(",");
		lines.push(`${this._name}{${labelStr}} ${this.value}`);
		return lines.join("\n");
	}

	reset(): void {
		this.value = 0;
	}
}

/**
 * Histogram metric - for recording distributions of values
 */
export class Histogram {
	private values: number[] = [];
	private buckets: number[];
	private labels: Record<string, string>;
	private _name: string;
	private _description: string;

	// Default buckets in seconds for latency measurements
	static DEFAULT_BUCKETS = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

	constructor(
		name: string,
		description: string,
		buckets: number[] = Histogram.DEFAULT_BUCKETS,
		labels: Record<string, string> = {},
	) {
		this._name = name;
		this._description = description;
		this.buckets = buckets;
		this.labels = labels;
	}

	/** Metric name */
	get name(): string {
		return this._name;
	}

	/** Metric description */
	get description(): string {
		return this._description;
	}

	/** Histogram buckets */
	get bucketValues(): number[] {
		return this.buckets;
	}

	/** Metric labels */
	get labelValues(): Record<string, string> {
		return this.labels;
	}

	observe(value: number): void {
		this.values.push(value);
		// Keep max 1000 values to prevent memory issues
		if (this.values.length > 1000) {
			this.values.shift();
		}
	}

	getCount(): number {
		return this.values.length;
	}

	getSum(): number {
		return this.values.reduce((a, b) => a + b, 0);
	}

	getBucketCounts(): Record<string, number> {
		const counts: Record<string, number> = {};
		for (const bucket of this.buckets) {
			counts[bucket.toString()] = this.values.filter((v) => v <= bucket).length;
		}
		counts["+Inf"] = this.values.length;
		return counts;
	}

	getPrometheusFormat(): string {
		const lines: string[] = [];
		const baseLabels = Object.entries(this.labels)
			.map(([k, v]) => `${k}="${v}"`)
			.join(",");

		lines.push(`# HELP ${this._name} ${this._description}`);
		lines.push(`# TYPE ${this._name} histogram`);

		const buckets = this.getBucketCounts();
		for (const bucket of this.buckets) {
			const bucketLabel = baseLabels ? `${baseLabels},le="${bucket}"` : `le="${bucket}"`;
			lines.push(`${this._name}_bucket{${bucketLabel}} ${buckets[bucket.toString()]}`);
		}
		lines.push(
			`${this._name}_bucket{${baseLabels ? `${baseLabels},le="+Inf"` : 'le="+Inf"'} ${buckets["+Inf"]}}`,
		);
		lines.push(`${this._name}_sum{${baseLabels}} ${this.getSum()}`);
		lines.push(`${this._name}_count{${baseLabels}} ${this.getCount()}`);

		return lines.join("\n");
	}

	reset(): void {
		this.values = [];
	}
}

/**
 * Gauge metric - goes up and down
 */
export class Gauge {
	private value = 0;
	private labels: Record<string, string>;
	private _name: string;
	private _description: string;

	constructor(name: string, description: string, labels: Record<string, string> = {}) {
		this._name = name;
		this._description = description;
		this.labels = labels;
	}

	/** Metric name */
	get name(): string {
		return this._name;
	}

	/** Metric description */
	get description(): string {
		return this._description;
	}

	/** Metric labels */
	get labelValues(): Record<string, string> {
		return this.labels;
	}

	set(value: number): void {
		this.value = value;
	}

	increment(amount = 1): void {
		this.value += amount;
	}

	decrement(amount = 1): void {
		this.value -= amount;
	}

	getValue(): number {
		return this.value;
	}

	getPrometheusFormat(): string {
		const lines: string[] = [];
		lines.push(`# HELP ${this._name} ${this._description}`);
		lines.push(`# TYPE ${this._name} gauge`);
		const labelStr = Object.entries(this.labels)
			.map(([k, v]) => `${k}="${v}"`)
			.join(",");
		lines.push(`${this._name}{${labelStr}} ${this.value}`);
		return lines.join("\n");
	}

	reset(): void {
		this.value = 0;
	}
}

/**
 * Metrics registry - holds and manages all metrics
 */
export class MetricsRegistry {
	private counters: Map<string, Counter> = new Map();
	private histograms: Map<string, Histogram> = new Map();
	private gauges: Map<string, Gauge> = new Map();

	registerCounter(name: string, description: string, labels: Record<string, string> = {}): Counter {
		const key = this.makeKey(name, labels);
		if (!this.counters.has(key)) {
			this.counters.set(key, new Counter(name, description, labels));
		}
		return this.counters.get(key)!;
	}

	registerHistogram(
		name: string,
		description: string,
		buckets?: number[],
		labels: Record<string, string> = {},
	): Histogram {
		const key = this.makeKey(name, labels);
		if (!this.histograms.has(key)) {
			this.histograms.set(key, new Histogram(name, description, buckets, labels));
		}
		return this.histograms.get(key)!;
	}

	registerGauge(name: string, description: string, labels: Record<string, string> = {}): Gauge {
		const key = this.makeKey(name, labels);
		if (!this.gauges.has(key)) {
			this.gauges.set(key, new Gauge(name, description, labels));
		}
		return this.gauges.get(key)!;
	}

	getCounter(name: string, labels: Record<string, string> = {}): Counter | undefined {
		return this.counters.get(this.makeKey(name, labels));
	}

	getHistogram(name: string, labels: Record<string, string> = {}): Histogram | undefined {
		return this.histograms.get(this.makeKey(name, labels));
	}

	getGauge(name: string, labels: Record<string, string> = {}): Gauge | undefined {
		return this.gauges.get(this.makeKey(name, labels));
	}

	/**
	 * Export all metrics in Prometheus text format
	 * https://prometheus.io/docs/instrumenting/exposition_formats/
	 */
	exportPrometheusFormat(): string {
		const sections: string[] = [];

		// Group counters by name
		const counterGroups = new Map<string, Counter[]>();
		for (const counter of this.counters.values()) {
			const list = counterGroups.get(counter.name) || [];
			list.push(counter);
			counterGroups.set(counter.name, list);
		}

		for (const [name, counters] of counterGroups) {
			if (counters.length === 0) continue;
			sections.push(`# HELP ${name} ${counters[0]?.description}`);
			sections.push(`# TYPE ${name} counter`);
			for (const counter of counters) {
				const labelStr = Object.entries(counter.getLabels())
					.map(([k, v]) => `${k}="${v}"`)
					.join(",");
				sections.push(`${name}{${labelStr}} ${counter.getValue()}`);
			}
		}

		// Group histograms by name
		const histogramGroups = new Map<string, Histogram[]>();
		for (const histogram of this.histograms.values()) {
			const list = histogramGroups.get(histogram.name) || [];
			list.push(histogram);
			histogramGroups.set(histogram.name, list);
		}

		for (const [name, histograms] of histogramGroups) {
			if (histograms.length === 0) continue;
			sections.push(`# HELP ${name} ${histograms[0]?.description}`);
			sections.push(`# TYPE ${name} histogram`);

			for (const histogram of histograms) {
				const baseLabels = Object.entries(histogram.labelValues)
					.map(([k, v]) => `${k}="${v}"`)
					.join(",");
				const buckets = histogram.getBucketCounts();

				for (const bucket of histogram.bucketValues) {
					const bucketLabel = baseLabels ? `${baseLabels},le="${bucket}"` : `le="${bucket}"`;
					sections.push(`${name}_bucket{${bucketLabel}} ${buckets[bucket.toString()]}`);
				}
				sections.push(
					`${name}_bucket{${baseLabels ? `${baseLabels},le="+Inf"` : 'le="+Inf"'} ${buckets["+Inf"]}}`,
				);
				sections.push(`${name}_sum{${baseLabels}} ${histogram.getSum()}`);
				sections.push(`${name}_count{${baseLabels}} ${histogram.getCount()}`);
			}
		}

		// Group gauges by name
		const gaugeGroups = new Map<string, Gauge[]>();
		for (const gauge of this.gauges.values()) {
			const list = gaugeGroups.get(gauge.name) || [];
			list.push(gauge);
			gaugeGroups.set(gauge.name, list);
		}

		for (const [name, gauges] of gaugeGroups) {
			if (gauges.length === 0) continue;
			sections.push(`# HELP ${name} ${gauges[0]?.description}`);
			sections.push(`# TYPE ${name} gauge`);
			for (const gauge of gauges) {
				const labelStr = Object.entries(gauge.labelValues)
					.map(([k, v]) => `${k}="${v}"`)
					.join(",");
				sections.push(`${name}{${labelStr}} ${gauge.getValue()}`);
			}
		}

		return sections.join("\n");
	}

	reset(): void {
		this.counters.clear();
		this.histograms.clear();
		this.gauges.clear();
	}

	private makeKey(name: string, labels: Record<string, string>): string {
		return `${name}:${JSON.stringify(labels)}`;
	}
}

/**
 * Global metrics registry singleton
 */
let globalRegistry: MetricsRegistry | null = null;

export function getMetricsRegistry(): MetricsRegistry {
	if (!globalRegistry) {
		globalRegistry = new MetricsRegistry();
	}
	return globalRegistry;
}

// Pre-defined metrics for AIDR
export const aidrMetrics = {
	// Counter: Total security decisions
	get decisionsTotal() {
		return getMetricsRegistry().registerCounter(
			"aidr_decisions_total",
			"Total number of security decisions made",
		);
	},

	// Counter: Decisions by verdict
	get decisionsByVerdict() {
		return {
			allow: getMetricsRegistry().registerCounter(
				"aidr_decisions_total",
				"Total number of security decisions made",
				{
					verdict: "allow",
				},
			),
			deny: getMetricsRegistry().registerCounter(
				"aidr_decisions_total",
				"Total number of security decisions made",
				{
					verdict: "deny",
				},
			),
			ask: getMetricsRegistry().registerCounter(
				"aidr_decisions_total",
				"Total number of security decisions made",
				{
					verdict: "ask",
				},
			),
		};
	},

	// Histogram: Detection latency in seconds
	get detectionDuration() {
		return getMetricsRegistry().registerHistogram(
			"aidr_detection_duration_seconds",
			"Time spent on detection in seconds",
			[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
		);
	},

	// Gauge: Active sessions
	get activeSessions() {
		return getMetricsRegistry().registerGauge("aidr_active_sessions", "Number of active sessions");
	},

	// Counter: Cache hits
	get cacheHitsTotal() {
		return getMetricsRegistry().registerCounter(
			"aidr_cache_hits_total",
			"Total number of cache hits",
		);
	},

	// Counter: Threats blocked
	get threatsBlockedTotal() {
		return getMetricsRegistry().registerCounter(
			"aidr_threats_blocked_total",
			"Total number of threats blocked",
		);
	},
};

class MetricsCollector {
	private metricsFilePath: string;
	private inMemoryCounters: Map<string, number> = new Map();
	private inMemoryHistograms: Map<string, number[]> = new Map();
	private enabled: boolean;

	constructor() {
		this.metricsFilePath = process.env.AIDR_METRICS_FILE || `${AIDR_DIR}/metrics.jsonl`;
		this.enabled =
			process.env.AIDR_DISABLE_METRICS !== "true" && process.env.AIDR_DISABLE_METRICS !== "1";
		this.ensureMetricsDir();
	}

	private ensureMetricsDir(): void {
		try {
			mkdirSync(dirname(this.metricsFilePath), { recursive: true });
		} catch {
			// Fail silently - metrics are best-effort
		}
	}

	private writeRecord(record: MetricRecord): void {
		if (!this.enabled) return;
		try {
			appendFileSync(this.metricsFilePath, `${JSON.stringify(record)}\n`);
		} catch {
			// Fail silently
		}
	}

	counter(name: string, value = 1, labels?: Record<string, string>): void {
		const key = labels ? `${name}:${JSON.stringify(labels)}` : name;
		const current = this.inMemoryCounters.get(key) || 0;
		this.inMemoryCounters.set(key, current + value);
		this.writeRecord({ timestamp: new Date().toISOString(), name, value, labels, type: "counter" });
	}

	gauge(name: string, value: number, labels?: Record<string, string>): void {
		this.writeRecord({ timestamp: new Date().toISOString(), name, value, labels, type: "gauge" });
	}

	histogram(name: string, value: number, labels?: Record<string, string>): void {
		const key = labels ? `${name}:${JSON.stringify(labels)}` : name;
		const values = this.inMemoryHistograms.get(key) || [];
		values.push(value);
		if (values.length > 1000) values.shift();
		this.inMemoryHistograms.set(key, values);
		this.writeRecord({
			timestamp: new Date().toISOString(),
			name,
			value,
			labels,
			type: "histogram",
		});
	}

	recordDetectionLatency(ms: number, verdict: string): void {
		this.histogram("detection_latency_ms", ms, { verdict });
		// Also record in Prometheus histogram (convert to seconds)
		aidrMetrics.detectionDuration.observe(ms / 1000);
	}

	recordVerdict(decision: "allow" | "deny" | "ask", category?: string): void {
		this.counter("verdict_count", 1, { decision, category: category || "unknown" });
		// Also record in Prometheus counters
		aidrMetrics.decisionsTotal.increment();
		aidrMetrics.decisionsByVerdict[decision].increment();
		if (decision === "deny") {
			aidrMetrics.threatsBlockedTotal.increment();
		}
	}

	recordCache(hit: boolean): void {
		this.counter("cache_hit", 1, { result: hit ? "hit" : "miss" });
		// Also record in Prometheus counters
		if (hit) {
			aidrMetrics.cacheHitsTotal.increment();
		}
	}

	recordError(type: string): void {
		this.counter("error_count", 1, { type });
	}

	recordSessionStart(): void {
		aidrMetrics.activeSessions.increment();
	}

	recordSessionEnd(): void {
		aidrMetrics.activeSessions.decrement();
	}

	getCacheHitRate(): number {
		const hits = this.inMemoryCounters.get('cache_hit:{"result":"hit"}') || 0;
		const misses = this.inMemoryCounters.get('cache_hit:{"result":"miss"}') || 0;
		const total = hits + misses;
		return total > 0 ? hits / total : 0;
	}

	getErrorRate(): number {
		const errors = this.inMemoryCounters.get('error_count:{"type":"internal"}') || 0;
		const totalVerdicts = Array.from(this.inMemoryCounters.entries())
			.filter(([k]) => k.startsWith("verdict_count:"))
			.reduce((sum, [, v]) => sum + v, 0);
		return totalVerdicts > 0 ? (errors / totalVerdicts) * 100 : 0;
	}

	getAverageDetectionLatency(): number {
		const allValues: number[] = [];
		for (const [key, values] of this.inMemoryHistograms) {
			if (key.startsWith("detection_latency_ms")) {
				allValues.push(...values);
			}
		}
		if (allValues.length === 0) return 0;
		return allValues.reduce((a, b) => a + b, 0) / allValues.length;
	}

	getVerdictCount(): number {
		return Array.from(this.inMemoryCounters.entries())
			.filter(([k]) => k.startsWith("verdict_count:"))
			.reduce((sum, [, v]) => sum + v, 0);
	}

	getSnapshot(): MetricsSnapshot {
		return {
			detection_latency_ms: this.getAverageDetectionLatency(),
			verdict_count: this.getVerdictCount(),
			cache_hit_rate: this.getCacheHitRate(),
			error_rate: this.getErrorRate(),
			timestamp: new Date().toISOString(),
		};
	}

	readMetrics(sinceMinutes = 60): MetricRecord[] {
		if (!existsSync(this.metricsFilePath)) return [];
		const cutoff = Date.now() - sinceMinutes * 60 * 1000;
		try {
			const content = readFileSync(this.metricsFilePath, "utf-8");
			return content
				.split("\n")
				.filter(Boolean)
				.map((line) => JSON.parse(line) as MetricRecord)
				.filter((r) => new Date(r.timestamp).getTime() > cutoff);
		} catch {
			return [];
		}
	}

	reset(): void {
		this.inMemoryCounters.clear();
		this.inMemoryHistograms.clear();
	}
}

let instance: MetricsCollector | null = null;

export function getMetricsCollector(): MetricsCollector {
	if (!instance) instance = new MetricsCollector();
	return instance;
}

export function createMetricsCollector(): MetricsCollector {
	return new MetricsCollector();
}

export const metrics = {
	recordDetectionLatency: (ms: number, verdict: string) =>
		getMetricsCollector().recordDetectionLatency(ms, verdict),
	recordVerdict: (decision: "allow" | "deny" | "ask", category?: string) =>
		getMetricsCollector().recordVerdict(decision, category),
	recordCache: (hit: boolean) => getMetricsCollector().recordCache(hit),
	recordError: (type: string) => getMetricsCollector().recordError(type),
	recordSessionStart: () => getMetricsCollector().recordSessionStart(),
	recordSessionEnd: () => getMetricsCollector().recordSessionEnd(),
	counter: (name: string, value?: number, labels?: Record<string, string>) =>
		getMetricsCollector().counter(name, value, labels),
	gauge: (name: string, value: number, labels?: Record<string, string>) =>
		getMetricsCollector().gauge(name, value, labels),
	histogram: (name: string, value: number, labels?: Record<string, string>) =>
		getMetricsCollector().histogram(name, value, labels),
	getSnapshot: () => getMetricsCollector().getSnapshot(),
};

export { MetricsCollector };
