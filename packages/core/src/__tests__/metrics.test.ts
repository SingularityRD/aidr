import { beforeEach, describe, expect, it } from "vitest";
import {
	aidrMetrics,
	Counter,
	Gauge,
	getMetricsCollector,
	getMetricsRegistry,
	Histogram,
	MetricsRegistry,
	metrics,
} from "../metrics.js";

describe("Counter", () => {
	it("should start at 0", () => {
		const counter = new Counter("test_counter", "Test counter");
		expect(counter.getValue()).toBe(0);
	});

	it("should increment by 1 by default", () => {
		const counter = new Counter("test_counter", "Test counter");
		counter.increment();
		expect(counter.getValue()).toBe(1);
	});

	it("should increment by specified amount", () => {
		const counter = new Counter("test_counter", "Test counter");
		counter.increment(5);
		expect(counter.getValue()).toBe(5);
	});

	it("should format in Prometheus format", () => {
		const counter = new Counter("test_counter", "Test counter", { verdict: "deny" });
		counter.increment(3);
		const promFormat = counter.getPrometheusFormat();
		expect(promFormat).toContain("# HELP test_counter Test counter");
		expect(promFormat).toContain("# TYPE test_counter counter");
		expect(promFormat).toContain('test_counter{verdict="deny"} 3');
	});

	it("should reset to 0", () => {
		const counter = new Counter("test_counter", "Test counter");
		counter.increment(5);
		counter.reset();
		expect(counter.getValue()).toBe(0);
	});
});

describe("Gauge", () => {
	it("should start at 0", () => {
		const gauge = new Gauge("test_gauge", "Test gauge");
		expect(gauge.getValue()).toBe(0);
	});

	it("should set value", () => {
		const gauge = new Gauge("test_gauge", "Test gauge");
		gauge.set(42);
		expect(gauge.getValue()).toBe(42);
	});

	it("should increment", () => {
		const gauge = new Gauge("test_gauge", "Test gauge");
		gauge.set(10);
		gauge.increment(5);
		expect(gauge.getValue()).toBe(15);
	});

	it("should decrement", () => {
		const gauge = new Gauge("test_gauge", "Test gauge");
		gauge.set(10);
		gauge.decrement(3);
		expect(gauge.getValue()).toBe(7);
	});

	it("should format in Prometheus format", () => {
		const gauge = new Gauge("test_gauge", "Test gauge", { service: "aidr" });
		gauge.set(42);
		const promFormat = gauge.getPrometheusFormat();
		expect(promFormat).toContain("# HELP test_gauge Test gauge");
		expect(promFormat).toContain("# TYPE test_gauge gauge");
		expect(promFormat).toContain('test_gauge{service="aidr"} 42');
	});
});

describe("Histogram", () => {
	it("should observe values", () => {
		const histogram = new Histogram("test_histogram", "Test histogram");
		histogram.observe(0.005);
		histogram.observe(0.01);
		histogram.observe(0.1);
		expect(histogram.getCount()).toBe(3);
	});

	it("should calculate sum correctly", () => {
		const histogram = new Histogram("test_histogram", "Test histogram");
		histogram.observe(1);
		histogram.observe(2);
		histogram.observe(3);
		expect(histogram.getSum()).toBe(6);
	});

	it("should calculate bucket counts", () => {
		const buckets = [0.005, 0.01, 0.025, 0.05, 0.1];
		const histogram = new Histogram("test_histogram", "Test histogram", buckets);
		histogram.observe(0.003);
		histogram.observe(0.007);
		histogram.observe(0.02);
		histogram.observe(0.08);
		const bucketCounts = histogram.getBucketCounts();
		expect(bucketCounts["0.005"]).toBe(1);
		expect(bucketCounts["0.01"]).toBe(2);
		expect(bucketCounts["0.025"]).toBe(3);
		expect(bucketCounts["0.05"]).toBe(3);
		expect(bucketCounts["0.1"]).toBe(4);
		expect(bucketCounts["+Inf"]).toBe(4);
	});

	it("should format in Prometheus format", () => {
		const histogram = new Histogram("test_histogram", "Test histogram", [0.1, 0.5, 1]);
		histogram.observe(0.05);
		histogram.observe(0.3);
		const promFormat = histogram.getPrometheusFormat();
		expect(promFormat).toContain("# HELP test_histogram Test histogram");
		expect(promFormat).toContain("# TYPE test_histogram histogram");
		expect(promFormat).toContain("test_histogram_bucket");
		expect(promFormat).toContain("test_histogram_sum");
		expect(promFormat).toContain("test_histogram_count");
	});

	it("should limit to 1000 values", () => {
		const histogram = new Histogram("test_histogram", "Test histogram");
		for (let i = 0; i < 1100; i++) {
			histogram.observe(i);
		}
		expect(histogram.getCount()).toBe(1000);
	});
});

describe("MetricsRegistry", () => {
	let registry: MetricsRegistry;

	beforeEach(() => {
		registry = new MetricsRegistry();
	});

	it("should register counters", () => {
		const counter = registry.registerCounter("decisions", "Total decisions", { verdict: "allow" });
		counter.increment();
		expect(registry.getCounter("decisions", { verdict: "allow" })?.getValue()).toBe(1);
	});

	it("should register histograms", () => {
		const histogram = registry.registerHistogram("latency", "Request latency");
		histogram.observe(0.1);
		expect(registry.getHistogram("latency")?.getCount()).toBe(1);
	});

	it("should register gauges", () => {
		const gauge = registry.registerGauge("active_sessions", "Active sessions");
		gauge.set(5);
		expect(registry.getGauge("active_sessions")?.getValue()).toBe(5);
	});

	it("should export Prometheus format", () => {
		const counter = registry.registerCounter("decisions", "Total decisions", { verdict: "allow" });
		counter.increment();
		const promFormat = registry.exportPrometheusFormat();
		expect(promFormat).toContain("# HELP decisions Total decisions");
		expect(promFormat).toContain("# TYPE decisions counter");
		expect(promFormat).toContain('decisions{verdict="allow"} 1');
	});

	it("should group metrics by name in Prometheus format", () => {
		const allowCounter = registry.registerCounter("decisions", "Total decisions", {
			verdict: "allow",
		});
		const denyCounter = registry.registerCounter("decisions", "Total decisions", {
			verdict: "deny",
		});
		allowCounter.increment();
		denyCounter.increment();
		const promFormat = registry.exportPrometheusFormat();
		const lines = promFormat.split("\n");
		// Should have only one HELP and TYPE line for decisions
		expect(lines.filter((l) => l.startsWith("# HELP decisions")).length).toBe(1);
		expect(lines.filter((l) => l.startsWith("# TYPE decisions")).length).toBe(1);
		expect(lines.filter((l) => l.startsWith('decisions{verdict="allow"}')).length).toBe(1);
		expect(lines.filter((l) => l.startsWith('decisions{verdict="deny"}')).length).toBe(1);
	});
});

describe("aidrMetrics", () => {
	beforeEach(() => {
		getMetricsRegistry().reset();
	});

	it("should track decisions total", () => {
		aidrMetrics.decisionsTotal.increment();
		expect(aidrMetrics.decisionsTotal.getValue()).toBe(1);
	});

	it("should track decisions by verdict", () => {
		aidrMetrics.decisionsByVerdict.allow.increment();
		aidrMetrics.decisionsByVerdict.deny.increment();
		expect(aidrMetrics.decisionsByVerdict.allow.getValue()).toBe(1);
		expect(aidrMetrics.decisionsByVerdict.deny.getValue()).toBe(1);
		expect(aidrMetrics.decisionsByVerdict.ask.getValue()).toBe(0);
	});

	it("should track detection duration", () => {
		aidrMetrics.detectionDuration.observe(0.5);
		aidrMetrics.detectionDuration.observe(1.0);
		expect(aidrMetrics.detectionDuration.getCount()).toBe(2);
		expect(aidrMetrics.detectionDuration.getSum()).toBe(1.5);
	});

	it("should track active sessions", () => {
		aidrMetrics.activeSessions.increment();
		aidrMetrics.activeSessions.increment();
		aidrMetrics.activeSessions.decrement();
		expect(aidrMetrics.activeSessions.getValue()).toBe(1);
	});

	it("should track cache hits", () => {
		aidrMetrics.cacheHitsTotal.increment();
		expect(aidrMetrics.cacheHitsTotal.getValue()).toBe(1);
	});

	it("should track threats blocked", () => {
		aidrMetrics.threatsBlockedTotal.increment();
		aidrMetrics.threatsBlockedTotal.increment();
		expect(aidrMetrics.threatsBlockedTotal.getValue()).toBe(2);
	});
});

describe("metrics helper", () => {
	beforeEach(() => {
		getMetricsRegistry().reset();
		getMetricsCollector().reset();
	});

	it("should record detection latency in milliseconds", () => {
		metrics.recordDetectionLatency(100, "deny");
		const snapshot = metrics.getSnapshot();
		expect(snapshot.detection_latency_ms).toBe(100);
	});

	it("should record verdict", () => {
		metrics.recordVerdict("deny", "malicious");
		expect(metrics.getSnapshot().verdict_count).toBe(1);
		expect(aidrMetrics.decisionsByVerdict.deny.getValue()).toBe(1);
	});

	it("should record cache hit", () => {
		metrics.recordCache(true);
		expect(metrics.getSnapshot().cache_hit_rate).toBe(1);
		expect(aidrMetrics.cacheHitsTotal.getValue()).toBe(1);
	});

	it("should record cache miss", () => {
		metrics.recordCache(false);
		expect(metrics.getSnapshot().cache_hit_rate).toBe(0);
	});

	it("should record session start and end", () => {
		metrics.recordSessionStart();
		metrics.recordSessionStart();
		expect(aidrMetrics.activeSessions.getValue()).toBe(2);
		metrics.recordSessionEnd();
		expect(aidrMetrics.activeSessions.getValue()).toBe(1);
	});
});
