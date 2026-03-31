#!/usr/bin/env node
/**
 * Test Performance Tracker
 *
 * Reads vitest JSON output and tracks test performance:
 * - Lists all tests taking > 5 seconds
 * - Exits with error if any test takes > 10 seconds
 */

import fs from "node:fs";
import path from "node:path";

const TEST_RESULTS_PATH = process.argv[2] || "./coverage/test-results.json";
const SLOW_THRESHOLD_MS = 5000; // 5 seconds
const MAX_ALLOWED_MS = 10000; // 10 seconds

function formatDuration(ms) {
	if (ms < 1000) return `${ms.toFixed(0)}ms`;
	return `${(ms / 1000).toFixed(2)}s`;
}

function main() {
	console.log("🔍 Test Performance Tracker\n");

	// Check if file exists
	const absolutePath = path.resolve(TEST_RESULTS_PATH);
	if (!fs.existsSync(absolutePath)) {
		console.error(`❌ Test results file not found: ${TEST_RESULTS_PATH}`);
		console.log("   Run tests with JSON reporter first:");
		console.log("   pnpm test:perf");
		process.exit(1);
	}

	// Parse test results
	let results;
	try {
		const content = fs.readFileSync(absolutePath, "utf-8");
		results = JSON.parse(content);
	} catch (error) {
		console.error(`❌ Failed to parse test results: ${error.message}`);
		process.exit(1);
	}

	// Extract test results from vitest JSON format
	const testResults = [];

	function extractTests(suite, filePath = "") {
		if (!suite) return;

		const currentPath = filePath || suite.name || "";

		// Handle test results array
		if (suite.testResults) {
			for (const test of suite.testResults) {
				testResults.push({
					name: `${currentPath} > ${test.name}`,
					duration: test.duration || 0,
					status: test.status,
				});
			}
		}

		// Handle nested suites
		if (suite.suites) {
			for (const childSuite of suite.suites) {
				extractTests(childSuite, currentPath);
			}
		}

		// Handle results array (vitest format)
		if (suite.results) {
			for (const result of suite.results) {
				if (result.type === "test") {
					testResults.push({
						name: result.name,
						duration: result.duration || 0,
						status: result.result?.state || "unknown",
					});
				} else if (result.type === "suite") {
					extractTests(result, currentPath);
				}
			}
		}
	}

	// Try different vitest JSON output formats
	if (results.testResults) {
		// Jest-like format
		for (const suite of results.testResults) {
			extractTests(suite, suite.name);
		}
	} else if (results.results) {
		// Vitest native format
		for (const result of results.results) {
			extractTests(result);
		}
	} else if (Array.isArray(results)) {
		// Array of suites
		for (const suite of results) {
			extractTests(suite);
		}
	}

	// Also try to find duration in the testFilepaths format
	if (results.testFilepaths && results.duration) {
		for (const filepath of results.testFilepaths) {
			testResults.push({
				name: filepath,
				duration: results.duration / results.testFilepaths.length,
				status: "unknown",
			});
		}
	}

	// Find slow tests
	const slowTests = testResults
		.filter((t) => t.duration > SLOW_THRESHOLD_MS)
		.sort((a, b) => b.duration - a.duration);

	const criticalTests = testResults.filter((t) => t.duration > MAX_ALLOWED_MS);

	// Print summary
	console.log(`📊 Total tests analyzed: ${testResults.length}`);
	console.log(`🐌 Slow tests (>5s): ${slowTests.length}`);
	console.log(`🚨 Critical slow tests (>10s): ${criticalTests.length}\n`);

	if (slowTests.length > 0) {
		console.log("───────────────────────────────────────────");
		console.log("Slow Tests (>5 seconds):");
		console.log("───────────────────────────────────────────");
		for (const test of slowTests) {
			const isCritical = test.duration > MAX_ALLOWED_MS;
			const icon = isCritical ? "🔴" : "🟡";
			const status = isCritical ? "CRITICAL" : "WARNING";
			console.log(`${icon} [${status}] ${test.name}`);
			console.log(`   Duration: ${formatDuration(test.duration)} | Status: ${test.status}\n`);
		}
	}

	// Calculate and show statistics
	if (testResults.length > 0) {
		const durations = testResults.map((t) => t.duration);
		const totalDuration = durations.reduce((a, b) => a + b, 0);
		const avgDuration = totalDuration / testResults.length;
		const maxDuration = Math.max(...durations);
		const minDuration = Math.min(...durations);

		console.log("───────────────────────────────────────────");
		console.log("Performance Statistics:");
		console.log("───────────────────────────────────────────");
		console.log(`Total execution time: ${formatDuration(totalDuration)}`);
		console.log(`Average test time: ${formatDuration(avgDuration)}`);
		console.log(`Fastest test: ${formatDuration(minDuration)}`);
		console.log(`Slowest test: ${formatDuration(maxDuration)}`);
	}

	console.log("\n───────────────────────────────────────────");

	// Exit with error if critical slow tests found
	if (criticalTests.length > 0) {
		console.error(`\n❌ FAIL: ${criticalTests.length} test(s) exceeded 10 second threshold`);
		console.error("   These tests need optimization.\n");
		process.exit(1);
	}

	if (slowTests.length > 0) {
		console.log(`\n⚠️  WARNING: ${slowTests.length} test(s) are slower than 5 seconds`);
		console.log("   Consider optimizing these tests for faster CI.\n");
	}

	console.log("✅ Test performance check passed\n");
	process.exit(0);
}

main();
