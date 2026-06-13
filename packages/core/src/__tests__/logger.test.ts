import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createChildLogger, createLogger, getLogger, setLogger } from "../logger.js";

const LOG_ENV_KEYS = [
	"AIDR_LOG_LEVEL",
	"AIDR_LOG_TO_FILE",
	"AIDR_LOG_FILE_PATH",
	"NODE_ENV",
] as const;

type LogEntry = Record<string, unknown> & { msg?: string; level?: string };

let originalEnv: Partial<Record<(typeof LOG_ENV_KEYS)[number], string | undefined>>;

beforeEach(() => {
	originalEnv = {};
	for (const key of LOG_ENV_KEYS) {
		originalEnv[key] = process.env[key];
		delete process.env[key];
	}
});

afterEach(() => {
	for (const key of LOG_ENV_KEYS) {
		const value = originalEnv[key];
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
});

async function makeLogFile(): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), "aidr-logger-test-"));
	return join(dir, "nested", "aidr.log");
}

async function readLogEntries(path: string): Promise<LogEntry[]> {
	const deadline = Date.now() + 1000;
	let lastError: unknown;

	while (Date.now() < deadline) {
		try {
			const raw = await readFile(path, "utf8");
			const lines = raw
				.split(/\r?\n/)
				.map((line) => line.trim())
				.filter(Boolean);
			if (lines.length > 0) return lines.map((line) => JSON.parse(line) as LogEntry);
		} catch (error) {
			lastError = error;
		}
		await new Promise((resolve) => setTimeout(resolve, 10));
	}

	throw lastError ?? new Error(`Timed out waiting for log file ${path}`);
}

async function createFileLogger(options?: Parameters<typeof createLogger>[0]): Promise<{
	logger: ReturnType<typeof createLogger>;
	logFile: string;
}> {
	const logFile = await makeLogFile();
	process.env.AIDR_LOG_TO_FILE = "true";
	process.env.AIDR_LOG_FILE_PATH = logFile;
	return { logger: createLogger(options), logFile };
}

describe("createLogger", () => {
	it("uses AIDR_LOG_LEVEL and falls back to info for invalid values", async () => {
		process.env.AIDR_LOG_LEVEL = "warn";
		let { logger, logFile } = await createFileLogger({ name: "level-env" });

		logger.info("hidden info");
		logger.warn("visible warn");
		logger.error("visible error");

		let entries = await readLogEntries(logFile);
		expect(entries.map((entry) => entry.msg)).toEqual(["visible warn", "visible error"]);
		expect(entries.map((entry) => entry.level)).toEqual(["WARN", "ERROR"]);

		process.env.AIDR_LOG_LEVEL = "verbose";
		({ logger, logFile } = await createFileLogger({ name: "level-fallback" }));

		logger.debug("hidden debug");
		logger.info("visible info");

		entries = await readLogEntries(logFile);
		expect(entries.map((entry) => entry.msg)).toEqual(["visible info"]);
		expect(entries[0].level).toBe("INFO");
	});

	it("lets an explicit level option override AIDR_LOG_LEVEL", async () => {
		process.env.AIDR_LOG_LEVEL = "error";
		const { logger, logFile } = await createFileLogger({ name: "level-option", level: "debug" });

		logger.debug("visible debug");

		const entries = await readLogEntries(logFile);
		expect(entries).toHaveLength(1);
		expect(entries[0].level).toBe("DEBUG");
		expect(entries[0].msg).toBe("visible debug");
	});

	it("writes JSON logs to the configured file and creates missing parent directories", async () => {
		process.env.NODE_ENV = "test";
		const { logger, logFile } = await createFileLogger({ name: "file-logger" });

		logger.info({ operation: "scan" }, "file log");

		const [entry] = await readLogEntries(logFile);
		expect(entry.name).toBe("file-logger");
		expect(entry.env).toBe("test");
		expect(entry.pid).toBe(process.pid);
		expect(entry.operation).toBe("scan");
		expect(entry.msg).toBe("file log");
		expect(entry.time).toEqual(expect.any(String));
	});

	it("redacts sensitive root, nested, header, and config fields", async () => {
		const { logger, logFile } = await createFileLogger({ name: "redaction" });

		logger.info(
			{
				api_key: "root-secret",
				payload: { accessToken: "nested-secret", keep: "visible" },
				headers: { authorization: "Bearer secret", "x-api-key": "header-secret" },
				config: { apiKey: "config-secret", token: "config-token" },
			},
			"redacted log",
		);

		const [entry] = await readLogEntries(logFile);
		expect(entry.api_key).toBe("[Redacted]");
		expect(entry.payload).toEqual({ accessToken: "[Redacted]", keep: "visible" });
		expect(entry.headers).toEqual({ authorization: "[Redacted]", "x-api-key": "[Redacted]" });
		expect(entry.config).toEqual({ apiKey: "[Redacted]", token: "[Redacted]" });
		expect(JSON.stringify(entry)).not.toContain("secret");
	});

	it("adds child logger component and metadata without losing parent fields", async () => {
		const { logger, logFile } = await createFileLogger({ name: "parent" });
		const child = createChildLogger(logger, "scanner", { requestId: "req-1" });

		child.info({ verdict: "allow" }, "child log");

		const [entry] = await readLogEntries(logFile);
		expect(entry.name).toBe("parent");
		expect(entry.component).toBe("scanner");
		expect(entry.requestId).toBe("req-1");
		expect(entry.verdict).toBe("allow");
		expect(entry.msg).toBe("child log");
	});
});

describe("default logger", () => {
	it("returns the same default logger until setLogger replaces it", () => {
		const first = getLogger();
		const second = getLogger();
		const replacement = pino({ enabled: false });

		setLogger(replacement);

		expect(second).toBe(first);
		expect(getLogger()).toBe(replacement);
	});
});
