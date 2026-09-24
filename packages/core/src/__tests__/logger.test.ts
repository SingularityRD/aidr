import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
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

function firstLogEntry(entries: LogEntry[]): LogEntry {
	const entry = entries[0];
	if (!entry) throw new Error("Expected at least one log entry");
	return entry;
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
		expect(firstLogEntry(entries).level).toBe("INFO");
	});

	it("lets an explicit level option override AIDR_LOG_LEVEL", async () => {
		process.env.AIDR_LOG_LEVEL = "error";
		const { logger, logFile } = await createFileLogger({ name: "level-option", level: "debug" });

		logger.debug("visible debug");

		const entries = await readLogEntries(logFile);
		expect(entries).toHaveLength(1);
		expect(firstLogEntry(entries).level).toBe("DEBUG");
		expect(firstLogEntry(entries).msg).toBe("visible debug");
	});

	it("writes JSON logs to the configured file and creates missing parent directories", async () => {
		process.env.NODE_ENV = "test";
		const { logger, logFile } = await createFileLogger({ name: "file-logger" });

		logger.info({ operation: "scan" }, "file log");

		const entry = firstLogEntry(await readLogEntries(logFile));
		expect(entry.name).toBe("file-logger");
		expect(entry.env).toBe("test");
		expect(entry.pid).toBe(process.pid);
		expect(entry.operation).toBe("scan");
		expect(entry.msg).toBe("file log");
		expect(entry.time).toEqual(expect.any(String));
	});

	it("resolves the default file under HOME without creating a literal tilde directory", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-logger-home-"));
		const home = join(root, "home");
		await mkdir(home);
		const previousCwd = process.cwd();
		const previousHome = process.env.HOME;
		try {
			process.chdir(root);
			process.env.HOME = home;
			process.env.AIDR_LOG_TO_FILE = "true";
			const logger = createLogger({ name: "default-path" });
			logger.info("home log");
			const logFile = join(home, ".singularity-aidr", "logs", "aidr.log");
			expect(firstLogEntry(await readLogEntries(logFile)).msg).toBe("home log");
			await expect(stat(join(root, "~"))).rejects.toMatchObject({ code: "ENOENT" });
			if (process.platform !== "win32") {
				expect((await stat(join(home, ".singularity-aidr", "logs"))).mode & 0o777).toBe(0o700);
				expect((await stat(logFile)).mode & 0o777).toBe(0o600);
			}
		} finally {
			process.chdir(previousCwd);
			if (previousHome === undefined) delete process.env.HOME;
			else process.env.HOME = previousHome;
			await rm(root, { recursive: true, force: true });
		}
	});

	it("hardens an existing log directory and file to owner-only permissions", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-logger-permissions-"));
		const logDirectory = join(root, "logs");
		const logFile = join(logDirectory, "aidr.log");
		await mkdir(logDirectory, { mode: 0o777 });
		await writeFile(logFile, "", { mode: 0o666 });
		if (process.platform !== "win32") {
			await chmod(logDirectory, 0o777);
			await chmod(logFile, 0o666);
		}
		process.env.AIDR_LOG_TO_FILE = "true";
		process.env.AIDR_LOG_FILE_PATH = logFile;

		const logger = createLogger({ name: "private-file-logger" });
		logger.info("private log");

		expect(firstLogEntry(await readLogEntries(logFile)).msg).toBe("private log");
		if (process.platform !== "win32") {
			expect((await stat(logDirectory)).mode & 0o777).toBe(0o700);
			expect((await stat(logFile)).mode & 0o777).toBe(0o600);
		}
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

		const entry = firstLogEntry(await readLogEntries(logFile));
		expect(entry.api_key).toBe("[Redacted]");
		expect(entry.payload).toEqual({ accessToken: "[Redacted]", keep: "visible" });
		expect(entry.headers).toEqual({ authorization: "[Redacted]", "x-api-key": "[Redacted]" });
		expect(entry.config).toEqual({ apiKey: "[Redacted]", token: "[Redacted]" });
		expect(JSON.stringify(entry)).not.toContain("secret");
	});

	it("redacts credentials embedded in free-form messages and arbitrary fields", async () => {
		const { logger, logFile } = await createFileLogger({ name: "free-form-redaction" });

		logger.warn(
			{
				command: "curl https://example.test?token=super-secret",
				details: "ghp_abcdefghijklmnopqrstuvwxyz123456",
			},
			"request failed: Authorization: Bearer super-secret",
		);

		const entry = firstLogEntry(await readLogEntries(logFile));
		const serialized = JSON.stringify(entry);
		expect(serialized).not.toContain("super-secret");
		expect(serialized).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz123456");
		expect(entry.msg).toContain("[Redacted]");
	});

	it("adds child logger component and metadata without losing parent fields", async () => {
		const { logger, logFile } = await createFileLogger({ name: "parent" });
		const child = createChildLogger(logger, "scanner", { requestId: "req-1" });

		child.info({ verdict: "allow" }, "child log");

		const entry = firstLogEntry(await readLogEntries(logFile));
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
