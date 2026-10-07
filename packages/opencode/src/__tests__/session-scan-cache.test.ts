import type { PluginInfo } from "@singularityrd/aidr-core";
import { describe, expect, it, vi } from "vitest";

const runs = vi.hoisted(() => ({ count: 0 }));

vi.mock("@singularityrd/aidr-core", async (importOriginal) => ({
	...(await importOriginal<typeof import("@singularityrd/aidr-core")>()),
	createScanHandler:
		(options: { discoverPlugins: () => Promise<PluginInfo[]>; onResult?: (m: string) => void }) =>
		async () => {
			runs.count += 1;
			try {
				const plugins = await options.discoverPlugins();
				options.onResult?.(`scanned ${plugins.map((plugin) => plugin.key).join(",")}`);
			} catch {
				// Like core: a failed scan is logged and reports no result.
			}
		},
}));

import {
	createCachedSessionScanner,
	MAX_PENDING_FINDINGS_SESSIONS,
	PENDING_FINDINGS_TTL_MS,
	PendingSessionFindings,
	SESSION_SCAN_CACHE_TTL_MS,
} from "../startup-scan.js";

const logger = { debug() {}, info() {}, warn() {}, error() {} } as never;

function plugin(key: string, version = "1.0.0"): PluginInfo {
	return { key, version, installPath: `/plugins/${key}`, lastUpdated: "2026-10-01" } as PluginInfo;
}

describe("cached OpenCode session scan", () => {
	it("reuses the result while the plugin set is unchanged and rescans on any change", async () => {
		runs.count = 0;
		let now = 1_000;
		let plugins = [plugin("a"), plugin("b")];
		const scan = createCachedSessionScanner(logger, undefined, {
			now: () => now,
			discoverPlugins: async () => plugins,
		});

		expect(await scan()).toBe("scanned a,b");
		expect(await scan()).toBe("scanned a,b");
		expect(runs.count).toBe(1);

		plugins = [plugin("a"), plugin("b", "1.0.1")];
		expect(await scan()).toBe("scanned a,b");
		expect(runs.count).toBe(2);

		plugins = [plugin("a"), plugin("b", "1.0.1"), plugin("c")];
		expect(await scan()).toBe("scanned a,b,c");
		expect(runs.count).toBe(3);

		now += SESSION_SCAN_CACHE_TTL_MS;
		await scan();
		expect(runs.count).toBe(4);
	});

	it("never caches a failed discovery", async () => {
		runs.count = 0;
		let fail = true;
		const scan = createCachedSessionScanner(logger, undefined, {
			discoverPlugins: async () => {
				if (fail) throw new Error("unreadable");
				return [plugin("a")];
			},
		});
		await scan();
		fail = false;
		expect(await scan()).toBe("scanned a");
		expect(await scan()).toBe("scanned a");
		expect(runs.count).toBe(2);
	});
});

describe("pending session findings", () => {
	it("delivers once per session", () => {
		const pending = new PendingSessionFindings();
		pending.set("s1", "finding");
		expect(pending.take("s2")).toBeUndefined();
		expect(pending.take("s1")).toBe("finding");
		expect(pending.take("s1")).toBeUndefined();
	});

	it("expires findings of sessions that never prompt", () => {
		let now = 0;
		const pending = new PendingSessionFindings(() => now);
		pending.set("idle", "finding");
		now += PENDING_FINDINGS_TTL_MS + 1;
		expect(pending.size).toBe(0);
		expect(pending.take("idle")).toBeUndefined();
	});

	it("keeps a bounded number of sessions, dropping the oldest", () => {
		const pending = new PendingSessionFindings();
		for (let index = 0; index <= MAX_PENDING_FINDINGS_SESSIONS; index++) {
			pending.set(`s${index}`, "finding");
		}
		expect(pending.size).toBe(MAX_PENDING_FINDINGS_SESSIONS);
		expect(pending.take("s0")).toBeUndefined();
		expect(pending.take(`s${MAX_PENDING_FINDINGS_SESSIONS}`)).toBe("finding");
	});
});
