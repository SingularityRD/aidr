/**
 * The generic per-session state store: atomic updates under concurrency,
 * bounded session count and document size, TTL expiry, and tamper evidence.
 */
import { chmod, readdir, readFile, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SessionStateError, SessionStateStore } from "../session-state-store.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

interface Counter {
	n: number;
}

const isCounter = (value: unknown): value is Counter =>
	typeof value === "object" && value !== null && typeof (value as Counter).n === "number";

let dir: string;

beforeEach(async () => {
	dir = join(await makeTmpDir(), "state");
});

afterEach(async () => {
	await removeTmpDir(join(dir, ".."));
});

function store(overrides: Partial<ConstructorParameters<typeof SessionStateStore>[0]> = {}) {
	return new SessionStateStore<Counter>(
		{ dir, namespace: "test", ttlMs: 60_000, maxSessions: 8, ...overrides },
		isCounter,
	);
}

const increment = (current: Counter | undefined) => {
	const next = { n: (current?.n ?? 0) + 1 };
	return { next, result: next.n };
};

describe("SessionStateStore", () => {
	it("persists per-session state across store instances without storing the session id", async () => {
		expect((await store().update("session-a", increment)).result).toBe(1);
		expect((await store().update("session-a", increment)).result).toBe(2);
		expect((await store().update("session-b", increment)).result).toBe(1);
		const files = await readdir(dir);
		expect(files.filter((f) => f.startsWith("test-"))).toHaveLength(2);
		for (const file of files.filter((f) => f.startsWith("test-"))) {
			expect(await readFile(join(dir, file), "utf8")).not.toContain("session-a");
		}
	});

	it("loses no update under concurrent writers", async () => {
		await Promise.all(Array.from({ length: 12 }, () => store().update("busy", increment)));
		expect((await store().update("busy", increment)).result).toBe(13);
	});

	it("creates the directory and files owner-only", async () => {
		await store().update("s", increment);
		if (process.platform === "win32") return;
		const { stat } = await import("node:fs/promises");
		expect((await stat(dir)).mode & 0o777).toBe(0o700);
		for (const file of await readdir(dir)) {
			if (file.endsWith(".json") || file.endsWith(".key")) {
				expect((await stat(join(dir, file))).mode & 0o777).toBe(0o600);
			}
		}
	});

	it("is bounded: keeps at most maxSessions files, oldest pruned first", async () => {
		const bounded = store({ maxSessions: 3 });
		for (let i = 0; i < 6; i++) {
			await bounded.update(`s${i}`, increment);
			// Distinct mtimes so "oldest" is well defined.
			const past = new Date(Date.now() - (10 - i) * 1000);
			await utimes(bounded.pathFor(`s${i}`), past, past);
		}
		const sessions = (await readdir(dir)).filter(
			(f) => f.startsWith("test-") && f.endsWith(".json"),
		);
		expect(sessions).toHaveLength(3);
		expect(sessions).toContain(`${bounded.pathFor("s5").split(/[\\/]/).pop()}`);
		expect(sessions).not.toContain(`${bounded.pathFor("s0").split(/[\\/]/).pop()}`);
	});

	it("refuses a document over its size bound", async () => {
		const big = new SessionStateStore<{ n: number; pad: string }>(
			{ dir, namespace: "test", ttlMs: 60_000, maxSessions: 8, maxDocumentBytes: 512 },
			(value): value is { n: number; pad: string } => isCounter(value),
		);
		await expect(
			big.update("s", () => ({ next: { n: 1, pad: "x".repeat(2000) }, result: 0 })),
		).rejects.toMatchObject({
			code: "too_large",
		});
	});

	it("expires state idle for longer than the TTL", async () => {
		let now = 1_000_000;
		const clocked = store({ ttlMs: 1000, now: () => now });
		expect((await clocked.update("s", increment)).result).toBe(1);
		now += 500;
		expect((await clocked.update("s", increment)).result).toBe(2);
		now += 5000;
		const expired = await clocked.update("s", increment);
		expect(expired.result).toBe(1);
		expect(expired.created).toBe(true);
		expect(expired.recovered).toBeUndefined();
	});

	it("detects a tampered document, resets it and reports the recovery", async () => {
		const s = store();
		await s.update("s", increment);
		await s.update("s", increment);
		const path = s.pathFor("s");
		const document = JSON.parse(await readFile(path, "utf8"));
		document.payload = document.payload.replace('"n":2', '"n":0');
		await writeFile(path, JSON.stringify(document));
		const outcome = await s.update("s", increment);
		expect(outcome.recovered).toBe("integrity");
		expect(outcome.result).toBe(1);
		// The reset document verifies again.
		expect((await s.update("s", increment)).recovered).toBeUndefined();
	});

	it("rejects a document replayed from another session", async () => {
		const s = store();
		await s.update("victim", increment);
		await s.update("attacker", increment);
		await s.update("attacker", increment);
		await writeFile(s.pathFor("victim"), await readFile(s.pathFor("attacker")));
		expect((await s.update("victim", increment)).recovered).toBe("integrity");
	});

	it("treats unparseable content and planted symlinks as untrusted", async () => {
		const s = store();
		await s.update("s", increment);
		await writeFile(s.pathFor("s"), "{not json");
		expect((await s.update("s", increment)).recovered).toBe("corrupt");
		if (process.platform === "win32") return;
		const target = join(dir, "..", "elsewhere.json");
		await writeFile(target, "{}");
		await rm(s.pathFor("s"));
		await symlink(target, s.pathFor("s"));
		expect((await s.update("s", increment)).recovered).toBe("unsafe_path");
		// The symlink itself was replaced; its target was never written.
		expect(await readFile(target, "utf8")).toBe("{}");
	});

	it("fails with a SessionStateError when the directory is unusable", async () => {
		const blocked = new SessionStateStore<Counter>(
			{
				dir: join(dir, "..", "file-not-dir", "state"),
				namespace: "test",
				ttlMs: 1000,
				maxSessions: 2,
			},
			isCounter,
		);
		await writeFile(join(dir, "..", "file-not-dir"), "x");
		await expect(blocked.update("s", increment)).rejects.toBeInstanceOf(SessionStateError);
	});

	it("times out on a held lock instead of waiting forever", async () => {
		const s = store({ lockTimeoutMs: 50, lockStaleMs: 60_000 });
		await s.update("s", increment);
		await writeFile(`${s.pathFor("s")}.lock`, "999999\n");
		await expect(s.update("s", increment)).rejects.toMatchObject({ code: "lock_timeout" });
	});

	it("takes over a stale lock left by a crashed writer", async () => {
		const s = store({ lockStaleMs: 1000 });
		await s.update("s", increment);
		const lock = `${s.pathFor("s")}.lock`;
		await writeFile(lock, "999999\n");
		const past = new Date(Date.now() - 60_000);
		await utimes(lock, past, past);
		expect((await s.update("s", increment)).result).toBe(2);
	});

	it("does not follow a read-only state directory into a clean result", async () => {
		if (process.platform === "win32" || process.getuid?.() === 0) return;
		const s = store();
		await s.update("s", increment);
		await chmod(dir, 0o500);
		try {
			await expect(s.update("s", increment)).rejects.toBeInstanceOf(SessionStateError);
		} finally {
			await chmod(dir, 0o700);
		}
	});
});
