/**
 * Small, bounded, TTL'd per-session state store in the AIDR state directory.
 *
 * Connector hooks are short-lived processes (Claude Code starts one per tool
 * call, often several at once), so anything that has to remember a session —
 * how often a call repeated, how many files were written — lives on disk. This
 * store is deliberately generic: each consumer owns a `namespace` and a
 * validator for its document, and several consumers can share one directory
 * and one integrity key.
 *
 * ## Guarantees
 *
 * - **Atomic**: every update is read-modify-write under an `O_EXCL` lock file
 *   (a lock older than `lockStaleMs` is taken over), and the new document is
 *   written to a temporary file and renamed into place.
 * - **Bounded**: one file per (namespace, session digest); a document larger than
 *   `maxDocumentBytes` is refused; at most `maxSessions` files per namespace are
 *   kept (oldest pruned first) and files idle for longer than `ttlMs` are
 *   discarded on read and pruned when a new session starts.
 * - **Tamper-evident**: each document carries an HMAC-SHA256 over its payload,
 *   keyed by a random per-directory key (`session-state.key`, owner-only). A
 *   document that fails the check, does not parse, names another session or
 *   namespace, is dated in the future, or is a symlink is NOT trusted: the
 *   update starts from an empty state and reports `recovered`, so the caller can
 *   say the signal was unavailable instead of pretending the session is clean.
 * - **Private**: the directory is created `0700` and every file `0600`; a
 *   directory that is a symlink or owned by another user is refused.
 *
 * The session id itself is never written: files are named and bound by its
 * SHA-256 digest.
 *
 * The default location is inside `~/.singularity-aidr`, which the self-defense
 * rules (CLT-SELF-008) deny the agent any access to — the agent cannot read,
 * reset or forge its own counters.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Stats } from "node:fs";
import { chmod, link, lstat, mkdir, open, readdir, rename, stat, unlink } from "node:fs/promises";
import { join } from "node:path";

export type SessionStateErrorCode = "io" | "lock_timeout" | "unsafe_path" | "too_large";

export class SessionStateError extends Error {
	constructor(
		readonly code: SessionStateErrorCode,
		message: string,
	) {
		super(message);
		this.name = "SessionStateError";
	}
}

/** Why a stored document was discarded instead of used. */
export type SessionStateRecovery = "integrity" | "corrupt" | "unsafe_path";

export interface SessionStateStoreOptions {
	/** Absolute directory; created owner-only when missing. */
	dir: string;
	/** Consumer namespace, e.g. `runaway` (lowercase, digits, dashes). */
	namespace: string;
	/** Documents idle for longer than this are discarded. */
	ttlMs: number;
	/** Most session files kept for this namespace. */
	maxSessions: number;
	maxDocumentBytes?: number;
	lockTimeoutMs?: number;
	lockStaleMs?: number;
	now?: () => number;
}

export interface SessionStateUpdateResult<R> {
	result: R;
	/** Set when a stored document existed but could not be trusted. */
	recovered?: SessionStateRecovery;
	/** True when this update started the session's state. */
	created: boolean;
}

const DOCUMENT_VERSION = 1;
const KEY_FILE = "session-state.key";
const KEY_BYTES = 32;
const DEFAULT_MAX_DOCUMENT_BYTES = 256 * 1024;
const DEFAULT_LOCK_TIMEOUT_MS = 750;
const DEFAULT_LOCK_STALE_MS = 5000;
/** Tolerated clock skew between concurrent hook processes. */
const FUTURE_SKEW_MS = 5 * 60 * 1000;
/** Orphaned temp and lock files are removed after this long. */
const ORPHAN_MS = 60 * 1000;
const NAMESPACE_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;

export function sessionStateDigest(sessionId: string): string {
	return createHash("sha256").update(sessionId, "utf8").digest("hex").slice(0, 32);
}

function errorCode(error: unknown): string | undefined {
	return typeof error === "object" && error !== null && "code" in error
		? String((error as { code: unknown }).code)
		: undefined;
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readSmallFile(path: string, maxBytes: number): Promise<Buffer | "too_large"> {
	const handle = await open(path, "r");
	try {
		const info = await handle.stat();
		if (info.size > maxBytes) return "too_large";
		const buffer = Buffer.alloc(info.size);
		let offset = 0;
		while (offset < buffer.length) {
			const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
			if (bytesRead === 0) break;
			offset += bytesRead;
		}
		return buffer.subarray(0, offset);
	} finally {
		await handle.close();
	}
}

async function writePrivateFile(path: string, data: string | Buffer): Promise<void> {
	const handle = await open(path, "wx", 0o600);
	try {
		await handle.writeFile(data);
	} finally {
		await handle.close();
	}
}

/** Create or verify the private state directory. */
async function preparePrivateDirectory(dir: string): Promise<void> {
	try {
		await mkdir(dir, { recursive: true, mode: 0o700 });
	} catch (error) {
		throw new SessionStateError(
			"io",
			`State directory could not be created (${errorCode(error)}).`,
		);
	}
	let info: Stats;
	try {
		info = await lstat(dir);
	} catch (error) {
		throw new SessionStateError("io", `State directory is unreadable (${errorCode(error)}).`);
	}
	if (info.isSymbolicLink() || !info.isDirectory()) {
		throw new SessionStateError("unsafe_path", "State directory is not a regular directory.");
	}
	if (process.platform !== "win32") {
		if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
			throw new SessionStateError("unsafe_path", "State directory is owned by another user.");
		}
		if ((info.mode & 0o077) !== 0) {
			await chmod(dir, 0o700).catch(() => undefined);
		}
	}
}

/** The directory's integrity key, created once (atomically) on first use. */
async function loadKey(dir: string): Promise<Buffer> {
	const path = join(dir, KEY_FILE);
	for (let attempt = 0; attempt < 3; attempt++) {
		try {
			const info = await lstat(path);
			if (info.isSymbolicLink() || !info.isFile()) {
				throw new SessionStateError("unsafe_path", "State key is not a regular file.");
			}
			const key = await readSmallFile(path, 1024);
			if (key === "too_large" || key.length !== KEY_BYTES) {
				throw new SessionStateError("unsafe_path", "State key has an unexpected size.");
			}
			return key;
		} catch (error) {
			if (error instanceof SessionStateError) throw error;
			if (errorCode(error) !== "ENOENT") {
				throw new SessionStateError("io", `State key is unreadable (${errorCode(error)}).`);
			}
		}
		// Publish a complete key with link(): it either appears whole or fails
		// with EEXIST because a concurrent process published one first.
		const tmp = join(dir, `${KEY_FILE}.${randomBytes(6).toString("hex")}.tmp`);
		try {
			await writePrivateFile(tmp, randomBytes(KEY_BYTES));
			await link(tmp, path);
		} catch (error) {
			if (errorCode(error) !== "EEXIST") {
				throw new SessionStateError("io", `State key could not be created (${errorCode(error)}).`);
			}
		} finally {
			await unlink(tmp).catch(() => undefined);
		}
	}
	throw new SessionStateError("io", "State key could not be established.");
}

function mac(key: Buffer, payload: string): string {
	return createHmac("sha256", key).update(payload, "utf8").digest("hex");
}

function macMatches(key: Buffer, payload: string, expected: unknown): boolean {
	if (typeof expected !== "string" || !/^[0-9a-f]{64}$/.test(expected)) return false;
	return timingSafeEqual(Buffer.from(mac(key, payload), "hex"), Buffer.from(expected, "hex"));
}

interface StoredPayload {
	ns: string;
	sid: string;
	updatedAt: number;
	data: unknown;
}

export class SessionStateStore<T> {
	private readonly maxDocumentBytes: number;
	private readonly lockTimeoutMs: number;
	private readonly lockStaleMs: number;
	private readonly now: () => number;

	constructor(
		private readonly options: SessionStateStoreOptions,
		private readonly validate: (value: unknown) => value is T,
	) {
		if (!NAMESPACE_PATTERN.test(options.namespace)) {
			throw new Error(`Invalid session state namespace: ${options.namespace}`);
		}
		this.maxDocumentBytes = options.maxDocumentBytes ?? DEFAULT_MAX_DOCUMENT_BYTES;
		this.lockTimeoutMs = options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
		this.lockStaleMs = options.lockStaleMs ?? DEFAULT_LOCK_STALE_MS;
		this.now = options.now ?? Date.now;
	}

	/** Absolute path of a session's document (for diagnostics and tests). */
	pathFor(sessionId: string): string {
		return join(
			this.options.dir,
			`${this.options.namespace}-${sessionStateDigest(sessionId)}.json`,
		);
	}

	/**
	 * Read, change and write one session's state atomically. `mutate` receives the
	 * current state (`undefined` when there is none, it expired, or it could not
	 * be trusted) and returns the next state plus a result for the caller.
	 *
	 * Throws {@link SessionStateError} when the state cannot be read or written at
	 * all; the caller must treat that as "signal unavailable", never as clean.
	 */
	async update<R>(
		sessionId: string,
		mutate: (current: T | undefined) => { next: T; result: R },
	): Promise<SessionStateUpdateResult<R>> {
		await preparePrivateDirectory(this.options.dir);
		const key = await loadKey(this.options.dir);
		const path = this.pathFor(sessionId);
		const sid = sessionStateDigest(sessionId);
		return this.withLock(path, async () => {
			const loaded = await this.load(path, key, sid);
			const created = loaded.current === undefined;
			if (created) await this.prune(path);
			const { next, result } = mutate(loaded.current);
			await this.save(path, key, sid, next);
			return {
				result,
				created,
				...(loaded.recovered ? { recovered: loaded.recovered } : {}),
			};
		});
	}

	private async load(
		path: string,
		key: Buffer,
		sid: string,
	): Promise<{ current?: T; recovered?: SessionStateRecovery }> {
		let info: Stats;
		try {
			info = await lstat(path);
		} catch (error) {
			if (errorCode(error) === "ENOENT") return {};
			throw new SessionStateError("io", `Session state is unreadable (${errorCode(error)}).`);
		}
		// A planted symlink or directory is never followed; the rename in save()
		// replaces the entry itself.
		if (info.isSymbolicLink() || !info.isFile()) return { recovered: "unsafe_path" };
		let raw: Buffer | "too_large";
		try {
			raw = await readSmallFile(path, this.maxDocumentBytes);
		} catch (error) {
			throw new SessionStateError("io", `Session state is unreadable (${errorCode(error)}).`);
		}
		if (raw === "too_large") return { recovered: "corrupt" };
		let document: unknown;
		try {
			document = JSON.parse(raw.toString("utf8"));
		} catch {
			return { recovered: "corrupt" };
		}
		if (
			typeof document !== "object" ||
			document === null ||
			(document as { v?: unknown }).v !== DOCUMENT_VERSION ||
			typeof (document as { payload?: unknown }).payload !== "string"
		) {
			return { recovered: "corrupt" };
		}
		const { payload, mac: storedMac } = document as { payload: string; mac?: unknown };
		if (!macMatches(key, payload, storedMac)) return { recovered: "integrity" };
		let parsed: StoredPayload;
		try {
			parsed = JSON.parse(payload) as StoredPayload;
		} catch {
			return { recovered: "integrity" };
		}
		const now = this.now();
		if (
			parsed.ns !== this.options.namespace ||
			parsed.sid !== sid ||
			typeof parsed.updatedAt !== "number" ||
			!Number.isFinite(parsed.updatedAt) ||
			parsed.updatedAt > now + FUTURE_SKEW_MS
		) {
			return { recovered: "integrity" };
		}
		if (parsed.updatedAt < now - this.options.ttlMs) return {};
		if (!this.validate(parsed.data)) return { recovered: "corrupt" };
		return { current: parsed.data };
	}

	private async save(path: string, key: Buffer, sid: string, data: T): Promise<void> {
		const payload = JSON.stringify({
			ns: this.options.namespace,
			sid,
			updatedAt: this.now(),
			data,
		} satisfies StoredPayload);
		const document = JSON.stringify({ v: DOCUMENT_VERSION, payload, mac: mac(key, payload) });
		if (Buffer.byteLength(document, "utf8") > this.maxDocumentBytes) {
			throw new SessionStateError("too_large", "Session state exceeds its size bound.");
		}
		const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
		try {
			await writePrivateFile(tmp, document);
			await this.renameWithRetry(tmp, path);
		} catch (error) {
			await unlink(tmp).catch(() => undefined);
			if (error instanceof SessionStateError) throw error;
			throw new SessionStateError(
				"io",
				`Session state could not be written (${errorCode(error)}).`,
			);
		}
	}

	/** Windows refuses a rename over a file another process has open; retry briefly. */
	private async renameWithRetry(from: string, to: string): Promise<void> {
		for (let attempt = 0; ; attempt++) {
			try {
				await rename(from, to);
				return;
			} catch (error) {
				const code = errorCode(error);
				if (attempt >= 5 || (code !== "EPERM" && code !== "EACCES" && code !== "EBUSY"))
					throw error;
				await sleep(10 * (attempt + 1));
			}
		}
	}

	/** Drop expired sessions and keep at most `maxSessions` for this namespace. */
	private async prune(currentPath: string): Promise<void> {
		let entries: string[];
		try {
			entries = await readdir(this.options.dir);
		} catch {
			return;
		}
		const now = this.now();
		const prefix = `${this.options.namespace}-`;
		const sessions: Array<{ path: string; mtimeMs: number }> = [];
		for (const entry of entries) {
			if (!entry.startsWith(prefix)) continue;
			const path = join(this.options.dir, entry);
			let info: Stats;
			try {
				info = await stat(path);
			} catch {
				continue;
			}
			if (entry.endsWith(".tmp") || entry.endsWith(".lock")) {
				if (now - info.mtimeMs > ORPHAN_MS && path !== `${currentPath}.lock`) {
					await unlink(path).catch(() => undefined);
				}
				continue;
			}
			if (!entry.endsWith(".json") || path === currentPath) continue;
			if (now - info.mtimeMs > this.options.ttlMs) {
				await unlink(path).catch(() => undefined);
				continue;
			}
			sessions.push({ path, mtimeMs: info.mtimeMs });
		}
		// Room for the session being created.
		const excess = sessions.length - (this.options.maxSessions - 1);
		if (excess <= 0) return;
		sessions.sort((a, b) => a.mtimeMs - b.mtimeMs);
		for (const session of sessions.slice(0, excess)) {
			await unlink(session.path).catch(() => undefined);
		}
	}

	private async withLock<R>(path: string, fn: () => Promise<R>): Promise<R> {
		const lockPath = `${path}.lock`;
		const deadline = Date.now() + this.lockTimeoutMs;
		for (;;) {
			try {
				await writePrivateFile(lockPath, `${process.pid}\n`);
				break;
			} catch (error) {
				if (errorCode(error) !== "EEXIST") {
					throw new SessionStateError("io", `Session state lock failed (${errorCode(error)}).`);
				}
			}
			try {
				const info = await stat(lockPath);
				if (Date.now() - info.mtimeMs > this.lockStaleMs) {
					await unlink(lockPath).catch(() => undefined);
					continue;
				}
			} catch {
				continue;
			}
			if (Date.now() > deadline) {
				throw new SessionStateError(
					"lock_timeout",
					"Timed out waiting for the session state lock.",
				);
			}
			await sleep(5 + Math.floor(Math.random() * 20));
		}
		try {
			return await fn();
		} finally {
			await unlink(lockPath).catch(() => undefined);
		}
	}
}
