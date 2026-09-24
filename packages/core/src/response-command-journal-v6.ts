import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { lstat, mkdir, open, readdir, readFile, rename, rm, rmdir, unlink } from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { createDeviceAttestation, type DeviceAttestation } from "./device-attestation.js";
import type {
	FleetResponseCommand,
	FleetResponseIdentity,
} from "./response-command-consumer-v6.js";

type FleetJournalPhase =
	| "polled"
	| "reject_intent"
	| "acknowledged"
	| "execute_intent"
	| "result_pending";

export interface FleetJournalCurrent {
	command: FleetResponseCommand;
	phase: FleetJournalPhase;
	resultCode: string | null;
}

export interface FleetJournalState {
	schema_version: 1;
	sequence: number;
	tenant_id: string;
	agent_id: string;
	installation_id: string;
	key_hash: string;
	current: FleetJournalCurrent | null;
	recent_ids: string[];
}

type Slot = "a" | "b";
type Envelope = { payload: FleetJournalState; mac: string };
type LockOwner = { pid: number; host: string; token: string; process_started_at_ms: number };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CODE = /^[a-z][a-z0-9_]{0,63}$/;
const TYPES = new Set(["agent_pause", "agent_resume", "network_isolate", "network_release"]);
const PHASES = new Set([
	"polled",
	"reject_intent",
	"acknowledged",
	"execute_intent",
	"result_pending",
]);
const MAX_JOURNAL_BYTES = 32_768;
const PROCESS_STARTED_AT_MS = Math.max(0, Math.trunc(Date.now() - process.uptime() * 1000));
const MAX_RECENT_FLEET_COMMANDS = 256;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertCommand(value: unknown): asserts value is FleetResponseCommand {
	if (
		!isRecord(value) ||
		typeof value.id !== "string" ||
		!UUID.test(value.id) ||
		!TYPES.has(value.commandType as string) ||
		typeof value.expiresAt !== "string" ||
		!Number.isFinite(Date.parse(value.expiresAt)) ||
		!Number.isSafeInteger(value.attempt) ||
		(value.attempt as number) < 1 ||
		(value.attempt as number) > 5 ||
		(value.rollbackOf !== null &&
			(typeof value.rollbackOf !== "string" || !UUID.test(value.rollbackOf)))
	) {
		throw new Error("invalid_fleet_journal_command");
	}
	const reverse = value.commandType === "agent_resume" || value.commandType === "network_release";
	if (reverse !== (value.rollbackOf !== null)) throw new Error("invalid_fleet_journal_rollback");
}

function assertState(
	value: unknown,
	identity: FleetResponseIdentity,
	attestation: DeviceAttestation,
): asserts value is FleetJournalState {
	if (
		!isRecord(value) ||
		value.schema_version !== 1 ||
		!Number.isSafeInteger(value.sequence) ||
		(value.sequence as number) < 0 ||
		value.tenant_id !== identity.tenantId ||
		value.agent_id !== identity.agentId ||
		value.installation_id !== attestation.installationId ||
		value.key_hash !== attestation.keyHash ||
		!Array.isArray(value.recent_ids) ||
		value.recent_ids.length > MAX_RECENT_FLEET_COMMANDS ||
		value.recent_ids.some((id) => typeof id !== "string" || !UUID.test(id)) ||
		new Set(value.recent_ids).size !== value.recent_ids.length
	) {
		throw new Error("invalid_fleet_journal_state");
	}
	if (value.current === null) return;
	if (
		!isRecord(value.current) ||
		!PHASES.has(value.current.phase as string) ||
		(value.current.resultCode !== null &&
			(typeof value.current.resultCode !== "string" || !CODE.test(value.current.resultCode)))
	) {
		throw new Error("invalid_fleet_journal_current");
	}
	assertCommand(value.current.command);
	if (value.recent_ids.includes(value.current.command.id))
		throw new Error("fleet_journal_cursor_conflict");
	if (value.current.phase !== "result_pending" && value.current.resultCode !== null) {
		throw new Error("invalid_fleet_journal_result_phase");
	}
}

function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value && typeof value === "object") {
		const fields = Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
		return `{${fields.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
	}
	return JSON.stringify(value);
}

function macFor(payload: FleetJournalState, key: string): string {
	return createHmac("sha256", key).update(canonical(payload)).digest("hex");
}

async function regularFile(path: string): Promise<boolean> {
	try {
		const info = await lstat(path);
		if (!info.isFile() || info.isSymbolicLink()) throw new Error("unsafe_fleet_journal_file");
		if (info.size > MAX_JOURNAL_BYTES) throw new Error("fleet_journal_too_large");
		return true;
	} catch (error) {
		if (isRecord(error) && error.code === "ENOENT") return false;
		throw error;
	}
}

async function writeSynced(path: string, content: string): Promise<void> {
	const handle = await open(path, "wx", 0o600);
	try {
		await handle.writeFile(content, "utf8");
		await handle.sync();
	} finally {
		await handle.close();
	}
}

function pidAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return !(isRecord(error) && error.code === "ESRCH");
	}
}

function errorCode(error: unknown): string | undefined {
	return isRecord(error) && typeof error.code === "string" ? error.code : undefined;
}

function ownerFileName(token: string): string {
	return `owner.${token}.json`;
}

function parseOwner(value: unknown, expectedToken?: string): LockOwner | null {
	if (
		!isRecord(value) ||
		!Number.isSafeInteger(value.pid) ||
		(value.pid as number) < 1 ||
		typeof value.host !== "string" ||
		value.host.length === 0 ||
		typeof value.token !== "string" ||
		!UUID.test(value.token) ||
		(expectedToken !== undefined && value.token !== expectedToken) ||
		!Number.isSafeInteger(value.process_started_at_ms) ||
		(value.process_started_at_ms as number) < 0
	) {
		return null;
	}
	return value as LockOwner;
}

function ownerAlive(owner: LockOwner): boolean {
	if (owner.host !== hostname()) return true;
	if (owner.pid === process.pid) return owner.process_started_at_ms === PROCESS_STARTED_AT_MS;
	// Node has no portable foreign-process start-time API. A live/unknown PID is
	// kept fail-closed so PID reuse cannot cause an active generation to be stolen.
	return pidAlive(owner.pid);
}

export class FleetResponseJournal {
	private readonly path: string;
	private readonly identity: FleetResponseIdentity;
	private readonly attestation: DeviceAttestation;
	private readonly key: string;
	private slot: Slot | null = null;
	private sequence = 0;

	constructor(
		path: string,
		identity: FleetResponseIdentity,
		apiKey: string,
		installationId: string,
	) {
		if (!isAbsolute(path)) throw new Error("fleet_journal_path_must_be_absolute");
		if (!apiKey.trim()) throw new Error("invalid_fleet_journal_key");
		this.path = resolve(path);
		this.identity = { ...identity };
		this.attestation = createDeviceAttestation(installationId, apiKey);
		// Keep the raw enrollment key only in memory as the MAC secret. The persisted
		// key hash binds the journal to this enrollment without making the journal
		// forgeable by anyone who can read its public binding fields.
		this.key = apiKey.trim();
	}

	private slotPath(slot: Slot): string {
		return `${this.path}.${slot}`;
	}

	private async ensureDirectory(): Promise<void> {
		const directory = dirname(this.path);
		await mkdir(directory, { recursive: true, mode: 0o700 });
		const info = await lstat(directory);
		if (!info.isDirectory() || info.isSymbolicLink())
			throw new Error("unsafe_fleet_journal_directory");
		// lstat rejects a directly linked journal directory. Windows may expose
		// both 8.3 and long path spellings for the same real directory, so a raw
		// realpath string comparison is not a sound link check here.
	}

	private async readSlot(slot: Slot): Promise<FleetJournalState | null> {
		const path = this.slotPath(slot);
		if (!(await regularFile(path))) return null;
		const raw = await readFile(path, "utf8");
		if (Buffer.byteLength(raw) > MAX_JOURNAL_BYTES) throw new Error("fleet_journal_too_large");
		const envelope = JSON.parse(raw) as unknown;
		if (
			!isRecord(envelope) ||
			!isRecord(envelope.payload) ||
			typeof envelope.mac !== "string" ||
			!/^[a-f0-9]{64}$/.test(envelope.mac)
		)
			throw new Error("invalid_fleet_journal_envelope");
		const expected = Buffer.from(
			macFor(envelope.payload as unknown as FleetJournalState, this.key),
			"hex",
		);
		const actual = Buffer.from(envelope.mac, "hex");
		if (!timingSafeEqual(expected, actual)) throw new Error("fleet_journal_integrity_failed");
		assertState(envelope.payload, this.identity, this.attestation);
		return envelope.payload;
	}

	async load(): Promise<FleetJournalState> {
		await this.ensureDirectory();
		const [a, b] = await Promise.all([this.readSlot("a"), this.readSlot("b")]);
		if (a && b && a.sequence === b.sequence) throw new Error("fleet_journal_sequence_conflict");
		const selected = !a ? b : !b ? a : a.sequence > b.sequence ? a : b;
		this.slot = selected === a && a ? "a" : selected ? "b" : null;
		this.sequence = selected?.sequence ?? 0;
		return (
			selected ?? {
				schema_version: 1,
				sequence: 0,
				tenant_id: this.identity.tenantId,
				agent_id: this.identity.agentId,
				installation_id: this.attestation.installationId,
				key_hash: this.attestation.keyHash,
				current: null,
				recent_ids: [],
			}
		);
	}

	async save(state: FleetJournalState): Promise<FleetJournalState> {
		assertState(state, this.identity, this.attestation);
		const next = { ...state, sequence: this.sequence + 1 } satisfies FleetJournalState;
		const envelope: Envelope = { payload: next, mac: macFor(next, this.key) };
		const target: Slot = this.slot === "a" ? "b" : "a";
		const targetPath = this.slotPath(target);
		const temporary = `${targetPath}.${randomUUID()}.tmp`;
		await this.ensureDirectory();
		await writeSynced(temporary, JSON.stringify(envelope));
		try {
			// The active slot remains intact until the new slot is fully synced.
			await rm(targetPath, { force: true });
			await rename(temporary, targetPath);
		} finally {
			await rm(temporary, { force: true });
		}
		this.slot = target;
		this.sequence = next.sequence;
		return next;
	}

	private async acquireLock(): Promise<string> {
		await this.ensureDirectory();
		const lockPath = `${this.path}.lock`;
		for (;;) {
			const token = randomUUID();
			const temporary = `${lockPath}.owner.${token}.tmp`;
			await writeSynced(
				temporary,
				JSON.stringify({
					pid: process.pid,
					host: hostname(),
					token,
					process_started_at_ms: PROCESS_STARTED_AT_MS,
				}),
			);
			try {
				try {
					await mkdir(lockPath, { mode: 0o700 });
				} catch (error) {
					if (errorCode(error) !== "EEXIST") throw error;
					if (await this.recoverDeadLock(lockPath)) continue;
					throw new Error("fleet_journal_locked");
				}
				const ownerPath = join(lockPath, ownerFileName(token));
				try {
					await rename(temporary, ownerPath);
					return token;
				} catch (error) {
					let removedOwner = false;
					try {
						await unlink(ownerPath);
						removedOwner = true;
					} catch (cleanupError) {
						if (errorCode(cleanupError) !== "ENOENT") throw cleanupError;
					}
					if (removedOwner) await rmdir(lockPath).catch(() => undefined);
					throw error;
				}
			} finally {
				await rm(temporary, { force: true });
			}
		}
	}

	private async recoverLegacyLock(lockPath: string): Promise<boolean> {
		const value = JSON.parse(await readFile(lockPath, "utf8")) as unknown;
		if (
			!isRecord(value) ||
			!Number.isSafeInteger(value.pid) ||
			(value.pid as number) < 1 ||
			typeof value.token !== "string" ||
			!UUID.test(value.token)
		) {
			throw new Error("fleet_journal_lock_invalid");
		}
		if (typeof value.host !== "string" || !value.host || value.host !== hostname()) return false;
		if (!Number.isSafeInteger(value.process_started_at_ms)) return false;
		if (pidAlive(value.pid as number)) {
			if (value.pid === process.pid && value.process_started_at_ms !== PROCESS_STARTED_AT_MS) {
				await unlink(lockPath);
				return true;
			}
			return false;
		}
		await unlink(lockPath);
		return true;
	}

	// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one fail-closed lock recovery transition
	private async recoverDeadLock(lockPath: string): Promise<boolean> {
		let metadata;
		try {
			metadata = await lstat(lockPath);
		} catch (error) {
			if (errorCode(error) === "ENOENT") return true;
			throw error;
		}
		if (metadata.isSymbolicLink()) throw new Error("fleet_journal_lock_invalid");
		if (metadata.isFile()) {
			if (metadata.size > MAX_JOURNAL_BYTES) throw new Error("fleet_journal_lock_invalid");
			return this.recoverLegacyLock(lockPath);
		}
		if (!metadata.isDirectory()) throw new Error("fleet_journal_lock_invalid");

		const names = await readdir(lockPath);
		if (names.length === 0) {
			return false;
		}
		if (names.length !== 1) throw new Error("fleet_journal_lock_invalid");
		const match = /^owner\.([0-9a-f-]{36})\.json$/i.exec(names[0] as string);
		if (!match || !UUID.test(match[1] as string)) throw new Error("fleet_journal_lock_invalid");
		const ownerPath = join(lockPath, names[0] as string);
		if (!(await regularFile(ownerPath))) return false;
		let owner: LockOwner | null = null;
		try {
			owner = parseOwner(JSON.parse(await readFile(ownerPath, "utf8")), match[1]);
		} catch {
			// A crash from an older writer may have exposed a partial final marker.
		}
		if (!owner) {
			throw new Error("fleet_journal_lock_invalid");
		}
		if (ownerAlive(owner)) return false;

		// Removing the token-specific marker claims this generation. A concurrent
		// old owner or recovery loser cannot remove a replacement generation.
		try {
			await unlink(ownerPath);
		} catch (error) {
			if (errorCode(error) === "ENOENT") return false;
			throw error;
		}
		try {
			await rmdir(lockPath);
			return true;
		} catch (error) {
			if (errorCode(error) === "ENOENT") return true;
			if (errorCode(error) === "ENOTEMPTY" || errorCode(error) === "EEXIST") return false;
			throw error;
		}
	}

	async withLock<T>(work: () => Promise<T>): Promise<T> {
		const token = await this.acquireLock();
		try {
			return await work();
		} finally {
			const lockPath = `${this.path}.lock`;
			const ownerPath = join(lockPath, ownerFileName(token));
			let owned = true;
			try {
				await unlink(ownerPath);
			} catch (error) {
				if (errorCode(error) === "ENOENT") owned = false;
				else throw error;
			}
			if (owned) {
				try {
					await rmdir(lockPath);
				} catch (error) {
					if (errorCode(error) !== "ENOENT") throw new Error("fleet_journal_lock_lost");
				}
			}
		}
	}
}

export function rememberCommand(state: FleetJournalState, commandId: string): FleetJournalState {
	if (!UUID.test(commandId)) throw new Error("invalid_fleet_command_id");
	return {
		...state,
		current: null,
		recent_ids: [...state.recent_ids.filter((id) => id !== commandId), commandId].slice(
			-MAX_RECENT_FLEET_COMMANDS,
		),
	};
}
