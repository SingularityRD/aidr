import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { link, lstat, mkdir, open, readFile, rename, rm, unlink } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import type {
	FleetResponseCommand,
	FleetResponseIdentity,
} from "./response-command-consumer-v6.js";

export type FleetJournalPhase =
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
	current: FleetJournalCurrent | null;
	recent_ids: string[];
}

type Slot = "a" | "b";
type Envelope = { payload: FleetJournalState; mac: string };

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
export const MAX_RECENT_FLEET_COMMANDS = 256;

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
): asserts value is FleetJournalState {
	if (
		!isRecord(value) ||
		value.schema_version !== 1 ||
		!Number.isSafeInteger(value.sequence) ||
		(value.sequence as number) < 0 ||
		value.tenant_id !== identity.tenantId ||
		value.agent_id !== identity.agentId ||
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

export class FleetResponseJournal {
	private readonly path: string;
	private readonly identity: FleetResponseIdentity;
	private readonly key: string;
	private slot: Slot | null = null;
	private sequence = 0;

	constructor(path: string, identity: FleetResponseIdentity, apiKey: string) {
		if (!isAbsolute(path)) throw new Error("fleet_journal_path_must_be_absolute");
		if (!apiKey.trim()) throw new Error("invalid_fleet_journal_key");
		this.path = resolve(path);
		this.identity = { ...identity };
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
		assertState(envelope.payload, this.identity);
		const expected = Buffer.from(macFor(envelope.payload, this.key), "hex");
		const actual = Buffer.from(envelope.mac, "hex");
		if (!timingSafeEqual(expected, actual)) throw new Error("fleet_journal_integrity_failed");
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
				current: null,
				recent_ids: [],
			}
		);
	}

	async save(state: FleetJournalState): Promise<FleetJournalState> {
		assertState(state, this.identity);
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
		const token = randomUUID();
		const temporary = `${lockPath}.${token}.tmp`;
		await writeSynced(temporary, JSON.stringify({ pid: process.pid, token }));
		try {
			try {
				await link(temporary, lockPath);
				return token;
			} catch (error) {
				if (!isRecord(error) || error.code !== "EEXIST") throw error;
			}
			await this.recoverDeadLock(lockPath);
			await link(temporary, lockPath);
			return token;
		} finally {
			await rm(temporary, { force: true });
		}
	}

	private async recoverDeadLock(lockPath: string): Promise<void> {
		const recoveryPath = `${lockPath}.recovery`;
		const recoveryToken = randomUUID();
		const temporary = `${recoveryPath}.${recoveryToken}.tmp`;
		await writeSynced(temporary, JSON.stringify({ pid: process.pid, token: recoveryToken }));
		try {
			try {
				await link(temporary, recoveryPath);
			} catch {
				throw new Error("fleet_journal_locked");
			}
			try {
				if (!(await regularFile(lockPath))) return;
				const owner = JSON.parse(await readFile(lockPath, "utf8")) as unknown;
				if (
					!isRecord(owner) ||
					!Number.isSafeInteger(owner.pid) ||
					(owner.pid as number) < 1 ||
					typeof owner.token !== "string" ||
					!UUID.test(owner.token)
				) {
					throw new Error("fleet_journal_lock_invalid");
				}
				if (pidAlive(owner.pid as number)) throw new Error("fleet_journal_locked");
				await unlink(lockPath);
			} finally {
				await rm(recoveryPath, { force: true });
			}
		} finally {
			await rm(temporary, { force: true });
		}
	}

	async withLock<T>(work: () => Promise<T>): Promise<T> {
		const token = await this.acquireLock();
		try {
			return await work();
		} finally {
			const lockPath = `${this.path}.lock`;
			if (await regularFile(lockPath)) {
				const owner = JSON.parse(await readFile(lockPath, "utf8")) as unknown;
				if (!isRecord(owner) || owner.token !== token) throw new Error("fleet_journal_lock_lost");
				await unlink(lockPath);
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
