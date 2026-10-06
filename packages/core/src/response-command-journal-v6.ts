import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, mkdir, open, readdir, readFile, rename, rm, rmdir, unlink } from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { createDeviceAttestation, type DeviceAttestation } from "./device-attestation.js";
import type {
	FleetResponseCommand,
	FleetResponseIdentity,
	FleetResponseSignedDelivery,
} from "./response-command-consumer-v6.js";

type FleetJournalPhase =
	| "polled"
	| "reject_intent"
	| "acknowledged"
	| "execute_intent"
	| "result_pending";

export interface FleetJournalCurrent {
	command: FleetResponseCommand;
	delivery: FleetResponseSignedDelivery;
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
	bootstrap_at: string;
	last_successful_poll_at: string | null;
	current: FleetJournalCurrent | null;
	recent_ids: string[];
	recent_expiries: Record<string, string>;
	response_control: FleetResponseControlHead;
}

export interface FleetResponseControlHead {
	status: "running" | "paused";
	pause_delivery: FleetResponseSignedDelivery | null;
	resume_delivery: FleetResponseSignedDelivery | null;
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
const MAX_JOURNAL_BYTES = 131_072;
const PROCESS_STARTED_AT_MS = Math.max(0, Math.trunc(Date.now() - process.uptime() * 1000));
export const MAX_RECENT_FLEET_COMMANDS = 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function journalTimestamp(value: unknown): number {
	if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))
		return NaN;
	const parsed = Date.parse(value);
	return parsed > 0 && new Date(parsed).toISOString() === value ? parsed : NaN;
}

function validJournalFreshness(value: Record<string, unknown>, now: number): boolean {
	const bootstrap = journalTimestamp(value.bootstrap_at);
	const poll =
		value.last_successful_poll_at === null
			? bootstrap
			: journalTimestamp(value.last_successful_poll_at);
	return Number.isFinite(now) && now > 0 && bootstrap <= now && poll >= bootstrap && poll <= now;
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
	stableKey = false,
	now = Date.now(),
): asserts value is FleetJournalState {
	if (
		!isRecord(value) ||
		value.schema_version !== 1 ||
		!Number.isSafeInteger(value.sequence) ||
		(value.sequence as number) < 0 ||
		value.tenant_id !== identity.tenantId ||
		value.agent_id !== identity.agentId ||
		value.installation_id !== attestation.installationId ||
		typeof value.key_hash !== "string" ||
		!/^[a-f0-9]{64}$/.test(value.key_hash) ||
		(!stableKey && value.key_hash !== attestation.keyHash) ||
		!validJournalFreshness(value, now) ||
		!Array.isArray(value.recent_ids) ||
		value.recent_ids.length > MAX_RECENT_FLEET_COMMANDS ||
		value.recent_ids.some((id) => typeof id !== "string" || !UUID.test(id)) ||
		new Set(value.recent_ids).size !== value.recent_ids.length ||
		!isRecord(value.recent_expiries) ||
		Object.keys(value.recent_expiries).length !== value.recent_ids.length ||
		value.recent_ids.some(
			(id) =>
				typeof (value.recent_expiries as Record<string, unknown>)[id] !== "string" ||
				!Number.isFinite(
					Date.parse(String((value.recent_expiries as Record<string, unknown>)[id])),
				),
		)
	) {
		throw new Error("invalid_fleet_journal_state");
	}
	assertControlHead(value.response_control, identity, attestation, stableKey);
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
	const delivery = value.current.delivery;
	if (
		!isRecord(delivery) ||
		delivery.alg !== "ed25519" ||
		typeof delivery.key_id !== "string" ||
		typeof delivery.sig_b64 !== "string" ||
		!/^[A-Za-z0-9+/]{86}==$/.test(delivery.sig_b64) ||
		!isRecord(delivery.payload) ||
		delivery.payload.schema_version !== 1 ||
		delivery.payload.purpose !== "aidr.fleet-response.command" ||
		delivery.payload.key_id !== delivery.key_id ||
		delivery.payload.tenant_id !== identity.tenantId ||
		delivery.payload.agent_id !== identity.agentId ||
		delivery.payload.installation_id !== attestation.installationId ||
		typeof delivery.payload.key_hash !== "string" ||
		!/^[a-f0-9]{64}$/.test(delivery.payload.key_hash) ||
		(!stableKey && delivery.payload.key_hash !== attestation.keyHash) ||
		delivery.payload.id !== value.current.command.id ||
		delivery.payload.command_type !== value.current.command.commandType ||
		delivery.payload.expires_at !== value.current.command.expiresAt ||
		delivery.payload.attempt !== value.current.command.attempt ||
		delivery.payload.rollback_of !== value.current.command.rollbackOf
	) {
		throw new Error("invalid_fleet_journal_delivery");
	}
	if (value.recent_ids.includes(value.current.command.id))
		throw new Error("fleet_journal_cursor_conflict");
	if (value.current.phase !== "result_pending" && value.current.resultCode !== null) {
		throw new Error("invalid_fleet_journal_result_phase");
	}
}

function controlDelivery(
	value: unknown,
	identity: FleetResponseIdentity,
	attestation: DeviceAttestation,
	stableKey: boolean,
	commandType: "agent_pause" | "agent_resume",
): value is FleetResponseSignedDelivery {
	if (
		!isRecord(value) ||
		value.alg !== "ed25519" ||
		typeof value.key_id !== "string" ||
		typeof value.sig_b64 !== "string" ||
		!/^[A-Za-z0-9+/]{86}==$/.test(value.sig_b64) ||
		!isRecord(value.payload)
	)
		return false;
	const payload = value.payload;
	return (
		payload.schema_version === 1 &&
		payload.purpose === "aidr.fleet-response.command" &&
		payload.key_id === value.key_id &&
		payload.tenant_id === identity.tenantId &&
		payload.agent_id === identity.agentId &&
		payload.installation_id === attestation.installationId &&
		typeof payload.key_hash === "string" &&
		/^[a-f0-9]{64}$/.test(payload.key_hash) &&
		(stableKey || payload.key_hash === attestation.keyHash) &&
		isRecord(payload.payload) &&
		Object.keys(payload.payload).length === 0 &&
		payload.command_type === commandType &&
		typeof payload.id === "string" &&
		UUID.test(payload.id) &&
		typeof payload.created_at === "string" &&
		Number.isFinite(Date.parse(payload.created_at))
	);
}

function assertControlHead(
	value: unknown,
	identity: FleetResponseIdentity,
	attestation: DeviceAttestation,
	stableKey: boolean,
): asserts value is FleetResponseControlHead {
	if (!isRecord(value) || (value.status !== "running" && value.status !== "paused"))
		throw new Error("invalid_fleet_response_control");
	if (value.status === "running" && value.pause_delivery === null && value.resume_delivery === null)
		return;
	if (
		!controlDelivery(value.pause_delivery, identity, attestation, stableKey, "agent_pause") ||
		value.pause_delivery.payload.rollback_of !== null
	)
		throw new Error("invalid_fleet_response_control");
	if (value.status === "paused" && value.resume_delivery === null) return;
	if (
		value.status !== "running" ||
		!controlDelivery(value.resume_delivery, identity, attestation, stableKey, "agent_resume") ||
		value.resume_delivery.payload.rollback_of !== value.pause_delivery.payload.id ||
		Date.parse(String(value.resume_delivery.payload.created_at)) <
			Date.parse(String(value.pause_delivery.payload.created_at))
	)
		throw new Error("invalid_fleet_response_control");
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

function sameRegularFile(value: Stats, expected: Stats): boolean {
	return (
		value.isFile() &&
		!value.isSymbolicLink() &&
		value.dev === expected.dev &&
		value.ino === expected.ino
	);
}

async function readBoundedRegularFile(path: string): Promise<string | null> {
	let before: Stats;
	try {
		before = await lstat(path);
	} catch (error) {
		if (errorCode(error) === "ENOENT") return null;
		throw error;
	}
	if (!before.isFile() || before.isSymbolicLink()) throw new Error("unsafe_fleet_journal_file");
	if (before.size > MAX_JOURNAL_BYTES) throw new Error("fleet_journal_too_large");
	const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
	try {
		const opened = await handle.stat();
		if (!sameRegularFile(opened, before)) throw new Error("unsafe_fleet_journal_file");
		const buffer = Buffer.alloc(MAX_JOURNAL_BYTES + 1);
		let bytes = 0;
		while (bytes < buffer.length) {
			const chunk = await handle.read(buffer, bytes, buffer.length - bytes, bytes);
			if (chunk.bytesRead === 0) break;
			bytes += chunk.bytesRead;
		}
		if (bytes > MAX_JOURNAL_BYTES) throw new Error("fleet_journal_too_large");
		const after = await lstat(path);
		if (!sameRegularFile(after, opened)) throw new Error("unsafe_fleet_journal_file");
		return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, bytes));
	} finally {
		await handle.close();
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
	private readonly stableKey: boolean;
	private slot: Slot | null = null;
	private sequence = 0;

	constructor(
		path: string,
		identity: FleetResponseIdentity,
		apiKey: string,
		installationId: string,
		stableJournalKey?: string,
		private readonly now: () => number = Date.now,
	) {
		if (!isAbsolute(path)) throw new Error("fleet_journal_path_must_be_absolute");
		if (!apiKey.trim()) throw new Error("invalid_fleet_journal_key");
		this.path = resolve(path);
		this.identity = { ...identity };
		this.attestation = createDeviceAttestation(installationId, apiKey);
		// Keep the raw enrollment key only in memory as the MAC secret. The persisted
		// key hash binds the journal to this enrollment without making the journal
		// forgeable by anyone who can read its public binding fields.
		this.stableKey = stableJournalKey !== undefined;
		if (
			stableJournalKey !== undefined &&
			(!/^[A-Za-z0-9+/]{43}=$/.test(stableJournalKey) ||
				Buffer.from(stableJournalKey, "base64").byteLength !== 32 ||
				Buffer.from(stableJournalKey, "base64").toString("base64") !== stableJournalKey)
		)
			throw new Error("invalid_fleet_journal_stable_key");
		this.key = stableJournalKey ?? apiKey.trim();
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
		const raw = await readBoundedRegularFile(path);
		if (raw === null) return null;
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
		assertState(envelope.payload, this.identity, this.attestation, this.stableKey, this.now());
		return envelope.payload;
	}

	private async latest(): Promise<{ state: FleetJournalState | null; slot: Slot | null }> {
		const [a, b] = await Promise.all([this.readSlot("a"), this.readSlot("b")]);
		if (a && b && a.sequence === b.sequence) throw new Error("fleet_journal_sequence_conflict");
		const selected = !a ? b : !b ? a : a.sequence > b.sequence ? a : b;
		return { state: selected, slot: selected === a && a ? "a" : selected ? "b" : null };
	}

	/** Read authenticated state without creating a directory, lock, or initial running head. */
	async inspect(): Promise<FleetJournalState | null> {
		try {
			const info = await lstat(dirname(this.path));
			if (!info.isDirectory() || info.isSymbolicLink())
				throw new Error("unsafe_fleet_journal_directory");
		} catch (error) {
			if (errorCode(error) === "ENOENT") return null;
			throw error;
		}
		return (await this.latest()).state;
	}

	private initialState(): FleetJournalState {
		return {
			schema_version: 1,
			sequence: 0,
			tenant_id: this.identity.tenantId,
			agent_id: this.identity.agentId,
			installation_id: this.attestation.installationId,
			key_hash: this.attestation.keyHash,
			bootstrap_at: new Date(this.now()).toISOString(),
			last_successful_poll_at: null,
			current: null,
			recent_ids: [],
			recent_expiries: {},
			response_control: { status: "running", pause_delivery: null, resume_delivery: null },
		};
	}

	/** Only an operator installing response control on a previously unrequired host may call this. */
	async bootstrapResponseControl(): Promise<FleetJournalState> {
		return this.withLock(async () => {
			const latest = await this.latest();
			this.slot = latest.slot;
			this.sequence = latest.state?.sequence ?? 0;
			return latest.state ?? this.save(this.initialState());
		});
	}

	async load(): Promise<FleetJournalState> {
		await this.ensureDirectory();
		const latest = await this.latest();
		if (!latest.state && this.stableKey) throw new Error("fleet_journal_bootstrap_required");
		this.slot = latest.slot;
		this.sequence = latest.state?.sequence ?? 0;
		return latest.state ?? this.initialState();
	}

	async save(state: FleetJournalState): Promise<FleetJournalState> {
		assertState(state, this.identity, this.attestation, this.stableKey, this.now());
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
		const rawOwner = await readBoundedRegularFile(ownerPath);
		if (rawOwner === null) return false;
		let owner: LockOwner | null = null;
		try {
			owner = parseOwner(JSON.parse(rawOwner), match[1]);
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

export function retainRecentCommands(state: FleetJournalState, now: number): FleetJournalState {
	if (!Number.isFinite(now)) throw new Error("invalid_fleet_journal_clock");
	const recent_ids = state.recent_ids.filter(
		(id) => Date.parse(state.recent_expiries[id] ?? "") > now,
	);
	return {
		...state,
		recent_ids,
		recent_expiries: Object.fromEntries(
			recent_ids.map((id) => [id, state.recent_expiries[id] as string]),
		),
	};
}

export function rememberCommand(
	state: FleetJournalState,
	commandId: string,
	now = Date.now(),
): FleetJournalState {
	if (!UUID.test(commandId)) throw new Error("invalid_fleet_command_id");
	const retained = retainRecentCommands(state, now);
	const expiry =
		state.current?.command.id === commandId
			? state.current.command.expiresAt
			: state.recent_expiries[commandId];
	if (!expiry) throw new Error("missing_fleet_command_expiry");
	if (Date.parse(expiry) <= now) return { ...retained, current: null };
	if (
		!retained.recent_ids.includes(commandId) &&
		retained.recent_ids.length >= MAX_RECENT_FLEET_COMMANDS
	)
		throw new Error("fleet_command_replay_cache_full");
	return {
		...retained,
		current: null,
		recent_ids: [...retained.recent_ids.filter((id) => id !== commandId), commandId],
		recent_expiries: { ...retained.recent_expiries, [commandId]: expiry },
	};
}
