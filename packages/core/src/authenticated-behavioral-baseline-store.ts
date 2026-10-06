import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { lstat, open, readdir, unlink } from "node:fs/promises";
import { join } from "node:path";
import type {
	BehavioralBaselineObservation,
	BehavioralBaselineStoreBounds,
} from "./behavioral-baseline-store.js";
import {
	type LearningReceiptContext,
	type VerifiedLearningReceipt,
	verifyLearningReceiptBundle,
} from "./behavioral-learning-receipt.js";
import { BEHAVIORAL_ORCHESTRATOR_BOUNDS } from "./behavioral-orchestrator.js";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import { preparePrivateLocalDirectory, preparePrivateLocalFile } from "./private-local-file.js";

export type AuthenticatedBehavioralObservation = BehavioralBaselineObservation & {
	fingerprint: string;
};

export interface AuthenticatedBehavioralBaselineStore {
	readonly context: LearningReceiptContext;
	load(sessionId: string): Promise<AuthenticatedBehavioralObservation[]>;
	transact<T>(
		sessionId: string,
		bundle: unknown,
		decide: (
			receipt: VerifiedLearningReceipt,
			observations: AuthenticatedBehavioralObservation[],
		) => Promise<{ value: T; accept: boolean }>,
	): Promise<T>;
	clearSession(tenantId: string, sessionId: string): Promise<void>;
	clearTenant(tenantId: string): Promise<void>;
}

export interface AuthenticatedBehavioralBaselineStoreOptions
	extends Partial<BehavioralBaselineStoreBounds> {
	context: LearningReceiptContext;
	/** Random secret from the OS vault; a public installation ID is not an authentication key. */
	authenticationKey: Buffer;
	storeDir?: string;
	now?: () => number;
}

interface Entry {
	bundle: unknown;
	acceptedAt: number;
	timestamp: number;
	executionId: string;
	approvalId: string;
	activation: {
		entitlementSerial: string;
		validFromMs: number;
		validUntilMs: number;
	};
}
interface Session {
	entries: Entry[];
	updatedAt: number;
}
interface Spent {
	executionId: string;
	approvalId: string;
	expiresAt: number;
}
interface Journal {
	schemaVersion: 3;
	namespace: string;
	binding: string;
	sessions: Record<string, Session>;
	spent: Spent[];
}

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_FUTURE_SKEW_MS = 60_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const own = (value: unknown): value is Record<string, unknown> =>
	value !== null && typeof value === "object" && !Array.isArray(value);
const identifier = (value: unknown): value is string =>
	typeof value === "string" &&
	value.length > 0 &&
	value.length <= 256 &&
	!/[\u0000-\u001f\u007f]/.test(value);

/**
 * V3 authenticates its replay ledger and observations in one private, locked,
 * synced replacement. It never reads legacy V1/V2 records. This protects normal
 * restart/concurrent-process replay, not rollback by the owner of the OS vault.
 */
export class FileAuthenticatedBehavioralBaselineStore
	implements AuthenticatedBehavioralBaselineStore
{
	readonly context: LearningReceiptContext;
	private readonly key: Buffer;
	private readonly root: string;
	private readonly path: string;
	private readonly namespace: string;
	private readonly binding: string;
	private readonly bounds: BehavioralBaselineStoreBounds;
	private readonly now: () => number;

	constructor(options: AuthenticatedBehavioralBaselineStoreOptions) {
		if (!Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.length !== 32)
			throw new Error("Behavioral journal requires a 32-byte secret authentication key");
		const defaults = BEHAVIORAL_ORCHESTRATOR_BOUNDS;
		this.bounds = {
			maxTenants: options.maxTenants ?? defaults.maxTenants,
			maxSessionsPerTenant: options.maxSessionsPerTenant ?? defaults.maxSessionsPerTenant,
			maxEventsPerSession: options.maxEventsPerSession ?? defaults.maxEventsPerSession,
			maxFingerprintsPerSession:
				options.maxFingerprintsPerSession ?? defaults.maxFingerprintsPerSession,
			retentionMs: options.retentionMs ?? defaults.retentionMs,
		};
		for (const [name, value] of Object.entries(this.bounds)) {
			if (
				!Number.isSafeInteger(value) ||
				value < 1 ||
				value > defaults[name as keyof typeof defaults]
			)
				throw new Error("Behavioral journal bounds are invalid");
		}
		this.context = structuredClone(options.context);
		Object.freeze(this.context.authorities.execution);
		Object.freeze(this.context.authorities.approval);
		Object.freeze(this.context.authorities);
		if (this.context.revokedEntitlementSerials)
			Object.freeze(this.context.revokedEntitlementSerials);
		Object.freeze(this.context);
		this.key = Buffer.from(options.authenticationKey);
		this.now = options.now ?? Date.now;
		this.namespace = JSON.stringify([
			this.context.tenantId,
			this.context.deviceId,
			this.context.agentRuntime,
		]);
		this.binding = JSON.stringify([
			this.context.policyDigest,
			this.context.corpusDigest,
			this.context.modelVersion,
			this.context.revocationEpoch ?? 0,
		]);
		this.root = resolvePath(
			options.storeDir ?? "~/.singularity-aidr/behavioral-baseline-authenticated",
		);
		const digest = createHash("sha256").update(this.namespace).digest("hex");
		this.path = join(this.root, `${digest}.v3.json`);
	}

	async load(sessionId: string): Promise<AuthenticatedBehavioralObservation[]> {
		this.assertSession(sessionId);
		return this.withLock(async () => {
			const state = await this.read();
			// Retention applies to disk as well as scoring, including clean-only sessions.
			const before = JSON.stringify(state);
			this.pruneSessions(state);
			state.spent = state.spent.filter((spent) => spent.expiresAt > this.now());
			if (JSON.stringify(state) !== before) await this.write(state);
			if (state.binding !== this.binding) return [];
			return this.observations(this.session(state, sessionId), sessionId);
		});
	}

	async transact<T>(
		sessionId: string,
		bundle: unknown,
		decide: (
			receipt: VerifiedLearningReceipt,
			observations: AuthenticatedBehavioralObservation[],
		) => Promise<{ value: T; accept: boolean }>,
	): Promise<T> {
		this.assertSession(sessionId);
		const proof = structuredClone(bundle);
		return this.withLock(async () => {
			const state = await this.read();
			const receipt = verifyLearningReceiptBundle(proof, this.context, {
				mode: "ingest",
				now: this.now(),
			});
			if (receipt.sessionId !== sessionId)
				throw new Error("Behavioral receipt session binding failed");
			state.spent = state.spent.filter((spent) => spent.expiresAt > this.now());
			if (
				state.spent.some(
					(spent) =>
						spent.executionId === receipt.executionId || spent.approvalId === receipt.approvalId,
				)
			)
				throw new Error("Behavioral learning receipt has already been consumed");
			if (
				state.spent.length >=
				this.bounds.maxSessionsPerTenant * this.bounds.maxEventsPerSession * 2
			)
				throw new Error("Behavioral receipt replay ledger is full");
			if (state.binding !== this.binding) {
				state.binding = this.binding;
				state.sessions = {};
			}
			this.pruneSessions(state);
			if (
				Object.values(state.sessions).some((session) =>
					session.entries.some(
						(entry) =>
							entry.executionId === receipt.executionId || entry.approvalId === receipt.approvalId,
					),
				)
			)
				throw new Error("Behavioral learning receipt has already been consumed");
			const observations = this.observations(this.session(state, sessionId), sessionId);
			const decision = await decide(structuredClone(receipt), observations);
			if (!decision.accept) return decision.value;
			const acceptedAt = this.now();
			// A slow analysis may not commit after either signed receipt expires.
			verifyLearningReceiptBundle(proof, this.context, { mode: "ingest", now: acceptedAt });
			if (receipt.observation.timestamp < acceptedAt - this.bounds.retentionMs)
				throw new Error("Behavioral observation is outside its retention window");
			const session = this.getOrCreateSession(state, sessionId, acceptedAt);
			session.entries.push({
				bundle: proof,
				acceptedAt,
				timestamp: receipt.observation.timestamp,
				executionId: receipt.executionId,
				approvalId: receipt.approvalId,
				activation: {
					entitlementSerial: this.context.entitlementSerial,
					validFromMs: this.context.validFromMs,
					validUntilMs: this.context.validUntilMs,
				},
			});
			session.entries = session.entries.slice(-this.bounds.maxEventsPerSession);
			session.updatedAt = acceptedAt;
			state.sessions[sessionId] = session;
			state.spent.push({
				executionId: receipt.executionId,
				approvalId: receipt.approvalId,
				expiresAt: receipt.expiresAt,
			});
			await this.write(state);
			return decision.value;
		});
	}

	async clearSession(tenantId: string, sessionId: string): Promise<void> {
		if (tenantId !== this.context.tenantId) return;
		this.assertSession(sessionId);
		await this.withLock(async () => {
			const state = await this.read();
			delete state.sessions[sessionId];
			state.spent = state.spent.filter((spent) => spent.expiresAt > this.now());
			await this.write(state);
		});
	}

	async clearTenant(tenantId: string): Promise<void> {
		if (tenantId !== this.context.tenantId) return;
		await this.withLock(async () => {
			const state = await this.read();
			state.sessions = {};
			state.spent = state.spent.filter((spent) => spent.expiresAt > this.now());
			await this.write(state);
		});
	}

	private assertSession(value: string): void {
		if (!identifier(value) || ["__proto__", "constructor", "prototype"].includes(value))
			throw new Error("Behavioral session identity is invalid");
	}

	private session(state: Journal, sessionId: string): Session | undefined {
		return Object.hasOwn(state.sessions, sessionId) ? state.sessions[sessionId] : undefined;
	}

	private getOrCreateSession(state: Journal, sessionId: string, acceptedAt: number): Session {
		const existing = this.session(state, sessionId);
		if (existing) return existing;
		if (Object.keys(state.sessions).length >= this.bounds.maxSessionsPerTenant) {
			const oldest = Object.keys(state.sessions).sort(
				(a, b) => (state.sessions[a]?.updatedAt ?? 0) - (state.sessions[b]?.updatedAt ?? 0),
			)[0];
			if (oldest) delete state.sessions[oldest];
		}
		return { entries: [], updatedAt: acceptedAt };
	}

	private observations(
		session: Session | undefined,
		sessionId: string,
	): AuthenticatedBehavioralObservation[] {
		const observations: AuthenticatedBehavioralObservation[] = [];
		const executions = new Set<string>();
		const approvals = new Set<string>();
		for (const entry of session?.entries ?? []) {
			if (entry.timestamp < this.now() - this.bounds.retentionMs) continue;
			const receipt = verifyLearningReceiptBundle(entry.bundle, this.context, {
				mode: "restore",
				now: this.now(),
				acceptedAt: entry.acceptedAt,
				activation: entry.activation,
			});
			if (
				receipt.sessionId !== sessionId ||
				receipt.executionId !== entry.executionId ||
				receipt.approvalId !== entry.approvalId ||
				receipt.observation.timestamp !== entry.timestamp ||
				executions.has(receipt.executionId) ||
				approvals.has(receipt.approvalId)
			)
				throw new Error("Behavioral baseline receipt identity is invalid");
			executions.add(receipt.executionId);
			approvals.add(receipt.approvalId);
			observations.push({ ...receipt.observation, fingerprint: receipt.fingerprint });
		}
		return observations;
	}

	private pruneSessions(state: Journal): void {
		const cutoff = this.now() - this.bounds.retentionMs;
		for (const [id, session] of Object.entries(state.sessions)) {
			session.entries = session.entries.filter((entry) => entry.timestamp >= cutoff);
			if (!session.entries.length) delete state.sessions[id];
		}
	}

	private mac(payload: Journal): string {
		return createHmac("sha256", this.key).update(JSON.stringify(payload)).digest("hex");
	}

	private async read(): Promise<Journal> {
		let raw: string;
		try {
			const info = await lstat(this.path);
			if (info.isSymbolicLink() || !info.isFile() || info.size > MAX_BYTES)
				throw new Error("Behavioral journal is unsafe or oversized");
			preparePrivateLocalFile(this.path);
			raw = await getFileContent(this.path);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			return {
				schemaVersion: 3,
				namespace: this.namespace,
				binding: this.binding,
				sessions: {},
				spent: [],
			};
		}
		const envelope: unknown = JSON.parse(raw);
		if (
			!own(envelope) ||
			!own(envelope.payload) ||
			typeof envelope.mac !== "string" ||
			!/^[a-f0-9]{64}$/.test(envelope.mac)
		)
			throw new Error("Behavioral journal authentication is invalid");
		const payload = envelope.payload as unknown as Journal;
		const actual = Buffer.from(envelope.mac, "hex");
		if (!timingSafeEqual(actual, Buffer.from(this.mac(payload), "hex")))
			throw new Error("Behavioral journal authentication is invalid");
		this.assertJournal(payload);
		return payload;
	}

	private assertJournal(state: Journal): void {
		if (
			state.schemaVersion !== 3 ||
			state.namespace !== this.namespace ||
			typeof state.binding !== "string" ||
			state.binding.length > 2048 ||
			!own(state.sessions) ||
			Object.keys(state.sessions).length > this.bounds.maxSessionsPerTenant ||
			!Array.isArray(state.spent) ||
			state.spent.length > this.bounds.maxSessionsPerTenant * this.bounds.maxEventsPerSession * 2
		)
			throw new Error("Behavioral journal schema or binding is invalid");
		const executionIds = new Set<string>();
		const approvalIds = new Set<string>();
		for (const spent of state.spent) {
			if (
				!own(spent) ||
				typeof spent.executionId !== "string" ||
				!UUID.test(spent.executionId) ||
				typeof spent.approvalId !== "string" ||
				!UUID.test(spent.approvalId) ||
				!Number.isSafeInteger(spent.expiresAt) ||
				executionIds.has(spent.executionId) ||
				approvalIds.has(spent.approvalId)
			)
				throw new Error("Behavioral replay ledger is invalid");
			executionIds.add(spent.executionId);
			approvalIds.add(spent.approvalId);
		}
		for (const [id, session] of Object.entries(state.sessions))
			this.assertSessionRecord(id, session);
	}

	private assertSessionRecord(id: string, session: Session): void {
		this.assertSession(id);
		if (
			!own(session) ||
			!Array.isArray(session.entries) ||
			session.entries.length > this.bounds.maxEventsPerSession ||
			!Number.isSafeInteger(session.updatedAt)
		)
			throw new Error("Behavioral journal session is invalid");
		for (const entry of session.entries) {
			if (
				!own(entry) ||
				!Number.isSafeInteger(entry.acceptedAt) ||
				!Number.isSafeInteger(entry.timestamp) ||
				typeof entry.executionId !== "string" ||
				!UUID.test(entry.executionId) ||
				typeof entry.approvalId !== "string" ||
				!UUID.test(entry.approvalId) ||
				!own(entry.activation) ||
				!identifier(entry.activation.entitlementSerial) ||
				!Number.isSafeInteger(entry.activation.validFromMs) ||
				!Number.isSafeInteger(entry.activation.validUntilMs) ||
				entry.activation.validFromMs > entry.acceptedAt ||
				entry.activation.validUntilMs <= entry.acceptedAt ||
				entry.timestamp > this.now() + MAX_FUTURE_SKEW_MS
			)
				throw new Error("Behavioral journal observation is invalid");
		}
	}

	private async write(state: Journal): Promise<void> {
		this.assertJournal(state);
		const envelope = { payload: state, mac: this.mac(state) };
		if (Buffer.byteLength(`${JSON.stringify(envelope, null, 2)}\n`) > MAX_BYTES)
			throw new Error("Behavioral journal capacity is exhausted");
		await atomicWriteJson(this.path, envelope);
		preparePrivateLocalFile(this.path);
	}

	private async withLock<T>(operation: () => Promise<T>): Promise<T> {
		preparePrivateLocalDirectory(this.root);
		// The namespace quota and every journal mutation share one store-root lock.
		const lockPath = join(this.root, ".transaction.lock");
		const deadline = performance.now() + 1_000;
		let handle: Awaited<ReturnType<typeof open>>;
		for (;;) {
			try {
				handle = await open(lockPath, "wx", 0o600);
				break;
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "EEXIST" || performance.now() >= deadline)
					throw new Error("Behavioral journal is locked or unavailable", { cause: error });
				await new Promise((resolve) => setTimeout(resolve, 10));
			}
		}
		try {
			await handle.writeFile(JSON.stringify({ pid: process.pid, token: randomUUID() }));
			await handle.sync();
			const exists = await lstat(this.path).then(
				() => true,
				(error: NodeJS.ErrnoException) => {
					if (error.code === "ENOENT") return false;
					throw error;
				},
			);
			if (
				!exists &&
				(await readdir(this.root)).filter((name) => name.endsWith(".v3.json")).length >=
					this.bounds.maxTenants
			)
				throw new Error("Behavioral journal namespace quota is exhausted");
			return await operation();
		} finally {
			await handle.close();
			await unlink(lockPath);
		}
	}
}

export function createAuthenticatedBehavioralBaselineStore(
	options: AuthenticatedBehavioralBaselineStoreOptions,
): FileAuthenticatedBehavioralBaselineStore {
	return new FileAuthenticatedBehavioralBaselineStore(options);
}
