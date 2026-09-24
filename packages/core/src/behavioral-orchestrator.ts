import { createHash } from "node:crypto";
import { BehavioralAnalyzer, type ToolCallEvent } from "./behavioral-analyzer.js";
import type {
	BehavioralBaselineObservation,
	BehavioralBaselineStore,
} from "./behavioral-baseline-store.js";
import { LOCAL_EMBEDDER_MODEL_VERSION } from "./behavioral-corpus.js";
import { LocalEmbeddingModel } from "./ml-model.js";

export { LOCAL_EMBEDDER_MODEL_VERSION } from "./behavioral-corpus.js";

import { NoveltyDetector } from "./novelty-detection.js";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

export type BehavioralDetectionOutcome = "anomalous" | "normal" | "learning" | "unavailable";
export type BehavioralDetectionLeg = "behavioral" | "novelty" | "ml";
export type BehavioralDetectionLegStatus = "ready" | "learning" | "unavailable";

export interface BehavioralDetectionInput {
	tenantId: string;
	sessionId: string;
	toolName: string;
	riskScore: number;
	timestamp: Date | number;
	command?: string;
	path?: string;
	url?: string;
	durationMs?: number;
	classificationText?: string;
	/** Trusted post-execution callers must opt in; tool-evaluation preflight never does. */
	learningAllowed?: boolean;
}

export interface BehavioralLegExplanation {
	leg: BehavioralDetectionLeg;
	status: BehavioralDetectionLegStatus;
	score: number | null;
	summary: string;
	evidence: string[];
	modelVersion?: string;
	unavailableReason?:
		| "not_configured"
		| "initialization_failed"
		| "empty_corpus"
		| "inference_failed"
		| "analysis_failed";
}

export interface BehavioralLearningDisposition {
	accepted: boolean;
	reason:
		| "accepted"
		| "explicitly_disabled"
		| "high_risk_event"
		| "anomaly_detected"
		| "detection_unavailable"
		| "fingerprint_limit";
	baselineSamplesBefore: number;
	baselineSamplesAfter: number;
	requiredBaselineSamples: number;
}

export interface BehavioralDetectionResult {
	outcome: BehavioralDetectionOutcome;
	anomalyScore: number | null;
	modelVersion: string | null;
	explanations: BehavioralLegExplanation[];
	learning: BehavioralLearningDisposition;
}

export interface BehavioralOrchestratorStats {
	tenantCount: number;
	sessionCount: number;
	totalBaselineSamples: number;
	tenantEvictions: number;
	sessionEvictions: number;
	inFlightScopes: number;
}

export interface BehavioralOrchestratorConfig {
	minBaselineSamples: number;
	maxTenants: number;
	maxSessionsPerTenant: number;
	maxEventsPerSession: number;
	maxFingerprintsPerSession: number;
	maxColdStartSamplesPerFingerprint: number;
	maxLearningRiskScore: number;
	behavioralAnomalyThreshold: number;
	maxEventAgeMs: number;
	maxFutureSkewMs: number;
	modelVersion: string;
}

interface EmbeddingThreatMatch {
	threatId: string;
	similarity: number;
	metadata: {
		category: string;
		severity: string;
		description: string;
	};
}

/** Narrow interface lets callers provide LocalEmbeddingModel or a supervised compatible model. */
export type BehavioralEmbeddingModel = Pick<
	LocalEmbeddingModel,
	"load" | "findSimilarThreats" | "getStats"
>;

export interface BehavioralOrchestratorDependencies {
	mlModel?: BehavioralEmbeddingModel;
	/**
	 * Retained to clear existing local records. Reads and writes stay disabled
	 * until verified execution receipts are bound to persisted observations.
	 */
	baselineStore?: BehavioralBaselineStore;
	/** Trusted provisioning ceiling: events cannot override signed consent or tenant. */
	provisionedPolicy?: { tenantId: string; learningAllowed: boolean };
	logger?: Logger;
	now?: () => number;
	createBehavioralAnalyzer?: () => BehavioralAnalyzer;
	createNoveltyDetector?: () => NoveltyDetector;
}

interface SessionState {
	/** Accepted observations, already reduced to pseudonymous novelty tokens. */
	observations: BehavioralBaselineObservation[];
	noveltyDetector: NoveltyDetector;
	baselineSamples: number;
	fingerprintCounts: Map<string, number>;
}

interface TenantState {
	sessions: Map<string, SessionState>;
}

type ModelState = "uninitialized" | "ready" | "initialization_failed" | "empty_corpus";

/**
 * Bounds the orchestrator applies in memory, and that any durable baseline store
 * must apply on disk. Exported so a store and its orchestrator cannot drift.
 * `retentionMs` is the event window `validateInput` already enforces.
 */
export const BEHAVIORAL_ORCHESTRATOR_BOUNDS = {
	maxTenants: 50,
	maxSessionsPerTenant: 20,
	maxEventsPerSession: 100,
	maxFingerprintsPerSession: 256,
	retentionMs: 30 * 24 * 60 * 60 * 1000,
} as const;

const DEFAULT_CONFIG: BehavioralOrchestratorConfig = {
	minBaselineSamples: 10,
	maxTenants: BEHAVIORAL_ORCHESTRATOR_BOUNDS.maxTenants,
	maxSessionsPerTenant: BEHAVIORAL_ORCHESTRATOR_BOUNDS.maxSessionsPerTenant,
	maxEventsPerSession: BEHAVIORAL_ORCHESTRATOR_BOUNDS.maxEventsPerSession,
	maxFingerprintsPerSession: BEHAVIORAL_ORCHESTRATOR_BOUNDS.maxFingerprintsPerSession,
	maxColdStartSamplesPerFingerprint: 5,
	maxLearningRiskScore: 50,
	behavioralAnomalyThreshold: 2.5,
	maxEventAgeMs: BEHAVIORAL_ORCHESTRATOR_BOUNDS.retentionMs,
	maxFutureSkewMs: 5 * 60 * 1000,
	modelVersion: "unversioned",
};

const MAX_ID_LENGTH = 256;
const MAX_TOOL_LENGTH = 512;
const MAX_VALUE_LENGTH = 16_384;

/**
 * Coordinates behavioral, novelty and local-ML detection without sharing learned
 * observations across tenant/session boundaries. Candidate events are scored
 * before they are committed to the baseline, and degraded detection never
 * produces a clean result or updates learning state.
 */
export class BehavioralDetectionOrchestrator {
	private readonly config: BehavioralOrchestratorConfig;
	private readonly tenants = new Map<string, TenantState>();
	private readonly logger: Logger;
	private readonly now: () => number;
	private readonly createBehavioralAnalyzer: () => BehavioralAnalyzer;
	private readonly createNoveltyDetector: () => NoveltyDetector;
	private readonly baselineStore: BehavioralBaselineStore | undefined;
	private readonly provisionedPolicy:
		| Readonly<{ tenantId: string; learningAllowed: boolean }>
		| undefined;
	private readonly scopeQueues = new Map<string, Promise<void>>();
	private mlModel: BehavioralEmbeddingModel | undefined;
	private modelVersion: string | null;
	private modelState: ModelState;
	private modelInitialization: Promise<void> | undefined;
	private modelGeneration = 0;
	private tenantEvictions = 0;
	private sessionEvictions = 0;

	constructor(
		config: Partial<BehavioralOrchestratorConfig> = {},
		dependencies: BehavioralOrchestratorDependencies = {},
	) {
		this.config = { ...DEFAULT_CONFIG, ...config };
		validateConfig(this.config);
		this.logger = dependencies.logger ?? nullLogger;
		this.now = dependencies.now ?? Date.now;
		this.baselineStore = dependencies.baselineStore;
		this.provisionedPolicy = dependencies.provisionedPolicy
			? Object.freeze({ ...dependencies.provisionedPolicy })
			: undefined;
		this.createBehavioralAnalyzer =
			dependencies.createBehavioralAnalyzer ??
			(() =>
				new BehavioralAnalyzer(
					this.config.maxEventsPerSession,
					this.config.behavioralAnomalyThreshold,
					this.logger,
				));
		this.createNoveltyDetector =
			dependencies.createNoveltyDetector ??
			(() =>
				new NoveltyDetector({
					minBaselineSamples: this.config.minBaselineSamples,
				}));
		// The embedder alone is not a threat database: the default stays
		// unavailable until a trusted caller supplies a populated model.
		const usesDefaultModel = dependencies.mlModel === undefined;
		this.mlModel =
			dependencies.mlModel ?? new LocalEmbeddingModel(LocalEmbeddingModel.createDefaultConfig());
		this.modelVersion =
			usesDefaultModel && config.modelVersion === undefined
				? LOCAL_EMBEDDER_MODEL_VERSION
				: this.config.modelVersion;
		this.modelState = "uninitialized";
	}

	async evaluate(input: BehavioralDetectionInput): Promise<BehavioralDetectionResult> {
		const event = this.validateInput(input);
		const scopeKey = `${event.tenantId}\u0000${event.sessionId}`;
		const prior = this.scopeQueues.get(scopeKey) ?? Promise.resolve();
		const operation = prior.catch(() => undefined).then(() => this.evaluateScoped(event));
		const tail = operation.then(
			() => undefined,
			() => undefined,
		);
		this.scopeQueues.set(scopeKey, tail);

		try {
			return await operation;
		} finally {
			if (this.scopeQueues.get(scopeKey) === tail) {
				this.scopeQueues.delete(scopeKey);
			}
		}
	}

	/** Load and validate a replacement before atomically making it active. */
	async refreshModel(model: BehavioralEmbeddingModel, version: string): Promise<void> {
		if (this.provisionedPolicy) {
			throw new Error("Provisioned corpus replacement requires a newly verified policy context");
		}
		if (!version.trim() || version.length > MAX_ID_LENGTH) {
			throw new Error("Model version must be a non-empty bounded string");
		}

		await model.load();
		const stats = await model.getStats();
		if (stats.threatCount < 1) {
			throw new Error("Refusing to activate an embedding model with an empty threat corpus");
		}

		this.mlModel = model;
		this.modelVersion = version;
		this.modelState = "ready";
		this.modelGeneration++;
		this.modelInitialization = undefined;
	}

	clearSession(tenantId: string, sessionId: string): boolean {
		const tenant = this.tenants.get(tenantId);
		this.dropPersisted(() => this.baselineStore?.clearSession(tenantId, sessionId));
		if (!tenant) return false;
		const removed = tenant.sessions.delete(sessionId);
		if (tenant.sessions.size === 0) this.tenants.delete(tenantId);
		return removed;
	}

	clearTenant(tenantId: string): boolean {
		this.dropPersisted(() => this.baselineStore?.clearTenant(tenantId));
		return this.tenants.delete(tenantId);
	}

	getStats(): BehavioralOrchestratorStats {
		let sessionCount = 0;
		let totalBaselineSamples = 0;
		for (const tenant of this.tenants.values()) {
			sessionCount += tenant.sessions.size;
			for (const session of tenant.sessions.values()) {
				totalBaselineSamples += session.baselineSamples;
			}
		}

		return {
			tenantCount: this.tenants.size,
			sessionCount,
			totalBaselineSamples,
			tenantEvictions: this.tenantEvictions,
			sessionEvictions: this.sessionEvictions,
			inFlightScopes: this.scopeQueues.size,
		};
	}

	private async evaluateScoped(
		event: ReturnType<BehavioralDetectionOrchestrator["validateInput"]>,
	): Promise<BehavioralDetectionResult> {
		const session = await this.getOrCreateSession(event.tenantId, event.sessionId);
		const samplesBefore = session.baselineSamples;
		const explanations = await Promise.all([
			this.evaluateBehavioralLeg(session, event, samplesBefore),
			this.evaluateNoveltyLeg(session, event, samplesBefore),
			this.evaluateMlLeg(event.classificationText),
		]);

		const readyScores = explanations
			.filter((explanation) => explanation.status === "ready")
			.map((explanation) => explanation.score ?? 0);
		const anomalyScore = readyScores.length > 0 ? Math.max(...readyScores) : null;
		const anomalyDetected = readyScores.some((score) => score > 0);
		const detectionUnavailable = explanations.some(
			(explanation) => explanation.status === "unavailable",
		);
		const fingerprint = buildFingerprint(event);
		const fingerprintCount = session.fingerprintCounts.get(fingerprint) ?? 0;
		const fingerprintLimitReached =
			(!session.fingerprintCounts.has(fingerprint) &&
				session.fingerprintCounts.size >= this.config.maxFingerprintsPerSession) ||
			(samplesBefore < this.config.minBaselineSamples &&
				fingerprintCount >= this.config.maxColdStartSamplesPerFingerprint);

		const learningReason = determineLearningReason({
			learningAllowed: event.learningAllowed,
			riskScore: event.riskScore,
			maxLearningRiskScore: this.config.maxLearningRiskScore,
			anomalyDetected,
			detectionUnavailable,
			fingerprintLimitReached,
		});

		const accepted = learningReason === "accepted";
		if (accepted) {
			await this.commitEvent(session, event, fingerprint);
		}

		const outcome = determineOutcome(explanations, anomalyDetected, detectionUnavailable);

		return {
			outcome,
			anomalyScore,
			// Only a leg that actually produced a score may claim a model version;
			// an unavailable leg must not make the result look evaluated.
			modelVersion:
				explanations.find(
					(explanation) => explanation.leg === "ml" && explanation.status === "ready",
				)?.modelVersion ?? null,
			explanations,
			learning: {
				accepted,
				reason: learningReason,
				baselineSamplesBefore: samplesBefore,
				baselineSamplesAfter: session.baselineSamples,
				requiredBaselineSamples: this.config.minBaselineSamples,
			},
		};
	}

	private async evaluateBehavioralLeg(
		session: SessionState,
		event: ValidatedBehavioralInput,
		samplesBefore: number,
	): Promise<BehavioralLegExplanation> {
		if (samplesBefore < this.config.minBaselineSamples) {
			return learningExplanation("behavioral", samplesBefore, this.config.minBaselineSamples);
		}

		try {
			const analyzer = this.createBehavioralAnalyzer();
			for (const observation of session.observations) {
				analyzer.recordEvent(toStoredToolCallEvent(observation, event.sessionId));
			}
			analyzer.recordEvent(toToolCallEvent(event));
			const result = analyzer.detectAnomaly(event.sessionId);
			return {
				leg: "behavioral",
				status: "ready",
				score: result.isAnomaly ? Math.round(result.confidence * 100) : 0,
				summary: result.reason,
				evidence: result.pattern
					? [
							`pattern=${result.pattern.type}`,
							...result.pattern.tools.map((tool) => `tool=${tool}`),
						]
					: [],
			};
		} catch {
			return unavailableExplanation("behavioral", "analysis_failed");
		}
	}

	private async evaluateNoveltyLeg(
		session: SessionState,
		event: ValidatedBehavioralInput,
		samplesBefore: number,
	): Promise<BehavioralLegExplanation> {
		if (samplesBefore < this.config.minBaselineSamples) {
			return learningExplanation("novelty", samplesBefore, this.config.minBaselineSamples);
		}

		try {
			const novelty = noveltyValues(event);
			const anomaly = await session.noveltyDetector.detectAnomaly("scope", {
				command: novelty.command,
				path: novelty.path,
				url: novelty.url,
				tool: novelty.tool,
				timestamp: new Date(event.timestamp),
				duration: event.durationMs,
				hour: new Date(event.timestamp).getUTCHours(),
			});
			if (!anomaly) {
				return {
					leg: "novelty",
					status: "ready",
					score: 0,
					summary: "No novel behavior detected",
					evidence: [],
				};
			}

			return {
				leg: "novelty",
				status: "ready",
				score: anomaly.score,
				summary: `${anomaly.anomalyType} detected`,
				evidence: [
					`severity=${anomaly.severity}`,
					`similarPastEvents=${anomaly.details.similarPastEvents ?? 0}`,
				],
			};
		} catch {
			return unavailableExplanation("novelty", "analysis_failed");
		}
	}

	private async evaluateMlLeg(classificationText: string): Promise<BehavioralLegExplanation> {
		await this.ensureModelInitialized();
		const activeModel = this.mlModel;
		const activeVersion = this.modelVersion;
		if (this.modelState !== "ready" || !activeModel) {
			// The local embedder always exists, so the leg reports the state it
			// actually reached: an empty corpus is a missing threat database, not
			// an absent model, and it still fails closed.
			return {
				...unavailableExplanation(
					"ml",
					this.modelState === "empty_corpus" ? "empty_corpus" : "initialization_failed",
				),
				modelVersion: activeVersion ?? undefined,
			};
		}

		try {
			const matches = (await activeModel.findSimilarThreats(
				classificationText,
				1,
			)) as EmbeddingThreatMatch[];
			const match = matches[0];
			if (!match) {
				return {
					leg: "ml",
					status: "ready",
					score: 0,
					summary: "No known threat embedding matched",
					evidence: [`modelVersion=${activeVersion ?? "unknown"}`],
					modelVersion: activeVersion ?? undefined,
				};
			}

			return {
				leg: "ml",
				status: "ready",
				score: Math.round(Math.max(0, Math.min(1, match.similarity)) * 100),
				summary: `Matched ${match.metadata.category} threat ${match.threatId}`,
				evidence: [
					`severity=${match.metadata.severity}`,
					`similarity=${match.similarity.toFixed(4)}`,
					`modelVersion=${activeVersion ?? "unknown"}`,
				],
				modelVersion: activeVersion ?? undefined,
			};
		} catch {
			return unavailableExplanation("ml", "inference_failed");
		}
	}

	private async ensureModelInitialized(): Promise<void> {
		if (!this.mlModel || this.modelState === "ready" || this.modelState === "empty_corpus") return;
		if (this.modelState === "initialization_failed" && this.modelInitialization === undefined)
			return;
		if (!this.modelInitialization) {
			const initializingModel = this.mlModel;
			const initializingGeneration = this.modelGeneration;
			this.modelInitialization = (async () => {
				let nextState: ModelState;
				try {
					await initializingModel?.load();
					const stats = await initializingModel?.getStats();
					nextState = (stats?.threatCount ?? 0) > 0 ? "ready" : "empty_corpus";
				} catch {
					nextState = "initialization_failed";
				}
				if (this.mlModel === initializingModel && this.modelGeneration === initializingGeneration) {
					this.modelState = nextState;
				}
			})();
		}
		await this.modelInitialization;
	}

	private async commitEvent(
		session: SessionState,
		event: ValidatedBehavioralInput,
		fingerprint: string,
	): Promise<void> {
		const novelty = noveltyValues(event);
		await session.noveltyDetector.updateProfile("scope", {
			command: novelty.command,
			path: novelty.path,
			url: novelty.url,
			tool: novelty.tool,
			duration: event.durationMs,
			hour: new Date(event.timestamp).getUTCHours(),
		});
		session.observations.push({
			toolName: event.toolName,
			timestamp: event.timestamp,
			riskScore: event.riskScore,
			commandToken: novelty.command,
			pathToken: novelty.path,
			urlToken: novelty.url,
			durationMs: event.durationMs,
		});
		if (session.observations.length > this.config.maxEventsPerSession) {
			session.observations.shift();
		}
		session.baselineSamples++;
		if (session.fingerprintCounts.has(fingerprint)) {
			session.fingerprintCounts.set(
				fingerprint,
				(session.fingerprintCounts.get(fingerprint) ?? 0) + 1,
			);
		} else if (session.fingerprintCounts.size < this.config.maxFingerprintsPerSession) {
			session.fingerprintCounts.set(fingerprint, 1);
		}
	}

	private dropPersisted(clear: () => Promise<void> | undefined): void {
		try {
			void clear()?.catch((error: unknown) => {
				this.logger.warn("Failed to clear persisted behavioural baseline", {
					error: String(error),
				});
			});
		} catch (error) {
			this.logger.warn("Failed to clear persisted behavioural baseline", { error: String(error) });
		}
	}

	private async getOrCreateSession(tenantId: string, sessionId: string): Promise<SessionState> {
		let tenant = this.tenants.get(tenantId);
		if (tenant) {
			this.tenants.delete(tenantId);
			this.tenants.set(tenantId, tenant);
		} else {
			if (this.tenants.size >= this.config.maxTenants) {
				const oldestTenant = this.tenants.keys().next().value as string | undefined;
				if (oldestTenant !== undefined) {
					this.tenants.delete(oldestTenant);
					this.tenantEvictions++;
				}
			}
			tenant = { sessions: new Map() };
			this.tenants.set(tenantId, tenant);
		}

		let session = tenant.sessions.get(sessionId);
		if (session) {
			tenant.sessions.delete(sessionId);
			tenant.sessions.set(sessionId, session);
			return session;
		}

		if (tenant.sessions.size >= this.config.maxSessionsPerTenant) {
			const oldestSession = tenant.sessions.keys().next().value as string | undefined;
			if (oldestSession !== undefined) {
				tenant.sessions.delete(oldestSession);
				this.sessionEvictions++;
			}
		}

		session = this.createEmptySession();
		tenant.sessions.set(sessionId, session);
		return session;
	}

	/**
	 * Persisted records have no verified post-execution receipt, so they cannot
	 * seed detection. Re-enable restore only when receipt verification is bound to
	 * every stored observation.
	 */
	private createEmptySession(): SessionState {
		return {
			observations: [],
			noveltyDetector: this.createNoveltyDetector(),
			baselineSamples: 0,
			fingerprintCounts: new Map(),
		};
	}

	private validateInput(input: BehavioralDetectionInput): ValidatedBehavioralInput {
		const tenantId = validateIdentifier(input.tenantId, "tenantId");
		if (this.provisionedPolicy && tenantId !== this.provisionedPolicy.tenantId) {
			throw new Error("Provisioned behavioral policy belongs to a different tenant");
		}
		const sessionId = validateIdentifier(input.sessionId, "sessionId");
		const toolName = validateValue(input.toolName, "toolName", MAX_TOOL_LENGTH, true);
		if (!Number.isFinite(input.riskScore) || input.riskScore < 0 || input.riskScore > 100) {
			throw new Error("riskScore must be a finite number from 0 to 100");
		}
		const timestamp = input.timestamp instanceof Date ? input.timestamp.getTime() : input.timestamp;
		const now = this.now();
		if (!Number.isFinite(timestamp)) throw new Error("timestamp must be valid");
		if (
			timestamp < now - this.config.maxEventAgeMs ||
			timestamp > now + this.config.maxFutureSkewMs
		) {
			throw new Error("timestamp is outside the accepted event window");
		}
		if (
			input.durationMs !== undefined &&
			(!Number.isFinite(input.durationMs) || input.durationMs < 0 || input.durationMs > 86_400_000)
		) {
			throw new Error("durationMs must be between 0 and 86400000");
		}

		const command = validateOptionalValue(input.command, "command");
		const path = validateOptionalValue(input.path, "path");
		const url = validateOptionalValue(input.url, "url");
		const explicitText = validateOptionalValue(input.classificationText, "classificationText");
		const classificationText =
			explicitText ?? [toolName, command, path, url].filter(Boolean).join("\n");

		return {
			tenantId,
			sessionId,
			toolName,
			riskScore: input.riskScore,
			timestamp,
			command,
			path,
			url,
			durationMs: input.durationMs,
			classificationText,
			learningAllowed: this.provisionedPolicy
				? this.provisionedPolicy.learningAllowed && input.learningAllowed === true
				: input.learningAllowed,
		};
	}
}

interface ValidatedBehavioralInput {
	tenantId: string;
	sessionId: string;
	toolName: string;
	riskScore: number;
	timestamp: number;
	command?: string;
	path?: string;
	url?: string;
	durationMs?: number;
	classificationText: string;
	learningAllowed?: boolean;
}

function toToolCallEvent(event: ValidatedBehavioralInput): ToolCallEvent {
	return {
		toolName: event.toolName,
		timestamp: event.timestamp,
		sessionId: event.sessionId,
		riskScore: event.riskScore,
	};
}

function toStoredToolCallEvent(
	observation: BehavioralBaselineObservation,
	sessionId: string,
): ToolCallEvent {
	return {
		toolName: observation.toolName,
		timestamp: observation.timestamp,
		sessionId,
		riskScore: observation.riskScore,
	};
}

function buildFingerprint(event: ValidatedBehavioralInput): string {
	return stableToken(
		"event",
		[event.toolName, event.command ?? "", event.path ?? "", event.url ?? ""].join("\u001f"),
	);
}

function noveltyValues(event: ValidatedBehavioralInput): {
	command?: string;
	path?: string;
	url?: string;
	tool: string;
} {
	return {
		command: event.command === undefined ? undefined : stableToken("command", event.command),
		path: event.path === undefined ? undefined : stableToken("path", event.path),
		url: event.url === undefined ? undefined : stableToken("url", event.url),
		tool: stableToken("tool", event.toolName),
	};
}

function stableToken(kind: string, value: string): string {
	return `${kind}:sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function learningExplanation(
	leg: "behavioral" | "novelty",
	current: number,
	required: number,
): BehavioralLegExplanation {
	return {
		leg,
		status: "learning",
		score: null,
		summary: `Baseline learning (${current}/${required} accepted samples)`,
		evidence: [],
	};
}

function unavailableExplanation(
	leg: BehavioralDetectionLeg,
	reason: NonNullable<BehavioralLegExplanation["unavailableReason"]>,
): BehavioralLegExplanation {
	return {
		leg,
		status: "unavailable",
		score: null,
		summary: `${leg} detection unavailable`,
		evidence: [],
		unavailableReason: reason,
	};
}

function validateIdentifier(value: string, field: string): string {
	return validateValue(value, field, MAX_ID_LENGTH, true);
}

function validateOptionalValue(value: string | undefined, field: string): string | undefined {
	if (value === undefined) return undefined;
	return validateValue(value, field, MAX_VALUE_LENGTH, false);
}

function validateValue(value: string, field: string, maxLength: number, required: boolean): string {
	if (
		typeof value !== "string" ||
		value.length > maxLength ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		throw new Error(`${field} must be a bounded string without control characters`);
	}
	if ((required && value.trim().length === 0) || value !== value.trim()) {
		throw new Error(`${field} must not be empty or padded with whitespace`);
	}
	return value;
}

function validateConfig(config: BehavioralOrchestratorConfig): void {
	const positiveIntegers: Array<keyof BehavioralOrchestratorConfig> = [
		"minBaselineSamples",
		"maxTenants",
		"maxSessionsPerTenant",
		"maxEventsPerSession",
		"maxFingerprintsPerSession",
		"maxColdStartSamplesPerFingerprint",
		"maxEventAgeMs",
		"maxFutureSkewMs",
	];
	for (const field of positiveIntegers) {
		const value = config[field];
		if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
			throw new Error(`${field} must be a positive integer`);
		}
	}
	if (
		!Number.isFinite(config.maxLearningRiskScore) ||
		config.maxLearningRiskScore < 0 ||
		config.maxLearningRiskScore > 100
	) {
		throw new Error("maxLearningRiskScore must be from 0 to 100");
	}
	if (
		!Number.isFinite(config.behavioralAnomalyThreshold) ||
		config.behavioralAnomalyThreshold <= 0
	) {
		throw new Error("behavioralAnomalyThreshold must be greater than zero");
	}
	if (!config.modelVersion.trim() || config.modelVersion.length > MAX_ID_LENGTH) {
		throw new Error("modelVersion must be a non-empty bounded string");
	}
}

function determineLearningReason(input: {
	learningAllowed: boolean | undefined;
	riskScore: number;
	maxLearningRiskScore: number;
	anomalyDetected: boolean;
	detectionUnavailable: boolean;
	fingerprintLimitReached: boolean;
}): BehavioralLearningDisposition["reason"] {
	if (input.learningAllowed !== true) return "explicitly_disabled";
	if (input.riskScore > input.maxLearningRiskScore) return "high_risk_event";
	if (input.anomalyDetected) return "anomaly_detected";
	if (input.detectionUnavailable) return "detection_unavailable";
	if (input.fingerprintLimitReached) return "fingerprint_limit";
	return "accepted";
}

function determineOutcome(
	explanations: BehavioralLegExplanation[],
	anomalyDetected: boolean,
	detectionUnavailable: boolean,
): BehavioralDetectionOutcome {
	if (anomalyDetected) return "anomalous";
	if (detectionUnavailable) return "unavailable";
	if (explanations.some((explanation) => explanation.status === "learning")) return "learning";
	return "normal";
}

export function createBehavioralDetectionOrchestrator(
	config?: Partial<BehavioralOrchestratorConfig>,
	dependencies?: BehavioralOrchestratorDependencies,
): BehavioralDetectionOrchestrator {
	return new BehavioralDetectionOrchestrator(config, dependencies);
}
