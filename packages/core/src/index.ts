// @singularityrd/aidr-core public API

export type {
	AigCveFinding,
	AigFingerprintMatch,
	AigInfraScanOptions,
	AigInfraScanSummary,
	AigInfraScanTarget,
	AigInfraTargetResult,
} from "./aig-infra-scan.js";
// Native AI-infrastructure scanner.
//
// Reimplements AIG's Infra Scan capability in-process from the compiled dataset:
// HTTP fingerprint probes, version extraction and CVE applicability, with no Go
// server, Python worker, Docker stack or LLM. See aig-infra-scan.ts.
export {
	compareVersions,
	cveCount,
	evaluateVersionRule,
	extractVersion,
	fingerprintCount,
	isScannableHost,
	isTargetAllowed,
	lookupCvesForProduct,
	probeMatches,
	resetAigScanCache,
	scanTarget,
	scanTargets,
} from "./aig-infra-scan.js";
export { evaluateInfrastructurePolicy, inspectInfrastructurePolicy } from "./aig-policy.js";
export type {
	AigAgentScanOptions,
	AigFinding,
	AigJailbreakScanOptions,
	AigMcpScanOptions,
	AigModelConfig,
	AigScanOptions,
	AigScanRequest,
	AigScanResult,
	AigScanType,
	AigTaskStatus,
} from "./aig-scan-client.js";
// AIG sidecar scan client
export {
	AigBridgeError,
	getAigScanResult,
	isAigAvailable,
	triggerAigScan,
} from "./aig-scan-client.js";
export type { AigSyncConfig, SyncStatus } from "./aig-sync.js";
export {
	applyUpdate as applyAigThreatUpdate,
	checkForUpdates as checkAigThreatUpdates,
	downloadUpdate as downloadAigThreatUpdate,
	fullSyncCycle as fullAigThreatSync,
	getSyncStatus as getAigSyncStatus,
} from "./aig-sync.js";
// Allowlist
export {
	addCommand,
	addFilePath,
	addUrl,
	emptyAllowlist,
	isAllowlisted,
	loadAllowlist,
	removeCommand,
	removeFilePath,
	removeUrl,
	saveAllowlist,
} from "./allowlist.js";
export type { ApprovedEntry, PendingEntry } from "./approval-store.js";
// Approval store
export { ApprovalStore } from "./approval-store.js";
// Audit log
export {
	type AuditLogLossState,
	buildAllowedResponseActionEntry,
	buildResponseActionEntry,
	buildRuntimeVerdictEntry,
	getAuditLogLossState,
	getRecentEntries,
	logAllowedResponseActions,
	logPluginScan,
	logResponseActions,
	logVerdict,
	recordAuditRotationDrop,
	recordAuditWriteFailure,
	resetAuditLogLossState,
	summarizeActionsForLog,
	toolInputSummaryForAudit,
} from "./audit-log.js";
// Native-host acceptance observations (inert outside a gate run)
export {
	createHostObservation,
	HOST_OBSERVATION_ENV,
	HOST_OBSERVATION_MARKER,
	type HostObservation,
	type HostObservationRecord,
	recordHostObservation,
} from "./host-observation.js";
// Tenant/session-isolated behavioral, novelty and ML orchestration
export {
	type BehavioralDetectionInput,
	type BehavioralDetectionLeg,
	type BehavioralDetectionLegStatus,
	BehavioralDetectionOrchestrator,
	type BehavioralDetectionOutcome,
	type BehavioralDetectionResult,
	type BehavioralEmbeddingModel,
	type BehavioralLearningDisposition,
	type BehavioralLegExplanation,
	type BehavioralOrchestratorConfig,
	type BehavioralOrchestratorDependencies,
	type BehavioralOrchestratorStats,
	BEHAVIORAL_ORCHESTRATOR_BOUNDS,
	createBehavioralDetectionOrchestrator,
	LOCAL_EMBEDDER_MODEL_VERSION,
} from "./behavioral-orchestrator.js";
// Durable, bounded baseline for the behavioural detector
export {
	type BehavioralBaselineObservation,
	type BehavioralBaselineSessionState,
	type BehavioralBaselineStore,
	type BehavioralBaselineStoreBounds,
	type BehavioralBaselineStoreOptions,
	createBehavioralBaselineStore,
	FileBehavioralBaselineStore,
} from "./behavioral-baseline-store.js";
// Build flavor
export { isCommercialBuild } from "./build-flavor.js";
// Cache
export { VerdictCache } from "./cache.js";
// Causal agent chain (message -> retrieval -> tool -> authorization -> action ->
// side effect -> intervention), ordered by position and logical clock, with a
// missing link reported as `chain_gap` and tamper-evident binding through the
// incident evidence receipts.
export {
	type CausalChain,
	type CausalChainFinding,
	type CausalChainFindingCode,
	CAUSAL_CHAIN_ORDER,
	CAUSAL_CHAIN_SCHEMA_VERSION,
	type CausalChainLink,
	type CausalChainLinkInput,
	type CausalChainOptions,
	type CausalChainReceiptOutcome,
	type CausalChainVerification,
	type CausalCorrelationIds,
	causalKindRank,
	causalLinkDigest,
	causalLinkDigestInput,
	causalLinkReceiptId,
	canonicalCausalChainJson,
	recordCausalChain,
	verifyCausalChainEvidence,
} from "./causal-chain.js";
// Clients
export { AmsiClient, isAmsiSupported } from "./clients/amsi.js";
// Control plane client (optional telemetry/licensing)
export { ControlPlaneClient, type ControlPlaneClientOptions } from "./clients/control-plane.js";
export type { FileCheckBatchResult, FileCheckResult } from "./clients/file-check.js";
export { FileCheckClient } from "./clients/file-check.js";
export type { PackageMetadata } from "./clients/package-registry.js";
export { RegistryClient, resolveDistDigest } from "./clients/package-registry.js";
export { UrlCheckClient } from "./clients/url-check.js";
export type {
	CommunityRule,
	CommunityRuleRegistryConfig,
	RuleContributor,
} from "./community-rules.js";
// Community Rules
export { CommunityRuleRegistry } from "./community-rules.js";
// Compliance Report (SOC 2 / ISO 27001)
export {
	type AuditLogSummary,
	type AvailabilityMetrics,
	type ComplianceReport,
	type ComplianceReportMetadata,
	type ContinuousMonitoring,
	type ControlEvidence,
	exportReport,
	generateISO27001Report,
	generateSOC2Report,
	type IncidentMetrics,
	type ISO27001Report,
	type ReportExportFormat,
	type ReportFramework,
	type SOC2Report,
} from "./compliance-report.js";
// Config
export { AIDR_DIR, loadConfig, resolvePath } from "./config.js";
export * from "./secret-store.js";
export type { ContainConfig } from "./contain.js";
// Auto-Contain
export { AutoContain, createDefaultContainConfig } from "./contain.js";
export type {
	AigDataIntegrityStatus,
	AigTargetKind,
	CveEntry,
	CveResult,
	CveRuleStatus,
	CveStats,
} from "./cve-checker.js";
// AIG compiled product/CVE data and MCP risk categories
export {
	checkFrameworkCves,
	checkPackageAgainstCveIndex,
	checkProductAgainstCveIndex,
	getAigCveIndexMetadata,
	getAigCveIndexPath,
	getAigDataIntegrityStatus,
	getCveStats,
	resetCveIndexCache,
	setTestIndexPath,
} from "./cve-checker.js";
// Scoped, short-lived user -> agent -> tool -> resource credentials.
export {
	canonicalDelegatedCredentialJson,
	DELEGATED_CREDENTIAL_ALGORITHM,
	DELEGATED_CREDENTIAL_TYPE,
	DELEGATED_CREDENTIAL_VERSION,
	type DelegatedCredentialClaimsV1,
	type DelegatedCredentialErrorCode,
	type DelegatedCredentialVerificationContext,
	type DelegatedCredentialVerificationResult,
	type DelegatedResourceIdentity,
	type DelegatedToolIdentity,
	delegationDoesNotEscalate,
	MAX_DELEGATED_CREDENTIAL_SECONDS,
	MAX_DELEGATION_DEPTH,
	parseDelegatedCredentialClaims,
	verifyDelegatedCredential,
} from "./delegated-credential.js";
export type { DetectionLeg } from "./detection-leg.js";
export { DetectionLegUnavailableError, describeHttpFailure } from "./detection-leg.js";
// DLP (Data Loss Prevention)
export type {
	ContentClassification,
	ContentClassifierConfig,
	DlpDirection,
	DlpException,
	DlpExceptionScope,
	DlpFinding,
	DlpInspectedResult,
	DlpLabel,
	DlpMatcher,
	DlpPolicy,
	DlpRule,
	DlpRuleAction,
	DlpScanAction,
	DlpScanRequest,
	DlpScanResult,
	DlpSensitivity,
	DlpUnavailableAction,
	DlpUnavailableReason,
	DlpUnavailableResult,
	EntropyMatch,
} from "./dlp/index.js";
export {
	ContentClassifier,
	createDlpContentFingerprint,
	createDlpMatchFingerprint,
	DLP_EXPIRED_EXCEPTION_DOMINANCE,
	DlpDirectionSchema,
	DlpExceptionSchema,
	DlpExceptionScopeSchema,
	DlpLabelSchema,
	DlpMatcherSchema,
	DlpPolicySchema,
	DlpRuleActionSchema,
	DlpRuleSchema,
	DlpScanRequestSchema,
	DlpSensitivitySchema,
	DlpTenantIsolationError,
	DlpUnavailableActionSchema,
	EntropyDetector,
	isDlpExceptionActive,
	pruneExpiredExceptions,
	scanDlpContent,
	scanDlpInput,
	scanDlpOutput,
} from "./dlp/index.js";
// Encryption
export {
	decryptBuffer,
	decryptFile,
	deriveKey,
	encryptBuffer,
	encryptFile,
	isEncrypted,
	migrateToEncrypted,
} from "./encryption.js";
// Decision engine
export { CONFIDENCE_THRESHOLD, DecisionEngine } from "./engine.js";
// Tenant-scoped AI exposure graph: persistent identity for agents, hosts,
// users, MCP servers, tools, credentials and data sources; cross-tenant
// records refused; staleness computed from an injected clock; coverage gaps
// reported as data.
export {
	canonicalExposureGraphJson,
	createSha256HasherContext as createExposureHasherContext,
	EXPOSURE_GRAPH_SCHEMA_VERSION,
	EXPOSURE_NODE_KINDS,
	type ExposureAuthorizationQuery,
	type ExposureCoverageReport,
	type ExposureEdge,
	type ExposureEdgeKind,
	type ExposureGraph,
	type ExposureGraphOptions,
	type ExposureNode,
	type ExposureNodeKind,
	type ExposureObservationEdge,
	type ExposureObservationInput,
	type ExposureObservationNode,
	type ExposureObservationRejection,
	type ExposureObservationRejectionCode,
	type ExposureObservationSource,
	type ExposureParseResult,
	type ExposureSourceStatus,
	type ExposureStaleness,
	type ExposureStalenessEntry,
	type ExposureStalenessReport,
	type ExposureUnreadableSource,
	exposureCoverage,
	exposureEdgeId,
	exposureEdgesTouching,
	exposureNodeId,
	exposureObservationDigest,
	exposureStaleness,
	exposureStalenessReport,
	type FoldExposureGraphResult,
	foldExposureObservations,
	type HasherContext as ExposureHasherContext,
} from "./exposure-graph.js";
// Adapters that turn the existing MCP inventory/discovery and AI-infrastructure
// fleet records into exposure observations, including the source statuses that
// become coverage gaps.
export {
	type ExposureFleetInventoryOptions,
	type ExposureMcpInventoryBatch,
	type ExposureMcpInventoryOptions,
	type ExposureSourceKind,
	exposureObservationsFromFleetInventory,
	exposureObservationsFromMcpInventory,
	exposureSourcesFromFleetInventory,
	mcpServerNaturalKey,
	mergeExposureObservationBatches,
} from "./exposure-sources.js";
// Strict policy-as-code compiler and dry-run evaluator.
export {
	compilePolicyDocument,
	compilePolicyDocumentYaml,
	type CompiledRuntimePolicy,
	parsePolicyDocument,
	type PolicyCompilationDiagnostic,
	type PolicyCompilationResult,
	type PolicyDocument,
	POLICY_DOCUMENT_ACTIONS,
	PolicyDocumentSchema,
	type PolicySimulationInput,
	type PolicySimulationResult,
	simulateRuntimePolicy,
} from "./policy-document.js";
// Runtime evaluator
export {
	allowVerdict,
	evaluateToolCall,
	type ToolDelegationContext,
	type ToolEvaluationContext,
	type ToolEvaluationRequest,
} from "./evaluator.js";
// Extractors
export {
	boundArtifact,
	extractFromBash,
	extractFromDelete,
	extractFromEdit,
	extractFromRead,
	extractFromToolCall,
	extractFromUnknownTool,
	extractFromWebFetch,
	extractFromWrite,
	extractUrls,
} from "./extractors.js";
// Versioned, append-only operator false-positive feedback bound to the policy
// revision and incident it judges: an identical resubmission is idempotent and a
// conflicting one is refused, never overwritten.
export {
	canonicalFalsePositiveFeedbackJson,
	createFalsePositiveFeedbackStore,
	createSha256HasherContext as createFeedbackHasherContext,
	FALSE_POSITIVE_FEEDBACK_SCHEMA_VERSION,
	FALSE_POSITIVE_GENESIS_HASH,
	type FalsePositiveFeedbackBinding,
	type FalsePositiveFeedbackFoldResult,
	type FalsePositiveFeedbackInput,
	type FalsePositiveFeedbackOrigin,
	type FalsePositiveFeedbackOutcome,
	type FalsePositiveFeedbackOutcomeStatus,
	type FalsePositiveFeedbackRecordInput,
	type FalsePositiveFeedbackRecordV1,
	type FalsePositiveFeedbackState,
	type FalsePositiveFeedbackStore,
	type FalsePositiveParseResult,
	type FalsePositiveRateByRevision,
	type FalsePositiveReasonCode,
	type FalsePositiveStoreFinding,
	type FalsePositiveStoreVerification,
	falsePositiveBindingKey,
	falsePositiveFeedbackHash,
	falsePositiveFeedbackHashInput,
	falsePositiveFeedbackHistory,
	falsePositiveFeedbackId,
	falsePositiveFeedbackState,
	falsePositiveFeedbackSubmissionDigest,
	falsePositiveRateByPolicyRevision,
	recordFalsePositiveFeedback,
	verifyFalsePositiveFeedbackStore,
} from "./false-positive-feedback.js";
export type {
	AnonymizedThreatPattern,
	FederatedConfig,
} from "./federated.js";
// Federated Learning (privacy-preserving threat sharing)
export { FederatedLearning } from "./federated.js";
// File utilities
export {
	atomicWriteJson,
	getFileContent,
	getFileContentSync,
	pruneOrphanedTmpFiles,
} from "./file-utils.js";
export {
	collectFleetInventory,
	defaultFleetInventoryPath,
	type FleetCollectionOptions,
	type FleetFreshness,
	type FleetInventory,
	type FleetInventoryEntry,
	type FleetReachability,
	fleetInventoryEntryId,
	loadFleetInventory,
	normalizeFleetTarget,
	normalizeFleetTargets,
	refreshFleetInventoryFreshness,
	saveFleetInventory,
} from "./fleet-inventory.js";
// Discovery providers: local collection is available; cloud and MDM adapters
// remain explicit unconfigured boundaries until customer integrations exist.
export {
	createDiscoveryProvider,
	discoveryFreshnessForInventory,
	LocalDiscoveryProvider,
	UnconfiguredDiscoveryProvider,
	type DiscoveryProvider,
	type DiscoveryProviderFreshness,
	type DiscoveryProviderRequest,
	type DiscoveryProviderResult,
	type DiscoveryProviderStatus,
	type ExternalDiscoveryProvider,
} from "./discovery-provider.js";
// Format (shared alert formatting)
export {
	formatSessionStartMessage,
	formatStartupClean,
	formatThreatBanner,
	formatUpdateNotice,
	kv,
	PAD,
	SEPARATOR_WIDTH,
	separatorLine,
	severityEmoji,
} from "./format.js";
// Guard (soft-gated connector orchestrator)
//
// `executeWithRollback` is the connector-facing shape of a response: the guard
// allowed the call and snapshotted the target, the connector runs the call, and
// this wrapper rolls the target back if the call fails.
export {
	addToAllowlist,
	approveAction,
	executeWithRollback,
	formatAskMessage,
	formatDenyMessage,
	type GuardResponseSettings,
	type GuardResult,
	guardInputSummary,
	guardToolCall,
	removeFromAllowlist,
	resolveGuardResponseSettings,
	rollbackSnapshotFromGuardResult,
	summarizeArtifacts,
} from "./guard.js";
// Health checks
export {
	formatHealthStatus,
	getHealthStatus,
	type HealthCheck,
	type HealthResult,
	type HealthStatus,
	type HealthStatusValue,
	isHealthy,
	runExtendedHealthChecks,
	runHealthChecks,
	toHealthResult,
} from "./health.js";
// Heuristics
export { HeuristicsEngine } from "./heuristics.js";
// Incidents (normalized signals + correlation engine)
export {
	appendEvidenceReceipt,
	anchorEvidenceHead,
	compareEvidenceClock,
	type CorrelateOptions,
	correlateIncidents,
	detectEvidenceTruncation,
	EVIDENCE_GENESIS_HASH,
	EVIDENCE_RECEIPT_VERSION,
	type EvidenceAnchorOutcome,
	type EvidenceArchiveRequest,
	type EvidenceArchiveResult,
	type EvidenceArchiveSink,
	type EvidenceBinding,
	type EvidenceChainFinding,
	type EvidenceChainVerification,
	type EvidenceClock,
	type EvidenceHashContext,
	type EvidenceParseResult,
	type EvidenceReceiptV1,
	type EvidenceVerifyResult,
	evidenceReceiptHash,
	evidenceReceiptHashInput,
	type Incident,
	type IncidentAnchorPayloadV1,
	type IncidentAnchorVerification,
	type IncidentStoreVerification,
	type IncidentSeverity,
	type NormalizedSignal,
	normalizeAuditEntriesToSignals,
	normalizeAuditEntryToSignals,
	parseEvidenceReceipt,
	persistIncidentRecords,
	type PersistIncidentRecordsOptions,
	type SignedIncidentAnchorReceiptV1,
	type SignalType,
	verifyEvidenceChain,
	verifyEvidenceReceipt,
	verifyIncidentSqliteStore,
	type VerifyIncidentAnchorOptions,
	verifySignedIncidentAnchorReceipt,
	type WriteIncidentAnchorOptions,
	writeSignedIncidentAnchorReceipt,
} from "./incidents/index.js";
// Installation ID
export { getInstallationId } from "./installation-id.js";
// Integrity (signed artifact manifest verification)
export {
	ArtifactIntegrityError,
	type ArtifactManifestV1,
	ArtifactManifestV1Schema,
	type IntegrityCheckResult,
	type IntegrityMismatch,
	type IntegrityStatus,
	verifyArtifactIntegrity,
	verifyArtifactIntegrityAndLog,
} from "./integrity/index.js";
// Intel packs (signed offline intelligence)
export { loadMergedIntelFromDisk } from "./intel/loader.js";
export type {
	IntelReputationProvider,
	ReputationResult,
	ReputationVerdict,
} from "./intel/provider.js";
export { createIntelReputationProvider } from "./intel/provider.js";
export type { DomainRiskEntry, IntelMerged } from "./intel/types.js";
// Signed, versioned reputation feed storage and fail-closed freshness state.
export {
	canonicalReputationFeedManifest,
	canonicalReputationFeedPayload,
	createFileReputationFeedSource,
	DEFAULT_REPUTATION_FEED_MAX_AGE_MS,
	DEFAULT_REPUTATION_FEED_MAX_PAYLOAD_BYTES,
	loadReputationFeed,
	REPUTATION_FEED_SCHEMA_VERSION,
	ReputationFeedManifestSchema,
	ReputationFeedPayloadSchema,
	ReputationFeedRecordSchema,
	ReputationFeedUnavailableError,
	ReputationFeedUpdateError,
	requireAvailableReputationFeed,
	rollbackReputationFeed,
	updateReputationFeed,
} from "./reputation-feed.js";
export type {
	ReputationFeedBundle,
	ReputationFeedLoadOptions,
	ReputationFeedLoadResult,
	ReputationFeedManifest,
	ReputationFeedPayload,
	ReputationFeedRecord,
	ReputationFeedSnapshot,
	ReputationFeedSource,
	ReputationFeedTransportProvenance,
	ReputationFeedUnavailable,
	ReputationFeedUnavailableReason,
	ReputationFeedUpdateOptions,
	ReputationIndicatorKind,
} from "./reputation-feed.js";
// Logger
export { createChildLogger, createLogger, getLogger, setLogger } from "./logger.js";
export type {
	AigMcpCategory,
	AigMcpDataStatus,
	AigPolicyAction,
	AigRiskLevel,
} from "./mcp-aig-categories.js";
export {
	aigRiskToPolicyAction,
	classifyMcpTool,
	getAigMcpDataStatus,
	getAllCategories,
	isAigMcpDataReady,
	loadAigMcpCategories,
	resetCategoryCache,
} from "./mcp-aig-categories.js";
export {
	discoverMcpServers,
	type McpDiscoveryAttestation,
	type McpDiscoveryAttestationOptions,
	type McpDiscoveryAttestationStatus,
	type McpDiscoveryOptions,
	type McpDiscoveryServer,
	type McpSignedManifestIndex,
} from "./mcp-discovery.js";
// JSONC-tolerant config reader shared by the inventory and policy call sites
export type { JsoncParseResult, JsoncParseStatus } from "./jsonc.js";
export { parseJsonc, stripJsonComments } from "./jsonc.js";
export type {
	McpInventoryCoverage,
	McpInventoryCoverageStatus,
	McpInventoryReport,
	McpInventorySourceStatus,
} from "./mcp-inventory.js";
// Metrics
export { getMetricsCollector, MetricsCollector, metrics } from "./metrics.js";
export type {
	EmbeddingModelConfig,
	ThreatEmbedding,
} from "./ml-model.js";
// ML Model (local 300KB embedding model)
export { LocalEmbeddingModel } from "./ml-model.js";
export type { AnomalyEvent, BehaviorProfile } from "./novelty-detection.js";
export { createNoveltyDetector, NoveltyDetector } from "./novelty-detection.js";
// Connector tool-name contract (aliases every connector's emitted tool names)
export {
	CONNECTOR_TOOL_SURFACES,
	type ConnectorToolSurface,
	type ConnectorToolSurfaceViolation,
	extractDeclaredToolNames,
	findConnectorToolSurfaceViolations,
	isCanonicalToolAlias,
} from "./connector-alias-contract.js";
export { scanModelOutput } from "./output-scanner.js";
export type { PackageCheckerConfig, PackageCheckInput } from "./package-checker.js";
// Package checker
export { PackageChecker } from "./package-checker.js";
export type { ParsedPackage } from "./package-extractor.js";
// Package extractor
export { extractPackagesFromCommand, extractPackagesFromManifest } from "./package-extractor.js";
// PII Detector (privacy protection)
export {
	detectPII,
	maskPII,
	type PIIFinding,
	type PIIReport,
	redactPII,
	validateNoPII,
} from "./pii-detector.js";
// Plugin scan cache
export {
	cacheKey,
	computeConfigHash,
	getCached,
	isCached,
	loadScanCache,
	saveScanCache,
	storeResult,
} from "./plugin-scan-cache.js";
// Plugin scanner
export { discoverPlugins, scanPlugin } from "./plugin-scanner.js";
// Quarantine
export {
	AutoQuarantine,
	getDefaultQuarantineConfig,
	type NotifyChannel,
	type QuarantineConfig,
	type QuarantinedItem,
} from "./quarantine.js";
export type {
	PreOperationSnapshot,
	ResponseActionRecord,
	ResponseOptions,
} from "./response-actions.js";
// Response layer: what the runtime DOES after it decides to block, and what it
// preserves before it lets a destructive call through.
//
// Off by default; snapshot semantics are copy-only because the connector runs
// before the tool call, so the blocked write never happened. The pre-operation
// (rollback) half is doubly gated: flag + non-empty protect_paths.
export {
	anyActionSucceeded,
	commandTargetPath,
	DEFAULT_RESPONSE_OPTIONS,
	fileArtifacts,
	isProtectedPath,
	rollbackPreOperationSnapshot,
	runPreAllowedResponseActions,
	runResponseActions,
	summarizeResponseActions,
	targetPathFor,
} from "./response-actions.js";
export type { ResponseAuditEntry, ResponseAuditorOptions } from "./response-audit.js";
// Response Audit — the tamper-evident signed chain.
//
// `ResponseAuditor.log` refuses to append without a valid Ed25519 signature, so a
// response record on this chain is signed or absent, never unsigned-but-present.
export {
	chainActionFor,
	createResponseAuditor,
	DEFAULT_RESPONSE_AUDIT_CONFIG,
	logResponseActionToChain,
	ResponseAuditor,
	type ResponseChainContext,
	type ResponseChainWrite,
	responseAuditorFromConfig,
} from "./response-audit.js";
// Response config
export {
	auditActionForMode,
	getDefaultResponseConfig,
	getDefaultResponseRules,
	type ResponseConfigFile,
	ResponseConfigurator,
	type ResponseMode,
	type ResponseRule,
	type ResponseSeverity,
} from "./response-config.js";
export type {
	Snapshot,
	SnapshotOptions,
	SnapshotResult,
	SnapshotRollbackResult,
	SnapshotSkip,
} from "./rollback.js";
// Auto-Rollback
export {
	AutoRollback,
	createAutoRollback,
	DEFAULT_SNAPSHOT_OPTIONS,
	DEFAULT_SNAPSHOTS_DIR,
} from "./rollback.js";
export type { RuleSyncConfig } from "./rule-sync.js";
// Real-Time Rule Sync
export { RealTimeRuleSync } from "./rule-sync.js";
// Scan handler
export { createScanHandler, runPluginScan, type ScanHandlerOptions } from "./scan-handler.js";
// Sentry
export { initSentry } from "./sentry.js";
// Session start orchestrator
export {
	runSessionStart,
	type SessionStartContext,
	type SessionStartCoverageFinding,
	type SessionStartResult,
} from "./session-start.js";
// Session start scan pipeline
export {
	fromCachedFinding,
	runSessionStartScan,
	type SessionStartScanContext,
	toAuditFindingData,
	toFindingData,
} from "./session-start-scan.js";
export {
	createSiemEvent,
	DurableSiemDelivery,
	type ElasticSiemConfig,
	type SentinelSiemConfig,
	SIEM_EVENT_JSON_SCHEMA,
	SIEM_EVENT_SCHEMA_VERSION,
	type SiemAdapterConfig,
	type SiemDeliveryHealth,
	type SiemDeliveryOptions,
	type SiemDeliveryReceipt,
	type SiemDeliveryStatus,
	type SiemEnqueueResult,
	type SiemEventEnvelope,
	type SiemFlushResult,
	type SiemProvider,
	SiemQueueCapacityError,
	SiemStateIntegrityError,
	type SplunkHecSiemConfig,
	type WebhookSiemConfig,
} from "./siem-delivery.js";
export {
	classifySyslogAddress,
	SIEM_SYSLOG_CONFIG_JSON_SCHEMA,
	type SyslogAddressClass,
	type SyslogSiemConfig,
	type SyslogTransport,
} from "./siem-syslog.js";
// SIEM export (CEF, LEEF, JSON, RFC 5424 syslog)
export {
	exportToCEF,
	exportToJSON,
	exportToLEEF,
	exportToSyslog,
	formatSyslogMessage,
	incidentToSiemRecord,
	type SiemExportFilter,
	type SyslogFormatOptions,
	SyslogMessageTooLargeError,
} from "./siem-export.js";
export type {
	DurableTelemetryEvent,
	TelemetryDeliveryResult,
	TelemetryEnqueueResult,
	TelemetryFlushResult,
	TelemetryQueueMetrics,
	TelemetryQueueOptions,
	TelemetryQueueReadinessEvidence,
	TelemetryQueueStatus,
} from "./telemetry-queue.js";
export { DurableTelemetryQueue, readTelemetryLossSummary, type TelemetryLossSummary } from "./telemetry-queue.js";
// Telemetry privacy boundary
export {
	redactTelemetryAttributes,
	redactTelemetryData,
	redactTelemetryString,
	sanitizeTelemetryEndpoint,
} from "./telemetry-redaction.js";
// Threat loader
export { loadThreats, loadThreatsFromDirs } from "./threat-loader.js";
export type {
	DetectionPhaseAttributes,
	SecurityDecisionAttributes,
	SpanContext,
	TracingConfig,
} from "./tracing.js";
// Deprecated local tracing compatibility surface (no external exporter).
export {
	addSpanEvent,
	endSpan,
	getCurrentSpan,
	getSpanContext,
	getTracer,
	initTracing,
	isTracingEnabled,
	loadTracingConfig,
	recordDetectionPhase,
	recordException,
	setSecurityDecisionAttributes,
	setSpanAttribute,
	setSpanAttributes,
	shutdownTracing,
	startActiveSpan,
	startSpan,
} from "./tracing.js";
// Trusted domains
export {
	extractDomain,
	isTrustedDomain,
	loadTrustedDomains,
} from "./trusted-domains.js";
export type {
	AgentRuntime,
	Allowlist,
	AllowlistConfig,
	AllowlistEntry,
	AmsiCheckConfig,
	AmsiCheckResult,
	Artifact,
	AuthConfig,
	CacheConfig,
	CachedEntry,
	CachedPluginScanResult,
	CachedVerdict,
	CacheStore,
	Config,
	ControlPlaneConfig,
	Decision,
	DelegationLineage,
	FileCheckConfig,
	HeuristicMatch,
	IncidentConfig,
	IntegrityConfig,
	IntelConfig,
	IntelPacksConfig,
	Logger,
	LoggingConfig,
	PackageCheckConfig,
	PackageCheckResult,
	PluginFinding,
	PluginFindingData,
	PluginInfo,
	PluginScanCache,
	PluginScanResult,
	SignalSources,
	Threat,
	ThreatData,
	TrustedDomain,
	UrlCheckConfig,
	UrlCheckFinding,
	UrlCheckResult,
	Verdict,
	VerdictSeverity,
} from "./types.js";
// Types
export {
	ActionSchema,
	AllowlistConfigSchema,
	ArtifactSchema,
	ArtifactTypeSchema,
	AuthConfigSchema,
	CacheConfigSchema,
	ConfigSchema,
	ControlPlaneConfigSchema,
	DecisionSchema,
	FileCheckConfigSchema,
	IncidentConfigSchema,
	IntegrityConfigSchema,
	IntelConfigSchema,
	IntelPacksConfigSchema,
	LoggingConfigSchema,
	nullLogger,
	PackageCheckConfigSchema,
	SensitivitySchema,
	SeveritySchema,
	ThreatSchema,
	UrlCheckConfigSchema,
	VerdictSeveritySchema,
} from "./types.js";
// URL utilities
export { hashCommand, normalizeFilePath, normalizeUrl } from "./url-utils.js";
// Build/runtime version used by health, telemetry and consumer CLIs.
export { getVersion, VERSION } from "./version.js";
export type { VersionCheckContext, VersionCheckResult } from "./version-check.js";
// Version check
export { checkForUpdate, isNewerVersion } from "./version-check.js";
// Verified managed identity and entitlement state for connector provisioning.
export {
	isEntitlementActive,
	loadManagedState,
	managedStatePath,
} from "./managed.js";
export type { ManagedState } from "./managed.js";
// Signed tenant detector policy: the single provisioning implementation every
// connector uses to build a `ToolEvaluationContext`. The policy file is fixed
// per agent runtime under `~/.singularity-aidr/detectors/`, so an operator
// delivers the same contract to Claude Code, OpenCode, OpenClaw, Codex and the
// Cursor/VS Code extension.
export {
	behavioralBaselineDir,
	canonicalDetectorPolicyPayload,
	type DetectorProvisionedContext,
	detectorPolicyPath,
	loadProvisionedDetectorContext,
} from "./detector-provisioning.js";
// Device enrollment binding used by the fleet response transport. This is not
// hardware or OS attestation; it is a server-verified installation/key pairing.
export {
	createDeviceAttestation,
	deviceAttestationMatches,
	deviceAttestationPayload,
	hashDeviceKey,
	parseDeviceAttestation,
} from "./device-attestation.js";
export type { DeviceAttestation, DeviceAttestationError } from "./device-attestation.js";
export { FleetResponseCommandConsumer } from "./response-command-consumer-v6.js";
export {
	FleetResponseCommandWorker,
	type FleetResponseWorkerOptions,
} from "./response-command-worker-v6.js";
export type {
	FleetResponseActionAdapter,
	FleetResponseAuditEvent,
	FleetResponseCommand,
	FleetResponseCommandType,
	FleetResponseConsumerOptions,
	FleetResponseCycleResult,
	FleetResponseIdentity,
} from "./response-command-consumer-v6.js";
// External response providers are explicit and empty by default. Without a
// registered provider, credential revocation and containment are unsupported.
export {
	ResponseProviderRegistry,
	RevocationProviderRegistry,
} from "./response-provider-registry.js";
export type {
	ResponseProvider,
	ResponseProviderAction,
	ResponseProviderOutcome,
	ResponseProviderRequest,
	RevocationProvider,
	RevocationProviderAction,
	RevocationProviderOutcome,
	RevocationProviderRequest,
} from "./response-provider-registry.js";
// Installed endpoint response-worker contract (capability, precondition, TTL,
// rollback receipt).
export {
	executeResponseStep,
	MemoryResponseJournal,
	planResponseRollback,
	planResponseStep,
	reportWorkerCapabilities,
	RESPONSE_CAPABILITIES,
} from "./response-worker-contract.js";
export type {
	ExecuteResponseOptions,
	ExecuteResponseResult,
	PlanResponseRequest,
	ResponseAdapter,
	ResponseCapability,
	ResponseJournal,
	ResponseJournalEntry,
	ResponsePlanDecision,
	ResponseReceipt,
	ResponseRollbackRequest,
	ResponseStep,
	ResponseStepOutcome,
	ResponseTargetBinding,
	WorkerCapabilityReport,
} from "./response-worker-contract.js";
// MCP tool identity, signed schema attestation and drift quarantine.
export {
	approveQuarantinedMcpToolset,
	attestMcpToolManifest,
	canonicalMcpToolManifest,
	diffMcpTools,
	FileMcpAttestationStore,
	mcpManifestHash,
	mcpToolsetHash,
	McpToolDefinitionSchema,
	McpToolManifestV1Schema,
	MemoryMcpAttestationStore,
	signMcpToolManifest,
	SignedMcpToolManifestV1Schema,
	verifySignedMcpToolManifest,
	writeMcpSignerHealthEvidence,
} from "./mcp-attestation.js";
export type {
	McpApprovalResult,
	McpAttestationDecision,
	McpAttestationStateStore,
	McpAttestationStateV1,
	McpCryptographicVerification,
	McpJsonValue,
	McpManifestRejectionReason,
	McpManifestVerifierConfig,
	McpQuarantinedManifest,
	McpSignerHealthEvidenceV1,
	McpToolDefinition,
	McpToolDrift,
	McpToolManifestV1,
	McpToolsetApproval,
	SignedMcpToolManifestV1,
} from "./mcp-attestation.js";
