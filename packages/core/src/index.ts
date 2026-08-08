// @singularityrd/aidr-core public API

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
	buildRuntimeVerdictEntry,
	getRecentEntries,
	logPluginScan,
	logVerdict,
} from "./audit-log.js";
// Build flavor
export { isCommercialBuild } from "./build-flavor.js";
// Cache
export { VerdictCache } from "./cache.js";
// Clients
export { AmsiClient, isAmsiSupported } from "./clients/amsi.js";
// Control plane client (optional telemetry/licensing)
export { ControlPlaneClient } from "./clients/control-plane.js";
// AIG sidecar scan client
export {
	AigBridgeError,
	getAigScanResult,
	isAigAvailable,
	triggerAigScan,
} from "./aig-scan-client.js";
export type {
	AigAgentScanOptions,
	AigFinding,
	AigInfraScanOptions,
	AigJailbreakScanOptions,
	AigMcpScanOptions,
	AigModelConfig,
	AigScanOptions,
	AigScanRequest,
	AigScanResult,
	AigScanType,
	AigTaskStatus,
} from "./aig-scan-client.js";
export {
	applyUpdate as applyAigThreatUpdate,
	checkForUpdates as checkAigThreatUpdates,
	downloadUpdate as downloadAigThreatUpdate,
	fullSyncCycle as fullAigThreatSync,
	getSyncStatus as getAigSyncStatus,
} from "./aig-sync.js";
export type { AigSyncConfig, SyncStatus } from "./aig-sync.js";
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
export type {
	AigDataIntegrityStatus,
	AigTargetKind,
	CveEntry,
	CveResult,
	CveRuleStatus,
	CveStats,
} from "./cve-checker.js";
export {
	aigRiskToPolicyAction,
	classifyMcpTool,
	getAigMcpDataStatus,
	getAllCategories,
	isAigMcpDataReady,
	loadAigMcpCategories,
	resetCategoryCache,
} from "./mcp-aig-categories.js";
export type {
	AigMcpCategory,
	AigMcpDataStatus,
	AigPolicyAction,
	AigRiskLevel,
} from "./mcp-aig-categories.js";
export type { FileCheckBatchResult, FileCheckResult } from "./clients/file-check.js";
export { FileCheckClient } from "./clients/file-check.js";
export type { PackageMetadata } from "./clients/package-registry.js";
export { RegistryClient } from "./clients/package-registry.js";
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
export type { ContainConfig } from "./contain.js";
// Auto-Contain
export { AutoContain, createDefaultContainConfig } from "./contain.js";
// DLP (Data Loss Prevention)
export type { ContentClassification, ContentClassifierConfig, EntropyMatch } from "./dlp/index.js";
export { ContentClassifier, EntropyDetector } from "./dlp/index.js";
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
// Runtime evaluator
export {
	allowVerdict,
	evaluateToolCall,
	type ToolEvaluationContext,
	type ToolEvaluationRequest,
} from "./evaluator.js";
// Extractors
export {
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
export {
	addToAllowlist,
	approveAction,
	formatAskMessage,
	formatDenyMessage,
	type GuardResult,
	guardToolCall,
	removeFromAllowlist,
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
	type CorrelateOptions,
	correlateIncidents,
	type Incident,
	type IncidentSeverity,
	type NormalizedSignal,
	normalizeAuditEntriesToSignals,
	normalizeAuditEntryToSignals,
	type SignalType,
} from "./incidents/index.js";
// Installation ID
export { getInstallationId } from "./installation-id.js";
// Integrity (signed artifact manifest verification)
export {
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
// Logger
export { createChildLogger, createLogger, getLogger, setLogger } from "./logger.js";
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
export type { ResponseAuditEntry, ResponseAuditorOptions } from "./response-audit.js";
// Response Audit
export { createResponseAuditor, ResponseAuditor } from "./response-audit.js";
// Response config
export {
	getDefaultResponseConfig,
	getDefaultResponseRules,
	type ResponseConfigFile,
	ResponseConfigurator,
	type ResponseMode,
	type ResponseRule,
	type ResponseSeverity,
} from "./response-config.js";
export type { Snapshot } from "./rollback.js";
// Auto-Rollback
export { AutoRollback, createAutoRollback } from "./rollback.js";
export type { RuleSyncConfig } from "./rule-sync.js";
// Real-Time Rule Sync
export { RealTimeRuleSync } from "./rule-sync.js";
// Scan handler
export { createScanHandler, runPluginScan, type ScanHandlerOptions } from "./scan-handler.js";
// Sentry
export { initSentry } from "./sentry.js";
// Telemetry privacy boundary
export {
	redactTelemetryAttributes,
	redactTelemetryData,
	redactTelemetryString,
	sanitizeTelemetryEndpoint,
} from "./telemetry-redaction.js";
// Session start orchestrator
export {
	runSessionStart,
	type SessionStartContext,
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
// SIEM export (CEF, LEEF, JSON)
export {
	exportToCEF,
	exportToJSON,
	exportToLEEF,
	type SiemExportFilter,
} from "./siem-export.js";
// Threat loader
export { loadThreats, loadThreatsFromDirs } from "./threat-loader.js";
export type {
	DetectionPhaseAttributes,
	SecurityDecisionAttributes,
	SpanContext,
	TracingConfig,
} from "./tracing.js";
// Tracing
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
export type { VersionCheckContext, VersionCheckResult } from "./version-check.js";
// Version check
export { checkForUpdate, isNewerVersion } from "./version-check.js";
// Build/runtime version used by health, telemetry and consumer CLIs.
export { VERSION, getVersion } from "./version.js";
