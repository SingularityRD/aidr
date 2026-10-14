// @singularityrd/aidr-core public API

// Agent environment & autonomy posture (aidr doctor / aidr discover --agents)
export {
	AGENT_HOSTS,
	AGENT_POSTURE_CHECKS,
	type AgentEnvironmentOptions,
	type AgentEnvironmentReport,
	type AgentHost,
	type AgentHostDetection,
	type AgentPostureCheck,
	type AgentPostureFinding,
	type AgentPostureSeverity,
	inspectAgentEnvironment,
} from "./agent-environment-posture.js";
// Agent permission profiles: least-privilege restrictions per connector and
// repository, evaluated by the shared evaluator on top of threat detection.
export {
	AGENT_PROFILE_ACTIONS,
	AGENT_PROFILE_CONNECTORS,
	AGENT_PROFILE_TOOL_CLASSES,
	type AgentProfile,
	type AgentProfileAction,
	type AgentProfileCall,
	type AgentProfileConnector,
	type AgentProfileContext,
	type AgentProfileDiagnostic,
	type AgentProfileDocument,
	AgentProfileDocumentSchema,
	type AgentProfileEnvironment,
	type AgentProfileEvaluation,
	type AgentProfileLayer,
	type AgentProfileOutcome,
	type AgentProfileSource,
	type AgentProfileValidation,
	agentProfileVerdict,
	classifyAgentTool,
	evaluateAgentProfile,
	evaluateAgentProfiles,
	mcpCallIdentity,
	mergeAgentProfileVerdict,
	parseAgentProfileSource,
	selectAgentProfiles,
	validateAgentProfileDocument,
	validateAgentProfileSource,
	WORKSPACE_PLACEHOLDER,
} from "./agent-profile.js";
export {
	buildAgentProfileContext,
	DEFAULT_LOCAL_AGENT_PROFILES_PATH,
	evaluateAgentProfilesForToolCall,
	inspectLocalAgentProfiles,
	LOCAL_AGENT_PROFILES_ENV,
	type LocalAgentProfilesState,
	localAgentProfileLayer,
	localAgentProfilesPath,
	managedAgentProfileLayer,
} from "./agent-profile-loader.js";
export {
	AGENT_PROFILE_TEMPLATE_NAMES,
	AGENT_PROFILE_TEMPLATES,
	agentProfileTemplateDocument,
} from "./agent-profile-templates.js";
// Agent-safety guardrails: diff-aware edit views and session runaway guard
export {
	buildEditViews,
	DELETED_TEST_FILE_VIEW,
	EDIT_LINE_VIEWS,
	type EditLineView,
	type EditViews,
	isTestFile,
	lineDiff,
	patchChanges,
	viewsForPath,
} from "./agent-safety/edit-views.js";
export {
	applyRunawayOutcome,
	checkRunaway,
	evaluateRunawayCall,
	isRunawayState,
	RUNAWAY_CATEGORY,
	RUNAWAY_SIGNAL_IDS,
	RUNAWAY_UNAVAILABLE_CATEGORY,
	type RunawayOutcome,
	type RunawaySignal,
	type RunawayState,
	recordToolOutcome,
	runawayStateDir,
	runawayVerdict,
	toolCallFingerprints,
	writtenPaths,
} from "./agent-safety/runaway-guard.js";
export { toolResultReportsFailure } from "./agent-safety/tool-outcome.js";
// AI model supply chain: trusted model sources (hubs and publisher organisations)
export {
	isTrustedModelSourceMatch,
	loadTrustedModelSources,
	MODEL_SOURCES_SUBDIR,
	modelRepoOrgs,
	NO_TRUSTED_MODEL_SOURCES,
	type TrustedModelSources,
} from "./ai-supply-chain.js";
// AI-BOM (AI Bill of Materials): redacted AI inventory and its CycloneDX 1.6 rendering.
export {
	type BuildCycloneDxOptions,
	buildCycloneDxBom,
	CYCLONEDX_SPEC_VERSION,
	type CycloneDxBom,
	type CycloneDxComponent,
	type CycloneDxProperty,
	type CycloneDxService,
	type CycloneDxVulnerability,
} from "./aibom/cyclonedx.js";
export {
	AI_INVENTORY_SCHEMA,
	type AiBomAgentInput,
	type AiInventory,
	type AiInventoryCoverage,
	type AiInventoryMcpServer,
	type AiInventoryPackage,
	type AiInventoryVulnerability,
	aiInventoryGaps,
	type CollectAiInventoryOptions,
	collectAiInventory,
	displayPath,
	packageUrl,
} from "./aibom/inventory.js";
export {
	type AiProjectScan,
	loadAiComponentCatalog,
	matchCatalogEntry,
	normalizePackageName,
	scanProjectForAiComponents,
} from "./aibom/project-scan.js";
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
	summarizeCveFindings,
} from "./aig-infra-scan.js";
export {
	evaluateInfrastructurePolicy,
	inspectInfrastructurePolicy,
	parseInfrastructureScanReport,
} from "./aig-policy.js";
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
	allowlistedArtifacts,
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
// Signed, hash-chained verdict log.
export {
	AUDIT_CHAIN_GENESIS,
	AUDIT_CHAIN_KEY_STORAGE_ENV,
	AUDIT_CHAIN_ROOT_VAULT_PREFIX,
	type AuditChainField,
	type AuditChainProblem,
	type AuditChainProblemKind,
	type AuditChainSettings,
	type AuditChainVerification,
	type AuditKeyRotationResult,
	auditChainDir,
	resetAuditChainCache,
	resolveAuditChainKeyStorage,
	rootFingerprint,
	rotateAuditChainRootKey,
	setAuditChainTestHooks,
	verifyAuditChain,
} from "./audit-chain.js";
// Audit log
export {
	type AuditLogLossState,
	buildAllowedResponseActionEntry,
	buildResponseActionEntry,
	buildRuntimeVerdictEntry,
	getAuditLogLossState,
	getRecentEntries,
	logAllowedResponseActions,
	logDashboardApprovalEvent,
	logIncident,
	logPluginScan,
	logResponseActions,
	logVerdict,
	readPersistedAuditLossState,
	recordAuditRotationDrop,
	recordAuditWriteFailure,
	resetAuditLogLossState,
	summarizeActionsForLog,
	toolInputSummaryForAudit,
} from "./audit-log.js";
export * from "./authenticated-behavioral-baseline-store.js";
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
export * from "./behavioral-learning.js";
export * from "./behavioral-learning-receipt.js";
// Tenant/session-isolated behavioral, novelty and ML orchestration
export {
	BEHAVIORAL_ORCHESTRATOR_BOUNDS,
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
	behavioralObservationForInput,
	createBehavioralDetectionOrchestrator,
	LOCAL_EMBEDDER_MODEL_VERSION,
} from "./behavioral-orchestrator.js";
// One block/ask message shape for every connector
export {
	approveCommand,
	type BlockApproval,
	type BlockMessageOptions,
	formatAgentBlockReason,
	formatBlockMessage,
} from "./block-message.js";
// Build flavor
export { isCommercialBuild } from "./build-flavor.js";
// Cache
export { VerdictCache } from "./cache.js";
// Canary credentials (honeytokens): deploy decoys, detect any agent touching them
export * from "./canary/index.js";
// Canary triggers in prompts and tool output, shared by every connector
export {
	CANARY_PROMPT_BLOCK_MESSAGE,
	type CanaryCheckStatus,
	checkPromptForCanaries,
	recordToolOutputCanaries,
} from "./canary-triggers.js";
// Causal agent chain (message -> retrieval -> tool -> authorization -> action ->
// side effect -> intervention), ordered by position and logical clock, with a
// missing link reported as `chain_gap` and tamper-evident binding through the
// incident evidence receipts.
export {
	CAUSAL_CHAIN_ORDER,
	CAUSAL_CHAIN_SCHEMA_VERSION,
	type CausalChain,
	type CausalChainFinding,
	type CausalChainFindingCode,
	type CausalChainLink,
	type CausalChainLinkInput,
	type CausalChainOptions,
	type CausalChainReceiptOutcome,
	type CausalChainVerification,
	type CausalCorrelationIds,
	canonicalCausalChainJson,
	causalKindRank,
	causalLinkDigest,
	causalLinkDigestInput,
	causalLinkReceiptId,
	recordCausalChain,
	verifyCausalChainEvidence,
} from "./causal-chain.js";
// Clients
export { AmsiClient, isAmsiSupported } from "./clients/amsi.js";
// Control plane client (optional telemetry/licensing)
export { ControlPlaneClient, type ControlPlaneClientOptions } from "./clients/control-plane.js";
export {
	assertSecureControlPlaneEndpoint,
	DEFAULT_CONTROL_PLANE_ENDPOINT,
} from "./clients/control-plane-url.js";
export type { FileCheckBatchResult, FileCheckResult } from "./clients/file-check.js";
export { FileCheckClient } from "./clients/file-check.js";
export type { PackageMetadata } from "./clients/package-registry.js";
export { RegistryClient, resolveDistDigest } from "./clients/package-registry.js";
export { UrlCheckClient } from "./clients/url-check.js";
// Code guard: AI supply-chain and secure-code rules over code an agent writes or runs
export {
	applySecureCodeWarnings,
	CODE_MATCH_PREFIX,
	type CodeBlock,
	type CodeFinding,
	type CodeGuardResult,
	CodeRuleSet,
	codeBlocksForToolCall,
	codeLanguageForPath,
	describeSecureCodeWarnings,
	inspectToolCallCode,
	isReportableFinding,
	isSecureCodeRule,
	matchCodeBlock,
	SECRET_RULE_ID,
	SECURE_CODE_WARNING_CATEGORY,
} from "./code-guard.js";
// Project code scan (`aidr scan --code`)
export {
	type CodeScanFinding,
	type CodeScanOptions,
	type CodeScanReport,
	scanCodePath,
} from "./code-scanner.js";
// Shell argv normalization (argv arrays -> inspected command text)
export {
	type CommandValueResult,
	commandFromArgv,
	commandFromValue,
	shellQuote,
} from "./command-argv.js";
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
export {
	AIDR_DIR,
	isInvalidConfig,
	loadConfig,
	resolveAuditSignedChain,
	resolvePath,
} from "./config.js";
// Connector tool-name contract (aliases every connector's emitted tool names)
export {
	CONNECTOR_TOOL_SURFACES,
	type ConnectorToolSurface,
	type ConnectorToolSurfaceViolation,
	extractDeclaredToolNames,
	findConnectorToolSurfaceViolations,
	isCanonicalToolAlias,
} from "./connector-alias-contract.js";
export type { ContainConfig } from "./contain.js";
// Auto-Contain
export { AutoContain, createDefaultContainConfig } from "./contain.js";
// Data and context poisoning protection (instruction/memory files, MCP tool metadata, memory writes)
export {
	AGENT_CONTROL_CONTENT,
	AGENT_CONTROL_PATH,
	type AgentWriteTarget,
	agentWriteTargets,
	CONTEXT_POISONING_SOURCE,
	evaluateContextPoisoning,
	isMemoryWriteTool,
	loadContextPoisoningRules,
	MCP_TOOL_METADATA,
	type McpToolMetadataFinding,
	type McpToolMetadataInput,
	MEMORY_WRITE_CONTENT,
	matchAgentControlPath,
	scanMcpToolMetadata,
	shellWriteTargets,
} from "./context-poisoning.js";
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
// Managed-mode dashboard approvals (out-of-band admin approval, signed single-use tokens)
export {
	type ApprovalRequestBody,
	type ApprovalRequestStatus,
	checkDashboardDecisions,
	DASHBOARD_APPROVAL_REQUEST_TIMEOUT_MS,
	DASHBOARD_APPROVAL_REQUEST_TTL_MS,
	DASHBOARD_APPROVAL_SOURCE,
	DASHBOARD_APPROVAL_TOKEN_MAX_TTL_MS,
	DASHBOARD_APPROVAL_TOTAL_BUDGET_MS,
	type DashboardApprovalBinding,
	type DashboardApprovalContext,
	type DashboardApprovalInput,
	type DashboardApprovalOptions,
	type DashboardApprovalOutcome,
	type DashboardApprovalStatus,
	type DashboardApprovalTokenPayload,
	type DashboardContextResult,
	type DashboardDecisionNotice,
	type DashboardRequestView,
	type DashboardTokenRejection,
	type DashboardTokenVerification,
	type DashboardUnavailableReason,
	dashboardApprovalLink,
	dashboardApprovalStatePath,
	dashboardArtifactDigest,
	dashboardToolName,
	listDashboardApprovalRequests,
	processDashboardApproval,
	resolveDashboardApprovalContext,
	verifyDashboardApprovalToken,
} from "./dashboard-approvals.js";
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
// Operator-created, time-limited detection exceptions (local store + signed policy)
export {
	type AddDetectionExceptionInput,
	type AppliedDetectionException,
	addDetectionException,
	applyDetectionExceptions,
	DETECTION_EXCEPTION_MAX_ENTRIES,
	DETECTION_EXCEPTION_MAX_TTL_MS,
	DETECTION_EXCEPTION_MIN_TTL_MS,
	DETECTION_EXCEPTION_REVOCATION_DOMAIN,
	type DetectionException,
	DetectionExceptionError,
	type DetectionExceptionStoreOptions,
	type DetectionExceptionSubject,
	type DetectionExceptionSubjectContext,
	type DetectionExceptionSubjectKind,
	type DetectionExceptionWire,
	DetectionExceptionWireSchema,
	detectionExceptionArtifactDigest,
	detectionExceptionStorePath,
	exceptionActive,
	findGitRepository,
	isProtectedRule,
	type ListedDetectionException,
	listDetectionExceptions,
	loadUsableLocalExceptions,
	normalizeRepoRemote,
	parseSignedDetectionExceptions,
	removeDetectionException,
	resolveDetectionExceptionSubjectContext,
	subjectMatches,
} from "./detection-exceptions.js";
export type { DetectionLeg } from "./detection-leg.js";
export { DetectionLegUnavailableError, describeHttpFailure } from "./detection-leg.js";
// Signed tenant detector policy: the single provisioning implementation every
// connector uses to build a `ToolEvaluationContext`. The policy file is fixed
// per agent runtime under `~/.singularity-aidr/detectors/`, so an operator
// delivers the same contract to Claude Code, OpenCode, OpenClaw, Codex and the
// Cursor/VS Code extension.
export {
	type BrokerLearningAuthorityBundle,
	behavioralBaselineDir,
	canonicalDetectorPolicyPayload,
	type DetectorProvisionedContext,
	detectorPolicyPath,
	exportBrokerLearningAuthority,
	loadProvisionedDetectorContext,
	loadProvisionedLearningApprovalContext,
	loadProvisionedLearningContext,
	type ProvisionedLearningContext,
} from "./detector-provisioning.js";
export type { DeviceAttestation, DeviceAttestationError } from "./device-attestation.js";
// Device enrollment binding used by the fleet response transport. This is not
// hardware or OS attestation; it is a server-verified installation/key pairing.
export {
	createDeviceAttestation,
	deviceAttestationMatches,
	deviceAttestationPayload,
	hashDeviceKey,
	parseDeviceAttestation,
} from "./device-attestation.js";
// Tenant-scoped local HTTP, cloud management and Intune discovery.
export { type CloudDiscoveryConfig, parseCloudDiscoveryConfig } from "./discovery-cloud-config.js";
export {
	type CloudDiscoveryEvidence,
	CloudDiscoveryProvider,
	cloudDiscoveryScopeHash,
	parseCloudDiscoveryEvidence,
} from "./discovery-cloud-provider.js";
export {
	createDiscoveryProvider,
	type DiscoveryProvider,
	type DiscoveryProviderFreshness,
	type DiscoveryProviderRequest,
	type DiscoveryProviderResult,
	type DiscoveryProviderStatus,
	discoveryFreshnessForInventory,
	type ExternalDiscoveryProvider,
	LocalDiscoveryProvider,
	UnconfiguredDiscoveryProvider,
} from "./discovery-provider.js";
export {
	DISCOVERY_TARGET_ID_PATTERN,
	discoveryTargetPseudonym,
	getDiscoveryTargetKey,
} from "./discovery-target-pseudonym.js";
// Display-only settings, first-run privacy notice, unprotected AI tools, `aidr report-fp`.
export {
	configuredSupportContact,
	safeDisplayUrl,
} from "./display-settings.js";
// DLP (Data Loss Prevention)
export type {
	ContentClassification,
	ContentClassifierConfig,
	DlpDetector,
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
	PrivacyDetectorMatch,
	PrivacyDetectorScan,
} from "./dlp/index.js";
export {
	ContentClassifier,
	createDlpContentFingerprint,
	createDlpMatchFingerprint,
	DLP_DETECTOR_ENTITY_TYPES,
	DLP_EXPIRED_EXCEPTION_DOMINANCE,
	DlpDetectorSchema,
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
	PRIVACY_DETECTOR_MAX_CHARS,
	privacyDetectorPlaceholder,
	pruneExpiredExceptions,
	scanDlpContent,
	scanDlpInput,
	scanDlpOutput,
	scanPrivacyDetectors,
	shellInertRedactionToken,
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
// Runtime evaluator
export {
	allowVerdict,
	evaluateToolCall,
	REPUTATION_NOT_CHECKED_CATEGORY,
	recordCanaryTrigger,
	reputationNotCheckedVerdict,
	type ToolDelegationContext,
	type ToolEvaluationContext,
	type ToolEvaluationRequest,
} from "./evaluator.js";
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
// Extractors
export {
	boundArtifact,
	contentWindows,
	extractFromBash,
	extractFromDelete,
	extractFromEdit,
	extractFromRead,
	extractFromToolCall,
	extractFromUnknownTool,
	extractFromWebFetch,
	extractFromWrite,
	extractUrls,
	INPUT_NOT_FULLY_INSPECTED,
	type InspectionLimit,
	inspectionLimitsHit,
	MAX_INSPECTED_CHARS,
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
export {
	type AuditedBlock,
	buildFalsePositiveReportBody,
	FALSE_POSITIVE_REASON_CODES,
	type FalsePositiveReportResult,
	findAuditedBlocks,
	submitFalsePositiveReport,
} from "./false-positive-report.js";
export type {
	AnonymizedThreatPattern,
	FederatedConfig,
} from "./federated.js";
// Federated Learning (privacy-preserving threat sharing)
export { FederatedLearning } from "./federated.js";
// Post-tool quarantine of agent-written files classified as malicious.
export {
	classifyFileContent,
	downloadTargetsFromCommand,
	type FileContentFinding,
	maliciousFindings,
	openConfiguredQuarantine,
	type PostToolQuarantineRequest,
	type PostToolQuarantineResult,
	type QuarantinedFileNotice,
	quarantineAgentWrittenFiles,
	writtenFilePaths,
} from "./file-quarantine.js";
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
// Security framework mapping (OWASP LLM 2025, OWASP Agentic 2026, MITRE ATLAS)
export {
	type AtlasTechnique,
	FRAMEWORK_IDS,
	FRAMEWORKS,
	type FrameworkDefinition,
	type FrameworkId,
	type FrameworkItemDefinition,
	frameworkItemLabel,
	frameworkItemTitle,
	frameworkOfItem,
	MITRE_ATLAS_TACTICS,
	MITRE_ATLAS_TECHNIQUES,
	OWASP_AGENTIC_2026,
	OWASP_LLM_2025,
} from "./framework-catalog.js";
export {
	buildCoverageMatrix,
	buildDashboardCoverageArtifact,
	type CoverageItem,
	type CoverageMatrix,
	type CoverageRule,
	type CoverageStatus,
	type CoverageTacticSummary,
	coverageMatrixToJson,
	FRAMEWORK_MAPPINGS_RELATIVE_PATH,
	type FrameworkAssessment,
	type FrameworkCoverage,
	type FrameworkMappings,
	type FrameworkMappingsParseResult,
	type FrameworkRuleRef,
	frameworkRefLabels,
	frameworkRefsFromJson,
	frameworkRefsToJson,
	loadFrameworkMappings,
	parseFrameworkMappings,
	parseFrameworkMappingsYaml,
	renderCoverageDocument,
	renderCoverageMarkdown,
	renderCoverageTable,
	resolveRuleFrameworks,
	toCoverageRules,
	validateFrameworkMappingsAgainstRules,
} from "./framework-mappings.js";
// Guard (soft-gated connector orchestrator)
//
// `executeWithRollback` is the connector-facing shape of a response: the guard
// allowed the call and snapshotted the target, the connector runs the call, and
// this wrapper rolls the target back if the call fails.
export {
	type AllowedCallSnapshotResult,
	type AskApprovalResolution,
	addToAllowlist,
	approveAction,
	executeWithRollback,
	formatAskMessage,
	formatDashboardApprovalNotice,
	formatDashboardDecisionNotices,
	formatDenyMessage,
	type GuardOptions,
	type GuardResponseSettings,
	type GuardResult,
	guardInputSummary,
	guardToolCall,
	HOST_DIALOG_RECORD_BUDGET_MS,
	type HostAskMode,
	type HostAskOptions,
	type HostAskResolution,
	hostAskMode,
	removeFromAllowlist,
	resolveAskWithDashboardApproval,
	resolveGuardResponseSettings,
	resolveHostAsk,
	rollbackSnapshotFromGuardResult,
	snapshotBeforeAllowedToolCall,
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
export {
	type HiddenUnicodeReport,
	inspectHiddenUnicode,
	renderInvisibleCharacters,
} from "./hidden-unicode.js";
// Connector entry-point deadlines, exit-after-answer and input hygiene.
export {
	type BoundedStdinResult,
	createHookResponder,
	exitAfterStdoutFlush,
	HOOK_DEADLINE_EXCEEDED,
	HOOK_DEADLINE_HEADROOM_MS,
	HOOK_HOST_TIMEOUT_MS,
	type HookAnswer,
	type HookDeadlineSpec,
	type HookResponder,
	type HookResponderOptions,
	hasMalformedCommandText,
	IN_PROCESS_TOOL_CALL_DEADLINE,
	isValidUtf8,
	isWellFormedToolCall,
	MIN_HOOK_DEADLINE_MS,
	malformedShellCommandReason,
	readBoundedStdinAsync,
	resolveHookDeadlineMs,
	withHookDeadline,
} from "./hook-deadline.js";
// Native-host acceptance observations (inert outside a gate run)
export {
	createHostObservation,
	HOST_OBSERVATION_ENV,
	HOST_OBSERVATION_MARKER,
	type HostObservation,
	type HostObservationRecord,
	recordHostObservation,
} from "./host-observation.js";
// Plain-language display text for rule titles, categories and sources
export {
	categoryLabel,
	displayReason,
	registerReasonDisplay,
	sourceLabel,
} from "./i18n/display.js";
// User-facing message catalog (en/tr) and locale resolution
export {
	createTranslator,
	currentLocale,
	DEFAULT_LOCALE,
	formatMessage,
	type Locale,
	MESSAGE_CATALOGS,
	type MessageKey,
	type MessageParams,
	normalizeLocale,
	resolveLocale,
	SUPPORTED_LOCALES,
	setConfiguredLocale,
	severityLabel,
	t,
	upperCaseFor,
} from "./i18n/index.js";
// Incidents (normalized signals + correlation engine)
export {
	anchorEvidenceHead,
	appendEvidenceReceipt,
	type CorrelateOptions,
	compareEvidenceClock,
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
	type IncidentSeverity,
	type IncidentStoreVerification,
	type NormalizedSignal,
	normalizeAuditEntriesToSignals,
	normalizeAuditEntryToSignals,
	type PersistIncidentRecordsOptions,
	parseEvidenceReceipt,
	persistIncidentRecords,
	type SignalType,
	type SignedIncidentAnchorReceiptV1,
	type VerifyIncidentAnchorOptions,
	verifyEvidenceChain,
	verifyEvidenceReceipt,
	verifyIncidentSqliteStore,
	verifySignedIncidentAnchorReceipt,
	type WriteIncidentAnchorOptions,
	writeSignedIncidentAnchorReceipt,
} from "./incidents/index.js";
// Connector initialisation failure (fail-closed load)
export {
	formatInitFailureMessage,
	type IntegrityFailureMessage,
	initFailureCode,
	integrityFailureMessage,
} from "./init-failure.js";
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
	isReleaseKeyMissing,
	runningAsSea,
	STANDALONE_RUNTIME_ARTIFACT_ID,
	standaloneRuntimeArtifact,
	verifyArtifactIntegrity,
	verifyArtifactIntegrityAndLog,
} from "./integrity/index.js";
// Intel packs (signed offline intelligence)
export { acceptPack, type PackAcceptance, type PackRefusalCode } from "./intel/acceptance.js";
export { loadMergedIntelFromDisk } from "./intel/loader.js";
export type {
	IntelReputationProvider,
	ReputationResult,
	ReputationVerdict,
} from "./intel/provider.js";
export { createIntelReputationProvider } from "./intel/provider.js";
export type { DomainRiskEntry, IntelMerged, StaleIntelPack } from "./intel/types.js";
// JSONC-tolerant config reader shared by the inventory and policy call sites
export type { JsoncParseResult, JsoncParseStatus } from "./jsonc.js";
export { parseJsonc, stripJsonComments } from "./jsonc.js";
// Vendor-signed licenses and customer packets (on-prem customer builds)
export {
	CUSTOMER_ID_PATTERN,
	CUSTOMER_PACKET_FILE_NAME,
	CUSTOMER_PACKET_FORMAT,
	type CustomerPacketPayload,
	type CustomerPacketSearchOptions,
	type CustomerPacketSensitivity,
	type CustomerRecord,
	customerPacketSearchPaths,
	customerRecordPath,
	defaultLicenseKeyRegistry,
	discoverCustomerPacket,
	installedLicensePath,
	LICENSE_FORMAT,
	LICENSE_PUBLIC_KEYS_FORMAT,
	type LicenseDocument,
	type LicenseErrorCode,
	type LicenseKeyRegistry,
	type LicensePayload,
	type LicenseState,
	LicenseVerificationError,
	type LicenseVerifyOptions,
	licenseState,
	licenseTermEndMs,
	parseLicensePublicKeyRegistry,
	readCustomerRecord,
	readInstalledLicense,
	readSignedDocumentFile,
	saveCustomerPacket,
	type VerifiedCustomerPacket,
	type VerifiedLicense,
	verifyCustomerPacket,
	verifyLicense,
} from "./license/index.js";
// Local-mode (unsigned, operator-written) DLP policy file.
export {
	DEFAULT_LOCAL_DLP_POLICY_PATH,
	inspectLocalDlpPolicy,
	LOCAL_DLP_POLICY_ENV,
	type LocalDlpPolicyState,
	localDlpPolicyPath,
} from "./local-dlp-policy.js";
// Logger
export { createChildLogger, createLogger, getLogger, setLogger } from "./logger.js";
export type { ApprovalPublicKeyEntry, ManagedState } from "./managed.js";
// Verified managed identity and entitlement state for connector provisioning.
export {
	getEffectiveManagedApiKey,
	isEntitlementActive,
	loadManagedState,
	managedStatePath,
	parseApprovalPublicKeys,
} from "./managed.js";
// Device-code enrollment (`aidr assistant`): the same one-time issuance journal startup uses.
export { enrollManagedInstallation, enrollmentPending } from "./managed-enrollment.js";
export type {
	AigMcpCategory,
	AigMcpDataStatus,
	AigPolicyAction,
	AigRiskLevel,
	McpServerCategoryMatch,
	McpServerClassificationInput,
} from "./mcp-aig-categories.js";
export {
	aigRiskToPolicyAction,
	classifyMcpServer,
	classifyMcpTool,
	getAigMcpDataStatus,
	getAllCategories,
	isAigMcpDataReady,
	loadAigMcpCategories,
	resetCategoryCache,
} from "./mcp-aig-categories.js";
export type {
	McpApprovalEntryRejection,
	McpApprovalKeyring,
	McpApprovalResult,
	McpApprovalSubject,
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
// MCP tool identity, signed schema attestation and drift quarantine.
export {
	approveQuarantinedMcpToolset,
	assertPrivateMcpStateDirectory,
	attestMcpToolManifest,
	canonicalMcpToolManifest,
	DEFAULT_MCP_APPROVAL_LIFETIME_MS,
	diffMcpTools,
	FileMcpAttestationStore,
	hasHonouredMcpApproval,
	MAX_MCP_APPROVAL_LIFETIME_MS,
	McpAttestationStateIntegrityError,
	McpStateDirectoryError,
	McpToolDefinitionSchema,
	McpToolManifestV1Schema,
	MemoryMcpAttestationStore,
	mcpApprovalBindingHash,
	mcpManifestHash,
	mcpToolsetHash,
	SignedMcpToolManifestV1Schema,
	signMcpToolManifest,
	signMcpToolsetApproval,
	verifyMcpToolsetApproval,
	verifySignedMcpToolManifest,
	writeMcpSignerHealthEvidence,
} from "./mcp-attestation.js";
export {
	detectMcpConfigSecrets,
	type McpSecretFinding,
	type McpSecretKind,
	type McpSecretLocation,
} from "./mcp-config-secrets.js";
export {
	discoverMcpServers,
	type McpDiscoveryAttestation,
	type McpDiscoveryAttestationOptions,
	type McpDiscoveryAttestationStatus,
	type McpDiscoveryOptions,
	type McpDiscoveryServer,
	type McpSignedManifestIndex,
} from "./mcp-discovery.js";
// Host MCP tool naming → canonical `mcp__<server>__<tool>` identity.
export {
	CANONICAL_MCP_PREFIX,
	canonicalMcpToolName,
	fallbackMcpServerIdentity,
	type KnownMcpServers,
	loadKnownMcpServers,
	type McpServerDeclaration,
	type McpToolIdentity,
	matchMcpServerDeclaration,
	mcpIdentityFromCanonicalName,
	mcpIdentityFromOpenClawName,
	mcpIdentityFromOpenCodeName,
	mcpIdentityFromVsCodeName,
	mcpPolicyServerIds,
	sanitizeOpenClawMcpName,
	sanitizeOpenCodeMcpName,
} from "./mcp-host-identity.js";
export {
	defaultMcpConfigPaths,
	type McpInventoryCoverage,
	type McpInventoryCoverageStatus,
	type McpInventoryReport,
	type McpInventorySourceStatus,
} from "./mcp-inventory.js";
export { redactLaunchToken, redactMcpLaunch } from "./mcp-launch-redaction.js";
export type { McpFetchOptions } from "./mcp-transport.js";
// Pinned-DNS MCP upstream transport used by the inline MCP gateway.
export { fetchMcpEndpoint, McpTransportError } from "./mcp-transport.js";
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
// Operator approval channel (file-backed, out-of-band; `aidr pending` / `aidr approve`)
export {
	artifactSetDigest,
	artifactValueDigest,
	type ConsumeOperatorApprovalInput,
	clearOperatorApprovalKeyCache,
	consumeOperatorApproval,
	createDefaultOperatorKeyProvider,
	describeOperatorApprovalKey,
	type ExternalSpendResult,
	findOperatorAllowlistGrant,
	getPendingAsk,
	type HostDialogAsk,
	isOperatorRevoked,
	type ListedPendingAsk,
	listHostDialogAsks,
	listOperatorApprovals,
	listPendingAsks,
	markOperatorAllowlistGrantUsed,
	OPERATOR_APPROVAL_DEFAULT_TTL_MS,
	OPERATOR_APPROVAL_KEY_ID,
	OPERATOR_APPROVAL_KEY_STORAGE_ENV,
	OPERATOR_APPROVAL_LEDGER_ID,
	OPERATOR_APPROVAL_MAX_TTL_MS,
	OPERATOR_APPROVAL_MIN_TTL_MS,
	type OperatorApproval,
	OperatorApprovalError,
	type OperatorApprovalErrorCode,
	type OperatorApprovalKeyStatus,
	type OperatorApprovalStoreOptions,
	type OperatorConsumeReason,
	type OperatorConsumeResult,
	type OperatorConsumptionAnchor,
	type OperatorKeyMaterial,
	type OperatorKeyProvider,
	type OperatorKeyStorage,
	type OperatorRecordKind,
	operatorApprovalStorePath,
	PENDING_ASK_TTL_MS,
	type PendingAsk,
	type PendingAskArtifact,
	type RecordOperatorApprovalOptions,
	type RecordPendingAskInput,
	recordHostDialogAsk,
	recordOperatorApproval,
	recordOperatorRevocation,
	recordPendingAsk,
	resolveOperatorKeyStorage,
	signOperatorRecord,
	spendExternalApprovalToken,
	verifyOperatorRecord,
	withOperatorFileLock,
} from "./operator-approvals.js";
export { type OutputFinding, scanModelOutput } from "./output-scanner.js";
// High-precision credential / payment-card detection shared by output scanning and the CLI
export { detectOutputSensitiveData, type OutputSensitiveMatch } from "./output-sensitive-data.js";
export type { PackageCheckerConfig, PackageCheckInput } from "./package-checker.js";
// Package checker
export { PackageChecker } from "./package-checker.js";
export type { ParsedPackage } from "./package-extractor.js";
// Package extractor
export { extractPackagesFromCommand, extractPackagesFromManifest } from "./package-extractor.js";
// Built-in common-PII baseline governed by tenant DLP policy
export {
	COMMON_PII_PLACEHOLDER_LABEL,
	COMMON_PII_TYPES,
	type CommonPiiBaselineFinding,
	type CommonPiiBaselineResult,
	type CommonPiiType,
	commonPiiRuleId,
	evaluateCommonPiiBaseline,
	maskCommonPiiInToolInput,
} from "./pii-baseline.js";
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
export {
	discoverPlugins,
	matchPluginContent,
	SKILL_RISK_TYPES,
	scanPlugin,
	skillRiskTypeForThreatId,
} from "./plugin-scanner.js";
// Strict policy-as-code compiler and dry-run evaluator.
export {
	type CompiledRuntimePolicy,
	compilePolicyDocument,
	compilePolicyDocumentYaml,
	POLICY_DOCUMENT_ACTIONS,
	type PolicyCompilationDiagnostic,
	type PolicyCompilationResult,
	type PolicyDocument,
	PolicyDocumentSchema,
	type PolicySimulationInput,
	type PolicySimulationResult,
	parsePolicyDocument,
	simulateRuntimePolicy,
} from "./policy-document.js";
// AI security posture findings (infra CVEs, MCP inventory, skill/plugin scan)
export {
	AGENT_POSTURE_FINDING_EVENT,
	buildAgentPostureFindingEvents,
	buildInfraScanFindingEvents,
	buildMcpInventoryFindingEvents,
	buildSkillScanFindingEvents,
	INFRA_SCAN_FINDING_EVENT,
	MCP_INVENTORY_FINDING_EVENT,
	newPostureScanId,
	normalizePostureSeverity,
	PLUGIN_SCAN_FINDING_EVENT,
	type PostureSeverity,
	projectPostureFields,
} from "./posture-events.js";
export {
	describePostureUploadError,
	POSTURE_UPLOAD_BATCH_SIZE,
	type PostureUploadOptions,
	type PostureUploadResult,
	uploadPostureEvents,
} from "./posture-upload.js";
export {
	formatPrivacyNotice,
	privacyNoticeFacts,
	takeFirstRunPrivacyNotice,
} from "./privacy-notice.js";
export { preparePrivateLocalDirectory, preparePrivateLocalFile } from "./private-local-file.js";
// Connector-side prompt inspection runner (config, tenant DLP, deadline, audit, failure policy)
export {
	initialPromptFailureState,
	inspectUserPrompt,
	isPromptTenantPolicyConfigured,
	MIN_PROMPT_INSPECTION_DEADLINE_MS,
	PROMPT_INSPECTION_DEADLINE_ENV,
	type PromptFailureState,
	type PromptInspectionOutcome,
	type PromptInspectionReason,
	type PromptInspectionRequest,
	promptFailureBlocks,
	promptFailureMode,
	resolvePromptInspectionDeadlineMs,
	uninspectedPromptOutcome,
} from "./prompt-inspection.js";
// Prompt protection (UserPromptSubmit-style inspection of the user's prompt)
export {
	DEFAULT_PROMPT_PROTECTION,
	locateSecrets,
	type PromptFindingCategory,
	type PromptFindingSummary,
	type PromptIncompleteInspection,
	type PromptProtectionDecision,
	type PromptProtectionResult,
	PromptScanDeadlineError,
	type PromptScanOptions,
	type PromptTenantDlp,
	type SecretLocation,
	scanPrompt,
} from "./prompt-protection.js";
// Jailbreak & content-safety prompt inspection
export {
	applyTenantPromptSafety,
	DEFAULT_PROMPT_SAFETY,
	PROMPT_SAFETY_LABELS,
	type PromptSafetyCategory,
	type PromptSafetyFinding,
	type PromptSafetyResult,
	scanPromptSafety,
	type TenantPromptSafetyPolicy,
} from "./prompt-safety.js";
export {
	scanCachedProvisionedOutput,
	scanProvisionedOutput,
} from "./provisioned-output-scanner.js";
// Quarantine
export {
	AutoQuarantine,
	getDefaultQuarantineConfig,
	type NotifyChannel,
	QUARANTINE_PAYLOAD_SUFFIX,
	type QuarantineConfig,
	QuarantineDeleteError,
	type QuarantinedItem,
	QuarantineRefusedError,
} from "./quarantine.js";
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
export type {
	ResponseAuditEntry,
	ResponseAuditorOptions,
	ResponseChainBrokenLink,
	ResponseChainVerification,
} from "./response-audit.js";
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
export {
	inspectResponseBarrier,
	type ResponseBarrierInspection,
	type ResponseBarrierOptions,
	type ResponseControlConfig,
	ResponseControlConfigSchema,
} from "./response-barrier.js";
export type {
	FleetResponseActionAdapter,
	FleetResponseAuditEvent,
	FleetResponseCommand,
	FleetResponseCommandType,
	FleetResponseConsumerOptions,
	FleetResponseCycleResult,
	FleetResponseIdentity,
	FleetResponseSignedDelivery,
} from "./response-command-consumer-v6.js";
export {
	FleetResponseActionInterrupted,
	FleetResponseCommandConsumer,
	verifyFleetResponseCommandDelivery,
} from "./response-command-consumer-v6.js";
export {
	type FleetJournalState,
	type FleetResponseControlHead,
	FleetResponseJournal,
} from "./response-command-journal-v6.js";
export {
	FleetResponseCommandWorker,
	type FleetResponseWorkerOptions,
} from "./response-command-worker-v6.js";
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
	ResponseProvider,
	ResponseProviderAction,
	ResponseProviderOutcome,
	ResponseProviderRequest,
	RevocationProvider,
	RevocationProviderAction,
	RevocationProviderOutcome,
	RevocationProviderRequest,
} from "./response-provider-registry.js";
// External response providers are explicit and empty by default. Without a
// registered provider, credential revocation and containment are unsupported.
export {
	ResponseProviderRegistry,
	RevocationProviderRegistry,
} from "./response-provider-registry.js";
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
// Installed endpoint response-worker contract (capability, precondition, TTL,
// rollback receipt).
export {
	executeResponseStep,
	MemoryResponseJournal,
	planResponseRollback,
	planResponseStep,
	RESPONSE_CAPABILITIES,
	reportWorkerCapabilities,
} from "./response-worker-contract.js";
export type {
	Snapshot,
	SnapshotOptions,
	SnapshotResult,
	SnapshotRollbackResult,
	SnapshotSkip,
	StoredSnapshotInfo,
} from "./rollback.js";
// Auto-Rollback
export {
	AutoRollback,
	createAutoRollback,
	DEFAULT_SNAPSHOT_OPTIONS,
	DEFAULT_SNAPSHOTS_DIR,
	RollbackRefusedError,
	SnapshotIncompleteError,
} from "./rollback.js";
// AIDR_THREATS_DIR / AIDR_ALLOWLISTS_DIR overrides (ignored in commercial builds, always reported)
export {
	RULE_DIR_ENV,
	type RuleDirKind,
	type RuleDirOverride,
	type RuleDirOverrideOptions,
	ruleDirOverride,
	ruleDirOverrideNotice,
	ruleDirOverrides,
} from "./rule-dir-override.js";
export type { RuleSyncConfig } from "./rule-sync.js";
// Real-Time Rule Sync
export { RealTimeRuleSync } from "./rule-sync.js";
// Scan handler
export { createScanHandler, runPluginScan, type ScanHandlerOptions } from "./scan-handler.js";
export * from "./secret-store.js";
export { type ModifiedPathOptions, modifiedPaths } from "./self-defense-paths.js";
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
	RULES_INCOMPLETE_MESSAGE,
	runSessionStartScan,
	runSessionStartScanWithReport,
	type SessionStartRulesIncomplete,
	type SessionStartScanContext,
	type SessionStartScanReport,
	toAuditFindingData,
	toFindingData,
} from "./session-start-scan.js";
export {
	SessionStateError,
	type SessionStateErrorCode,
	type SessionStateRecovery,
	SessionStateStore,
	type SessionStateStoreOptions,
	type SessionStateUpdateResult,
	sessionStateDigest,
} from "./session-state-store.js";
export { normalizeShellText } from "./shell-normalize.js";
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
export {
	classifySyslogAddress,
	SIEM_SYSLOG_CONFIG_JSON_SCHEMA,
	type SyslogAddressClass,
	type SyslogSiemConfig,
	type SyslogTransport,
} from "./siem-syslog.js";
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
export {
	DurableTelemetryQueue,
	readTelemetryLossSummary,
	type TelemetryLossSummary,
} from "./telemetry-queue.js";
// Telemetry privacy boundary
export {
	redactTelemetryAttributes,
	redactTelemetryData,
	redactTelemetryString,
	sanitizeTelemetryEndpoint,
} from "./telemetry-redaction.js";
export {
	boundTerminalText,
	escapeTerminalText,
	hasUnsafeTerminalCharacters,
	TRUNCATION_MARKER,
} from "./terminal-text.js";
// Threat loader
export {
	loadThreats,
	loadThreatsFromDirs,
	loadThreatsFromDirsWithReport,
	loadThreatsWithReport,
	type MergedThreatLoadReport,
	type ThreatLoadError,
	type ThreatLoadReport,
} from "./threat-loader.js";
// Session toxic-flow ("lethal trifecta") and behavioral chain detection
export {
	recordToolOutputFlow,
	TOXIC_FLOW_THREAT_IDS,
	type ToolOutputFlowInput,
	type ToolOutputFlowResult,
	type ToxicFlowChain,
} from "./toxic-flow.js";
// Toxic-flow capability patterns (threats/flow/capabilities.yaml)
export {
	FLOW_CAPABILITIES_RELATIVE_PATH,
	type FlowCapabilityPatterns,
	loadFlowCapabilities,
	parseFlowCapabilitiesYaml,
} from "./toxic-flow-capabilities.js";
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
	isTrustedUrl,
	loadTrustedDomains,
} from "./trusted-domains.js";
export type {
	AgentProfileVerdictRef,
	AgentRuntime,
	AiSupplyChainConfig,
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
	FrameworkRefs,
	FrameworkRefsJson,
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
	PoisoningProtectionConfig,
	PromptContentSafetyCategory,
	PromptContentSafetyConfig,
	PromptProtectionConfig,
	PromptProtectionMode,
	RuleSeverity,
	RunawayConfig,
	SecureCodeConfig,
	SignalSources,
	Threat,
	ThreatData,
	ToxicFlowConfig,
	TrustedDomain,
	UrlCheckConfig,
	UrlCheckFinding,
	UrlCheckResult,
	Verdict,
	VerdictSeverity,
	VerdictWarning,
} from "./types.js";
// Types
export {
	ActionSchema,
	AgentSafetyConfigSchema,
	AiSupplyChainConfigSchema,
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
	PoisoningProtectionConfigSchema,
	PromptContentSafetySchema,
	PromptProtectionConfigSchema,
	PromptProtectionModeSchema,
	RunawayConfigSchema,
	SecureCodeConfigSchema,
	SensitivitySchema,
	SeveritySchema,
	ThreatSchema,
	UrlCheckConfigSchema,
	VerdictSeveritySchema,
} from "./types.js";
export {
	detectUnprotectedAiTools,
	UNSUPPORTED_AI_TOOL_IDS,
	type UnprotectedAiTool,
} from "./unprotected-agents.js";
// Desktop-installer self-update (`aidr update`, session-start update notice)
export type {
	CatalogVerification,
	InstallerCatalog,
	InstallerCatalogFile,
	InstallerPlatform,
	SignedDocument,
} from "./update/catalog.js";
export {
	INSTALLER_PLATFORMS,
	parseCatalogPublicKey,
	verifyCatalogDocument,
	verifyPublishedCatalog,
} from "./update/catalog.js";
export type { UpdateCheck, UpdateCheckState, UpdateNotice, UpdateStatus } from "./update/check.js";
export {
	checkInstallerUpdate,
	compareReleaseVersions,
	installerUpdateNotice,
	installerUpdatesApply,
	readUpdateState,
	resolveManagedApiKey,
	resolveUpdateSource,
	UPDATE_STATE_FILE,
	writeUpdateState,
} from "./update/check.js";
export type {
	InstallerLayout,
	MdmStatus,
	TrustedCatalogKeys,
	UpdateAutoMode,
	UpdateEnvironmentDeps,
} from "./update/environment.js";
export {
	CATALOG_KEY_FILE,
	detectMdmManaged,
	effectiveAutoMode,
	installerLayoutFor,
	installerPlatform,
	LINUX_MDM_MARKER,
	trustedCatalogKeys,
	WINDOWS_MDM_POLICY_KEY,
	WINDOWS_MDM_POLICY_VALUE,
} from "./update/environment.js";
export type { SourceDeps, SourceErrorCode, UpdateSource } from "./update/source.js";
export { downloadVerified, installerLocation, loadCatalog } from "./update/source.js";
// URL utilities
export { hashCommand, normalizeFilePath, normalizeUrl } from "./url-utils.js";
// Build/runtime version used by health, telemetry and consumer CLIs.
export { getVersion, VERSION } from "./version.js";
export type { VersionCheckContext, VersionCheckResult } from "./version-check.js";
// Version check
export { checkForUpdate, isNewerVersion, versionCheckEndpoint } from "./version-check.js";
export { windowsTargetsAreAlreadyPrivate } from "./windows-private-acl-probe.js";
export {
	initializeInstalledWindowsResponseWorker,
	loadInstalledWindowsResponseWorker,
	runInstalledWindowsResponseWorker,
	validateInstalledWindowsResponseRemoval,
} from "./windows-response-worker.js";
