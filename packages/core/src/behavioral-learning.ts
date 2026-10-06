import { randomUUID } from "node:crypto";
import { z } from "zod";
import {
	assertLearningAuthorityPrivateKey,
	createLearningExecutionReceipt,
	type LearningReceiptContext,
	learningInputDigest,
	type SignedLearningExecutionReceipt,
	verifyLearningReceiptBundle,
} from "./behavioral-learning-receipt.js";
import {
	type BehavioralDetectionInput,
	type BehavioralDetectionResult,
	behavioralObservationForInput,
} from "./behavioral-orchestrator.js";
import { canonicalJson } from "./canonical-json.js";
import { loadProvisionedLearningContext } from "./detector-provisioning.js";
import { evaluateToolCall, type ToolEvaluationRequest } from "./evaluator.js";
import { MAX_OUTPUT_SCAN_BYTES } from "./output-scanner.js";
import { scanProvisionedOutput } from "./provisioned-output-scanner.js";
import type { AgentRuntime } from "./types.js";

interface LearningExecutionAuthority {
	keyId: string;
	privateKeyPem: string;
}

const RequestSchema = z
	.object({
		sessionId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
		toolName: z.literal("Bash"),
		toolInput: z
			.object({
				command: z
					.string()
					.min(1)
					.refine((text) => Boolean(text.trim()) && !text.includes("\0")),
				execution_shell: z.enum(["powershell.exe", "/bin/sh"]),
			})
			.strict(),
		artifacts: z.array(z.never()).length(0),
	})
	.strict();

function checkedRequest(value: ToolEvaluationRequest): ToolEvaluationRequest {
	const request = RequestSchema.parse(value);
	if (
		request.toolInput.execution_shell !==
		(process.platform === "win32" ? "powershell.exe" : "/bin/sh")
	)
		throw new Error("Authorized learning execution shell does not match this host");
	learningInputDigest(request.toolInput);
	Object.freeze(request.toolInput);
	Object.freeze(request.artifacts);
	return Object.freeze(request);
}

function sameContext(
	actual: LearningReceiptContext,
	expected: LearningReceiptContext,
	allowRenewal = false,
): void {
	const comparable = (context: LearningReceiptContext) =>
		allowRenewal ? { ...context, entitlementSerial: "", validFromMs: 0, validUntilMs: 0 } : context;
	if (canonicalJson(comparable(actual)) !== canonicalJson(comparable(expected)))
		throw new Error("Learning authority changed during the execution boundary");
}

function behavioralInput(
	context: LearningReceiptContext,
	request: Pick<ToolEvaluationRequest, "sessionId" | "toolName" | "toolInput">,
	timestamp: number,
	durationMs: number,
): BehavioralDetectionInput {
	return {
		tenantId: context.tenantId,
		sessionId: request.sessionId,
		toolName: request.toolName,
		riskScore: 0,
		timestamp,
		durationMs,
		command: String(request.toolInput.command),
		classificationText: canonicalJson(request.toolInput),
		learningAllowed: false,
	};
}

/** Static resources belong to the installed broker, never the request JSON. */
export async function prepareAuthorizedLearningExecution(
	agentRuntime: AgentRuntime,
	value: ToolEvaluationRequest,
	authority: LearningExecutionAuthority,
	resources: { threatsDir: string; allowlistsDir: string },
): Promise<{
	request: ToolEvaluationRequest;
	receiptContext: LearningReceiptContext;
	inputDigest: string;
}> {
	const request = checkedRequest(value);
	const installed = await loadProvisionedLearningContext(agentRuntime);
	assertLearningAuthorityPrivateKey(
		installed.receiptContext,
		"execution",
		authority.keyId,
		authority.privateKeyPem,
	);
	const verdict = await evaluateToolCall(request, {
		...resources,
		agentRuntime,
		...installed.detectorContext,
	});
	if (verdict.decision !== "allow")
		throw new Error("Learning execution was not permitted by tool enforcement");
	const detection = await installed.orchestrator.evaluate(
		behavioralInput(installed.receiptContext, request, Date.now(), 0),
	);
	if (
		detection.outcome === "anomalous" ||
		detection.outcome === "unavailable" ||
		!detection.explanations.some(
			(leg) => leg.leg === "ml" && leg.status === "ready" && leg.score === 0,
		)
	)
		throw new Error("Learning execution has no clean independent local detection result");
	const fresh = await loadProvisionedLearningContext(agentRuntime);
	// Enforcement itself can refresh a grant. No execution has begun yet; only
	// a serial/window renewal under the same current paid protection may rebind it.
	sameContext(fresh.receiptContext, installed.receiptContext, true);
	return {
		request,
		receiptContext: structuredClone(fresh.receiptContext),
		inputDigest: learningInputDigest(request.toolInput),
	};
}

/**
 * The protected execution authority calls this only after its foreground process
 * really exits zero with complete bounded output. Bare SDK callbacks are not callers.
 */
export async function issueAuthorizedLearningExecution(
	agentRuntime: AgentRuntime,
	value: ToolEvaluationRequest,
	options: LearningExecutionAuthority & {
		startedAt: number;
		completedAt: number;
		output: string;
		receiptContext: LearningReceiptContext;
		inputDigest: string;
	},
): Promise<SignedLearningExecutionReceipt> {
	const request = checkedRequest(value);
	if (learningInputDigest(request.toolInput) !== options.inputDigest)
		throw new Error("Executed input differs from the authorized preflight request");
	if (
		!Number.isSafeInteger(options.startedAt) ||
		!Number.isSafeInteger(options.completedAt) ||
		options.completedAt < options.startedAt ||
		options.completedAt - options.startedAt > 60_000 ||
		options.completedAt > Date.now() ||
		typeof options.output !== "string" ||
		Buffer.byteLength(options.output, "utf8") > MAX_OUTPUT_SCAN_BYTES
	)
		throw new Error("Execution completion or bounded output is unavailable");
	const installed = await loadProvisionedLearningContext(agentRuntime);
	sameContext(installed.receiptContext, options.receiptContext);
	assertLearningAuthorityPrivateKey(
		installed.receiptContext,
		"execution",
		options.keyId,
		options.privateKeyPem,
	);
	if ((await scanProvisionedOutput([options.output], agentRuntime)).length > 0)
		throw new Error("Execution output is not clean or completely inspected");
	const fresh = await loadProvisionedLearningContext(agentRuntime);
	sameContext(fresh.receiptContext, options.receiptContext);
	const context = fresh.receiptContext;
	const now = Date.now();
	const { observation, fingerprint } = behavioralObservationForInput(
		behavioralInput(context, request, options.completedAt, options.completedAt - options.startedAt),
	);
	return createLearningExecutionReceipt(
		{
			kind: "aidr.behavioral.execution.v1",
			schemaVersion: 1,
			executionId: randomUUID(),
			tenantId: context.tenantId,
			deviceId: context.deviceId,
			agentRuntime,
			sessionId: request.sessionId,
			toolName: request.toolName,
			inputDigest: options.inputDigest,
			policyDigest: context.policyDigest,
			corpusDigest: context.corpusDigest,
			modelVersion: context.modelVersion,
			entitlementSerial: context.entitlementSerial,
			startedAt: new Date(options.startedAt).toISOString(),
			completedAt: new Date(options.completedAt).toISOString(),
			issuedAt: new Date(now).toISOString(),
			expiresAt: new Date(Math.min(now + 86_400_000, context.validUntilMs)).toISOString(),
			outcome: "success",
			outputInspection: "clean",
			observation: {
				...observation,
				riskScore: 0,
				durationMs: options.completedAt - options.startedAt,
			},
			fingerprint,
		},
		options.privateKeyPem,
		options.keyId,
		context,
	);
}

/** Verify both authorities and the actual input before the one-time durable transaction. */
export async function ingestBehavioralLearningReceipt(
	agentRuntime: AgentRuntime,
	bundle: unknown,
	toolInput: Record<string, unknown>,
): Promise<BehavioralDetectionResult> {
	const input = structuredClone(toolInput);
	const installed = await loadProvisionedLearningContext(agentRuntime);
	const receipt = verifyLearningReceiptBundle(bundle, installed.receiptContext, { mode: "ingest" });
	if (learningInputDigest(input) !== receipt.inputDigest)
		throw new Error("Learning ingestion input does not match the executed operation");
	const request = checkedRequest({
		sessionId: receipt.sessionId,
		toolName: receipt.toolName,
		toolInput: input,
		artifacts: [],
	});
	return installed.orchestrator.ingestAuthenticatedExecution(
		behavioralInput(
			installed.receiptContext,
			request,
			receipt.observation.timestamp,
			receipt.observation.durationMs ?? 0,
		),
		bundle,
		input,
		async () =>
			sameContext(
				(await loadProvisionedLearningContext(agentRuntime)).receiptContext,
				installed.receiptContext,
			),
	);
}
