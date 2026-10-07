import { readFile } from "node:fs/promises";
import { ArtifactIntegrityError } from "@singularityrd/aidr-core";
import { GatewayConfigError } from "./config.mjs";
import { McpGatewayRefusal } from "./coverage.mjs";

/**
 * Sanitised diagnostics for the operator CLIs.
 *
 * A failure is reported as `<stage>` or `<stage>:<detail>`, where both parts
 * come from fixed vocabularies: the stage the command was in, and a code
 * derived from the error type (never its free-text message, which could carry
 * a path, token fragment or upstream data). Exit codes: 2 for usage, 1 for any
 * other failure.
 */

const CODE = /^[a-z0-9_]{1,64}$/;

/**
 * Errors thrown with a fixed literal message elsewhere in this package. Only
 * these messages are converted into a detail code.
 */
const KNOWN_MESSAGES = new Set([
	"invalid token environment variable",
	"stdio client binding rejected",
	"unsupported stdio notification",
	"stdio notification rejected",
	"stdio gateway unavailable",
	"invalid stdio gateway response",
	"stdio frame too large",
	"unterminated stdio frame",
	"bridge_response_too_large",
	"invalid stdio protocol version",
	"invalid gateway request id",
	"unexpected stdio response",
	"initialize during pending requests",
	"stdio requests exceeded",
	"standalone_profile_invalid",
	"standalone_privacy_unavailable",
	"upstream_auth_unavailable",
	"unknown tenant server",
	"approval rejected",
]);

export class OperatorStageError extends Error {
	constructor(stage, cause) {
		super(stage);
		this.name = "OperatorStageError";
		this.stage = stage;
		this.cause = cause;
	}
}

/** Run one step of an operator command, tagging any failure with its stage code. */
export async function stage(code, work) {
	try {
		return await work();
	} catch (cause) {
		throw cause instanceof OperatorStageError ? cause : new OperatorStageError(code, cause);
	}
}

function snake(message) {
	return message
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "_")
		.replace(/^_|_$/g, "")
		.slice(0, 64);
}

function detailCode(cause) {
	if (cause instanceof ArtifactIntegrityError) {
		const status = cause.result?.status;
		return typeof status === "string" && CODE.test(status) ? status : "failed";
	}
	if (cause instanceof GatewayConfigError || cause instanceof McpGatewayRefusal)
		return CODE.test(cause.code) ? cause.code : null;
	if (cause instanceof SyntaxError) return "invalid_json";
	const errno = cause?.code;
	if (typeof errno === "string" && /^E[A-Z0-9]{2,20}$/.test(errno)) return errno.toLowerCase();
	if (cause instanceof Error && KNOWN_MESSAGES.has(cause.message)) return snake(cause.message);
	return null;
}

/** The single-line, secret-free reason printed by an operator CLI. */
export function diagnosticReason(error) {
	const stageCode = error instanceof OperatorStageError ? error.stage : "unexpected_failure";
	const detail = detailCode(error instanceof OperatorStageError ? error.cause : error);
	return detail ? `${stageCode}:${detail}` : stageCode;
}

/** Print `<program> failed: <reason>` and return the process exit code. */
export function reportFailure(program, error, stderr = process.stderr) {
	stderr.write(`${program} failed: ${diagnosticReason(error)}\n`);
	return 1;
}

/** Read and parse the gateway configuration file with stage-tagged failures. */
export async function readGatewayConfig(path) {
	const text = await stage("config_unreadable", () => readFile(path, "utf8"));
	return stage("config_parse_failed", () => JSON.parse(text));
}
