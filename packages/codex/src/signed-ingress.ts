import { createHash, randomUUID, sign, type KeyLike } from "node:crypto";
import { stableJson } from "./types.js";

const SIGNED_CALLER_SCHEMA = "aidr-signed-caller/v1";
const INGRESS_SCHEMA = "aidr-signed-http-ingress/v1";
const SIGNED_CALLER_HEADER = "X-AutoSecOps-AIDR-Signed-Caller";

export interface SignedIngressRequest {
	schema_version: typeof INGRESS_SCHEMA;
	principal: { id: string; credential_digest: { algorithm: string; value: string } };
	event: Record<string, unknown> & {
		kind: "tool_call_requested" | "mcp_call_started";
		scope: Record<string, unknown>;
	};
	tool: Record<string, unknown> & {
		scope: Record<string, unknown>;
		tool_name: string;
		arguments: unknown;
	};
	connector: string;
	title: string;
	description?: string;
	requested_by?: string;
	target?: string;
	mcp?: Record<string, unknown>;
}

export interface SignedIngressResponse {
	schema_version: typeof INGRESS_SCHEMA;
	route: "read_only" | "wt05";
	receipt_digest: { algorithm: "sha256"; value: string };
	replayed: boolean;
}

export interface SignedIngressClientOptions {
	endpoint: string;
	tenantId: string;
	teamId: string;
	callerId: string;
	keyGeneration: number;
	privateKey: KeyLike;
	nextSequence: () => number | Promise<number>;
	timeoutMs?: number;
	fetchImpl?: typeof fetch;
	now?: () => Date;
	requestId?: () => string;
}

export class SignedIngressError extends Error {
	constructor(message: string, readonly status?: number) {
		super(message);
		this.name = "SignedIngressError";
	}
}

interface SignedCallerEnvelope {
	schema_version: typeof SIGNED_CALLER_SCHEMA;
	tenant_id: string;
	team_id: string;
	caller_id: string;
	key_generation: number;
	sequence: number;
	request_id: string;
	connector: string;
	tool: string;
	request_digest: string;
	signed_at: string;
	signature: string;
}

function ingressURL(endpoint: string): string {
	const base = endpoint.replace(/\/+$/, "");
	return base.endsWith("/api")
		? `${base}/v1/aidr/ingress/tool-calls`
		: `${base}/api/v1/aidr/ingress/tool-calls`;
}

function validIdentifier(value: string): boolean {
	return /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateRequest(request: SignedIngressRequest, options: SignedIngressClientOptions): void {
	const eventScope = request?.event?.scope;
	const toolScope = request?.tool?.scope;
	if (
		!isRecord(request) ||
		request.schema_version !== INGRESS_SCHEMA ||
		!validIdentifier(request.principal?.id ?? "") ||
		request.principal?.credential_digest?.algorithm !== "sha256" ||
		typeof request.principal?.credential_digest?.value !== "string" ||
		!/^[a-f0-9]{64}$/.test(request.principal.credential_digest.value) ||
		!validIdentifier(request.connector ?? "") ||
		!validIdentifier(request.tool?.tool_name ?? "") ||
		typeof request.title !== "string" ||
		!request.title.trim() ||
		(request.event?.kind !== "tool_call_requested" && request.event?.kind !== "mcp_call_started") ||
		!isRecord(eventScope) ||
		!isRecord(toolScope) ||
		eventScope.tenant_id !== options.tenantId ||
		eventScope.team_id !== options.teamId ||
		!Object.values(eventScope).every((value) => typeof value === "string" && validIdentifier(value)) ||
		stableJson(eventScope) !== stableJson(toolScope) ||
		request.event.source !== request.connector ||
		request.tool.source !== request.connector ||
		request.tool?.arguments === undefined
	) {
		throw new SignedIngressError("invalid signed ingress request");
	}
}

function validateResponse(value: unknown, status: number): SignedIngressResponse {
	const response = value as Partial<SignedIngressResponse> | null;
	if (
		response?.schema_version !== INGRESS_SCHEMA ||
		(response.route !== "read_only" && response.route !== "wt05") ||
		(response.route === "read_only" ? status !== 200 : status !== 202) ||
		response.receipt_digest?.algorithm !== "sha256" ||
		!/^[a-f0-9]{64}$/.test(response.receipt_digest?.value ?? "") ||
		typeof response.replayed !== "boolean"
	) {
		throw new SignedIngressError("invalid signed ingress response");
	}
	return response as SignedIngressResponse;
}

export class SignedIngressClient {
	private readonly endpoint: string;
	private readonly timeoutMs: number;
	private readonly fetchImpl: typeof fetch;
	private readonly now: () => Date;
	private readonly requestId: () => string;

	constructor(private readonly options: SignedIngressClientOptions) {
		this.timeoutMs = options.timeoutMs ?? 5_000;
		this.fetchImpl = options.fetchImpl ?? fetch;
		this.now = options.now ?? (() => new Date());
		this.requestId = options.requestId ?? randomUUID;
		try {
			const endpoint = new URL(options.endpoint);
			if (
				endpoint.protocol !== "https:" ||
				endpoint.username || endpoint.password || endpoint.search || endpoint.hash
			) {
				throw new Error("invalid signed ingress endpoint");
			}
			this.endpoint = ingressURL(endpoint.href);
		} catch {
			throw new SignedIngressError("invalid signed ingress endpoint");
		}
		if (
			!validIdentifier(options.tenantId) ||
			!validIdentifier(options.teamId) ||
			!validIdentifier(options.callerId) ||
			!Number.isSafeInteger(options.keyGeneration) ||
			options.keyGeneration <= 0 ||
			!Number.isFinite(this.timeoutMs) ||
			this.timeoutMs <= 0 ||
			this.timeoutMs > 15_000
		) {
			throw new SignedIngressError("invalid signed ingress client configuration");
		}
	}

	async submit(request: SignedIngressRequest): Promise<SignedIngressResponse> {
		validateRequest(request, this.options);
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeoutMs);
		try {
			const body = JSON.stringify(request);
			const sequence = await Promise.race([
				this.options.nextSequence(),
				new Promise<never>((_resolve, reject) => {
					controller.signal.addEventListener(
						"abort", () => reject(new SignedIngressError("signed ingress timed out")), { once: true },
					);
				}),
			]);
			const requestId = this.requestId();
			if (!Number.isSafeInteger(sequence) || sequence <= 0 || !validIdentifier(requestId)) {
				throw new SignedIngressError("invalid signed ingress sequence or request id");
			}

			const unsigned: Omit<SignedCallerEnvelope, "signature"> = {
				schema_version: SIGNED_CALLER_SCHEMA,
				tenant_id: this.options.tenantId,
				team_id: this.options.teamId,
				caller_id: this.options.callerId,
				key_generation: this.options.keyGeneration,
				sequence,
				request_id: requestId,
				connector: request.connector,
				tool: request.tool.tool_name,
				request_digest: createHash("sha256").update(body).digest("hex"),
				// Go's time.RFC3339Nano omits all trailing fractional zeros.
				signed_at: this.now().toISOString().replace(/0+Z$/, "Z").replace(/\.Z$/, "Z"),
			};
			const signature = sign(null, Buffer.from(JSON.stringify(unsigned), "utf8"), this.options.privateKey);
			const envelope: SignedCallerEnvelope = { ...unsigned, signature: signature.toString("base64") };
			const header = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
			controller.signal.throwIfAborted();
			const response = await this.fetchImpl(this.endpoint, {
				method: "POST",
				redirect: "error",
				headers: { "Content-Type": "application/json", [SIGNED_CALLER_HEADER]: header },
				body,
				signal: controller.signal,
			});
			if (response.status !== 200 && response.status !== 202) {
				throw new SignedIngressError("signed ingress rejected the request", response.status);
			}
			return validateResponse(await response.json(), response.status);
		} catch (error) {
			if (error instanceof SignedIngressError) throw error;
			throw new SignedIngressError(
				controller.signal.aborted ? "signed ingress timed out" : "signed ingress unavailable",
			);
		} finally {
			clearTimeout(timer);
		}
	}
}
