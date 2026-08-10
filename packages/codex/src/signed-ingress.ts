import { createHash, randomUUID, sign, type KeyLike } from "node:crypto";

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

function validateRequest(request: SignedIngressRequest): void {
	if (
		request.schema_version !== INGRESS_SCHEMA ||
		!validIdentifier(request.principal?.id ?? "") ||
		!validIdentifier(request.connector ?? "") ||
		!validIdentifier(request.tool?.tool_name ?? "") ||
		!request.title?.trim() ||
		(request.event?.kind !== "tool_call_requested" && request.event?.kind !== "mcp_call_started") ||
		JSON.stringify(request.event?.scope) !== JSON.stringify(request.tool?.scope) ||
		request.tool?.arguments === undefined
	) {
		throw new SignedIngressError("invalid signed ingress request");
	}
}

function validateResponse(value: unknown): SignedIngressResponse {
	const response = value as Partial<SignedIngressResponse> | null;
	if (
		response?.schema_version !== INGRESS_SCHEMA ||
		(response.route !== "read_only" && response.route !== "wt05") ||
		response.receipt_digest?.algorithm !== "sha256" ||
		!/^[a-f0-9]{64}$/.test(response.receipt_digest?.value ?? "") ||
		typeof response.replayed !== "boolean"
	) {
		throw new SignedIngressError("invalid signed ingress response");
	}
	return response as SignedIngressResponse;
}

export class SignedIngressClient {
	private readonly timeoutMs: number;
	private readonly fetchImpl: typeof fetch;
	private readonly now: () => Date;
	private readonly requestId: () => string;

	constructor(private readonly options: SignedIngressClientOptions) {
		this.timeoutMs = options.timeoutMs ?? 5_000;
		this.fetchImpl = options.fetchImpl ?? fetch;
		this.now = options.now ?? (() => new Date());
		this.requestId = options.requestId ?? randomUUID;
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
		validateRequest(request);
		const body = JSON.stringify(request);
		const sequence = await this.options.nextSequence();
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
			// Go's time.RFC3339Nano canonical form omits a zero fractional part.
			signed_at: this.now().toISOString().replace(".000Z", "Z"),
		};
		const signature = sign(null, Buffer.from(JSON.stringify(unsigned), "utf8"), this.options.privateKey);
		const envelope: SignedCallerEnvelope = { ...unsigned, signature: signature.toString("base64") };
		const header = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");

		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeoutMs);
		try {
			const response = await this.fetchImpl(ingressURL(this.options.endpoint), {
				method: "POST",
				headers: { "Content-Type": "application/json", [SIGNED_CALLER_HEADER]: header },
				body,
				signal: controller.signal,
			});
			if (response.status !== 200 && response.status !== 202) {
				throw new SignedIngressError("signed ingress rejected the request", response.status);
			}
			return validateResponse(await response.json());
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
