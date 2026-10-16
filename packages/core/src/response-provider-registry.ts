/**
 * Explicit external response providers.
 *
 * The registry is intentionally empty by default. There is no built-in OS
 * containment or cloud credential provider in core. A missing provider is a
 * typed `unsupported_action`, never an implicit success or a best-effort call.
 */
export type ResponseProviderAction = "revoke_credential" | "contain";

export interface ResponseProviderRequest {
	action: ResponseProviderAction;
	target: string;
	providerId?: string;
	commandId?: string;
	idempotencyKey?: string;
	metadata?: Readonly<Record<string, string>>;
}

export type ResponseProviderOutcome =
	| {
			status: "applied";
			/** Provider-observed evidence, not a claim of universal host state. */
			observed: string;
			rollbackToken: string | null;
	  }
	| { status: "noop"; observed: string }
	| { status: "failed"; code: string; detail: string }
	| { status: "unsupported"; code: "unsupported_action"; detail: string };

export interface ResponseProvider {
	/** Stable, operator-visible provider name; never a secret or URL. */
	readonly providerId: string;
	readonly actions: readonly ResponseProviderAction[];
	/** Apply only the explicitly named provider action. */
	execute(request: ResponseProviderRequest): Promise<ResponseProviderOutcome>;
	/** Independent provider observation required before an applied result is accepted. */
	verify?(
		request: ResponseProviderRequest,
	): Promise<{ observed: true; evidence: string } | { observed: false; code: string }>;
}

const ACTIONS = new Set<ResponseProviderAction>(["revoke_credential", "contain"]);
const PROVIDER_ID = /^[a-z][a-z0-9_.:-]{1,63}$/;
const RESULT_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_TARGET_LENGTH = 512;
const MAX_DETAIL_LENGTH = 256;

function safeText(value: unknown, fallback: string): string {
	if (typeof value !== "string" || value.trim() === "") return fallback;
	const bounded = value
		.trim()
		.slice(0, MAX_DETAIL_LENGTH)
		.replace(/[\r\n\u0000]/g, " ");
	return bounded || fallback;
}

function validProvider(value: unknown): value is ResponseProvider {
	if (!value || typeof value !== "object") return false;
	const provider = value as Partial<ResponseProvider>;
	return (
		typeof provider.providerId === "string" &&
		PROVIDER_ID.test(provider.providerId) &&
		Array.isArray(provider.actions) &&
		provider.actions.length > 0 &&
		new Set(provider.actions).size === provider.actions.length &&
		provider.actions.every(
			(action) => typeof action === "string" && ACTIONS.has(action as ResponseProviderAction),
		) &&
		typeof provider.execute === "function" &&
		(provider.verify === undefined || typeof provider.verify === "function")
	);
}

function unsupported(action: ResponseProviderAction, providerId?: string): ResponseProviderOutcome {
	const suffix =
		providerId !== undefined && PROVIDER_ID.test(providerId) ? ` for ${providerId}` : "";
	return {
		status: "unsupported",
		code: "unsupported_action",
		detail: `no registered provider supports ${action}${suffix}`,
	};
}

function failed(code: string, detail: string): ResponseProviderOutcome {
	return { status: "failed", code, detail: safeText(detail, "provider action failed") };
}

function validObservation(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.trim().length > 0 &&
		value.length <= MAX_DETAIL_LENGTH &&
		!/[\r\n\u0000]/.test(value)
	);
}

/**
 * Registry for provider-backed response actions. It does not ship a provider.
 * Callers must register an allowlisted implementation and independently verify
 * any applied result before treating it as evidence.
 */
export class ResponseProviderRegistry {
	private readonly providers = new Map<string, ResponseProvider>();

	constructor(providers: readonly ResponseProvider[] = []) {
		for (const provider of providers) this.register(provider);
	}

	register(provider: ResponseProvider): void {
		if (!validProvider(provider)) throw new Error("invalid_response_provider");
		if (this.providers.has(provider.providerId)) throw new Error("duplicate_response_provider");
		this.providers.set(provider.providerId, provider);
	}

	remove(providerId: string): boolean {
		return this.providers.delete(providerId);
	}

	list(): readonly string[] {
		return [...this.providers.keys()].sort();
	}

	supports(action: ResponseProviderAction, providerId?: string): boolean {
		return this.resolve(action, providerId) !== undefined;
	}

	providerFor(action: ResponseProviderAction, providerId?: string): ResponseProvider | undefined {
		return this.resolve(action, providerId);
	}

	async execute(request: ResponseProviderRequest): Promise<ResponseProviderOutcome> {
		if (!ACTIONS.has(request.action)) return unsupported(request.action);
		if (
			typeof request.target !== "string" ||
			request.target.trim() === "" ||
			request.target.length > MAX_TARGET_LENGTH ||
			/[\r\n\u0000]/.test(request.target)
		) {
			return failed("invalid_provider_target", "provider target is invalid");
		}
		const provider = this.resolve(request.action, request.providerId);
		if (!provider) return unsupported(request.action, request.providerId);
		let raw: unknown;
		try {
			raw = await provider.execute({ ...request, providerId: provider.providerId });
		} catch {
			return failed("provider_execution_failed", "provider execution failed");
		}
		if (!raw || typeof raw !== "object" || !("status" in raw)) {
			return failed("provider_result_invalid", "provider returned an invalid result");
		}
		const outcome = raw as Record<string, unknown>;
		if (outcome.status === "unsupported") return unsupported(request.action, provider.providerId);
		if (outcome.status === "failed") {
			const code =
				typeof outcome.code === "string" && RESULT_CODE.test(outcome.code)
					? outcome.code
					: "provider_execution_failed";
			return failed(code, "provider action failed");
		}
		if (outcome.status !== "applied" && outcome.status !== "noop") {
			return failed("provider_result_invalid", "provider returned an invalid result");
		}
		if (!validObservation(outcome.observed)) {
			return failed("provider_observation_invalid", "provider returned invalid observation");
		}
		if (
			outcome.status === "applied" &&
			outcome.rollbackToken !== null &&
			typeof outcome.rollbackToken !== "string"
		) {
			return failed("provider_result_invalid", "provider returned an invalid rollback token");
		}
		// A registry update during an external action must not let a replacement
		// provider attest to an action it did not perform.
		const verification = await this.verifyWith(provider, request);
		if (verification.observed === false)
			return failed(verification.code, "provider could not independently verify the action");
		return outcome.status === "noop"
			? { status: "noop", observed: safeText(verification.evidence, "provider state verified") }
			: {
					status: "applied",
					observed: safeText(verification.evidence, "provider state verified"),
					rollbackToken: outcome.rollbackToken as string | null,
				};
	}

	/** Verify a previously persisted execute intent without replaying the action. */
	async verify(
		request: ResponseProviderRequest,
	): Promise<{ observed: true; evidence: string } | { observed: false; code: string }> {
		const provider = this.resolve(request.action, request.providerId);
		if (!provider) return { observed: false, code: "unsupported_action" };
		return this.verifyWith(provider, request);
	}

	private async verifyWith(
		provider: ResponseProvider,
		request: ResponseProviderRequest,
	): Promise<{ observed: true; evidence: string } | { observed: false; code: string }> {
		if (this.providers.get(provider.providerId) !== provider)
			return { observed: false, code: "provider_changed_during_action" };
		if (!provider.verify) return { observed: false, code: "provider_observation_unavailable" };
		try {
			const result = await provider.verify({ ...request, providerId: provider.providerId });
			if (this.providers.get(provider.providerId) !== provider)
				return { observed: false, code: "provider_changed_during_action" };
			if (!result || result.observed !== true || !validObservation(result.evidence)) {
				return { observed: false, code: "provider_verification_failed" };
			}
			return { observed: true, evidence: safeText(result.evidence, "provider state verified") };
		} catch {
			return { observed: false, code: "provider_verification_failed" };
		}
	}

	private resolve(
		action: ResponseProviderAction,
		providerId?: string,
	): ResponseProvider | undefined {
		if (providerId !== undefined) {
			if (!PROVIDER_ID.test(providerId)) return undefined;
			const provider = this.providers.get(providerId);
			return provider?.actions.includes(action) ? provider : undefined;
		}
		const candidates = [...this.providers.values()].filter((provider) =>
			provider.actions.includes(action),
		);
		return candidates.length === 1 ? candidates[0] : undefined;
	}
}

/** Compatibility names for integrations that only use credential revocation. */
export type {
	ResponseProvider as RevocationProvider,
	ResponseProviderAction as RevocationProviderAction,
	ResponseProviderOutcome as RevocationProviderOutcome,
	ResponseProviderRequest as RevocationProviderRequest,
};
export { ResponseProviderRegistry as RevocationProviderRegistry };
