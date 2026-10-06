import { isInvalidConfig, loadConfig } from "@singularityrd/aidr-core";

/** Host-owned privacy-service configuration, separate from SDK/reputation config. */
export interface PrivacyGatewayOptions {
	origin: string;
	destinationId: string;
	tls: { ca: Buffer; cert: Buffer; key: Buffer };
	credentials: () =>
		| { userToken: string; deviceToken: string; providerToken: string }
		| Promise<{ userToken: string; deviceToken: string; providerToken: string }>;
}

export interface SDKPrivateOptions {
	privacyGateway?: PrivacyGatewayOptions;
}

export interface PrivacyTextSendOptions {
	requestId?: string;
	reviewCaseId?: string;
	signal?: AbortSignal;
}

export interface PrivacyTextGateway {
	send(
		text: string,
		options: PrivacyTextSendOptions,
	): Promise<{ decision: string; outputText: string | null }>;
}

export class AIDRPrivacyTextError extends Error {
	constructor(public readonly code: string) {
		super(code);
		this.name = "AIDRPrivacyTextError";
	}
}

/** Arbitrary host callbacks cannot receive raw payloads in an installed mandatory profile. */
export async function assertPrivacyCallbacksAllowed(): Promise<void> {
	try {
		const installed = await loadConfig();
		if (isInvalidConfig(installed) || installed.privacy?.required) throw new Error();
	} catch {
		throw new AIDRPrivacyTextError("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
	}
}

/** Copy key material before an asynchronous import; later caller mutations cannot change it. */
export function snapshotPrivacyGateway(
	options?: SDKPrivateOptions,
): PrivacyGatewayOptions | undefined {
	try {
		if (options === undefined || options.privacyGateway === undefined) return undefined;
		const gateway = options.privacyGateway;
		if (
			typeof gateway.origin !== "string" ||
			typeof gateway.destinationId !== "string" ||
			typeof gateway.credentials !== "function"
		)
			throw new Error();
		const tls = {} as PrivacyGatewayOptions["tls"];
		for (const name of ["ca", "cert", "key"] as const) {
			const value = gateway.tls[name];
			if (!Buffer.isBuffer(value) || !value.length || value.length > 1024 * 1024) throw new Error();
			tls[name] = Buffer.from(value);
		}
		return {
			origin: gateway.origin,
			destinationId: gateway.destinationId,
			credentials: gateway.credentials,
			tls,
		};
	} catch {
		throw new AIDRPrivacyTextError("PRIVACY_GATEWAY_CONFIG_INVALID");
	}
}

/** Load the operator-installed private package. Callers cannot supply a provider callback. */
export async function loadPrivacyTextGateway(
	options: PrivacyGatewayOptions,
): Promise<PrivacyTextGateway> {
	try {
		const packageId = "@singularity/aidr-privacy/platform";
		const platform = await import(packageId);
		if (typeof platform.TextGatewayClient !== "function") throw new Error();
		return new platform.TextGatewayClient({
			...options,
			tls: {
				ca: Buffer.from(options.tls.ca),
				cert: Buffer.from(options.tls.cert),
				key: Buffer.from(options.tls.key),
			},
		}) as PrivacyTextGateway;
	} catch {
		throw new AIDRPrivacyTextError("PRIVACY_GATEWAY_UNAVAILABLE");
	}
}
