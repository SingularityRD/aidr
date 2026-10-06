import { z } from "zod";
import { resolveSecretStore } from "./secret-store.js";

const identity = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
const uuid = z.string().uuid();
const secretReference = z.union([
	z.object({ env: z.string().regex(/^[A-Z][A-Z0-9_]{0,127}$/) }).strict(),
	z
		.object({
			vault: z
				.object({
					store: z.enum(["windows-dpapi", "macos-keychain", "linux-secret-service"]),
					id: identity,
				})
				.strict(),
		})
		.strict(),
]);
const servicePrincipal = z.object({ clientId: uuid, clientSecret: secretReference }).strict();
const base = { schemaVersion: z.literal(1), tenantId: identity };
const scopeStrings = (pattern: RegExp, max = 100) =>
	z.array(z.string().max(1024).regex(pattern)).min(1).max(max);

/** No endpoints, plaintext credentials, ambient credentials or metadata discovery. */
const CloudDiscoveryConfigSchema = z.discriminatedUnion("provider", [
	z
		.object({
			...base,
			provider: z.literal("aws"),
			accountId: z.string().regex(/^\d{12}$/),
			regions: scopeStrings(/^(?:af|ap|ca|eu|il|me|mx|sa|us)-(?!gov-)[a-z]+-\d$/, 20),
			resourceTypes: scopeStrings(/^[a-z0-9-]+(?::[A-Za-z0-9_-]+)?$/),
			credentials: z
				.object({
					accessKeyId: secretReference,
					secretAccessKey: secretReference,
					sessionToken: secretReference.optional(),
				})
				.strict(),
		})
		.strict(),
	z
		.object({
			...base,
			provider: z.literal("azure"),
			directoryTenantId: uuid,
			subscriptionIds: z.array(uuid).min(1).max(20),
			resourceGroups: scopeStrings(/^[A-Za-z0-9_().-]{1,90}$/),
			credentials: servicePrincipal,
		})
		.strict(),
	z
		.object({
			...base,
			provider: z.literal("gcp"),
			projectNumbers: scopeStrings(/^\d{6,20}$/, 20),
			assetTypes: scopeStrings(/^[a-z][a-z0-9.-]*\.googleapis\.com\/[A-Za-z][A-Za-z0-9]*$/),
			credentials: z
				.object({
					serviceAccountEmail: z
						.string()
						.max(254)
						.regex(/^[a-z0-9-]+@[a-z0-9.-]+\.iam\.gserviceaccount\.com$/),
					privateKey: secretReference,
				})
				.strict(),
		})
		.strict(),
	z
		.object({
			...base,
			provider: z.literal("intune"),
			directoryTenantId: uuid,
			deviceIds: z.array(uuid).min(1).max(1000),
			credentials: servicePrincipal,
		})
		.strict(),
]);

export type CloudDiscoveryConfig = z.infer<typeof CloudDiscoveryConfigSchema>;
export type DiscoverySecretReference = z.infer<typeof secretReference>;
export type DiscoverySecretResolver = (reference: DiscoverySecretReference) => string;

export function parseCloudDiscoveryConfig(value: unknown): CloudDiscoveryConfig {
	const parsed = CloudDiscoveryConfigSchema.safeParse(value);
	if (!parsed.success) throw new Error("discovery_provider_config_invalid");
	const config = parsed.data;
	if (config.provider === "aws") {
		config.regions = [...new Set(config.regions)].sort();
		config.resourceTypes = [...new Set(config.resourceTypes)].sort();
	} else if (config.provider === "gcp") {
		config.projectNumbers = [...new Set(config.projectNumbers)].sort();
		config.assetTypes = [...new Set(config.assetTypes)].sort();
	} else {
		config.directoryTenantId = config.directoryTenantId.toLowerCase();
		if (config.provider === "azure") {
			config.subscriptionIds = [
				...new Set(config.subscriptionIds.map((id) => id.toLowerCase())),
			].sort();
			config.resourceGroups = [
				...new Set(config.resourceGroups.map((group) => group.toLowerCase())),
			].sort();
		} else config.deviceIds = [...new Set(config.deviceIds.map((id) => id.toLowerCase()))].sort();
	}
	return config;
}

/** Credentials are resolved afresh every cycle, so external/vault rotation takes effect. */
export function resolveDiscoverySecret(reference: DiscoverySecretReference): string {
	let value: string | null | undefined;
	try {
		value =
			"env" in reference
				? process.env[reference.env]
				: resolveSecretStore({ selection: reference.vault.store }).get(reference.vault.id);
	} catch {
		throw new Error("discovery_credentials_unavailable");
	}
	if (!value || Buffer.byteLength(value, "utf8") > 64 * 1024 || value.includes("\0")) {
		throw new Error("discovery_credentials_unavailable");
	}
	return value;
}
