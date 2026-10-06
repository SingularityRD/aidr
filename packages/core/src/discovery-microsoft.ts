import type { CloudDiscoveryContext, DiscoveryResource } from "./discovery-cloud-http.js";
import { appendDiscoveryResource, discoveryPageToken } from "./discovery-cloud-http.js";

async function microsoftToken(context: CloudDiscoveryContext, audience: string): Promise<string> {
	const config = context.config;
	if (config.provider !== "azure" && config.provider !== "intune")
		throw new Error("discovery_provider_config_invalid");
	const body = new URLSearchParams({
		client_id: config.credentials.clientId,
		client_secret: context.secret(config.credentials.clientSecret),
		scope: `${audience}/.default`,
		grant_type: "client_credentials",
	});
	const token = await context.http.json(
		`https://login.microsoftonline.com/${config.directoryTenantId}/oauth2/v2.0/token`,
		{
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: body.toString(),
		},
	);
	if (
		typeof token.access_token !== "string" ||
		!/^[A-Za-z0-9._~-]{1,16384}$/.test(token.access_token) ||
		token.token_type !== "Bearer" ||
		typeof token.expires_in !== "number" ||
		token.expires_in < 60
	)
		throw new Error("discovery_credentials_rejected");
	return token.access_token;
}

export async function discoverMicrosoftResources(
	context: CloudDiscoveryContext,
): Promise<DiscoveryResource[]> {
	const config = context.config;
	if (config.provider !== "azure" && config.provider !== "intune")
		throw new Error("discovery_provider_config_invalid");
	const audience =
		config.provider === "azure" ? "https://management.azure.com" : "https://graph.microsoft.com";
	const token = await microsoftToken(context, audience);
	const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
	const resources: DiscoveryResource[] = [];
	const observedAt = new Date(context.now()).toISOString();
	if (config.provider === "intune") {
		// Direct reads keep the API request inside the explicitly authorized device IDs.
		for (const deviceId of [...new Set(config.deviceIds.map((id) => id.toLowerCase()))]) {
			const device = await context.http.json(
				`https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/${deviceId}?$select=id,operatingSystem`,
				{ headers },
			);
			if (typeof device.id !== "string" || device.id.toLowerCase() !== deviceId)
				throw new Error("discovery_resource_scope_mismatch");
			appendDiscoveryResource(resources, {
				id: deviceId,
				type: "mdm.managed_device",
				scope: `intune:${config.directoryTenantId.toLowerCase()}`,
				observedAt,
			});
		}
		return resources;
	}
	const subscriptions = config.subscriptionIds.map((id) => id.toLowerCase());
	const groups = config.resourceGroups.map((group) => group.toLowerCase());
	const query = `Resources | where resourceGroup in~ (${groups.map((group) => `'${group}'`).join(",")}) | project id, type, location, subscriptionId, resourceGroup | order by id asc`;
	let pageToken: string | undefined;
	let totalRecords: number | undefined;
	const seen = new Set<string>();
	do {
		const page = await context.http.json(
			"https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01",
			{
				method: "POST",
				headers,
				body: JSON.stringify({
					subscriptions,
					query,
					options: {
						resultFormat: "objectArray",
						$top: 100,
						...(pageToken ? { $skipToken: pageToken } : {}),
					},
				}),
			},
		);
		if (
			!Array.isArray(page.data) ||
			!Number.isSafeInteger(page.count) ||
			page.count !== page.data.length ||
			!Number.isSafeInteger(page.totalRecords) ||
			(page.totalRecords as number) < page.data.length ||
			(page.totalRecords as number) > 1000 ||
			(page.resultTruncated !== "true" && page.resultTruncated !== "false")
		)
			throw new Error("discovery_response_invalid");
		if (totalRecords !== undefined && totalRecords !== page.totalRecords)
			throw new Error("discovery_response_incomplete");
		totalRecords = page.totalRecords as number;
		for (const value of page.data) {
			if (!value || typeof value !== "object" || Array.isArray(value))
				throw new Error("discovery_response_invalid");
			const row = value as Record<string, unknown>;
			if (
				typeof row.id !== "string" ||
				typeof row.type !== "string" ||
				typeof row.subscriptionId !== "string" ||
				typeof row.resourceGroup !== "string" ||
				typeof row.location !== "string"
			)
				throw new Error("discovery_response_invalid");
			const subscription = row.subscriptionId.toLowerCase();
			const group = row.resourceGroup.toLowerCase();
			const prefix = `/subscriptions/${subscription}/resourcegroups/${group}/providers/`;
			if (
				!subscriptions.includes(subscription) ||
				!groups.includes(group) ||
				!row.id.toLowerCase().startsWith(prefix) ||
				!/^[a-zA-Z0-9.]+\/[a-zA-Z0-9./]+$/.test(row.type) ||
				row.location.length > 64 ||
				!/^[a-zA-Z0-9_-]*$/.test(row.location)
			)
				throw new Error("discovery_resource_scope_mismatch");
			appendDiscoveryResource(resources, {
				id: row.id.toLowerCase(),
				type: row.type.toLowerCase(),
				scope: `azure:${subscription}:${group}`,
				...(row.location ? { region: row.location } : {}),
				observedAt,
			});
		}
		pageToken = discoveryPageToken(page.$skipToken, seen);
		if (page.resultTruncated === "true" && !pageToken)
			throw new Error("discovery_response_incomplete");
	} while (pageToken);
	if (resources.length !== totalRecords) throw new Error("discovery_response_incomplete");
	return resources;
}
