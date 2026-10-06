import { createPrivateKey, sign } from "node:crypto";
import type { CloudDiscoveryContext, DiscoveryResource } from "./discovery-cloud-http.js";
import { appendDiscoveryResource, discoveryPageToken } from "./discovery-cloud-http.js";

async function googleToken(context: CloudDiscoveryContext): Promise<string> {
	const config = context.config;
	if (config.provider !== "gcp") throw new Error("discovery_provider_config_invalid");
	const now = Math.floor(context.now() / 1000);
	const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
	const claims = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ iss: config.credentials.serviceAccountEmail, scope: "https://www.googleapis.com/auth/cloud-platform", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 })}`;
	let assertion: string;
	try {
		const key = createPrivateKey(context.secret(config.credentials.privateKey));
		if (key.asymmetricKeyType !== "rsa" || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048)
			throw new Error("discovery_credentials_rejected");
		assertion = `${claims}.${sign("RSA-SHA256", Buffer.from(claims), key).toString("base64url")}`;
	} catch {
		throw new Error("discovery_credentials_unavailable");
	}
	const token = await context.http.json("https://oauth2.googleapis.com/token", {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
			assertion,
		}).toString(),
	});
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

export async function discoverGcpResources(
	context: CloudDiscoveryContext,
): Promise<DiscoveryResource[]> {
	const config = context.config;
	if (config.provider !== "gcp") throw new Error("discovery_provider_config_invalid");
	const token = await googleToken(context);
	const resources: DiscoveryResource[] = [];
	const observedAt = new Date(context.now()).toISOString();
	for (const project of [...new Set(config.projectNumbers)]) {
		let pageToken: string | undefined;
		const seen = new Set<string>();
		do {
			const url = new URL(
				`https://cloudasset.googleapis.com/v1/projects/${project}:searchAllResources`,
			);
			url.searchParams.set("pageSize", "100");
			for (const assetType of [...new Set(config.assetTypes)])
				url.searchParams.append("assetTypes", assetType);
			url.searchParams.set("readMask", "name,assetType,project,location");
			if (pageToken) url.searchParams.set("pageToken", pageToken);
			const page = await context.http.json(url.toString(), {
				headers: { authorization: `Bearer ${token}` },
			});
			// Google omits default-valued repeated fields from an empty JSON response.
			if (page.results !== undefined && !Array.isArray(page.results))
				throw new Error("discovery_response_invalid");
			for (const value of (page.results ?? []) as unknown[]) {
				if (!value || typeof value !== "object" || Array.isArray(value))
					throw new Error("discovery_response_invalid");
				const row = value as Record<string, unknown>;
				if (
					typeof row.name !== "string" ||
					typeof row.assetType !== "string" ||
					typeof row.project !== "string" ||
					(row.location !== undefined && typeof row.location !== "string")
				)
					throw new Error("discovery_response_invalid");
				if (
					row.project !== `projects/${project}` ||
					!config.assetTypes.includes(row.assetType) ||
					!/^\/\/[a-z0-9.-]+\.googleapis\.com\/[A-Za-z0-9_./:-]+$/.test(row.name) ||
					(typeof row.location === "string" &&
						(row.location.length > 64 || !/^[a-zA-Z0-9_-]*$/.test(row.location)))
				)
					throw new Error("discovery_resource_scope_mismatch");
				appendDiscoveryResource(resources, {
					id: row.name,
					type: row.assetType,
					scope: `gcp:${project}`,
					...(row.location ? { region: row.location as string } : {}),
					observedAt,
				});
			}
			pageToken = discoveryPageToken(page.nextPageToken, seen);
		} while (pageToken);
	}
	return resources;
}
