import { createHash, createHmac } from "node:crypto";
import {
	appendDiscoveryResource,
	type CloudDiscoveryContext,
	type DiscoveryResource,
	discoveryPageToken,
} from "./discovery-cloud-http.js";

interface Credentials {
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken?: string;
}

function signedRequest(
	service: "sts" | "tagging",
	region: string,
	body: string,
	credentials: Credentials,
	now: number,
): { url: string; init: RequestInit } {
	if (!Number.isFinite(now)) throw new Error("discovery_clock_invalid");
	const dateTime = new Date(now).toISOString().replace(/[:-]|\.\d{3}/g, "");
	const date = dateTime.slice(0, 8);
	const host = `${service}.${region}.amazonaws.com`;
	const headers: Record<string, string> = {
		"content-type":
			service === "sts" ? "application/x-www-form-urlencoded" : "application/x-amz-json-1.1",
		host,
		"x-amz-date": dateTime,
	};
	if (credentials.sessionToken) headers["x-amz-security-token"] = credentials.sessionToken;
	if (service === "tagging")
		headers["x-amz-target"] = "ResourceGroupsTaggingAPI_20170126.GetResources";
	const signedHeaders = Object.keys(headers).sort().join(";");
	const canonicalHeaders = Object.keys(headers)
		.sort()
		.map((key) => `${key}:${headers[key]}\n`)
		.join("");
	const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
	const canonical = ["POST", "/", "", canonicalHeaders, signedHeaders, sha256(body)].join("\n");
	const scope = `${date}/${region}/${service}/aws4_request`;
	const stringToSign = ["AWS4-HMAC-SHA256", dateTime, scope, sha256(canonical)].join("\n");
	let key: Buffer = Buffer.from(`AWS4${credentials.secretAccessKey}`);
	for (const value of [date, region, service, "aws4_request"]) {
		key = createHmac("sha256", key).update(value).digest();
	}
	const signature = createHmac("sha256", key).update(stringToSign).digest("hex");
	headers.authorization = `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
	return { url: `https://${host}/`, init: { method: "POST", headers, body } };
}

function callerAccount(xml: string): string {
	// STS has a small fixed XML response. Reject entities/declarations instead of
	// introducing a general XML parser or accepting account text from an error body.
	if (/[&]|<!/.test(xml)) throw new Error("discovery_response_invalid");
	const response = xml.match(
		/^\s*(?:<\?xml[^<>]*\?>\s*)?<GetCallerIdentityResponse(?:\s+xmlns=(["'])https:\/\/sts\.amazonaws\.com\/doc\/2011-06-15\/\1)?>\s*<GetCallerIdentityResult>([\s\S]*?)<\/GetCallerIdentityResult>\s*<ResponseMetadata>\s*<RequestId>[^<>]+<\/RequestId>\s*<\/ResponseMetadata>\s*<\/GetCallerIdentityResponse>\s*$/,
	);
	if (!response) throw new Error("discovery_response_invalid");
	const fields = new Map<string, string>();
	const remainder = response[2]?.replace(
		/<(Arn|UserId|Account)>([^<>]+)<\/\1>/g,
		(_match, name: string, value: string) => {
			if (fields.has(name)) throw new Error("discovery_response_invalid");
			fields.set(name, value);
			return "";
		},
	);
	const account = fields.get("Account");
	if (remainder?.trim() || fields.size !== 3 || !account || !/^\d{12}$/.test(account)) {
		throw new Error("discovery_response_invalid");
	}
	return account;
}

/** Management inventory of tagged/previously tagged resources in the explicit scope only. */
export async function discoverAwsResources(
	context: CloudDiscoveryContext,
): Promise<DiscoveryResource[]> {
	const config = context.config;
	if (config.provider !== "aws") throw new Error("discovery_provider_config_invalid");
	if (config.regions.some((region) => region.startsWith("cn-") || region.startsWith("us-gov-"))) {
		throw new Error("discovery_scope_unsupported");
	}
	let credentials: Credentials;
	try {
		credentials = {
			accessKeyId: context.secret(config.credentials.accessKeyId),
			secretAccessKey: context.secret(config.credentials.secretAccessKey),
			...(config.credentials.sessionToken
				? { sessionToken: context.secret(config.credentials.sessionToken) }
				: {}),
		};
		if (
			!/^[A-Z0-9]{16,128}$/.test(credentials.accessKeyId) ||
			!/^[\x21-\x7e]{1,1024}$/.test(credentials.secretAccessKey) ||
			(credentials.sessionToken !== undefined &&
				!/^[\x21-\x7e]{1,16384}$/.test(credentials.sessionToken)) ||
			(credentials.accessKeyId.startsWith("ASIA") && !credentials.sessionToken)
		) {
			throw new Error("Invalid credentials");
		}
	} catch {
		throw new Error("discovery_credentials_unavailable");
	}
	const resources: DiscoveryResource[] = [];
	const observedAt = new Date(context.now()).toISOString();
	for (const region of config.regions) {
		const identity = signedRequest(
			"sts",
			region,
			"Action=GetCallerIdentity&Version=2011-06-15",
			credentials,
			context.now(),
		);
		if (
			callerAccount(await context.http.request(identity.url, identity.init)) !== config.accountId
		) {
			throw new Error("discovery_scope_mismatch");
		}
		const seenTokens = new Set<string>();
		let token: string | undefined;
		do {
			const body = JSON.stringify({
				ResourceTypeFilters: config.resourceTypes,
				ResourcesPerPage: 100,
				...(token ? { PaginationToken: token } : {}),
			});
			const request = signedRequest("tagging", region, body, credentials, context.now());
			const page = await context.http.json(request.url, request.init);
			if (!Array.isArray(page.ResourceTagMappingList) || page.ResourceTagMappingList.length > 100) {
				throw new Error("discovery_response_invalid");
			}
			for (const entry of page.ResourceTagMappingList) {
				if (
					!entry ||
					typeof entry !== "object" ||
					Array.isArray(entry) ||
					typeof entry.ResourceARN !== "string"
				) {
					throw new Error("discovery_response_invalid");
				}
				const arn = entry.ResourceARN.match(
					/^arn:aws:([a-z0-9-]+):([a-z]{2}-[a-z]+-\d):(\d{12}):([A-Za-z0-9_-]+)[:/](.+)$/,
				);
				if (!arn || arn[2] !== region || arn[3] !== config.accountId)
					throw new Error("discovery_scope_mismatch");
				const type = `${arn[1]}:${arn[4]}`;
				if (!config.resourceTypes.includes(type) && !config.resourceTypes.includes(arn[1] ?? "")) {
					throw new Error("discovery_scope_mismatch");
				}
				appendDiscoveryResource(resources, {
					id: entry.ResourceARN,
					type,
					scope: `aws:${config.accountId}:${region}`,
					region,
					observedAt,
				});
			}
			if (typeof page.PaginationToken === "string" && page.PaginationToken.length > 2048)
				throw new Error("discovery_pagination_invalid");
			token = discoveryPageToken(page.PaginationToken, seenTokens);
		} while (token);
	}
	return resources;
}
