import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { discoverAwsResources } from "../discovery-aws.js";
import { parseCloudDiscoveryConfig } from "../discovery-cloud-config.js";
import { type CloudDiscoveryContext, DiscoveryHttpClient } from "../discovery-cloud-http.js";

const ACCOUNT = "123456789012";
const REGION = "eu-west-1";
const INSTANCE = `arn:aws:ec2:${REGION}:${ACCOUNT}:instance/i-fixture`;
const NOW = Date.UTC(2026, 9, 6, 12, 30, 45);
const SECRETS: Record<string, string> = {
	AWS_DISCOVERY_ID: "AKIAIOSFODNN7EXAMPLE",
	AWS_DISCOVERY_SECRET: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	AWS_DISCOVERY_TOKEN: "fixture-session-token",
};

function identity(account = ACCOUNT): string {
	return `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::${account}:user/fixture</Arn><UserId>AIDAFIXTURE</UserId><Account>${account}</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>fixture-request</RequestId></ResponseMetadata></GetCallerIdentityResponse>`;
}
function mapping(arn = INSTANCE) {
	return {
		ResourceARN: arn,
		Tags: [{ Key: "fixture-sensitive-tag", Value: "must-not-be-persisted" }],
	};
}
function fixture(
	pages: unknown[] = [{ ResourceTagMappingList: [mapping()] }],
	options: {
		identityXml?: string;
		config?: Record<string, unknown>;
		secrets?: Record<string, string>;
	} = {},
) {
	const request = vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
		if (new URL(String(url)).hostname.startsWith("sts."))
			return new Response(options.identityXml ?? identity());
		return Response.json(pages.shift() ?? { ResourceTagMappingList: [] });
	});
	const config = parseCloudDiscoveryConfig({
		schemaVersion: 1,
		provider: "aws",
		tenantId: "tenant-fixture",
		accountId: ACCOUNT,
		regions: [REGION],
		resourceTypes: ["ec2:instance"],
		credentials: {
			accessKeyId: { env: "AWS_DISCOVERY_ID" },
			secretAccessKey: { env: "AWS_DISCOVERY_SECRET" },
		},
		...options.config,
	});
	const context: CloudDiscoveryContext = {
		config,
		http: new DiscoveryHttpClient(
			[
				`sts.${REGION}.amazonaws.com`,
				`tagging.${REGION}.amazonaws.com`,
				"sts.us-east-1.amazonaws.com",
				"tagging.us-east-1.amazonaws.com",
			],
			{ fetch: request },
		),
		secret: (reference) => {
			if (!("env" in reference)) throw new Error("fixture-secret-missing");
			const value = (options.secrets ?? SECRETS)[reference.env];
			if (!value) throw new Error("fixture-private-secret-failure");
			return value;
		},
		now: () => NOW,
	};
	return { context, request };
}

describe("AWS scoped management discovery", () => {
	it("verifies account before the read and returns ARN identity without tag contents", async () => {
		const { context, request } = fixture();
		const resources = await discoverAwsResources(context);
		expect(resources).toEqual([
			{
				id: INSTANCE,
				type: "ec2:instance",
				scope: `aws:${ACCOUNT}:${REGION}`,
				region: REGION,
				observedAt: new Date(NOW).toISOString(),
			},
		]);
		expect(JSON.stringify(resources)).not.toContain("fixture-sensitive-tag");
		expect(JSON.stringify(resources)).not.toContain("must-not-be-persisted");
		expect(request.mock.calls.map(([url]) => String(url))).toEqual([
			`https://sts.${REGION}.amazonaws.com/`,
			`https://tagging.${REGION}.amazonaws.com/`,
		]);
		const sts = request.mock.calls[0]?.[1];
		expect(sts?.body).toBe("Action=GetCallerIdentity&Version=2011-06-15");
		const headers = sts?.headers as Record<string, string>;
		expect(headers["x-amz-date"]).toBe("20261006T123045Z");
		expect(headers.authorization).toMatch(
			/^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/20261006\/eu-west-1\/sts\/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[a-f0-9]{64}$/,
		);
		// Fixed request vector independently calculated with the AWS SigV4 algorithm.
		expect(headers.authorization).toContain(
			"Signature=a4dd168c47743d232bfb32be941e80afb075972ce5f4c3c9d775a26cb1df8677",
		);
		const tagging = request.mock.calls[1]?.[1];
		expect(JSON.parse(String(tagging?.body))).toEqual({
			ResourceTypeFilters: ["ec2:instance"],
			ResourcesPerPage: 100,
		});
		expect((tagging?.headers as Record<string, string>)["x-amz-target"]).toBe(
			"ResourceGroupsTaggingAPI_20170126.GetResources",
		);
	});

	it("binds STS and tagging signatures to each configured region", async () => {
		const { context, request } = fixture(
			[{ ResourceTagMappingList: [] }, { ResourceTagMappingList: [] }],
			{ config: { regions: [REGION, "us-east-1"] } },
		);
		expect(await discoverAwsResources(context)).toEqual([]);
		expect(request).toHaveBeenCalledTimes(4);
		expect((request.mock.calls[2]?.[1]?.headers as Record<string, string>).authorization).toContain(
			"/us-east-1/sts/aws4_request",
		);
	});

	it("requires exact credential-account identity before reading any resources", async () => {
		const { context, request } = fixture(undefined, { identityXml: identity("999999999999") });
		await expect(discoverAwsResources(context)).rejects.toThrow("discovery_scope_mismatch");
		expect(request).toHaveBeenCalledOnce();
	});

	it.each([
		"<ErrorResponse><Account>123456789012</Account></ErrorResponse>",
		identity().replace(
			"<Account>123456789012</Account>",
			"<Account>123456789012</Account><Account>123456789012</Account>",
		),
		identity().replace("<Account>123456789012</Account>", "<Account>&account;</Account>"),
		identity().replace("</GetCallerIdentityResponse>", ""),
	])("rejects malformed or ambiguous STS responses", async (xml) => {
		const { context, request } = fixture(undefined, { identityXml: xml });
		await expect(discoverAwsResources(context)).rejects.toThrow("discovery_response_invalid");
		expect(request).toHaveBeenCalledOnce();
	});

	it("signs explicit temporary session credentials", async () => {
		const { context, request } = fixture(undefined, {
			config: {
				credentials: {
					accessKeyId: { env: "AWS_DISCOVERY_ID" },
					secretAccessKey: { env: "AWS_DISCOVERY_SECRET" },
					sessionToken: { env: "AWS_DISCOVERY_TOKEN" },
				},
			},
		});
		await discoverAwsResources(context);
		for (const [, init] of request.mock.calls) {
			const headers = init?.headers as Record<string, string>;
			expect(headers["x-amz-security-token"]).toBe("fixture-session-token");
			expect(headers.authorization).toContain("x-amz-security-token");
		}
	});

	it.each([
		{},
		{ ...SECRETS, AWS_DISCOVERY_ID: "ASIAIOSFODNN7EXAMPLE" },
		{ ...SECRETS, AWS_DISCOVERY_ID: "bad\r\nheader" },
	])("masks credential failures and never reads ambient credentials", async (secrets) => {
		const { context, request } = fixture(undefined, { secrets });
		await expect(discoverAwsResources(context)).rejects.toThrow(
			"discovery_credentials_unavailable",
		);
		expect(request).not.toHaveBeenCalled();
	});

	it.each([
		`arn:aws:ec2:${REGION}:999999999999:instance/i-fixture`,
		`arn:aws:ec2:us-east-1:${ACCOUNT}:instance/i-fixture`,
		`arn:aws:ec2:${REGION}:${ACCOUNT}:volume/vol-fixture`,
		`arn:aws-cn:ec2:${REGION}:${ACCOUNT}:instance/i-fixture`,
		"arn:aws:s3:::global-bucket",
		"https://metadata.example/resource",
	])("rejects foreign or unprovable resource scope", async (arn) => {
		const { context } = fixture([{ ResourceTagMappingList: [mapping(arn)] }]);
		await expect(discoverAwsResources(context)).rejects.toThrow("discovery_scope_mismatch");
	});

	it("supports service-only filters and colon resource prefixes", async () => {
		const arn = `arn:aws:lambda:${REGION}:${ACCOUNT}:function:fixture`;
		const { context } = fixture([{ ResourceTagMappingList: [mapping(arn)] }], {
			config: { resourceTypes: ["lambda"] },
		});
		expect(await discoverAwsResources(context)).toEqual([
			expect.objectContaining({ id: arn, type: "lambda:function" }),
		]);
	});

	it("follows bounded pagination including a covered empty tagged scope", async () => {
		const { context, request } = fixture([
			{ ResourceTagMappingList: [], PaginationToken: "next-page" },
			{ ResourceTagMappingList: [mapping()] },
		]);
		expect(await discoverAwsResources(context)).toHaveLength(1);
		expect(JSON.parse(String(request.mock.calls[2]?.[1]?.body))).toMatchObject({
			PaginationToken: "next-page",
		});
		expect(await discoverAwsResources(fixture([{ ResourceTagMappingList: [] }]).context)).toEqual(
			[],
		);
	});

	it("rejects pagination and resource replays", async () => {
		const tokenReplay = fixture([
			{ ResourceTagMappingList: [], PaginationToken: "same" },
			{ ResourceTagMappingList: [], PaginationToken: "same" },
		]);
		await expect(discoverAwsResources(tokenReplay.context)).rejects.toThrow(
			"discovery_pagination_invalid",
		);
		const resourceReplay = fixture([
			{ ResourceTagMappingList: [mapping()], PaginationToken: "next" },
			{ ResourceTagMappingList: [mapping()] },
		]);
		await expect(discoverAwsResources(resourceReplay.context)).rejects.toThrow(
			"discovery_resource_replayed",
		);
	});

	it("stops an unbounded provider page stream", async () => {
		const pages = Array.from({ length: 100 }, (_, page) => ({
			ResourceTagMappingList: [],
			PaginationToken: `page-${page}`,
		}));
		const { context, request } = fixture(pages);
		await expect(discoverAwsResources(context)).rejects.toThrow("discovery_page_limit_exceeded");
		expect(request).toHaveBeenCalledTimes(101);
	});

	it("caps resource inventory across pages", async () => {
		const pages = Array.from({ length: 11 }, (_, page) => ({
			ResourceTagMappingList: Array.from({ length: 100 }, (_, resource) =>
				mapping(`arn:aws:ec2:${REGION}:${ACCOUNT}:instance/i-${page}-${resource}`),
			),
			PaginationToken: `page-${page}`,
		}));
		await expect(discoverAwsResources(fixture(pages).context)).rejects.toThrow(
			"discovery_resource_limit_exceeded",
		);
	});

	it("resolves externally rotated credential references afresh for each cycle", async () => {
		const secrets = { ...SECRETS };
		const { context, request } = fixture(undefined, { secrets });
		await discoverAwsResources(context);
		const rotatedId = `AKIA${randomBytes(8).toString("hex").toUpperCase()}`;
		secrets.AWS_DISCOVERY_ID = rotatedId;
		await discoverAwsResources(context);
		expect((request.mock.calls[2]?.[1]?.headers as Record<string, string>).authorization).toContain(
			`Credential=${rotatedId}/`,
		);
	});

	it.each([
		{ ResourceTagMappingList: null },
		{},
		{ ResourceTagMappingList: [null] },
		{ ResourceTagMappingList: [], PaginationToken: 42 },
	])("rejects malformed tagging pages", async (page) => {
		const { context } = fixture([page]);
		await expect(discoverAwsResources(context)).rejects.toThrow(
			/discovery_(response|pagination)_invalid/,
		);
	});
});
