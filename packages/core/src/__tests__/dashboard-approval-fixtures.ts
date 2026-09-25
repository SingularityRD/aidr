/**
 * Test fixtures for managed-mode dashboard approvals: a signed entitlement that
 * publishes `approval_public_keys`, a token signer, and an in-memory fake of the
 * control plane's `approval-requests` API (usable as a `fetch` or as a real
 * loopback HTTP server for built connector bundles).
 */

import { generateKeyPairSync, type KeyObject, randomBytes, randomUUID, sign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { canonicalDetectorPolicyPayload } from "../detector-provisioning.js";

export const DASHBOARD_TEST_TENANT = "tenant-dashboard";
export const DASHBOARD_TEST_API_KEY = "aidr_test_api_key_0123456789";
export const DASHBOARD_TEST_IID = "11111111-2222-4333-8444-555555555555";
export const APPROVAL_KEY_ID = "approval-key-1";

export interface Ed25519Pair {
	privateKey: KeyObject;
	publicKey: KeyObject;
	publicKeyPem: string;
	spkiB64: string;
}

export function ed25519Pair(): Ed25519Pair {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return {
		privateKey,
		publicKey,
		publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
		spkiB64: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
	};
}

/** Canonical JSON (sorted keys), as the control plane signs it. */
export function canonical(value: unknown): string {
	return canonicalDetectorPolicyPayload(value);
}

export function signApprovalToken(payload: Record<string, unknown>, key: KeyObject): string {
	const bytes = Buffer.from(canonical(payload), "utf8");
	return `${bytes.toString("base64url")}.${sign(null, bytes, key).toString("base64url")}`;
}

export interface ManagedFixture {
	entitlementKeys: Ed25519Pair;
	approvalKeys: Ed25519Pair;
	tenantId: string;
	entitlement: Record<string, unknown>;
	/** managed.json content with an ed25519-signed entitlement. */
	managedState: Record<string, unknown>;
}

export function managedFixture(
	options: { approvalPublicKeys?: unknown[] | null; tenantId?: string } = {},
): ManagedFixture {
	const entitlementKeys = ed25519Pair();
	const approvalKeys = ed25519Pair();
	const tenantId = options.tenantId ?? DASHBOARD_TEST_TENANT;
	const now = Date.now();
	const approvalPublicKeys =
		options.approvalPublicKeys === undefined
			? [{ key_id: APPROVAL_KEY_ID, public_key_spki_b64: approvalKeys.spkiB64 }]
			: options.approvalPublicKeys;
	const entitlement: Record<string, unknown> = {
		schema_version: 2,
		tenant_id: tenantId,
		subscription_tier: "enterprise",
		included_agents: 5,
		extra_agents: 0,
		allowed_agents: 5,
		premium_modules: [],
		...(approvalPublicKeys ? { approval_public_keys: approvalPublicKeys } : {}),
		issued_at: new Date(now - 60_000).toISOString(),
		expires_at: new Date(now + 3_600_000).toISOString(),
		grace_until: new Date(now + 7_200_000).toISOString(),
		serial: "dashboard-serial-1",
		revocation_epoch: 1,
	};
	const managedState = {
		entitlement,
		entitlement_alg: "ed25519",
		entitlement_key_id: "entitlement-key-1",
		entitlement_sig: sign(
			null,
			Buffer.from(canonical(entitlement)),
			entitlementKeys.privateKey,
		).toString("base64"),
	};
	return { entitlementKeys, approvalKeys, tenantId, entitlement, managedState };
}

/** A runtime config for managed mode against `endpoint`. */
export function managedConfig(
	fixture: ManagedFixture,
	endpoint: string,
	extra: Record<string, unknown> = {},
): Record<string, unknown> {
	return {
		mode: "managed",
		auth: { api_key: DASHBOARD_TEST_API_KEY },
		control_plane: {
			enabled: true,
			endpoint,
			allow_insecure_loopback: endpoint.startsWith("http://127.0.0.1"),
			send_audit_logs: false,
			remote_policy_cache_enabled: false,
		},
		licensing: {
			public_keys_pem: [fixture.entitlementKeys.publicKeyPem],
			revocations_enabled: false,
		},
		version_check: { enabled: false },
		...extra,
	};
}

/** Write config.json, managed.json and the installation id into `<home>/.singularity-aidr`. */
export async function writeManagedHome(
	home: string,
	fixture: ManagedFixture,
	config: Record<string, unknown>,
): Promise<string> {
	const dir = join(home, ".singularity-aidr");
	await mkdir(dir, { recursive: true });
	await writeFile(join(dir, "config.json"), JSON.stringify(config));
	await writeFile(join(dir, "managed.json"), JSON.stringify(fixture.managedState));
	await writeFile(join(dir, "installation-id"), DASHBOARD_TEST_IID);
	return dir;
}

export interface FakeRequest {
	id: string;
	body: Record<string, unknown>;
	status: "pending" | "approved" | "denied" | "expired";
	token?: string;
	keyId?: string;
}

interface FakeResponse {
	status: number;
	body: Record<string, unknown>;
}

/**
 * In-memory control plane for `approval-requests`. Idempotent on
 * (tenant, iid, action_id) like the real one; tokens are signed with the
 * fixture's approval key and bound to the stored request.
 */
export class FakeControlPlane {
	readonly requests = new Map<string, FakeRequest>();
	readonly calls: Array<{ method: string; path: string }> = [];
	/** When set, every call waits this long (for timeout tests). */
	delayMs = 0;
	private server: Server | null = null;

	constructor(
		private readonly fixture: ManagedFixture,
		private readonly apiKey = DASHBOARD_TEST_API_KEY,
	) {}

	handle(method: string, path: string, auth: string | undefined, raw: string): FakeResponse {
		this.calls.push({ method, path });
		const route = /\/v1\/approval-requests(?:\/([^/?]+))?$/.exec(path.split("?")[0] ?? "");
		if (!route) return { status: 503, body: { error: "unavailable" } };
		if (auth !== `Bearer ${this.apiKey}`)
			return { status: 401, body: { error: "invalid_api_key" } };
		const id = route[1];
		if (method === "POST" && !id) {
			const body = JSON.parse(raw) as Record<string, unknown>;
			for (const request of this.requests.values()) {
				if (request.body.iid === body.iid && request.body.action_id === body.action_id) {
					return { status: 200, body: { request_id: request.id, status: request.status } };
				}
			}
			const request: FakeRequest = { id: randomUUID(), body, status: "pending" };
			this.requests.set(request.id, request);
			return { status: 201, body: { request_id: request.id, status: "pending" } };
		}
		if (method === "GET" && id) {
			const request = this.requests.get(decodeURIComponent(id));
			if (!request) return { status: 404, body: { error: "not_found" } };
			return {
				status: 200,
				body: {
					status: request.status,
					...(request.token ? { token: request.token, key_id: request.keyId } : {}),
				},
			};
		}
		return { status: 405, body: { error: "method_not_allowed" } };
	}

	/** Approve a request: sign a token bound to it (fields overridable for negative tests). */
	approve(
		requestId: string,
		overrides: Record<string, unknown> = {},
		options: { key?: KeyObject; keyId?: string } = {},
	): string {
		const request = this.requests.get(requestId);
		if (!request) throw new Error(`unknown request ${requestId}`);
		const now = Date.now();
		const payload = {
			v: 1,
			tenant_id: this.fixture.tenantId,
			iid: request.body.iid,
			action_id: request.body.action_id,
			artifact_digest: request.body.artifact_digest,
			tool: request.body.tool,
			decision: "approve",
			approver_id: "admin-user-1",
			issued_at: new Date(now - 1_000).toISOString(),
			expires_at: new Date(now + 10 * 60_000).toISOString(),
			nonce: randomBytes(18).toString("base64url"),
			...overrides,
		};
		request.status = "approved";
		request.token = signApprovalToken(payload, options.key ?? this.fixture.approvalKeys.privateKey);
		request.keyId = options.keyId ?? APPROVAL_KEY_ID;
		return request.token;
	}

	deny(requestId: string): void {
		const request = this.requests.get(requestId);
		if (request) request.status = "denied";
	}

	/** Only request id, for the single outstanding request. */
	onlyRequestId(): string {
		const ids = [...this.requests.keys()];
		if (ids.length !== 1) throw new Error(`expected one request, found ${ids.length}`);
		return ids[0] as string;
	}

	/** A `fetch` implementation served by this fake (honours the abort signal). */
	readonly fetch: typeof fetch = async (input, init) => {
		const url = new URL(typeof input === "string" ? input : input.toString());
		const headers = new Headers(init?.headers);
		const signal = init?.signal ?? undefined;
		if (this.delayMs > 0) {
			await new Promise<void>((resolve, reject) => {
				const timer = setTimeout(resolve, this.delayMs);
				signal?.addEventListener("abort", () => {
					clearTimeout(timer);
					reject(signal.reason ?? new DOMException("aborted", "AbortError"));
				});
			});
		}
		const result = this.handle(
			init?.method ?? "GET",
			url.pathname,
			headers.get("authorization") ?? undefined,
			typeof init?.body === "string" ? init.body : "",
		);
		return new Response(JSON.stringify(result.body), {
			status: result.status,
			headers: { "content-type": "application/json" },
		});
	};

	/** Serve over loopback HTTP (for built bundles); returns the base URL. */
	async listen(): Promise<string> {
		this.server = createServer((req, res) => {
			let raw = "";
			req.on("data", (chunk) => {
				raw += chunk;
			});
			req.on("end", () => {
				const result = this.handle(
					req.method ?? "GET",
					req.url ?? "/",
					req.headers.authorization,
					raw,
				);
				res.writeHead(result.status, { "content-type": "application/json" });
				res.end(JSON.stringify(result.body));
			});
		});
		await new Promise<void>((ready) => this.server?.listen(0, "127.0.0.1", ready));
		const address = this.server.address();
		if (!address || typeof address === "string") throw new Error("fake control plane did not bind");
		return `http://127.0.0.1:${address.port}`;
	}

	async close(): Promise<void> {
		const server = this.server;
		this.server = null;
		if (server) await new Promise<void>((done) => server.close(() => done()));
	}
}
