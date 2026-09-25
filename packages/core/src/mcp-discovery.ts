import { createHash } from "node:crypto";
import { resolve } from "node:path";
import {
	type McpAttestationStateStore,
	type McpAttestationStateV1,
	type McpManifestRejectionReason,
	mcpApprovalBindingHash,
	type SignedMcpToolManifestV1,
	verifySignedMcpToolManifest,
} from "./mcp-attestation.js";
import { inspectMcpServerInventory, type McpInventoryItem } from "./mcp-inventory.js";
import { redactMcpLaunch } from "./mcp-launch-redaction.js";

function inventoryId(sourcePath: string, name: string, projectPath?: string): string {
	const resolvedPath = resolve(sourcePath);
	const canonicalPath = process.platform === "win32" ? resolvedPath.toLowerCase() : resolvedPath;
	// A project-scoped server shares its file and possibly its name with other
	// scopes, so the project is part of its identity. Top-level servers keep
	// their original two-part id.
	const identity =
		projectPath === undefined ? [canonicalPath, name] : [canonicalPath, name, projectPath];
	return createHash("sha256")
		.update("aidr-mcp-inventory-v1\0")
		.update(JSON.stringify(identity))
		.digest("hex");
}

/** Local binding of a discovered server to a publisher-signed tool manifest. */
export type McpSignedManifestIndex =
	| ReadonlyMap<string, SignedMcpToolManifestV1>
	| Readonly<Record<string, SignedMcpToolManifestV1>>;

export interface McpDiscoveryAttestationOptions {
	/** Tenant identity that owns this local inventory and approval state. */
	tenantId?: string;
	/**
	 * Tenant keyring: trusted MCP publisher key ids mapped to Ed25519 public keys.
	 * Trusted-publisher provisioning and signer key custody are external to this
	 * module; when the keyring is absent the report says so and no server can be
	 * reported as verified from it.
	 */
	keyring?: ReadonlyMap<string, string> | Readonly<Record<string, string>>;
	/** Signer key ids the tenant has revoked. */
	revokedKeyIds?: ReadonlySet<string> | readonly string[];
	/**
	 * Signed manifests bound to discovered servers, keyed by inventory id or by the
	 * configured server name. A manifest is untrusted input: it is only ever
	 * reported as verified after it passes the shared verification path against the
	 * tenant keyring.
	 */
	manifests?: McpSignedManifestIndex;
	/** Tenant attestation state, where operator approvals and quarantines are recorded. */
	store?: McpAttestationStateStore;
	/** Verification time; defaults to the wall clock. */
	now?: Date;
}

export interface McpDiscoveryOptions {
	/** Tool-manifest attestation inputs; absent means nothing can be verified. */
	attestation?: McpDiscoveryAttestationOptions;
	/**
	 * Attach the server's command line with credentials redacted
	 * (`redactMcpLaunch`). Off by default: the discovery report and posture
	 * uploads never carry arguments; local exports such as the AI-BOM opt in.
	 */
	includeRedactedLaunch?: boolean;
}

export type McpDiscoveryAttestationStatus =
	| "approved"
	| "unapproved"
	| "quarantined"
	| "unsigned"
	| "unverifiable"
	| "rejected";

/**
 * Per-server tool-manifest evidence. `keyring` and `approval_state` are stated
 * explicitly so an absent keyring or an unreadable approval record is never
 * presented as a trust result.
 */
export interface McpDiscoveryAttestation {
	status: McpDiscoveryAttestationStatus;
	/** "configured" only when a tenant keyring was supplied; never a caller boolean. */
	keyring: "configured" | "absent";
	/** Whether recorded operator approval state was consulted and readable. */
	approval_state: "available" | "unavailable";
	/** Signer key id from the candidate manifest. */
	key_id?: string;
	/** Server identity carried inside the signed manifest. */
	server_id?: string;
	/** SHA-256 of the verified toolset, when a signature verified. */
	toolset_hash?: string;
	/** Toolset hash currently held in quarantine for this server. */
	quarantined_toolset_hash?: string;
	/** Machine-readable explanation for any status other than "approved". */
	reason?: string;
}

export interface McpDiscoveryServer {
	inventory_id: string;
	name: string;
	source: string;
	/** Claude Code project the server is scoped to (`~/.claude.json` `projects`); absent otherwise. */
	project?: string;
	transport: "remote" | "stdio";
	endpoint: string | null;
	risk_hints: string[];
	configuration_sha256: string;
	attestation: McpDiscoveryAttestation;
	/** Redacted command line; present only with `includeRedactedLaunch`. */
	launch?: { command: string | null; args: string[] };
}

function keyringIsConfigured(
	keyring: McpDiscoveryAttestationOptions["keyring"],
): keyring is NonNullable<McpDiscoveryAttestationOptions["keyring"]> {
	if (!keyring) return false;
	if ("size" in keyring && typeof keyring.size === "number") return keyring.size > 0;
	return Object.keys(keyring).length > 0;
}

function manifestFor(
	index: McpSignedManifestIndex | undefined,
	key: string,
): SignedMcpToolManifestV1 | undefined {
	if (!index) return undefined;
	if (index instanceof Map) return index.get(key);
	if (!Object.hasOwn(index, key)) return undefined;
	return (index as Readonly<Record<string, SignedMcpToolManifestV1>>)[key];
}

const UNVERIFIABLE_REASONS: Partial<Record<McpManifestRejectionReason, string>> = {
	untrusted_signer: "unknown_signer",
	invalid_public_key: "invalid_public_key",
};

/**
 * Verify one discovered server's signed manifest against the tenant keyring and
 * report the recorded approval state.
 *
 * Every branch is positive evidence or its explicit absence: a missing keyring,
 * a missing manifest, an unknown signer and a failed signature are all distinct
 * from "approved", and an approval can only come from the persisted attestation
 * state keyed by the signed server id.
 */
async function attestDiscoveredServer(
	item: McpInventoryItem,
	id: string,
	options: McpDiscoveryAttestationOptions,
): Promise<McpDiscoveryAttestation> {
	if (!keyringIsConfigured(options.keyring)) {
		return {
			status: "unverifiable",
			keyring: "absent",
			approval_state: "unavailable",
			reason: "no_keyring",
		};
	}
	const signed = manifestFor(options.manifests, id) ?? manifestFor(options.manifests, item.name);
	if (!signed) {
		return {
			status: "unsigned",
			keyring: "configured",
			approval_state: "unavailable",
			reason: "no_signed_manifest",
		};
	}

	const verified = verifySignedMcpToolManifest(signed, {
		trustedSigners: options.keyring,
		expectedServerId: item.name,
		...(options.revokedKeyIds ? { revokedKeyIds: new Set(options.revokedKeyIds) } : {}),
		...(options.now ? { now: options.now } : {}),
	});
	if (!verified.valid) {
		const unverifiableReason = UNVERIFIABLE_REASONS[verified.reason];
		return {
			status: unverifiableReason ? "unverifiable" : "rejected",
			keyring: "configured",
			approval_state: "unavailable",
			key_id: signed.key_id,
			server_id: signed.manifest.server_id,
			reason: unverifiableReason ?? verified.reason,
		};
	}

	const verifiedEvidence = {
		keyring: "configured" as const,
		key_id: verified.signed.key_id,
		server_id: verified.signed.manifest.server_id,
		toolset_hash: verified.toolsetHash,
	};
	const store = options.store;
	if (!store?.read) {
		return {
			...verifiedEvidence,
			status: "unapproved",
			approval_state: "unavailable",
			reason: "approval_state_unavailable",
		};
	}
	if (!options.tenantId) {
		return {
			...verifiedEvidence,
			status: "unverifiable",
			approval_state: "unavailable",
			reason: "tenant_binding_unavailable",
		};
	}
	const bindingSha256 = mcpApprovalBindingHash({
		serverId: verified.signed.manifest.server_id,
		keyId: verified.signed.key_id,
		signerKeySha256: verified.signerKeySha256,
		connection: ["discovery-v1", options.tenantId, id, item.configurationSha256],
	});

	let state: McpAttestationStateV1 | null;
	try {
		// Read-only: generating a report must not advance replay state or create a
		// quarantine for a server that has not been used.
		state = await store.read(verified.signed.manifest.server_id);
	} catch {
		return {
			...verifiedEvidence,
			status: "unverifiable",
			approval_state: "unavailable",
			reason: "state_unavailable",
		};
	}
	if (!state) {
		return {
			...verifiedEvidence,
			status: "unapproved",
			approval_state: "available",
			reason: "not_approved",
		};
	}
	if (verified.signed.manifest.sequence < state.highestSequence) {
		return {
			...verifiedEvidence,
			status: "rejected",
			approval_state: "available",
			reason: "sequence_replay",
		};
	}
	if (
		verified.signed.manifest.sequence === state.highestSequence &&
		verified.manifestHash !== state.highestManifestHash
	) {
		return {
			...verifiedEvidence,
			status: "rejected",
			approval_state: "available",
			reason: "sequence_conflict",
		};
	}
	if (verified.signed.manifest.sequence > state.highestSequence) {
		return {
			...verifiedEvidence,
			status: "unapproved",
			approval_state: "available",
			reason: "manifest_not_observed",
		};
	}
	if (state.quarantine) {
		return {
			...verifiedEvidence,
			status: "quarantined",
			approval_state: "available",
			quarantined_toolset_hash: state.quarantine.toolsetHash,
			reason: "quarantined_pending_operator_approval",
		};
	}
	const approved = state.approvedToolsets.some(
		(entry) =>
			state.activeToolsetHash === verified.toolsetHash &&
			entry.toolsetHash === verified.toolsetHash &&
			entry.keyId === verified.signed.key_id &&
			entry.signerKeySha256 === verified.signerKeySha256 &&
			entry.bindingSha256 === bindingSha256,
	);
	if (approved) {
		return { ...verifiedEvidence, status: "approved", approval_state: "available" };
	}
	return {
		...verifiedEvidence,
		status: "unapproved",
		approval_state: "available",
		reason: "not_approved",
	};
}

/**
 * Public inventory never exports server arguments, credentials, headers or URL
 * queries. Each entry now carries tool-manifest attestation evidence derived
 * from the tenant keyring and the persisted approval state, so a discovered
 * server is not reported as an unqualified inventory row.
 */
export async function discoverMcpServers(paths?: string[], options: McpDiscoveryOptions = {}) {
	const report = await inspectMcpServerInventory(paths);
	const attestationOptions = options.attestation ?? {};
	const servers = await Promise.all(
		report.items.map(async (item) => {
			let endpoint: string | null = null;
			try {
				if (item.url) endpoint = new URL(item.url).origin;
			} catch {
				/* Invalid URLs remain unverified. */
			}
			const id = inventoryId(item.sourcePath, item.name, item.projectPath);
			return {
				inventory_id: id,
				name: item.name,
				source: item.sourcePath,
				...(item.projectPath !== undefined ? { project: item.projectPath } : {}),
				transport: item.url ? ("remote" as const) : ("stdio" as const),
				endpoint,
				risk_hints: item.riskHints,
				configuration_sha256: item.configurationSha256,
				attestation: await attestDiscoveredServer(item, id, attestationOptions),
				...(options.includeRedactedLaunch
					? { launch: redactMcpLaunch(item.command, item.args) }
					: {}),
			};
		}),
	);
	return {
		schema_version: 1,
		scanned_at: new Date().toISOString(),
		scope:
			"Local JSON/JSONC MCP configurations; not cloud-wide discovery. Tool-manifest attestation reflects only the operator-supplied tenant keyring, the supplied signed manifests and the recorded approval state; absence of a keyring is reported as unverifiable.",
		sources: report.sources,
		// Coverage is published next to `servers` so an unreadable configuration
		// is reported as a gap instead of as an empty (but complete) inventory.
		coverage: {
			status: report.coverage.status,
			total_sources: report.coverage.totalSources,
			read_sources: report.coverage.readSources,
			missing_sources: report.coverage.missingSources,
			invalid_sources: report.coverage.invalidSources,
			servers_not_enumerated: report.coverage.serversNotEnumerated,
			sources_not_enumerated: report.coverage.sourcesNotEnumerated,
		},
		servers,
	};
}
