import { lstat, realpath } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, isAbsolute, join, parse, relative, sep } from "node:path";
import { evaluateInfrastructurePolicy } from "./aig-policy.js";
import { isCommercialBuild } from "./build-flavor.js";

import { resolvePath } from "./config.js";
import { getFileContent } from "./file-utils.js";
import { matchPackageIntel } from "./intel/api.js";
import { loadMergedIntelFromDisk } from "./intel/loader.js";
import {
	isPremiumModuleEnabled,
	loadRevocationsCache,
	type ManagedState,
	revocationBindingForState,
} from "./managed.js";
import { inspectMcpServerInventory } from "./mcp-inventory.js";
import {
	legacyMcpToolSelector,
	matchesMcpToolSelector,
	mcpToolSelector,
} from "./mcp-tool-identity.js";
import { isPrivateIpAddress } from "./mcp-transport.js";
import {
	extractPackagesFromCommand,
	extractPackagesFromManifest,
	isPackageManagerCommand,
} from "./package-extractor.js";
import { readFileEditPayload } from "./tool-normalization.js";
import type { Artifact, Config, Verdict } from "./types.js";

async function resolvePathPart(current: string, part: string): Promise<string | null> {
	const next = join(current, part);
	try {
		return await realpath(next);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") return null;
		try {
			if ((await lstat(next)).isSymbolicLink()) return null;
		} catch (statError) {
			if ((statError as NodeJS.ErrnoException).code !== "ENOENT") return null;
		}
		return next;
	}
}

/**
 * Resolve a path the way the filesystem will, following existing symlinks. A
 * symlink whose target is missing, or any unexpected filesystem error, returns
 * null so callers treat the path as outside every scope.
 */
export async function resolvePolicyPath(path: string): Promise<string | null> {
	const input = process.platform === "win32" ? path.replace(/\//g, "\\") : path;
	const absolute = isAbsolute(input) ? input : `${process.cwd()}${sep}${input}`;
	const root = parse(absolute).root;
	if (!root) return null;

	let current = root;
	for (const part of absolute.slice(root.length).split(sep)) {
		if (!part || part === ".") continue;
		if (part === "..") {
			current = dirname(current);
			continue;
		}

		const resolved = await resolvePathPart(current, part);
		if (!resolved) return null;
		current = resolved;
	}
	return current;
}

async function isUnderRoot(candidatePath: string, root: string): Promise<boolean> {
	const [candidate, resolvedRoot] = await Promise.all([
		resolvePolicyPath(candidatePath),
		resolvePolicyPath(root),
	]);
	if (!candidate || !resolvedRoot) return false;
	const fromRoot = relative(resolvedRoot, candidate);
	return (
		fromRoot === "" ||
		(fromRoot !== ".." && !fromRoot.startsWith(`..${sep}`) && !isAbsolute(fromRoot))
	);
}

function parseUrlHost(raw: string): { host: string; isIp: boolean } | null {
	try {
		const u = new URL(raw);
		const host = u.hostname
			.trim()
			.replace(/^\[|\]$/g, "")
			.replace(/\.+$/, "");
		if (!host) return null;
		return { host, isIp: isIP(host) !== 0 };
	} catch {
		return null;
	}
}

function isSubdomainOrExact(host: string, domain: string): boolean {
	const h = host.toLowerCase();
	const d = domain.toLowerCase().replace(/^\.+/, "").replace(/\.+$/, "");
	if (!d) return false;
	return h === d || h.endsWith(`.${d}`);
}

async function loadUrlDenylistHosts(path: string): Promise<Set<string>> {
	try {
		const raw = await getFileContent(path, "utf-8");
		const set = new Set<string>();
		for (const line of raw.split(/\r?\n/)) {
			const trimmed = line.trim();
			if (!trimmed || trimmed.startsWith("#")) continue;
			const parsed = parseUrlHost(trimmed);
			if (parsed) set.add(parsed.host.toLowerCase());
			else set.add(trimmed.toLowerCase());
		}
		return set;
	} catch {
		return new Set();
	}
}

type CachedIntel = {
	loadedAt: number;
	identity: string;
	merged: Awaited<ReturnType<typeof loadMergedIntelFromDisk>>;
};

let cachedIntel: CachedIntel | null = null;

async function getMergedIntelCached(
	config: Config,
	managedState: ManagedState,
): Promise<CachedIntel["merged"]> {
	const now = Date.now();
	const ttlMs = Math.max(0, Number(config.intel_packs?.cache_ttl_seconds ?? 60)) * 1000;

	let revocations: { pack_ids?: string[]; key_ids?: string[] } | null = null;
	const requireRevocations =
		config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0;
	try {
		if (requireRevocations) {
			const signed = await loadRevocationsCache(
				resolvePath(config.licensing.revocations_cache_path),
				config.licensing.public_keys_pem,
				revocationBindingForState(managedState),
			);
			if (signed?.payload?.revocations) {
				revocations = {
					pack_ids: signed.payload.revocations.pack_ids,
					key_ids: signed.payload.revocations.key_ids,
				};
			}
		}
	} catch {
		revocations = null;
	}
	const entitlement = managedState.entitlement;
	const identity = JSON.stringify({
		packsDir: resolvePath(config.intel_packs.packs_dir),
		trustedKeysPath: resolvePath(config.intel_packs.trusted_keys_path),
		entitlement:
			entitlement?.schema_version === 2
				? {
						tenant: entitlement.tenant_id,
						serial: entitlement.serial,
						expiresAt: entitlement.expires_at,
						graceUntil: entitlement.grace_until,
						alg: managedState.entitlement_alg,
						signature: managedState.entitlement_sig,
					}
				: null,
		requireRevocations,
		revocations,
	});
	if (cachedIntel && cachedIntel.identity === identity && now - cachedIntel.loadedAt < ttlMs)
		return cachedIntel.merged;

	const merged = await loadMergedIntelFromDisk({
		packsDir: config.intel_packs?.packs_dir,
		trustedKeysPath: config.intel_packs?.trusted_keys_path,
		requireRevocations,
		revocations,
	});
	cachedIntel = { loadedAt: now, identity, merged };
	return merged;
}

function getFilePathFromToolInput(toolInput: Record<string, unknown>): string | null {
	const candidates = [toolInput.file_path, toolInput.filePath, toolInput.path] as unknown[];
	for (const c of candidates) {
		if (typeof c === "string" && c.trim()) return c.trim();
	}
	return null;
}

function getContentFromToolInput(toolInput: Record<string, unknown>): string | null {
	const candidates = [toolInput.content, toolInput.new_string, toolInput.text] as unknown[];
	for (const c of candidates) {
		if (typeof c === "string" && c.trim()) return c;
	}
	return null;
}

function makeVerdict(params: {
	decision: "ask" | "deny";
	category: string;
	severity: Verdict["severity"];
	source: string;
	artifact: string;
	threatId: string;
	reasons: string[];
	confidence: number;
}): Verdict {
	return {
		decision: params.decision,
		category: params.category,
		confidence: params.confidence,
		severity: params.severity,
		source: params.source,
		artifacts: [params.artifact],
		matchedThreatId: params.threatId,
		reasons: params.reasons,
	};
}

/**
 * Server/tool readings of an MCP call. `mcp__<server>__<tool>` is split at
 * every `__` (first split first, the historical reading); the generic `MCP`
 * tool reads `tool_input.server` / `tool_input.name`.
 */
function mcpPolicyIdentities(
	toolName: string,
	toolInput: Record<string, unknown> | undefined,
): { server: string; tool: string }[] {
	if (toolName.startsWith("mcp__")) {
		const rest = toolName.slice("mcp__".length);
		const identities: { server: string; tool: string }[] = [];
		for (let index = rest.indexOf("__"); index !== -1; index = rest.indexOf("__", index + 1)) {
			const server = rest.slice(0, index);
			const tool = rest.slice(index + 2);
			if (server && tool) identities.push({ server, tool });
		}
		return identities;
	}
	if (toolName === "MCP" && toolInput?.tool_input && typeof toolInput.tool_input === "object") {
		const ti = toolInput.tool_input as Record<string, unknown>;
		if (typeof ti.server === "string" && ti.server && typeof ti.name === "string" && ti.name) {
			return [{ server: ti.server, tool: ti.name }];
		}
	}
	return [];
}

function includesExactId(values: readonly string[], id: string): boolean {
	return values.some((value) => value.trim() === id);
}

export async function evaluatePolicy(
	toolName: string,
	artifacts: Artifact[],
	config: Config,
	toolInput?: Record<string, unknown>,
	/** Current state after the caller verifies its signature and applies revocations. */
	managedState: ManagedState = {},
): Promise<Verdict | null> {
	if (!config.policy.enabled) return null;
	const infrastructureVerdict = await evaluateInfrastructurePolicy(artifacts, config);
	if (infrastructureVerdict?.decision === "deny") return infrastructureVerdict;

	// --- Intel: legacy denylist file + signed intel packs ---
	// Back-compat: if `intel.enabled` is on, we also consider signed packs on disk.
	const packsConfigured = config.intel_packs?.enabled === true || config.intel?.enabled === true;
	const enforcePremium = isCommercialBuild() || config.mode === "managed";
	const packsEntitled = !enforcePremium || isPremiumModuleEnabled(managedState, "intel_packs");
	if (packsConfigured && !packsEntitled) cachedIntel = null;
	const merged =
		packsConfigured && packsEntitled
			? await getMergedIntelCached(config, managedState).catch(() => null)
			: null;
	const signedPacksEnabled = config.intel_packs?.enabled === true && packsEntitled;
	if (signedPacksEnabled && !merged) {
		return makeVerdict({
			decision: "ask",
			category: "detection_unavailable",
			severity: "warning",
			source: "intel",
			artifact: "intel-packs",
			threatId: "INTEL-UNAVAILABLE-001",
			reasons: ["Signed intel pack loading failed; intel coverage is unavailable"],
			confidence: 0,
		});
	}
	const mergedState = merged as (typeof merged & { availability?: string; detail?: string }) | null;
	if (signedPacksEnabled && mergedState?.availability !== "available") {
		return makeVerdict({
			decision: "ask",
			category: "detection_unavailable",
			severity: "warning",
			source: "intel",
			artifact: "intel-packs",
			threatId: "INTEL-UNAVAILABLE-001",
			reasons: [mergedState?.detail ?? "Signed intel pack coverage is unavailable"],
			confidence: 0,
		});
	}
	const denyHosts =
		config.intel?.enabled === true
			? await loadUrlDenylistHosts(resolvePath(config.intel.url_denylist_path))
			: new Set<string>();

	for (const a of artifacts) {
		if (a.type !== "url") continue;
		const parsed = parseUrlHost(a.value);
		const host = parsed?.host?.toLowerCase();
		if (!host) continue;

		// Allowlist beats denylist in intel packs (policy/network layer can still deny).
		if (merged?.urlAllowHosts.has(host)) continue;

		if ((denyHosts.size > 0 && denyHosts.has(host)) || merged?.urlDenyHosts.has(host)) {
			return makeVerdict({
				decision: "deny",
				category: "network_egress",
				severity: "critical",
				source: "intel",
				artifact: a.value,
				threatId: "INTEL-URL-001",
				reasons: ["URL denylist match"],
				confidence: 1.0,
			});
		}

		const risk = merged?.domainRisk.get(host);
		if (risk) {
			const decision = risk.action === "deny" ? "deny" : "ask";
			const sev = risk.severity === "critical" ? "critical" : "warning";
			return makeVerdict({
				decision,
				category: "network_egress",
				severity: sev,
				source: "intel",
				artifact: a.value,
				threatId: "INTEL-DOMAIN-001",
				reasons: [risk.reason ?? "Domain risk match"],
				confidence: typeof risk.confidence === "number" ? risk.confidence : 0.9,
			});
		}
	}

	// --- Intel: package denylist (edge-first, no network) ---
	if (merged) {
		for (const a of artifacts) {
			if (a.type !== "command") continue;
			for (const pkg of extractPackagesFromCommand(a.value)) {
				const hit = matchPackageIntel(merged, { name: pkg.name });
				if (!hit) continue;
				if (hit.verdict === "deny") {
					return makeVerdict({
						decision: "deny",
						category: "supply_chain",
						severity: "critical",
						source: "intel",
						artifact: pkg.name,
						threatId: "INTEL-PKG-001",
						reasons: [hit.reason],
						confidence: hit.confidence,
					});
				}
			}
		}

		// Manifest edits: package.json / requirements.txt content being written/edited.
		// (We only use toolInput here to keep file_path <-> content association correct.)
		if (toolInput && (toolName === "Write" || toolName === "Edit")) {
			const payload = toolName === "Edit" ? readFileEditPayload(toolInput) : null;
			const edits = payload?.patch
				? (payload.edits ?? [])
				: [
						{
							filePath: getFilePathFromToolInput(toolInput) ?? "",
							content: getContentFromToolInput(toolInput) ?? "",
						},
					];
			for (const { filePath, content } of edits) {
				if (!filePath || !content) continue;
				for (const pkg of extractPackagesFromManifest(filePath, content)) {
					const hit = matchPackageIntel(merged, { name: pkg.name });
					if (!hit) continue;
					if (hit.verdict === "deny") {
						return makeVerdict({
							decision: "deny",
							category: "supply_chain",
							severity: "critical",
							source: "intel",
							artifact: pkg.name,
							threatId: "INTEL-PKG-002",
							reasons: [hit.reason],
							confidence: hit.confidence,
						});
					}
				}
			}
		}
	}

	// --- Network policy ---
	if (config.policy.network.enabled) {
		const allow = config.policy.network.allow_domains ?? [];
		const deny = config.policy.network.deny_domains ?? [];

		for (const a of artifacts) {
			if (a.type !== "url") continue;
			const parsed = parseUrlHost(a.value);
			if (!parsed) continue;

			if (
				parsed.isIp &&
				config.policy.network.deny_private_ips &&
				isPrivateIpAddress(parsed.host)
			) {
				const decision = config.policy.network.deny_action === "block" ? "deny" : "ask";
				return makeVerdict({
					decision,
					category: "network_egress",
					severity: decision === "deny" ? "critical" : "warning",
					source: "policy",
					artifact: a.value,
					threatId: "POL-NET-001",
					reasons: ["Private IP egress blocked"],
					confidence: 0.95,
				});
			}

			if (deny.some((d) => isSubdomainOrExact(parsed.host, d))) {
				const decision = config.policy.network.deny_action === "block" ? "deny" : "ask";
				return makeVerdict({
					decision,
					category: "network_egress",
					severity: decision === "deny" ? "critical" : "warning",
					source: "policy",
					artifact: a.value,
					threatId: "POL-NET-002",
					reasons: ["Domain denylist match"],
					confidence: 0.95,
				});
			}

			if (allow.length > 0 && !allow.some((d) => isSubdomainOrExact(parsed.host, d))) {
				const decision = config.policy.network.outside_allow_action === "block" ? "deny" : "ask";
				return makeVerdict({
					decision,
					category: "network_egress",
					severity: decision === "deny" ? "critical" : "warning",
					source: "policy",
					artifact: a.value,
					threatId: "POL-NET-003",
					reasons: ["Domain not in allowlist"],
					confidence: 0.8,
				});
			}
		}
	}

	// --- Filesystem policy (write roots + deny patterns) ---
	if (config.policy.filesystem.enabled) {
		const isWriteLike = toolName === "Write" || toolName === "Edit" || toolName === "Delete";
		const filePaths = new Set<string>();
		const primaryPath = toolInput ? getFilePathFromToolInput(toolInput) : null;
		if (primaryPath) filePaths.add(primaryPath);
		for (const artifact of artifacts) {
			if (artifact.type === "file_path" && artifact.context === "edit" && artifact.value.trim()) {
				filePaths.add(artifact.value.trim());
			}
		}

		if (isWriteLike && filePaths.size > 0) {
			const allowedRoots = (config.policy.filesystem.allowed_write_roots ?? []).map((p) =>
				resolvePath(p),
			);

			for (const filePath of filePaths) {
				let withinAllowedRoot = false;
				for (const root of allowedRoots) {
					if (await isUnderRoot(filePath, root)) {
						withinAllowedRoot = true;
						break;
					}
				}
				if (allowedRoots.length > 0 && !withinAllowedRoot) {
					const decision =
						config.policy.filesystem.outside_root_action === "block" ? "deny" : "ask";
					return makeVerdict({
						decision,
						category: "file_write",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: filePath,
						threatId: "POL-FS-001",
						reasons: ["Write outside allowed roots"],
						confidence: 0.9,
					});
				}

				const resolvedFilePath = await resolvePolicyPath(filePath);
				for (const pattern of config.policy.filesystem.deny_write_patterns ?? []) {
					try {
						const re = new RegExp(pattern, "i");
						if (re.test(filePath) || (resolvedFilePath && re.test(resolvedFilePath))) {
							return makeVerdict({
								decision: "deny",
								category: "file_write",
								severity: "critical",
								source: "policy",
								artifact: filePath,
								threatId: "POL-FS-002",
								reasons: ["Write path denied by policy"],
								confidence: 0.95,
							});
						}
					} catch {
						return makeVerdict({
							decision: "ask",
							category: "detection_unavailable",
							severity: "warning",
							source: "policy",
							artifact: filePath,
							threatId: "POL-FS-UNAVAILABLE-001",
							reasons: ["Filesystem deny pattern is invalid and was skipped"],
							confidence: 0,
						});
					}
				}
			}
		}
	}

	// --- Shell policy (regex patterns) ---
	if (config.policy.shell.enabled && toolName === "Bash" && toolInput) {
		const command = typeof toolInput.command === "string" ? toolInput.command : "";
		if (command) {
			for (const pattern of config.policy.shell.deny_patterns ?? []) {
				try {
					const re = new RegExp(pattern, "i");
					if (re.test(command)) {
						const decision = config.policy.shell.deny_action === "block" ? "deny" : "ask";
						return makeVerdict({
							decision,
							category: "command_execution",
							severity: decision === "deny" ? "critical" : "warning",
							source: "policy",
							artifact: command.slice(0, 200),
							threatId: "POL-SH-001",
							reasons: ["Command denied by policy"],
							confidence: 0.9,
						});
					}
				} catch {
					return makeVerdict({
						decision: "ask",
						category: "detection_unavailable",
						severity: "warning",
						source: "policy",
						artifact: command.slice(0, 200),
						threatId: "POL-SH-UNAVAILABLE-001",
						reasons: ["Shell deny pattern is invalid and was skipped"],
						confidence: 0,
					});
				}
			}
		}
	}

	// --- Runtime defaults ---
	const rt = config.policy.runtime_defaults as Record<string, unknown> | undefined;
	if (rt) {
		// Package action (takes priority over command action for package-manager commands)
		const pkgAction = rt.package_action as string | undefined;
		if (pkgAction && (pkgAction === "block" || pkgAction === "require_approval")) {
			const hasCommand = artifacts.some((a) => a.type === "command");
			if (hasCommand) {
				const cmdArtifact = artifacts.find((a) => a.type === "command");
				const cmd = cmdArtifact?.value ?? "";
				const isPkgCmd = isPackageManagerCommand(cmd);
				if (isPkgCmd) {
					const decision = pkgAction === "block" ? "deny" : "ask";
					const packages = extractPackagesFromCommand(cmd);
					return makeVerdict({
						decision,
						category: "supply_chain",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: packages[0]?.name ?? cmd,
						threatId: "POL-DEFAULT-PKG-001",
						reasons: ["Package install blocked by runtime default"],
						confidence: 0.9,
					});
				}
			}
		}

		// Command action
		const cmdAction = rt.command_action as string | undefined;
		if (cmdAction && (cmdAction === "block" || cmdAction === "require_approval")) {
			if (toolName === "Bash" && artifacts.some((a) => a.type === "command")) {
				const decision = cmdAction === "block" ? "deny" : "ask";
				return makeVerdict({
					decision,
					category: "command_execution",
					severity: decision === "deny" ? "critical" : "warning",
					source: "policy",
					artifact: "...",
					threatId: "POL-DEFAULT-CMD-001",
					reasons: ["Command blocked by runtime default"],
					confidence: 0.9,
				});
			}
		}

		// File action
		const fileAction = rt.file_action as string | undefined;
		if (fileAction && (fileAction === "block" || fileAction === "require_approval")) {
			const isWriteLike = toolName === "Write" || toolName === "Edit" || toolName === "Delete";
			if (isWriteLike && artifacts.some((a) => a.type === "file_path")) {
				const decision = fileAction === "block" ? "deny" : "ask";
				const fileArtifact = artifacts.find((a) => a.type === "file_path");
				return makeVerdict({
					decision,
					category: "file_write",
					severity: decision === "deny" ? "critical" : "warning",
					source: "policy",
					artifact: fileArtifact?.value ?? "",
					threatId: "POL-DEFAULT-FILE-001",
					reasons: ["File operation blocked by runtime default"],
					confidence: 0.9,
				});
			}
		}

		// URL action
		const urlAction = rt.url_action as string | undefined;
		if (urlAction && (urlAction === "block" || urlAction === "require_approval")) {
			if (artifacts.some((a) => a.type === "url")) {
				const decision = urlAction === "block" ? "deny" : "ask";
				const urlArtifact = artifacts.find((a) => a.type === "url");
				return makeVerdict({
					decision,
					category: "network_egress",
					severity: decision === "deny" ? "critical" : "warning",
					source: "policy",
					artifact: urlArtifact?.value ?? "",
					threatId: "POL-DEFAULT-URL-001",
					reasons: ["URL blocked by runtime default"],
					confidence: 0.9,
				});
			}
		}

		// Output action
		const outAction = rt.output_action as string | undefined;
		if (outAction && (outAction === "block" || outAction === "require_approval")) {
			if (
				toolName === "PostToolUse" &&
				artifacts.some((a) => a.type === "content" && a.context === "agent_output")
			) {
				const decision = outAction === "block" ? "deny" : "ask";
				const outArtifact = artifacts.find((a) => a.type === "content");
				return makeVerdict({
					decision,
					category: "output_scan",
					severity: decision === "deny" ? "critical" : "warning",
					source: "policy",
					artifact: outArtifact?.value ?? "",
					threatId: "POL-DEFAULT-OUT-001",
					reasons: ["Output blocked by runtime default"],
					confidence: 0.9,
				});
			}
		}
	}

	// --- MCP policy ---
	if (config.policy.mcp.enabled) {
		const isMcpCall = toolName.startsWith("mcp__") || toolName === "MCP";
		const identities = mcpPolicyIdentities(toolName, toolInput);
		const mcpServerId = identities[0]?.server;
		const mcpToolName = identities[0]?.tool;
		const anyIdentity = (
			predicate: (server: string, tool: string) => boolean,
		): { server: string; tool: string } | undefined =>
			identities.find((identity) => predicate(identity.server, identity.tool));

		if (isMcpCall && (!mcpServerId || !mcpToolName)) {
			// An MCP call whose server/tool cannot be identified cannot be matched
			// against server or tool rules; treat it as an unknown server instead
			// of skipping MCP policy altogether.
			const unknownAction = config.policy.mcp.unknown_server_action ?? "require_approval";
			if (unknownAction !== "allow") {
				const blocked = unknownAction === "block";
				return makeVerdict({
					decision: blocked ? "deny" : "ask",
					category: "mcp_tool_call",
					severity: blocked ? "critical" : "warning",
					source: "policy",
					artifact: toolName,
					threatId: "POL-MCP-001",
					reasons: ["MCP server or tool could not be identified"],
					confidence: 0.9,
				});
			}
		}

		if (mcpServerId && mcpToolName) {
			const fullToolId =
				legacyMcpToolSelector(mcpServerId, mcpToolName) ??
				mcpToolSelector(mcpServerId, mcpToolName);

			// Deny and approval rules match any reading of an ambiguous
			// `mcp__a__b__c` name (server `a` or `a__b`), so a server whose
			// name contains the separator cannot slip past its own rule.
			if (anyIdentity((server, tool) => matchesMcpToolSelector(config.policy.mcp.deny_tools, server, tool))) {
				return makeVerdict({
					decision: "deny",
					category: "mcp_tool_call",
					severity: "critical",
					source: "policy",
					artifact: fullToolId,
					threatId: "POL-MCP-002",
					reasons: ["MCP tool denied by policy"],
					confidence: 0.95,
				});
			}

			if (anyIdentity((server) => includesExactId(config.policy.mcp.deny_servers, server))) {
				return makeVerdict({
					decision: "deny",
					category: "mcp_tool_call",
					severity: "critical",
					source: "policy",
					artifact: fullToolId,
					threatId: "POL-MCP-006",
					reasons: ["MCP server denied by policy"],
					confidence: 0.95,
				});
			}

			if (
				anyIdentity((server, tool) =>
					matchesMcpToolSelector(config.policy.mcp.require_approval_tools, server, tool),
				)
			) {
				return makeVerdict({
					decision: "ask",
					category: "mcp_tool_call",
					severity: "warning",
					source: "policy",
					artifact: fullToolId,
					threatId: "POL-MCP-003",
					reasons: ["MCP tool requires approval"],
					confidence: 0.9,
				});
			}

			if (
				anyIdentity((server) => includesExactId(config.policy.mcp.require_approval_servers, server))
			) {
				return makeVerdict({
					decision: "ask",
					category: "mcp_tool_call",
					severity: "warning",
					source: "policy",
					artifact: fullToolId,
					threatId: "POL-MCP-007",
					reasons: ["MCP server requires approval"],
					confidence: 0.9,
				});
			}

			const explicitlyAllowed =
				matchesMcpToolSelector(config.policy.mcp.allow_tools, mcpServerId, mcpToolName) ||
				includesExactId(config.policy.mcp.allow_servers, mcpServerId);
			let isInInventory = false;
			const riskHints = new Set<string>();
			const unreadableInventoryPaths: string[] = [];
			let conflictingInventory = false;
			let configurationSha256: string | undefined;

			const inventoryPaths = config.policy.mcp.inventory_paths ?? [];
			for (const invPath of inventoryPaths) {
				const resolved = resolvePath(invPath);
				const report = await inspectMcpServerInventory([resolved]);
				const sourceStatus = report.sources[0]?.status;
				if (sourceStatus === "missing") continue;
				if (sourceStatus !== "read") {
					unreadableInventoryPaths.push(resolved);
					continue;
				}

				if (report.coverage.status !== "read") unreadableInventoryPaths.push(resolved);
				for (const serverCfg of report.items) {
					if (serverCfg.name !== mcpServerId) continue;
					isInInventory = true;
					if (configurationSha256 && configurationSha256 !== serverCfg.configurationSha256) {
						conflictingInventory = true;
					}
					configurationSha256 = serverCfg.configurationSha256;
					for (const hint of serverCfg.riskHints) riskHints.add(hint);
				}
			}

			// An allow rule may skip policy risk checks, never missing or contradictory
			// source evidence. Tool-manifest attestation is outside this policy function.
			if (
				unreadableInventoryPaths.length > 0 ||
				conflictingInventory ||
				(explicitlyAllowed && !isInInventory)
			) {
				const reason =
					unreadableInventoryPaths.length > 0
						? `MCP inventory unreadable or incomplete: ${unreadableInventoryPaths.join(", ")}`
						: conflictingInventory
							? "MCP inventory has conflicting server declarations"
							: "MCP allow rule has no inventory evidence";
				const blocked = config.policy.mcp.unknown_server_action === "block";
				return makeVerdict({
					decision: blocked ? "deny" : "ask",
					category: "mcp_tool_call",
					severity: blocked ? "critical" : "warning",
					source: "policy",
					artifact: fullToolId,
					threatId: "POL-MCP-008",
					reasons: [reason],
					confidence: 0.9,
				});
			}

			if (explicitlyAllowed) return null;

			if (riskHints.size > 0) {
				const riskyAction = config.policy.mcp.risky_server_action ?? "block";
				if (riskyAction === "block") {
					return makeVerdict({
						decision: "deny",
						category: "mcp_tool_call",
						severity: "critical",
						source: "policy",
						artifact: fullToolId,
						threatId: "POL-MCP-001",
						reasons: [`MCP server risk indicators: ${[...riskHints].join(", ")}`],
						confidence: 0.95,
					});
				}
				if (riskyAction === "require_approval") {
					return makeVerdict({
						decision: "ask",
						category: "mcp_tool_call",
						severity: "warning",
						source: "policy",
						artifact: fullToolId,
						threatId: "POL-MCP-001",
						reasons: [`MCP server risk indicators: ${[...riskHints].join(", ")}`],
						confidence: 0.9,
					});
				}
				return null;
			}

			if (!isInInventory) {
				const unknownAction = config.policy.mcp.unknown_server_action ?? "require_approval";
				if (unknownAction === "block") {
					return makeVerdict({
						decision: "deny",
						category: "mcp_tool_call",
						severity: "critical",
						source: "policy",
						artifact: fullToolId,
						threatId: "POL-MCP-001",
						reasons: ["MCP server not in inventory"],
						confidence: 0.9,
					});
				}
				if (unknownAction === "require_approval") {
					return makeVerdict({
						decision: "ask",
						category: "mcp_tool_call",
						severity: "warning",
						source: "policy",
						artifact: fullToolId,
						threatId: "POL-MCP-001",
						reasons: ["MCP server not in inventory"],
						confidence: 0.9,
					});
				}
				// "allow" — fall through
			}

			const defaultAction = config.policy.mcp.default_action ?? "require_approval";
			if (defaultAction === "block") {
				return makeVerdict({
					decision: "deny",
					category: "mcp_tool_call",
					severity: "critical",
					source: "policy",
					artifact: fullToolId,
					threatId: "POL-MCP-005",
					reasons: ["MCP tool blocked by default policy"],
					confidence: 0.9,
				});
			}
			if (defaultAction === "require_approval") {
				return makeVerdict({
					decision: "ask",
					category: "mcp_tool_call",
					severity: "warning",
					source: "policy",
					artifact: fullToolId,
					threatId: "POL-MCP-005",
					reasons: ["MCP tool requires approval by default"],
					confidence: 0.9,
				});
			}
			// "allow" — fall through
		}
	}

	return infrastructureVerdict;
}
