import { isIP } from "node:net";

import { resolvePath } from "./config.js";
import { getFileContent } from "./file-utils.js";
import { matchPackageIntel } from "./intel/api.js";
import { loadMergedIntelFromDisk } from "./intel/loader.js";
import { loadRevocationsCache } from "./managed.js";
import { extractPackagesFromCommand, extractPackagesFromManifest } from "./package-extractor.js";
import type { Artifact, Config, Verdict } from "./types.js";

function normalizePathForCompare(p: string): string {
	const normalized = p.replace(/\\/g, "/");
	return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function isUnderRoot(candidatePath: string, root: string): boolean {
	const c = normalizePathForCompare(candidatePath);
	let r = normalizePathForCompare(root);
	if (!r.endsWith("/")) r += "/";
	return c === r.slice(0, -1) || c.startsWith(r);
}

function parseUrlHost(raw: string): { host: string; isIp: boolean } | null {
	try {
		const u = new URL(raw);
		const host = u.hostname.trim();
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

function isPrivateIp(host: string): boolean {
	// Minimal IPv4 private range checks; only enforce for literal IP hosts.
	const parts = host.split(".").map((n) => Number.parseInt(n, 10));
	if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) return false;
	const [a, b] = parts;
	if (a === 10) return true;
	if (a === 127) return true;
	if (a === 192 && b === 168) return true;
	if (a === 172 && b !== undefined && b >= 16 && b <= 31) return true;
	return false;
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
	merged: Awaited<ReturnType<typeof loadMergedIntelFromDisk>>;
};

let cachedIntel: CachedIntel | null = null;

async function getMergedIntelCached(config: Config): Promise<CachedIntel["merged"]> {
	const now = Date.now();
	const ttlMs = Math.max(0, Number(config.intel_packs?.cache_ttl_seconds ?? 60)) * 1000;
	if (cachedIntel && now - cachedIntel.loadedAt < ttlMs) return cachedIntel.merged;

	let revocations: { pack_ids?: string[]; key_ids?: string[] } | null = null;
	try {
		if (config.licensing.revocations_enabled && config.licensing.public_keys_pem.length > 0) {
			const signed = await loadRevocationsCache(
				resolvePath(config.licensing.revocations_cache_path),
				config.licensing.public_keys_pem,
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

	const merged = await loadMergedIntelFromDisk({
		packsDir: config.intel_packs?.packs_dir,
		trustedKeysPath: config.intel_packs?.trusted_keys_path,
		revocations,
	});
	cachedIntel = { loadedAt: now, merged };
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

export async function evaluatePolicy(
	toolName: string,
	artifacts: Artifact[],
	config: Config,
	toolInput?: Record<string, unknown>,
): Promise<Verdict | null> {
	if (!config.policy.enabled) return null;

	// --- Intel: legacy denylist file + signed intel packs ---
	// Back-compat: if `intel.enabled` is on, we also consider signed packs on disk.
	const packsEnabled = config.intel_packs?.enabled === true || config.intel?.enabled === true;
	const merged = packsEnabled ? await getMergedIntelCached(config).catch(() => null) : null;
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
			const filePath = getFilePathFromToolInput(toolInput);
			const content = getContentFromToolInput(toolInput);
			if (filePath && content) {
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

			if (parsed.isIp && config.policy.network.deny_private_ips && isPrivateIp(parsed.host)) {
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
		const filePath = toolInput ? getFilePathFromToolInput(toolInput) : null;

		if (isWriteLike && filePath) {
			const allowedRoots = (config.policy.filesystem.allowed_write_roots ?? []).map((p) =>
				resolvePath(p),
			);

			if (allowedRoots.length > 0 && !allowedRoots.some((root) => isUnderRoot(filePath, root))) {
				const decision = config.policy.filesystem.outside_root_action === "block" ? "deny" : "ask";
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

			for (const pattern of config.policy.filesystem.deny_write_patterns ?? []) {
				try {
					const re = new RegExp(pattern, "i");
					if (re.test(filePath)) {
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
					// Ignore invalid patterns.
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
					// Ignore invalid patterns.
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
				const isPkgCmd =
					/\b(?:npm|yarn|pnpm|pip|pip3|gem|brew|apt|apk|choco|scoop|cargo|go\s+install|nuget)\b/i.test(
						cmd,
					);
				if (isPkgCmd) {
					const decision = pkgAction === "block" ? "deny" : "ask";
					const packages = extractPackagesFromCommand(cmd);
					return makeVerdict({
						decision,
						category: "supply_chain",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: packages.length > 0 ? packages[0]!.name : cmd,
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
			const isWriteLike = toolName === "Write" || toolName === "Edit";
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
					reasons: ["File write blocked by runtime default"],
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
		let mcpServerId: string | undefined;
		let mcpToolName: string | undefined;

		if (toolName.startsWith("mcp__")) {
			const parts = toolName.split("__");
			mcpServerId = parts[1];
			mcpToolName = parts.slice(2).join("__");
		} else if (toolName === "MCP" && toolInput?.tool_input) {
			const ti = toolInput.tool_input as Record<string, unknown>;
			mcpServerId = typeof ti.server === "string" ? ti.server : undefined;
			mcpToolName = typeof ti.name === "string" ? ti.name : undefined;
		}

		if (mcpServerId && mcpToolName) {
			const fullToolId = `${mcpServerId}.${mcpToolName}`;

			if (config.policy.mcp.deny_tools.includes(fullToolId)) {
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

			if (config.policy.mcp.require_approval_tools.includes(fullToolId)) {
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

			// If server is explicitly allowed, skip remaining risk checks
			if (config.policy.mcp.allow_servers.includes(mcpServerId)) {
				return null;
			}

			let isInInventory = false;
			let isRiskyServer = false;

			const inventoryPaths = config.policy.mcp.inventory_paths ?? [];
			for (const invPath of inventoryPaths) {
				try {
					const resolved = resolvePath(invPath);
					const content = await getFileContent(resolved, "utf-8").catch(() => null);
					if (!content) continue;

					const parsed = JSON.parse(content) as {
						mcpServers?: Record<string, { command?: string; args?: string[] }>;
					};
					const servers = parsed.mcpServers ?? {};
					const serverCfg = servers[mcpServerId];

					if (serverCfg) {
						isInInventory = true;
						const cmd = (serverCfg.command ?? "").toLowerCase();
						if (
							cmd === "bash" ||
							cmd === "sh" ||
							cmd === "zsh" ||
							cmd === "npx" ||
							cmd === "npx--yes"
						) {
							isRiskyServer = true;
						}
					}
				} catch {
					// Ignore invalid inventory files
				}
			}

			if (isRiskyServer) {
				return makeVerdict({
					decision: "deny",
					category: "mcp_tool_call",
					severity: "critical",
					source: "policy",
					artifact: fullToolId,
					threatId: "POL-MCP-001",
					reasons: ["MCP server uses shell_wrapper_command"],
					confidence: 0.95,
				});
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

	return null;
}
