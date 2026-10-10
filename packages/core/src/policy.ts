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
 *
 * A relative path is resolved against `workingDirectory`: the directory the
 * tool call runs in as reported by the host, which is not necessarily the
 * hook process's own cwd. It defaults to `process.cwd()` only for callers that
 * have no host context.
 */
export async function resolvePolicyPath(
	path: string,
	workingDirectory: string = process.cwd(),
): Promise<string | null> {
	const input = process.platform === "win32" ? path.replace(/\//g, "\\") : path;
	const absolute = isAbsolute(input) ? input : `${workingDirectory}${sep}${input}`;
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

async function isUnderRoot(
	candidatePath: string,
	root: string,
	workingDirectory: string,
): Promise<boolean> {
	const [candidate, resolvedRoot] = await Promise.all([
		resolvePolicyPath(candidatePath, workingDirectory),
		resolvePolicyPath(root, workingDirectory),
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
 * tool reads `tool_input.server` / `tool_input.name`. Deny and approval rules
 * match any reading; allow and inventory rules use `resolveMcpReadings`.
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

/**
 * The readings of an MCP call that allow and inventory rules are applied to.
 * Readings whose server is a configured (inventory) server win, longest server
 * name first; when none is configured, the historical first split is used, which
 * then has no inventory evidence. Never empty for a non-empty `identities`.
 */
function resolveMcpReadings(
	identities: readonly { server: string; tool: string }[],
	configuredServers: ReadonlyMap<string, unknown>,
): { server: string; tool: string }[] {
	const configured = identities
		.filter((identity) => configuredServers.has(identity.server))
		.sort((a, b) => b.server.length - a.server.length);
	return configured.length > 0 ? configured : identities.slice(0, 1);
}

/** `verdict` with `other`'s reasons appended (deduplicated). */
function withExtraReasons(verdict: Verdict, other: Verdict): Verdict {
	const reasons = [...verdict.reasons];
	for (const reason of other.reasons) if (!reasons.includes(reason)) reasons.push(reason);
	return reasons.length === verdict.reasons.length ? verdict : { ...verdict, reasons };
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
	/**
	 * The trusted working directory of the tool call (the host-reported one).
	 * Relative file targets resolve against it, never against the hook
	 * process's cwd, which can differ from where the tool actually writes.
	 */
	options: { workingDirectory?: string } = {},
): Promise<Verdict | null> {
	if (!config.policy.enabled) return null;
	const workingDirectory = options.workingDirectory ?? process.cwd();
	const infrastructureVerdict = await evaluateInfrastructurePolicy(artifacts, config);
	if (infrastructureVerdict?.decision === "deny") return infrastructureVerdict;

	// Every rule is evaluated: a deny returns at once, while an ask (or a gap
	// such as an unavailable intel pack or an invalid deny pattern) is held so
	// that a later deny rule still applies. The first held finding names the
	// outcome; later ones contribute their reasons.
	let pending: Verdict | null = null;
	const hold = (verdict: Verdict): void => {
		pending = pending ? withExtraReasons(pending, verdict) : verdict;
	};
	const decided = (verdict: Verdict): Verdict =>
		pending ? withExtraReasons(verdict, pending) : verdict;
	/** A deny to return now, or null after holding a non-deny finding. */
	const settle = (verdict: Verdict): Verdict | null => {
		if (verdict.decision === "deny") return decided(verdict);
		hold(verdict);
		return null;
	};
	const outcome = (): Verdict | null =>
		pending && infrastructureVerdict
			? withExtraReasons(pending, infrastructureVerdict)
			: (pending ?? infrastructureVerdict);

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
	const mergedState = merged as (typeof merged & { availability?: string; detail?: string }) | null;
	// Unavailable intel is a gap, never a clean result; the remaining policy
	// (and the legacy denylist) still runs.
	if (signedPacksEnabled && !merged) {
		hold(
			makeVerdict({
				decision: "ask",
				category: "detection_unavailable",
				severity: "warning",
				source: "intel",
				artifact: "intel-packs",
				threatId: "INTEL-UNAVAILABLE-001",
				reasons: ["Signed intel pack loading failed; intel coverage is unavailable"],
				confidence: 0,
			}),
		);
	} else if (signedPacksEnabled && mergedState?.availability !== "available") {
		hold(
			makeVerdict({
				decision: "ask",
				category: "detection_unavailable",
				severity: "warning",
				source: "intel",
				artifact: "intel-packs",
				threatId: "INTEL-UNAVAILABLE-001",
				reasons: [mergedState?.detail ?? "Signed intel pack coverage is unavailable"],
				confidence: 0,
			}),
		);
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
			return decided(
				makeVerdict({
					decision: "deny",
					category: "network_egress",
					severity: "critical",
					source: "intel",
					artifact: a.value,
					threatId: "INTEL-URL-001",
					reasons: ["URL denylist match"],
					confidence: 1.0,
				}),
			);
		}

		const risk = merged?.domainRisk.get(host);
		if (risk) {
			const decision = risk.action === "deny" ? "deny" : "ask";
			const sev = risk.severity === "critical" ? "critical" : "warning";
			const denied = settle(
				makeVerdict({
					decision,
					category: "network_egress",
					severity: sev,
					source: "intel",
					artifact: a.value,
					threatId: "INTEL-DOMAIN-001",
					reasons: [risk.reason ?? "Domain risk match"],
					confidence: typeof risk.confidence === "number" ? risk.confidence : 0.9,
				}),
			);
			if (denied) return denied;
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
					return decided(
						makeVerdict({
							decision: "deny",
							category: "supply_chain",
							severity: "critical",
							source: "intel",
							artifact: pkg.name,
							threatId: "INTEL-PKG-001",
							reasons: [hit.reason],
							confidence: hit.confidence,
						}),
					);
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
						return decided(
							makeVerdict({
								decision: "deny",
								category: "supply_chain",
								severity: "critical",
								source: "intel",
								artifact: pkg.name,
								threatId: "INTEL-PKG-002",
								reasons: [hit.reason],
								confidence: hit.confidence,
							}),
						);
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
				const denied = settle(
					makeVerdict({
						decision,
						category: "network_egress",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: a.value,
						threatId: "POL-NET-001",
						reasons: ["Private IP egress blocked"],
						confidence: 0.95,
					}),
				);
				if (denied) return denied;
				continue;
			}

			if (deny.some((d) => isSubdomainOrExact(parsed.host, d))) {
				const decision = config.policy.network.deny_action === "block" ? "deny" : "ask";
				const denied = settle(
					makeVerdict({
						decision,
						category: "network_egress",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: a.value,
						threatId: "POL-NET-002",
						reasons: ["Domain denylist match"],
						confidence: 0.95,
					}),
				);
				if (denied) return denied;
				continue;
			}

			if (allow.length > 0 && !allow.some((d) => isSubdomainOrExact(parsed.host, d))) {
				const decision = config.policy.network.outside_allow_action === "block" ? "deny" : "ask";
				const denied = settle(
					makeVerdict({
						decision,
						category: "network_egress",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: a.value,
						threatId: "POL-NET-003",
						reasons: ["Domain not in allowlist"],
						confidence: 0.8,
					}),
				);
				if (denied) return denied;
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
					if (await isUnderRoot(filePath, root, workingDirectory)) {
						withinAllowedRoot = true;
						break;
					}
				}
				if (allowedRoots.length > 0 && !withinAllowedRoot) {
					const decision =
						config.policy.filesystem.outside_root_action === "block" ? "deny" : "ask";
					const denied = settle(
						makeVerdict({
							decision,
							category: "file_write",
							severity: decision === "deny" ? "critical" : "warning",
							source: "policy",
							artifact: filePath,
							threatId: "POL-FS-001",
							reasons: ["Write outside allowed roots"],
							confidence: 0.9,
						}),
					);
					if (denied) return denied;
				}

				// Every deny pattern is evaluated. An invalid one is a recorded gap
				// that never hides a later valid pattern.
				const resolvedFilePath = await resolvePolicyPath(filePath, workingDirectory);
				for (const pattern of config.policy.filesystem.deny_write_patterns ?? []) {
					try {
						const re = new RegExp(pattern, "i");
						if (re.test(filePath) || (resolvedFilePath && re.test(resolvedFilePath))) {
							return decided(
								makeVerdict({
									decision: "deny",
									category: "file_write",
									severity: "critical",
									source: "policy",
									artifact: filePath,
									threatId: "POL-FS-002",
									reasons: ["Write path denied by policy"],
									confidence: 0.95,
								}),
							);
						}
					} catch {
						hold(
							makeVerdict({
								decision: "ask",
								category: "detection_unavailable",
								severity: "warning",
								source: "policy",
								artifact: filePath,
								threatId: "POL-FS-UNAVAILABLE-001",
								reasons: ["Filesystem deny pattern is invalid and was skipped"],
								confidence: 0,
							}),
						);
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
						const denied = settle(
							makeVerdict({
								decision,
								category: "command_execution",
								severity: decision === "deny" ? "critical" : "warning",
								source: "policy",
								artifact: command.slice(0, 200),
								threatId: "POL-SH-001",
								reasons: ["Command denied by policy"],
								confidence: 0.9,
							}),
						);
						if (denied) return denied;
						break;
					}
				} catch {
					// An invalid pattern is a recorded gap; the remaining patterns
					// still run, so a later valid deny pattern is not skipped.
					hold(
						makeVerdict({
							decision: "ask",
							category: "detection_unavailable",
							severity: "warning",
							source: "policy",
							artifact: command.slice(0, 200),
							threatId: "POL-SH-UNAVAILABLE-001",
							reasons: ["Shell deny pattern is invalid and was skipped"],
							confidence: 0,
						}),
					);
				}
			}
		}
	}

	// --- Runtime defaults ---
	const rt = config.policy.runtime_defaults as Record<string, unknown> | undefined;
	if (rt) {
		// Package action (takes priority over command action for package-manager commands)
		const pkgAction = rt.package_action as string | undefined;
		let packageActionApplied = false;
		if (pkgAction && (pkgAction === "block" || pkgAction === "require_approval")) {
			const hasCommand = artifacts.some((a) => a.type === "command");
			if (hasCommand) {
				const cmdArtifact = artifacts.find((a) => a.type === "command");
				const cmd = cmdArtifact?.value ?? "";
				const isPkgCmd = isPackageManagerCommand(cmd);
				if (isPkgCmd) {
					const decision = pkgAction === "block" ? "deny" : "ask";
					const packages = extractPackagesFromCommand(cmd);
					const denied = settle(
						makeVerdict({
							decision,
							category: "supply_chain",
							severity: decision === "deny" ? "critical" : "warning",
							source: "policy",
							artifact: packages[0]?.name ?? cmd,
							threatId: "POL-DEFAULT-PKG-001",
							reasons: ["Package install blocked by runtime default"],
							confidence: 0.9,
						}),
					);
					if (denied) return denied;
					packageActionApplied = true;
				}
			}
		}

		// Command action
		const cmdAction = rt.command_action as string | undefined;
		if (
			!packageActionApplied &&
			cmdAction &&
			(cmdAction === "block" || cmdAction === "require_approval")
		) {
			if (toolName === "Bash" && artifacts.some((a) => a.type === "command")) {
				const decision = cmdAction === "block" ? "deny" : "ask";
				const denied = settle(
					makeVerdict({
						decision,
						category: "command_execution",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: "...",
						threatId: "POL-DEFAULT-CMD-001",
						reasons: ["Command blocked by runtime default"],
						confidence: 0.9,
					}),
				);
				if (denied) return denied;
			}
		}

		// File action
		const fileAction = rt.file_action as string | undefined;
		if (fileAction && (fileAction === "block" || fileAction === "require_approval")) {
			const isWriteLike = toolName === "Write" || toolName === "Edit" || toolName === "Delete";
			if (isWriteLike && artifacts.some((a) => a.type === "file_path")) {
				const decision = fileAction === "block" ? "deny" : "ask";
				const fileArtifact = artifacts.find((a) => a.type === "file_path");
				const denied = settle(
					makeVerdict({
						decision,
						category: "file_write",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: fileArtifact?.value ?? "",
						threatId: "POL-DEFAULT-FILE-001",
						reasons: ["File operation blocked by runtime default"],
						confidence: 0.9,
					}),
				);
				if (denied) return denied;
			}
		}

		// URL action
		const urlAction = rt.url_action as string | undefined;
		if (urlAction && (urlAction === "block" || urlAction === "require_approval")) {
			if (artifacts.some((a) => a.type === "url")) {
				const decision = urlAction === "block" ? "deny" : "ask";
				const urlArtifact = artifacts.find((a) => a.type === "url");
				const denied = settle(
					makeVerdict({
						decision,
						category: "network_egress",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: urlArtifact?.value ?? "",
						threatId: "POL-DEFAULT-URL-001",
						reasons: ["URL blocked by runtime default"],
						confidence: 0.9,
					}),
				);
				if (denied) return denied;
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
				const denied = settle(
					makeVerdict({
						decision,
						category: "output_scan",
						severity: decision === "deny" ? "critical" : "warning",
						source: "policy",
						artifact: outArtifact?.value ?? "",
						threatId: "POL-DEFAULT-OUT-001",
						reasons: ["Output blocked by runtime default"],
						confidence: 0.9,
					}),
				);
				if (denied) return denied;
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
				const denied = settle(
					makeVerdict({
						decision: blocked ? "deny" : "ask",
						category: "mcp_tool_call",
						severity: blocked ? "critical" : "warning",
						source: "policy",
						artifact: toolName,
						threatId: "POL-MCP-001",
						reasons: ["MCP server or tool could not be identified"],
						confidence: 0.9,
					}),
				);
				if (denied) return denied;
			}
		}

		if (mcpServerId && mcpToolName) {
			const fullToolId =
				legacyMcpToolSelector(mcpServerId, mcpToolName) ??
				mcpToolSelector(mcpServerId, mcpToolName);

			// Deny and approval rules match any reading of an ambiguous
			// `mcp__a__b__c` name (server `a` or `a__b`), so a server whose
			// name contains the separator cannot slip past its own rule.
			if (
				anyIdentity((server, tool) =>
					matchesMcpToolSelector(config.policy.mcp.deny_tools, server, tool),
				)
			) {
				return decided(
					makeVerdict({
						decision: "deny",
						category: "mcp_tool_call",
						severity: "critical",
						source: "policy",
						artifact: fullToolId,
						threatId: "POL-MCP-002",
						reasons: ["MCP tool denied by policy"],
						confidence: 0.95,
					}),
				);
			}

			if (anyIdentity((server) => includesExactId(config.policy.mcp.deny_servers, server))) {
				return decided(
					makeVerdict({
						decision: "deny",
						category: "mcp_tool_call",
						severity: "critical",
						source: "policy",
						artifact: fullToolId,
						threatId: "POL-MCP-006",
						reasons: ["MCP server denied by policy"],
						confidence: 0.95,
					}),
				);
			}

			if (
				anyIdentity((server, tool) =>
					matchesMcpToolSelector(config.policy.mcp.require_approval_tools, server, tool),
				)
			) {
				const denied = settle(
					makeVerdict({
						decision: "ask",
						category: "mcp_tool_call",
						severity: "warning",
						source: "policy",
						artifact: fullToolId,
						threatId: "POL-MCP-003",
						reasons: ["MCP tool requires approval"],
						confidence: 0.9,
					}),
				);
				if (denied) return denied;
				return outcome();
			}

			if (
				anyIdentity((server) => includesExactId(config.policy.mcp.require_approval_servers, server))
			) {
				const denied = settle(
					makeVerdict({
						decision: "ask",
						category: "mcp_tool_call",
						severity: "warning",
						source: "policy",
						artifact: fullToolId,
						threatId: "POL-MCP-007",
						reasons: ["MCP server requires approval"],
						confidence: 0.9,
					}),
				);
				if (denied) return denied;
				return outcome();
			}

			// Inventory evidence is gathered once for every reading of the name, so
			// the server a `mcp__a__b__c` call resolves to is chosen from the
			// configured servers rather than from the first `__` split.
			const unreadableInventoryPaths: string[] = [];
			const inventory = new Map<string, { sha256: Set<string>; riskHints: Set<string> }>();
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
					if (!identities.some((identity) => identity.server === serverCfg.name)) continue;
					const entry = inventory.get(serverCfg.name) ?? {
						sha256: new Set<string>(),
						riskHints: new Set<string>(),
					};
					entry.sha256.add(serverCfg.configurationSha256);
					for (const hint of serverCfg.riskHints) entry.riskHints.add(hint);
					inventory.set(serverCfg.name, entry);
				}
			}

			// Readings whose server is a configured server. When several configured
			// servers fit (server `a` exposing tool `b__c` and server `a__b` exposing
			// tool `c` both produce `mcp__a__b__c`), every one of them must satisfy
			// the allow rule and contributes its risk hints: a server cannot borrow
			// another server's allow by choosing a tool name with `__` in it.
			const readings = resolveMcpReadings(identities, inventory);
			const primary = readings[0] ?? { server: mcpServerId, tool: mcpToolName };
			const resolvedToolId =
				legacyMcpToolSelector(primary.server, primary.tool) ??
				mcpToolSelector(primary.server, primary.tool);
			const isInInventory = readings.some((reading) => inventory.has(reading.server));
			const conflictingInventory = readings.some(
				(reading) => (inventory.get(reading.server)?.sha256.size ?? 0) > 1,
			);
			const riskHints = new Set<string>(
				readings.flatMap((reading) => [...(inventory.get(reading.server)?.riskHints ?? [])]),
			);
			const explicitlyAllowed = readings.every(
				(reading) =>
					matchesMcpToolSelector(config.policy.mcp.allow_tools, reading.server, reading.tool) ||
					includesExactId(config.policy.mcp.allow_servers, reading.server),
			);

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
				const denied = settle(
					makeVerdict({
						decision: blocked ? "deny" : "ask",
						category: "mcp_tool_call",
						severity: blocked ? "critical" : "warning",
						source: "policy",
						artifact: resolvedToolId,
						threatId: "POL-MCP-008",
						reasons: [reason],
						confidence: 0.9,
					}),
				);
				if (denied) return denied;
				return outcome();
			}

			if (explicitlyAllowed) return outcome();

			if (riskHints.size > 0) {
				const riskyAction = config.policy.mcp.risky_server_action ?? "block";
				if (riskyAction === "block") {
					return decided(
						makeVerdict({
							decision: "deny",
							category: "mcp_tool_call",
							severity: "critical",
							source: "policy",
							artifact: resolvedToolId,
							threatId: "POL-MCP-001",
							reasons: [`MCP server risk indicators: ${[...riskHints].join(", ")}`],
							confidence: 0.95,
						}),
					);
				}
				if (riskyAction === "require_approval") {
					const denied = settle(
						makeVerdict({
							decision: "ask",
							category: "mcp_tool_call",
							severity: "warning",
							source: "policy",
							artifact: resolvedToolId,
							threatId: "POL-MCP-001",
							reasons: [`MCP server risk indicators: ${[...riskHints].join(", ")}`],
							confidence: 0.9,
						}),
					);
					if (denied) return denied;
					return outcome();
				}
				return outcome();
			}

			if (!isInInventory) {
				const unknownAction = config.policy.mcp.unknown_server_action ?? "require_approval";
				if (unknownAction === "block") {
					return decided(
						makeVerdict({
							decision: "deny",
							category: "mcp_tool_call",
							severity: "critical",
							source: "policy",
							artifact: resolvedToolId,
							threatId: "POL-MCP-001",
							reasons: ["MCP server not in inventory"],
							confidence: 0.9,
						}),
					);
				}
				if (unknownAction === "require_approval") {
					const denied = settle(
						makeVerdict({
							decision: "ask",
							category: "mcp_tool_call",
							severity: "warning",
							source: "policy",
							artifact: resolvedToolId,
							threatId: "POL-MCP-001",
							reasons: ["MCP server not in inventory"],
							confidence: 0.9,
						}),
					);
					if (denied) return denied;
					return outcome();
				}
				// "allow" — fall through
			}

			const defaultAction = config.policy.mcp.default_action ?? "require_approval";
			if (defaultAction === "block") {
				return decided(
					makeVerdict({
						decision: "deny",
						category: "mcp_tool_call",
						severity: "critical",
						source: "policy",
						artifact: resolvedToolId,
						threatId: "POL-MCP-005",
						reasons: ["MCP tool blocked by default policy"],
						confidence: 0.9,
					}),
				);
			}
			if (defaultAction === "require_approval") {
				const denied = settle(
					makeVerdict({
						decision: "ask",
						category: "mcp_tool_call",
						severity: "warning",
						source: "policy",
						artifact: resolvedToolId,
						threatId: "POL-MCP-005",
						reasons: ["MCP tool requires approval by default"],
						confidence: 0.9,
					}),
				);
				if (denied) return denied;
				return outcome();
			}
			// "allow" — fall through
		}
	}

	return outcome();
}
