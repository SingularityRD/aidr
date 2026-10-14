/**
 * The Codex hook registrations AIDR owns, shared by the per-user installer
 * (connector-install.ts), the system-wide installer (machine-hooks.ts) and the
 * trust inspection (codex-trust.ts). A handler is AIDR's only when its command
 * names `aidr-codex-hook`; every other handler is kept as read.
 */

/** Matches the AIDR Codex hook in a handler command. */
export const CODEX_HOOK_PATTERN = /\baidr-codex-hook\b/;

/** The Codex registrations AIDR owns, in the documented form (packages/codex/README.md). */
const CODEX_HOOK_EVENTS: ReadonlyArray<{ event: string; matcher?: string }> = [
	{ event: "PreToolUse", matcher: "^(Bash|apply_patch|mcp__.+)$" },
	{ event: "UserPromptSubmit" },
	{ event: "PostToolUse", matcher: "^(Bash|mcp__.+)$" },
];

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAidrCodexHook(hook: unknown): boolean {
	return (
		isPlainObject(hook) && typeof hook.command === "string" && CODEX_HOOK_PATTERN.test(hook.command)
	);
}

/** Remove every AIDR handler from a Codex hooks object, keeping everything else. */
export function stripCodexHooks(hooks: Record<string, unknown>): {
	hooks: Record<string, unknown>;
	removed: number;
} {
	const next: Record<string, unknown> = {};
	let removed = 0;
	for (const [event, entries] of Object.entries(hooks)) {
		if (!Array.isArray(entries)) {
			next[event] = entries;
			continue;
		}
		const kept: unknown[] = [];
		for (const entry of entries) {
			if (!isPlainObject(entry) || !Array.isArray(entry.hooks)) {
				kept.push(entry);
				continue;
			}
			const remaining = entry.hooks.filter((hook) => !isAidrCodexHook(hook));
			removed += entry.hooks.length - remaining.length;
			if (remaining.length === entry.hooks.length) kept.push(entry);
			else if (remaining.length > 0) kept.push({ ...entry, hooks: remaining });
		}
		if (kept.length > 0 || entries.length === 0) next[event] = kept;
	}
	return { hooks: next, removed };
}

/** The hooks object with AIDR's three handlers (re)registered once, everything else kept. */
export function codexDesiredHooks(
	existing: Record<string, unknown>,
	command: string,
): Record<string, unknown> {
	const { hooks } = stripCodexHooks(existing);
	for (const { event, matcher } of CODEX_HOOK_EVENTS) {
		const entries = Array.isArray(hooks[event]) ? [...(hooks[event] as unknown[])] : [];
		entries.push({
			...(matcher ? { matcher } : {}),
			hooks: [{ type: "command", command, timeout: 10 }],
		});
		hooks[event] = entries;
	}
	return hooks;
}
