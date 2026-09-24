/** Exact, collision-free identity for an MCP server/tool pair. */
export function mcpToolSelector(server: string, tool: string): string {
	return JSON.stringify([server, tool]);
}

/**
 * Existing `server.tool` selectors are unambiguous only when neither component
 * contains a dot. Keep those simple selectors compatible; dotted identities
 * must use the JSON tuple selector above.
 */
export function legacyMcpToolSelector(server: string, tool: string): string | null {
	return server.includes(".") || tool.includes(".") ? null : `${server}.${tool}`;
}

export function parseLegacyMcpToolSelector(
	selector: string,
): [server: string, tool: string] | null {
	const separator = selector.indexOf(".");
	if (separator <= 0 || separator !== selector.lastIndexOf(".")) return null;
	return [selector.slice(0, separator), selector.slice(separator + 1)];
}

export function matchesMcpToolSelector(
	selectors: readonly string[],
	server: string,
	tool: string,
): boolean {
	const exact = mcpToolSelector(server, tool);
	const legacy = legacyMcpToolSelector(server, tool);
	return selectors.some((selector) => {
		const value = selector.trim();
		return value === exact || (legacy !== null && value === legacy);
	});
}
