#!/usr/bin/env node

/**
 * Singularity AIDR MCP server for Claude Code.
 * Provides two tools:
 * - aidr_allowlist_add: Disabled; allowlist changes must be operator-controlled and out-of-band
 * - aidr_allowlist_remove: Remove a URL, command, or file path from the allowlist (ungated)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
	hashCommand,
	initSentry,
	type Logger,
	loadAllowlist,
	loadConfig,
	removeCommand,
	removeFilePath,
	removeUrl,
	saveAllowlist,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import pino from "pino";
import { z } from "zod";
import { artifactTypeLabel } from "./format.js";

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

// Initialize Sentry
initSentry({ name: "aidr-claude-code-mcp" });

declare const __AIDR_VERSION__: string;

const server = new McpServer({
	name: "aidr",
	version: __AIDR_VERSION__,
});

const ARTIFACT_TYPE = z
	.enum(["url", "command", "file_path"])
	.describe("Type of artifact: url, command, or file_path");

function textResult(text: string, isError?: boolean) {
	const result: { content: { type: "text"; text: string }[]; isError?: boolean } = {
		content: [{ type: "text" as const, text }],
	};
	if (isError) result.isError = true;
	return result;
}

server.registerTool(
	"aidr_allowlist_add",
	{
		title: "Singularity AIDR: Add to Allowlist",
		description:
			"Permanently allow a specific URL, command, or file path that was previously flagged by Singularity AIDR. " +
			"Requires the user to have recently approved this exact artifact through Singularity AIDR's security dialog.",
		inputSchema: z.object({
			type: ARTIFACT_TYPE,
			value: z.string().describe("The exact URL, command, or file path to allowlist"),
			reason: z.string().optional().describe("Why this is being allowlisted"),
		}),
	},
	async () => {
		// Approval records are intentionally agent-writable session artifacts. They
		// must never authorize a persistent security-policy mutation.
		return textResult(
			"Cannot add to allowlist from an agent-callable tool. Ask the operator to update the AIDR allowlist through the out-of-band operator/CLI flow.",
			true,
		);
	},
);

server.registerTool(
	"aidr_allowlist_remove",
	{
		title: "Singularity AIDR: Remove from Allowlist",
		description:
			"Remove a URL, command, or file path from the Singularity AIDR allowlist, restoring security checks for it.",
		inputSchema: z.object({
			type: ARTIFACT_TYPE,
			value: z
				.string()
				.describe(
					"The URL or file path to remove, or for commands: the command text or its SHA-256 hash",
				),
		}),
	},
	async ({ type, value }) => {
		try {
			const config = await loadConfig(undefined, logger);
			const allowlist = await loadAllowlist(config.allowlist, logger);

			let removed: boolean;
			if (type === "url") {
				removed = removeUrl(allowlist, value);
			} else if (type === "command") {
				// Try raw value first (may already be a hash), then hash as command text
				removed = removeCommand(allowlist, value);
				if (!removed) {
					removed = removeCommand(allowlist, hashCommand(value));
				}
			} else {
				removed = removeFilePath(allowlist, value);
			}

			const label = artifactTypeLabel(type);
			if (!removed) {
				return textResult(`${label} not found in the allowlist.`);
			}

			await saveAllowlist(allowlist, config.allowlist, logger);
			return textResult(
				`Removed ${label} from Singularity AIDR allowlist. Security checks will apply to this ${label} again.`,
			);
		} catch (e) {
			return textResult(`Failed to remove from allowlist: ${e}`, true);
		}
	},
);

async function main(): Promise<void> {
	await verifyArtifactIntegrityAndLog({
		artifactDir: __dirname,
		artifactId: "claude-code/dist",
		logger,
	});
	const transport = new StdioServerTransport();
	await server.connect(transport);
}

main().catch((e) => {
	logger.error("MCP server failed", { error: String(e) });
	process.exit(1);
});
