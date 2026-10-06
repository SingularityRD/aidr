const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const vscode = require("vscode");

const REQUIRED_COMMANDS = [
	"aidr.enableProtection",
	"aidr.disableProtection",
	"aidr.openConfig",
	"aidr.openAuditLog",
	"aidr.showHookHealth",
];

const REQUIRED_CURSOR_EVENTS = [
	"beforeShellExecution",
	"preToolUse",
	"postToolUse",
	"afterAgentResponse",
	"beforeMCPExecution",
	"beforeReadFile",
];

const host = readRequiredEnv("AIDR_E2E_HOST");
const extensionId = readRequiredEnv("AIDR_E2E_EXTENSION_ID");
const scopeSettingKey = readRequiredEnv("AIDR_E2E_SCOPE_SETTING_KEY");
const managedMarker = readRequiredEnv("AIDR_E2E_MANAGED_MARKER");
const hookMode = readRequiredEnv("AIDR_E2E_HOOK_MODE");
const hooksRelativePath = readRequiredEnv("AIDR_E2E_HOOKS_RELATIVE_PATH");
const hookRunnerPath = readRequiredEnv("AIDR_E2E_HOOK_RUNNER_PATH");
const resultsFilePath = process.env.AIDR_E2E_RESULTS_FILE?.trim() || undefined;
const verbose = isVerbose();

const workspacePath = getWorkspacePath();
const hookConfigPath = path.join(workspacePath, hooksRelativePath);
const TEST_CASES = [
	{
		id: "configure-workspace-scope",
		name: "configure workspace scope",
		run: configureWorkspaceScope,
	},
	{
		id: "extension-activates",
		name: "extension activates",
		run: verifyExtensionActivation,
	},
	{
		id: "commands-registered",
		name: "aidr commands are registered",
		run: verifyCommandsRegistered,
	},
	{
		id: "enable-protection-writes-hooks",
		name: "enable protection writes managed hooks",
		run: verifyEnableProtection,
	},
	{
		id: "hook-health-command",
		name: "hook health command runs without error",
		run: verifyHookHealthCommand,
	},
	{
		id: "dangerous-write-blocked",
		name: "managed hook blocks dangerous write",
		run: verifyHookPipelineBlocksThreat,
	},
	{
		id: "hook-response-shape-consistent",
		name: "hook responses have consistent shape across event types",
		run: verifyHookResponseShapeAcrossEvents,
	},
	{
		id: "disable-protection-removes-hooks",
		name: "disable protection removes managed hooks",
		run: verifyDisableProtection,
	},
];

async function run() {
	const failures = [];
	const results = [];
	try {
		for (const testCase of TEST_CASES) {
			await runCase(testCase, failures, results);
		}
	} finally {
		// Write the outcome before cleaning up. Cleanup can fail - on Windows a
		// file watcher or antivirus holding a handle makes `rmSync` throw
		// ENOTEMPTY - and when it ran first, that failure destroyed every result the
		// run had just produced: the host reported a crash instead of 8/8, so a
		// green suite looked like a broken one. A cleanup problem is worth
		// reporting, but it must never be the reason the evidence disappears.
		writeResults(results);
		cleanupWorkspaceArtifacts();
	}

	if (failures.length > 0) {
		throw new Error(
			`Extension host E2E failed (${failures.length} case(s)):\n\n${failures.join("\n\n")}`,
		);
	}
}

module.exports = { run };

async function runCase(testCase, failures, results) {
	const startedAt = Date.now();
	try {
		await testCase.run();
		results.push({
			id: testCase.id,
			name: testCase.name,
			status: "pass",
			durationMs: Date.now() - startedAt,
		});
		if (verbose) {
			console.log(`[aidr-e2e] PASS: ${testCase.name}`);
		}
	} catch (error) {
		const details = formatError(error);
		results.push({
			id: testCase.id,
			name: testCase.name,
			status: "fail",
			error: details,
			durationMs: Date.now() - startedAt,
		});
		console.error(`[aidr-e2e] FAIL: ${testCase.name}\n${details}`);
		failures.push(`${testCase.name}\n${details}`);
	}
}

async function configureWorkspaceScope() {
	cleanupWorkspaceArtifacts();
	await vscode.workspace
		.getConfiguration()
		.update(scopeSettingKey, "workspace", vscode.ConfigurationTarget.Workspace);
	await vscode.workspace
		.getConfiguration()
		.update("aidr.hookRunnerPath", hookRunnerPath, vscode.ConfigurationTarget.Global);
}

async function verifyExtensionActivation() {
	const extension = vscode.extensions.getExtension(extensionId);
	assert.ok(extension, `Expected extension "${extensionId}" to be loaded`);
	await extension.activate();
	assert.equal(extension.isActive, true, `Expected extension "${extensionId}" to be active`);
}

async function verifyCommandsRegistered() {
	const commands = await vscode.commands.getCommands(true);
	for (const commandId of REQUIRED_COMMANDS) {
		assert.ok(commands.includes(commandId), `Expected command "${commandId}" to be registered`);
	}
}

async function verifyEnableProtection() {
	await vscode.commands.executeCommand("aidr.enableProtection");
	assert.ok(fs.existsSync(hookConfigPath), `Expected hook config at ${hookConfigPath}`);

	const config = readJsonFile(hookConfigPath);
	if (host === "cursor") {
		verifyCursorManagedHooks(config);
	} else {
		verifyVsCodeManagedHooks(config);
	}

	const managedCommands = collectManagedCommands(config);
	assert.ok(managedCommands.length > 0, "Expected at least one managed hook command");
	assert.ok(
		managedCommands.some(
			(command) => command.includes(` ${hookMode} `) || command.endsWith(` ${hookMode}`),
		),
		`Expected managed command to invoke mode "${hookMode}"`,
	);
}

async function verifyHookHealthCommand() {
	await vscode.commands.executeCommand("aidr.showHookHealth");
}

async function verifyHookPipelineBlocksThreat() {
	assert.ok(fs.existsSync(hookRunnerPath), `Expected hook runner at ${hookRunnerPath}`);

	const payload =
		hookMode === "cursor"
			? {
					hook_event_name: "preToolUse",
					tool_name: "Write",
					tool_input: {
						file_path: "/home/user/.ssh/authorized_keys",
						content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
					},
				}
			: {
					tool_name: "Write",
					tool_input: {
						file_path: "/home/user/.ssh/authorized_keys",
						content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
					},
				};

	const response = runHook(payload);
	if (hookMode === "cursor") {
		assert.equal(response.decision, "deny", "Expected Cursor hook decision=deny");
		assert.equal(response.permission, "deny", "Expected Cursor hook permission=deny");
		assert.ok(
			typeof response.reason === "string",
			"Expected Cursor deny response to include reason",
		);
		return;
	}

	const hookSpecificOutput = asObject(response.hookSpecificOutput);
	const decision = hookSpecificOutput.permissionDecision;
	assert.ok(
		decision === "deny" || decision === "ask",
		`Expected VS Code hook decision deny|ask, got "${String(decision)}"`,
	);
}

async function verifyHookResponseShapeAcrossEvents() {
	if (hookMode !== "cursor") {
		return;
	}

	assert.ok(fs.existsSync(hookRunnerPath), `Expected hook runner at ${hookRunnerPath}`);

	const payloads = [
		{
			event: "preToolUse",
			payload: {
				hook_event_name: "preToolUse",
				tool_name: "Write",
				tool_input: {
					file_path: "/tmp/notes.txt",
					content: "just some notes",
				},
			},
		},
		{
			event: "beforeShellExecution",
			payload: {
				hook_event_name: "beforeShellExecution",
				command: "echo hello",
				cwd: "/tmp",
			},
		},
		{
			event: "beforeReadFile",
			payload: {
				hook_event_name: "beforeReadFile",
				file_path: "/tmp/notes.txt",
				content: "",
				attachments: [],
			},
		},
		{
			event: "beforeMCPExecution",
			payload: {
				hook_event_name: "beforeMCPExecution",
				tool_name: "MCP",
				tool_input: { query: "repo metadata" },
			},
		},
	];

	for (const { event, payload } of payloads) {
		const response = runHook(payload);

		assert.ok(
			"decision" in response,
			`${event}: response missing "decision" field (got keys: ${Object.keys(response).join(", ")})`,
		);
		assert.ok(
			"permission" in response,
			`${event}: response missing "permission" field (got keys: ${Object.keys(response).join(", ")})`,
		);
		assert.equal(
			response.decision,
			response.permission,
			`${event}: "decision" (${String(response.decision)}) and "permission" (${String(response.permission)}) must match`,
		);
	}
}

async function verifyDisableProtection() {
	await vscode.commands.executeCommand("aidr.disableProtection");
	if (!fs.existsSync(hookConfigPath)) {
		return;
	}

	const config = readJsonFile(hookConfigPath);
	const managedCommands = collectManagedCommands(config);
	assert.equal(managedCommands.length, 0, "Expected no managed hook commands after disable");
}

function verifyCursorManagedHooks(config) {
	const hooks = asObject(config.hooks);
	for (const eventName of REQUIRED_CURSOR_EVENTS) {
		const entries = Array.isArray(hooks[eventName]) ? hooks[eventName] : [];
		const managedEntry = entries.find(
			(entry) =>
				entry &&
				typeof entry === "object" &&
				typeof entry.command === "string" &&
				entry.command.includes(managedMarker),
		);
		assert.ok(managedEntry, `Expected managed Cursor hook for event "${eventName}"`);
		assert.equal(managedEntry.failClosed, true, `Managed Cursor hook "${eventName}" must fail closed`);
		assert.equal(managedEntry.timeout, 30, `Managed Cursor hook "${eventName}" must have a bounded timeout`);

		if (eventName === "preToolUse" && managedEntry) {
			assert.equal(managedEntry.matcher, undefined, "Managed preToolUse must cover every tool without a matcher filter");
		}
	}
}

function verifyVsCodeManagedHooks(config) {
	const hooks = asObject(config.hooks);
	for (const eventName of ["PreToolUse", "PostToolUse"]) {
		const eventHooks = Array.isArray(hooks[eventName]) ? hooks[eventName] : [];
		assert.ok(eventHooks.length > 0, `Expected ${eventName} entries in VS Code settings hooks`);

		const hasManagedCommand = eventHooks.some((matcherEntry) => {
			const hooksArray =
				matcherEntry && typeof matcherEntry === "object" ? matcherEntry.hooks : undefined;
			if (!Array.isArray(hooksArray)) {
				return false;
			}
			return hooksArray.some(
				(hookEntry) =>
					hookEntry &&
					typeof hookEntry === "object" &&
					typeof hookEntry.command === "string" &&
					hookEntry.command.includes(managedMarker),
			);
		});
		assert.ok(hasManagedCommand, `Expected managed command hook in VS Code ${eventName} entries`);
	}
}

function collectManagedCommands(config) {
	const hooks = asObject(config.hooks);
	return host === "cursor"
		? collectCursorManagedCommands(hooks)
		: collectVsCodeManagedCommands(hooks);
}

function isManagedCommand(entry) {
	return (
		entry &&
		typeof entry === "object" &&
		typeof entry.command === "string" &&
		entry.command.includes(managedMarker)
	);
}

function collectCursorManagedCommands(hooks) {
	return Object.values(hooks)
		.filter(Array.isArray)
		.flatMap((entries) => entries.filter(isManagedCommand).map((entry) => entry.command));
}

function collectVsCodeManagedCommands(hooks) {
	const commands = [];
	for (const eventHooks of Object.values(hooks)) {
		if (!Array.isArray(eventHooks)) continue;
		for (const matcherEntry of eventHooks) {
			if (!matcherEntry || typeof matcherEntry !== "object" || !Array.isArray(matcherEntry.hooks)) {
				continue;
			}
			commands.push(
				...matcherEntry.hooks.filter(isManagedCommand).map((hookEntry) => hookEntry.command),
			);
		}
	}
	return commands;
}

function runHook(payload) {
	const nodePath = process.env.VSCODE_NODE_EXEC_PATH || process.execPath;
	const options = {
		encoding: "utf8",
		input: `${JSON.stringify(payload)}`,
		env: {
			...process.env,
			ELECTRON_RUN_AS_NODE: "1",
		},
	};
	const stdout = execFileSync(nodePath, [hookRunnerPath, hookMode], options);
	return parseHookStdout(stdout);
}

function parseHookStdout(stdout) {
	if (!stdout.trim()) {
		return {};
	}
	return JSON.parse(stdout.trim());
}

function readJsonFile(filePath) {
	return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function getWorkspacePath() {
	const folder = vscode.workspace.workspaceFolders?.[0];
	assert.ok(folder, "Expected a workspace folder for extension E2E");
	return folder.uri.fsPath;
}

function cleanupWorkspaceArtifacts() {
	for (const relativePath of [".cursor", ".claude", ".vscode"]) {
		// Retry: on Windows a host process or file watcher can still hold a handle on
		// a file inside the directory for a moment after the host stops, which makes
		// a recursive delete throw ENOTEMPTY. It is transient, and leaving test
		// artifacts behind in the workspace is harmless compared with failing a run.
		try {
			fs.rmSync(path.join(workspacePath, relativePath), {
				recursive: true,
				force: true,
				maxRetries: 10,
				retryDelay: 100,
			});
		} catch {
			// Best effort: the next run recreates whatever it needs.
		}
	}
}

function asObject(value) {
	return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function readRequiredEnv(name) {
	const value = process.env[name]?.trim();
	if (!value) {
		throw new Error(`Missing required env var: ${name}`);
	}
	return value;
}

function formatError(error) {
	if (error instanceof Error) {
		return error.stack || error.message;
	}
	return String(error);
}

function writeResults(results) {
	if (!resultsFilePath) {
		return;
	}

	try {
		fs.writeFileSync(
			resultsFilePath,
			`${JSON.stringify(
				{
					host,
					generatedAt: new Date().toISOString(),
					cases: results,
				},
				null,
				2,
			)}\n`,
			"utf8",
		);
	} catch (error) {
		if (verbose) {
			console.error(`[aidr-e2e] Failed to write case results: ${formatError(error)}`);
		}
	}
}

function isVerbose() {
	const value = process.env.AIDR_E2E_VERBOSE?.trim().toLowerCase();
	return value === "1" || value === "true" || value === "yes" || value === "on";
}
