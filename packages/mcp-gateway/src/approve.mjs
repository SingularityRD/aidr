#!/usr/bin/env node
import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { reportFailure, stage } from "./diagnostics.mjs";
import { approveQuarantinedToolset } from "./operator-approval.mjs";
import { openVerifiedGateway } from "./operator-startup.mjs";

/**
 * aidr-mcp-approve: the out-of-band operator approval command.
 *
 * Every approval is signed with the operator approval key, an Ed25519 private
 * key kept in a passphrase-encrypted PKCS#8 file. The gateway only holds the
 * matching public key (`approvalKeys` in its configuration), so a process that
 * can write the gateway state directory - including an agent running as the
 * same user as a stdio bridge - cannot create an approval the gateway honours.
 * The passphrase is read from the terminal (no echo) or, when stdin is not a
 * terminal, from the first line of stdin; never from arguments or environment.
 */

const USAGE = `usage: aidr-mcp-approve --generate-key <keyFile> <approvalKeyId>
       aidr-mcp-approve --key <keyFile> [--expires-in-days <1-366>] <config.json> <tenantId> <serverId> <toolsetHash> <bindingSha256> <operatorId> <reason>
`;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const MIN_PASSPHRASE = 12;
const DAY_MS = 24 * 60 * 60 * 1000;

function usage() {
	process.stderr.write(USAGE);
	process.exitCode = 2;
}

/** Apply terminal keystrokes to a line: "done", "cancel" or the updated text. */
function applyKeystrokes(value, text) {
	let line = value;
	for (const char of text) {
		if (char === "\r" || char === "\n") return { line, status: "done" };
		if (char === "\u0003") return { line, status: "cancel" };
		line = char === "\u007f" || char === "\b" ? line.slice(0, -1) : line + char;
	}
	return { line, status: "more" };
}

/** Read one line from a non-echoing terminal prompt or from piped stdin. */
async function readSecretLine(prompt) {
	const input = process.stdin;
	if (!input.isTTY) {
		let text = "";
		for await (const chunk of input) {
			text += chunk.toString("utf8");
			if (text.includes("\n")) break;
		}
		return text.split(/\r?\n/, 1)[0];
	}
	process.stderr.write(prompt);
	input.setRawMode(true);
	input.resume();
	return new Promise((resolve, reject) => {
		let value = "";
		const onData = (data) => {
			const { line, status } = applyKeystrokes(value, data.toString("utf8"));
			value = line;
			if (status === "more") return;
			input.setRawMode(false);
			input.pause();
			input.off("data", onData);
			process.stderr.write("\n");
			if (status === "cancel") reject(new Error("approval cancelled"));
			else resolve(value);
		};
		input.on("data", onData);
	});
}

async function readPassphrase(confirm) {
	const passphrase = await readSecretLine("Operator approval key passphrase: ");
	if (confirm && process.stdin.isTTY) {
		const again = await readSecretLine("Repeat passphrase: ");
		if (again !== passphrase) throw new Error("approval passphrase mismatch");
	}
	return passphrase;
}

async function generateKey(keyFile, keyId) {
	if (!ID.test(keyId)) throw new Error("invalid approval key id");
	const passphrase = await readPassphrase(true);
	if (typeof passphrase !== "string" || passphrase.length < MIN_PASSPHRASE)
		throw new Error("approval passphrase too short");
	const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase },
	});
	// Exclusive create: never overwrite an existing operator key.
	await writeFile(keyFile, privateKey, { flag: "wx", mode: 0o600 });
	process.stdout.write(`${JSON.stringify({ approvalKeys: { [keyId]: publicKey } }, null, 2)}\n`);
}

/** Load the encrypted operator key and find its id in the gateway configuration. */
async function loadApprovalKey(keyFile, approvalKeys) {
	const info = await stat(keyFile);
	if (process.platform !== "win32" && (info.mode & 0o077) !== 0)
		throw new Error("approval key permissions too open");
	const pem = await readFile(keyFile, "utf8");
	// An unencrypted key loads without a passphrase; the operator key must not.
	let loadsWithoutPassphrase = false;
	try {
		createPrivateKey({ key: pem, format: "pem" });
		loadsWithoutPassphrase = true;
	} catch {
		loadsWithoutPassphrase = false;
	}
	if (loadsWithoutPassphrase) throw new Error("approval key not encrypted");
	const passphrase = await readPassphrase(false);
	let privateKey;
	try {
		privateKey = createPrivateKey({ key: pem, format: "pem", passphrase });
	} catch {
		throw new Error("approval key passphrase rejected");
	}
	if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("approval key not configured");
	const publicPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
	const keyId = Object.keys(approvalKeys).find((id) => approvalKeys[id] === publicPem);
	if (!keyId) throw new Error("approval key not configured");
	return { keyId, privateKey };
}

function parseApproveArgs(args) {
	let keyFile;
	let expiresInDays = 90;
	const rest = [...args];
	while (rest[0]?.startsWith("--")) {
		const flag = rest.shift();
		const value = rest.shift();
		if (flag === "--key" && value) keyFile = value;
		else if (flag === "--expires-in-days" && /^\d{1,3}$/.test(value ?? "")) {
			expiresInDays = Number(value);
			if (expiresInDays < 1 || expiresInDays > 366) return null;
		} else return null;
	}
	const [configPath, tenantId, serverId, toolsetHash, bindingSha256, approvedBy, ...reasonParts] =
		rest;
	if (
		!keyFile ||
		!configPath ||
		!tenantId ||
		!serverId ||
		!toolsetHash ||
		!bindingSha256 ||
		!approvedBy ||
		reasonParts.length === 0
	)
		return null;
	return {
		keyFile,
		expiresInDays,
		configPath,
		tenantId,
		serverId,
		toolsetHash,
		bindingSha256,
		approvedBy,
		reason: reasonParts.join(" "),
	};
}

async function approve(options) {
	const gateway = await openVerifiedGateway(options.configPath);
	const approvalKey = await stage("approval_key_unavailable", () =>
		loadApprovalKey(options.keyFile, gateway.config.approvalKeys),
	);
	const result = await stage("approval_failed", async () => {
		const approval = await approveQuarantinedToolset(gateway, {
			tenantId: options.tenantId,
			serverId: options.serverId,
			toolsetHash: options.toolsetHash,
			bindingSha256: options.bindingSha256,
			approvedBy: options.approvedBy,
			reason: options.reason,
			approvalKey,
			lifetimeMs: options.expiresInDays * DAY_MS,
		});
		if (!approval.approved) throw new Error("approval rejected");
		return approval;
	});
	process.stdout.write(`Approved MCP toolset ${result.toolsetHash}\n`);
}

const args = process.argv.slice(2);
if (args[0] === "--generate-key") {
	if (args.length !== 3) usage();
	else {
		try {
			await stage("approval_key_generation_failed", () => generateKey(args[1], args[2]));
		} catch (error) {
			process.exitCode = reportFailure("AIDR MCP approval key generation", error);
		}
	}
} else {
	const options = parseApproveArgs(args);
	if (!options) usage();
	else {
		try {
			await approve(options);
		} catch (error) {
			process.exitCode = reportFailure("AIDR MCP toolset approval", error);
		}
	}
}
