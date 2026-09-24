import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

const execFile = promisify(execFileCallback);

export async function sha512Integrity(file) {
	const hash = createHash("sha512");
	for await (const chunk of createReadStream(file)) hash.update(chunk);
	return `sha512-${hash.digest("base64")}`;
}

export async function queryNpmIntegrity(name, version, registry) {
	try {
		const { stdout } = await execFile(
			"npm",
			["view", `${name}@${version}`, "dist.integrity", "--json", "--registry", registry],
			{ encoding: "utf8", maxBuffer: 1024 * 1024 },
		);
		const integrity = JSON.parse(stdout);
		if (typeof integrity !== "string" || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(integrity)) {
			throw new Error(`registry returned an invalid sha512 integrity value for ${name}@${version}`);
		}
		return integrity;
	} catch (error) {
		const diagnostic = `${error?.stdout ?? ""}\n${error?.stderr ?? ""}`;
		if (/\bE404\b|404 Not Found/i.test(diagnostic)) return null;
		throw new Error(`Could not inspect ${name}@${version}: ${error.message}`, { cause: error });
	}
}

export async function planNpmPublication(candidates, { version, registry, viewIntegrity = queryNpmIntegrity }) {
	const missing = [];
	for (const candidate of candidates) {
		const expectedIntegrity = await sha512Integrity(candidate.file);
		const publishedIntegrity = await viewIntegrity(candidate.name, version, registry);
		if (publishedIntegrity === null) {
			missing.push(candidate);
			continue;
		}
		if (publishedIntegrity !== expectedIntegrity) {
			throw new Error(
				`Registry integrity mismatch for ${candidate.name}@${version}: expected ${expectedIntegrity}, received ${publishedIntegrity}`,
			);
		}
	}
	return missing;
}

function parseArguments(argv) {
	const options = { candidates: [] };
	for (let index = 0; index < argv.length; index += 1) {
		const option = argv[index];
		const value = argv[index + 1];
		if (!value) throw new Error(`Missing value for ${option}`);
		if (option === "--version") options.version = value;
		else if (option === "--registry") options.registry = value;
		else if (option === "--candidate") {
			const separator = value.indexOf("=");
			if (separator < 1 || separator === value.length - 1) throw new Error(`Invalid candidate ${value}`);
			options.candidates.push({ name: value.slice(0, separator), file: value.slice(separator + 1) });
		} else throw new Error(`Unknown option ${option}`);
		index += 1;
	}
	if (!/^\d+\.\d+\.\d+$/.test(options.version ?? "")) throw new Error("--version must be x.y.z");
	if (!options.registry || options.candidates.length === 0) throw new Error("--registry and at least one --candidate are required");
	return options;
}

async function main() {
	const options = parseArguments(process.argv.slice(2));
	const missing = await planNpmPublication(options.candidates, options);
	for (const candidate of options.candidates) {
		if (!missing.includes(candidate)) console.error(`Already published and verified: ${candidate.name}@${options.version}`);
	}
	for (const candidate of missing) process.stdout.write(`${candidate.file}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	main().catch((error) => {
		console.error(error.message);
		process.exitCode = 1;
	});
}
