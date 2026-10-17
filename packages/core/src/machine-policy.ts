/**
 * Machine policy: the settings an administrator sets for every user of a
 * computer, in a place only an administrator can write.
 *
 *   Windows  HKLM\SOFTWARE\Policies\Singularity AIDR   (Group Policy, Intune, the MSI's AIDR_POLICY_* properties)
 *   Linux    /etc/singularity-aidr/managed.json         (root-owned, not group/world writable; the package hook's AIDR_POLICY_* variables)
 *   macOS    /etc/singularity-aidr/managed.json         (same file and checks; written by the fleet lifecycle manager, deploy/fleet/unix)
 *
 * Keys (the registry value names and the JSON keys are the same):
 *   control_plane_url          company control plane (`control_plane.endpoint`)
 *   enrollment_key             fleet enrollment key (`aidr_fleet_...`), exchanged on first use
 *   licensing_public_keys_pem  deployment signing keys (`licensing.public_keys_pem`)
 *   ca_file, use_os_trust_store, https_proxy, no_proxy   outbound network (`network.*`)
 *   support_contact_url, privacy_notice_url              shown to users (`organization.*`)
 *   approvals_mode             dashboard_only | host_dialog (`operator_approvals.approvals_mode`)
 *   offline_policy             keep_enforcing_local | block_after_grace (`control_plane.offline_policy`)
 *   protection_locked          editors refuse "Disable protection"; hooks ignore the local allowlist and
 *                              local exceptions, and the CLI refuses to add them (protection-lock.ts, not config)
 *
 * The machine policy wins over the user's config.json for these keys. A policy
 * that fails its checks is refused as a whole and reported (`aidr setup`,
 * logs); it is never half-applied. The `enrollment_key` is readable by every
 * local user by design: a fleet key is multi-use, seat-capped, expiring and
 * revocable, unlike a one-time enrollment code.
 */
import { spawnSync } from "node:child_process";
import { createPublicKey } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, win32 } from "node:path";
import { z } from "zod";
import { APPROVALS_MODES, OFFLINE_POLICIES } from "./types.js";

export const LINUX_MACHINE_POLICY_PATH = "/etc/singularity-aidr/managed.json";
export const WINDOWS_MACHINE_POLICY_KEY = "HKLM\\SOFTWARE\\Policies\\Singularity AIDR";

/** Fleet enrollment key format (multi-use; issued by the control plane). */
export const FLEET_ENROLLMENT_KEY_PATTERN = /^aidr_fleet_[A-Za-z0-9_-]{16,256}$/;

const MAX_POLICY_BYTES = 64 * 1024;
const MAX_URL_LENGTH = 2048;
const CACHE_TTL_MS = 60_000;

/** Registry values the policy key may hold that are not machine-policy keys. */
const OTHER_POLICY_VALUES = new Set(["MdmManaged"]);

function urlWith(protocols: string[], allowCredentials = false) {
	return z
		.string()
		.min(1)
		.max(MAX_URL_LENGTH)
		.refine(
			(value) => {
				if (/[\s\x00-\x1f\x7f]/u.test(value)) return false;
				try {
					const url = new URL(value);
					return (
						protocols.includes(url.protocol) &&
						(url.protocol === "mailto:" || !!url.hostname) &&
						(allowCredentials || (!url.username && !url.password))
					);
				} catch {
					return false;
				}
			},
			`must be a ${protocols.join(" or ")} URL`,
		);
}

const absolutePath = z
	.string()
	.min(1)
	.max(1024)
	.refine((value) => isAbsolute(value) || win32.isAbsolute(value), "must be an absolute path");

/** Normalise one Ed25519/RSA/EC SPKI public key (PEM or base64 DER) to PEM; throws when invalid. */
function publicKeyPem(value: string): string {
	// A PEM block may arrive flattened onto one line (a registry string): use its body.
	const body = value.replace(/-----(?:BEGIN|END) PUBLIC KEY-----/gu, "").replace(/\s+/gu, "");
	if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(body)) throw new Error("not base64");
	const key = createPublicKey({ key: Buffer.from(body, "base64"), format: "der", type: "spki" });
	return key.export({ type: "spki", format: "pem" }).toString();
}

const publicKeys = z
	.array(z.string().min(1).max(8192))
	.min(1)
	.max(16)
	.transform((keys, ctx) => {
		const pems: string[] = [];
		for (const key of keys) {
			try {
				pems.push(publicKeyPem(key));
			} catch {
				ctx.addIssue({ code: z.ZodIssueCode.custom, message: "is not a public key" });
				return z.NEVER;
			}
		}
		return [...new Set(pems)];
	});

const MachinePolicySchema = z
	.object({
		control_plane_url: urlWith(["https:"]),
		enrollment_key: z
			.string()
			.regex(FLEET_ENROLLMENT_KEY_PATTERN, "must be a fleet enrollment key (aidr_fleet_...)"),
		licensing_public_keys_pem: publicKeys,
		ca_file: absolutePath,
		use_os_trust_store: z.boolean(),
		https_proxy: urlWith(["http:", "https:"], true),
		no_proxy: z.string().max(4096),
		support_contact_url: urlWith(["https:", "mailto:"]),
		privacy_notice_url: urlWith(["https:"]),
		approvals_mode: z.enum(APPROVALS_MODES),
		offline_policy: z.enum(OFFLINE_POLICIES),
		protection_locked: z.boolean(),
	})
	.partial()
	.strict();

export type MachinePolicy = z.infer<typeof MachinePolicySchema>;
export const MACHINE_POLICY_KEYS = Object.keys(
	MachinePolicySchema.shape,
) as (keyof MachinePolicy)[];

export type MachinePolicyRead =
	| { state: "none" }
	| { state: "refused"; source: string; reason: string }
	| { state: "loaded"; source: string; policy: MachinePolicy };

export interface MachinePolicyDeps {
	platform?: NodeJS.Platform;
	env?: NodeJS.ProcessEnv;
	/** Linux policy file (tests); default {@link LINUX_MACHINE_POLICY_PATH}. */
	path?: string;
	/** Owner uid the file and its directory must have (tests); default 0 (root). */
	trustedOwnerUid?: number;
	stat?: (path: string) => { uid: number; mode: number; size: number; isFile(): boolean };
	readFile?: (path: string) => string;
	/** `reg query <key>` output, or null when the key does not exist (tests stub it). */
	regQueryKey?: (key: string) => string | null;
}

/** Validate a raw policy document (JSON object, or values read from the registry). */
export function parseMachinePolicy(
	raw: Record<string, unknown>,
): { ok: true; policy: MachinePolicy } | { ok: false; reason: string } {
	const document: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(raw)) {
		if (OTHER_POLICY_VALUES.has(key) || key.startsWith("$")) continue;
		// An empty value (an MSI property that was not passed) means "not set".
		if (value === "" || value === null) continue;
		document[key] = value;
	}
	const parsed = MachinePolicySchema.safeParse(document);
	if (parsed.success) return { ok: true, policy: parsed.data };
	const issue = parsed.error.issues[0];
	const where = issue?.path.join(".") || "policy";
	if (issue?.code === "unrecognized_keys") {
		return { ok: false, reason: `unknown key(s): ${issue.keys.join(", ")}` };
	}
	return { ok: false, reason: `${where} ${issue?.message ?? "is invalid"}` };
}

/** Split a registry string that lists public keys (PEM blocks, or base64 SPKI separated by space, comma, semicolon or \0). */
export function splitPublicKeyList(text: string): string[] {
	const pems = text.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g) ?? [];
	const rest = text.replace(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g, " ");
	const tokens = rest.split(/(?:\\0|[\s;,])+/u).filter(Boolean);
	return [...pems, ...tokens];
}

function registryBoolean(value: string): boolean | string {
	const text = value.trim().toLowerCase();
	if (["0x1", "1", "true", "yes"].includes(text)) return true;
	if (["0x0", "0", "false", "no"].includes(text)) return false;
	return value;
}

/** The values of `reg query <key>` output as a raw policy document. */
export function parseRegQueryOutput(output: string): Record<string, unknown> {
	const raw: Record<string, unknown> = {};
	for (const line of output.split(/\r?\n/u)) {
		const match = /^ {2,}(\S+) {2,}(REG_[A-Z_]+)(?: {2,}(.*))?$/u.exec(line);
		if (!match) continue;
		const [, name, type, value = ""] = match as unknown as [string, string, string, string?];
		raw[name] = registryValue(name, type, value.trimEnd());
	}
	return raw;
}

/** One registry value as the policy schema expects it ("" means unset). */
function registryValue(name: string, type: string, text: string): unknown {
	if (!text) return "";
	if (name === "licensing_public_keys_pem") return splitPublicKeyList(text);
	if (name === "use_os_trust_store" || name === "protection_locked") return registryBoolean(text);
	return type === "REG_MULTI_SZ" ? text.split("\\0").filter(Boolean).join(",") : text;
}

function regExecutable(env: NodeJS.ProcessEnv): string {
	return join(
		env.SystemRoot?.trim() || env.SYSTEMROOT?.trim() || "C:\\Windows",
		"System32",
		"reg.exe",
	);
}

function defaultRegQueryKey(env: NodeJS.ProcessEnv): (key: string) => string | null {
	return (key) => {
		try {
			const result = spawnSync(regExecutable(env), ["query", key], {
				encoding: "utf8",
				timeout: 5_000,
				windowsHide: true,
			});
			return result.status === 0 ? (result.stdout ?? "") : null;
		} catch {
			return null;
		}
	};
}

function readWindowsPolicy(deps: MachinePolicyDeps): MachinePolicyRead {
	const query = deps.regQueryKey ?? defaultRegQueryKey(deps.env ?? process.env);
	const output = query(WINDOWS_MACHINE_POLICY_KEY);
	if (output === null) return { state: "none" };
	const raw = parseRegQueryOutput(output);
	const relevant = Object.keys(raw).filter((key) => !OTHER_POLICY_VALUES.has(key));
	if (relevant.length === 0) return { state: "none" };
	const parsed = parseMachinePolicy(raw);
	return parsed.ok
		? { state: "loaded", source: WINDOWS_MACHINE_POLICY_KEY, policy: parsed.policy }
		: { state: "refused", source: WINDOWS_MACHINE_POLICY_KEY, reason: parsed.reason };
}

type PolicyStat = ReturnType<NonNullable<MachinePolicyDeps["stat"]>>;

/**
 * Why the file is not an administrator's (null when it is): a file or directory
 * another account could have written is not a machine policy.
 */
function unsafeOwnership(
	path: string,
	file: PolicyStat,
	stat: (path: string) => PolicyStat,
	owner: number,
): string | null {
	const ownerName = owner === 0 ? "root" : `uid ${owner}`;
	const writableByOthers = (entry: PolicyStat) => entry.uid !== owner || (entry.mode & 0o022) !== 0;
	if (writableByOthers(file)) {
		return `must be owned by ${ownerName} and not writable by group or others`;
	}
	try {
		if (writableByOthers(stat(dirname(path)))) {
			return `${dirname(path)} must be owned by ${ownerName} and not writable by others`;
		}
	} catch {
		return "its directory cannot be checked";
	}
	return null;
}

function readLinuxPolicy(deps: MachinePolicyDeps): MachinePolicyRead {
	const path = deps.path ?? LINUX_MACHINE_POLICY_PATH;
	const stat = deps.stat ?? ((target: string) => statSync(target));
	const owner = deps.trustedOwnerUid ?? 0;
	let file: PolicyStat;
	try {
		file = stat(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return { state: "none" };
		return { state: "refused", source: path, reason: "the file cannot be read" };
	}
	const refuse = (reason: string): MachinePolicyRead => ({
		state: "refused",
		source: path,
		reason,
	});
	if (!file.isFile()) return refuse("not a regular file");
	if (file.size > MAX_POLICY_BYTES) return refuse("larger than 64 KiB");
	const unsafe = unsafeOwnership(path, file, stat, owner);
	if (unsafe) return refuse(unsafe);
	let document: unknown;
	try {
		document = JSON.parse((deps.readFile ?? ((target) => readFileSync(target, "utf8")))(path));
	} catch {
		return refuse("not valid JSON");
	}
	if (!document || typeof document !== "object" || Array.isArray(document)) {
		return refuse("not a JSON object");
	}
	const parsed = parseMachinePolicy(document as Record<string, unknown>);
	return parsed.ok
		? { state: "loaded", source: path, policy: parsed.policy }
		: refuse(parsed.reason);
}

let cached: { at: number; result: MachinePolicyRead } | null = null;

/** Forget the per-process copy (tests, and after `aidr setup` changed nothing it can see). */
export function clearMachinePolicyCache(): void {
	cached = null;
}

/**
 * Read this computer's machine policy. Never throws. The default (no deps)
 * read is kept for a minute per process, so a hook does not start reg.exe for
 * every configuration load.
 */
export function readMachinePolicy(deps?: MachinePolicyDeps): MachinePolicyRead {
	const useCache = deps === undefined;
	if (useCache && cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.result;
	const platform = deps?.platform ?? process.platform;
	let result: MachinePolicyRead;
	try {
		result =
			platform === "win32"
				? readWindowsPolicy(deps ?? {})
				: platform === "linux" || platform === "darwin"
					? readLinuxPolicy(deps ?? {})
					: { state: "none" };
	} catch {
		result = { state: "none" };
	}
	if (useCache) cached = { at: Date.now(), result };
	return result;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
	!!value && typeof value === "object" && !Array.isArray(value);

function section(data: Record<string, unknown>, name: string): Record<string, unknown> {
	return isObject(data[name]) ? { ...(data[name] as Record<string, unknown>) } : {};
}

/**
 * The raw config document with the machine policy laid over it (the policy
 * wins). Applied before schema validation, so the result is validated and the
 * control-plane endpoint must still be HTTPS.
 */
export function overlayMachinePolicy(
	data: Record<string, unknown>,
	policy: MachinePolicy,
): Record<string, unknown> {
	const next: Record<string, unknown> = { ...data };
	const controlPlane = section(next, "control_plane");
	if (policy.control_plane_url) controlPlane.endpoint = policy.control_plane_url;
	if (policy.offline_policy) controlPlane.offline_policy = policy.offline_policy;
	next.control_plane = controlPlane;

	if (policy.licensing_public_keys_pem) {
		next.licensing = {
			...section(next, "licensing"),
			public_keys_pem: [...policy.licensing_public_keys_pem],
		};
	}

	const network = section(next, "network");
	for (const key of ["ca_file", "use_os_trust_store", "https_proxy", "no_proxy"] as const) {
		if (policy[key] !== undefined) network[key] = policy[key];
	}
	next.network = network;

	const organization = section(next, "organization");
	for (const key of ["support_contact_url", "privacy_notice_url"] as const) {
		if (policy[key] !== undefined) organization[key] = policy[key];
	}
	next.organization = organization;

	if (policy.approvals_mode) {
		next.operator_approvals = {
			...section(next, "operator_approvals"),
			approvals_mode: policy.approvals_mode,
		};
	}

	// The fleet key enrolls a managed install that has no credential of its
	// own yet; it never replaces one, and local mode never reads it.
	const auth = section(next, "auth");
	const hasCredential = ["api_key", "api_key_ref", "enrollment_token", "enrollment_token_ref"].some(
		(key) => auth[key] !== undefined && auth[key] !== "",
	);
	if (policy.enrollment_key && next.mode === "managed" && !hasCredential) {
		next.auth = { ...auth, enrollment_token: policy.enrollment_key };
	}
	return next;
}
