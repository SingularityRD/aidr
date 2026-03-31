import { resolvePath } from "../config.js";
import { getFileContent } from "../file-utils.js";

const DEFAULT_KEYRING_PATH = "~/.singularity-aidr/intel/keys.json";
const DEFAULT_ENTITLEMENT_PATH = "~/.singularity-aidr/entitlement.json";

function normalizeKeyMap(obj: unknown): Map<string, Uint8Array> {
	const map = new Map<string, Uint8Array>();
	if (!obj || typeof obj !== "object") return map;

	const root = obj as Record<string, unknown>;
	const record =
		("intel_keys" in root ? root.intel_keys : undefined) ??
		("keys" in root ? root.keys : undefined) ??
		obj;

	if (!record || typeof record !== "object") return map;

	for (const [keyId, b64] of Object.entries(record as Record<string, unknown>)) {
		if (typeof keyId !== "string" || typeof b64 !== "string") continue;
		const id = keyId.trim();
		const raw = b64.trim();
		if (!id || !raw) continue;
		let bytes: Uint8Array;
		try {
			bytes = Buffer.from(raw, "base64");
		} catch {
			continue;
		}
		if (bytes.length !== 32) continue; // aes-256-gcm key
		map.set(id, bytes);
	}
	return map;
}

async function readJsonFile(path: string): Promise<unknown | null> {
	try {
		const raw = await getFileContent(path, "utf-8");
		return JSON.parse(raw) as unknown;
	} catch {
		return null;
	}
}

export async function loadIntelKeyring(
	params: { keyringPath?: string; entitlementPath?: string } = {},
): Promise<Map<string, Uint8Array>> {
	// Entitlement file has priority (control plane can refresh this).
	const entitlementPath = resolvePath(params.entitlementPath ?? DEFAULT_ENTITLEMENT_PATH);
	const keyringPath = resolvePath(params.keyringPath ?? DEFAULT_KEYRING_PATH);

	const entitlement = await readJsonFile(entitlementPath);
	const fromEnt = normalizeKeyMap(entitlement);
	if (fromEnt.size > 0) return fromEnt;

	const keyring = await readJsonFile(keyringPath);
	return normalizeKeyMap(keyring);
}
