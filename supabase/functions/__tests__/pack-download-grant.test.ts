import { describe, expect, it } from "vitest";
import {
	packKeyFingerprint,
	publicPackDownloadOrigin,
	readPackDownloadGrant,
	signPackDownloadGrant,
	validPackDownloadGrantSecret,
	verifyPackKeyFingerprint,
} from "../_shared/pack-download-grant.ts";

const SECRET = "pack-download-grant-secret-32-bytes-minimum";
const KEY_HASH = "a".repeat(64);
const grant = {
	key_id: "33333333-3333-4333-8333-333333333333",
	key_fingerprint: "",
	tenant_id: "11111111-1111-4111-8111-111111111111",
	pack_id: "intel",
	version: "1.0.0",
	expires_at: 1_800_000_600,
};

describe("revocable pack download grants", () => {
	it("signs a scoped grant without placing the API-key hash in the URL token", async () => {
		const fingerprint = await packKeyFingerprint(KEY_HASH, SECRET);
		const token = await signPackDownloadGrant({ ...grant, key_fingerprint: fingerprint }, SECRET);
		const decoded = JSON.parse(Buffer.from(token.split(".")[0]!, "base64url").toString("utf8"));
		expect(decoded).toMatchObject({ key_id: grant.key_id, tenant_id: grant.tenant_id, pack_id: "intel", version: "1.0.0" });
		expect(token).not.toContain(KEY_HASH);
		expect(await verifyPackKeyFingerprint(KEY_HASH, fingerprint, SECRET)).toBe(true);
		expect(await verifyPackKeyFingerprint("b".repeat(64), fingerprint, SECRET)).toBe(false);
		expect(await readPackDownloadGrant(token, SECRET, 1_800_000_000)).toMatchObject({ pack_id: "intel", version: "1.0.0" });
	});

	it("rejects tampered, expired, excessive-lifetime, and malformed grants", async () => {
		const fingerprint = await packKeyFingerprint(KEY_HASH, SECRET);
		const token = await signPackDownloadGrant({ ...grant, key_fingerprint: fingerprint }, SECRET);
		expect(await readPackDownloadGrant(`${token.slice(0, -1)}x`, SECRET, 1_800_000_000)).toBeNull();
		expect(await readPackDownloadGrant(token, SECRET, grant.expires_at)).toBeNull();
		const tooLong = await signPackDownloadGrant({ ...grant, key_fingerprint: fingerprint, expires_at: 1_800_004_000 }, SECRET);
		expect(await readPackDownloadGrant(tooLong, SECRET, 1_800_000_000)).toBeNull();
		expect(await readPackDownloadGrant("not-a-grant", SECRET)).toBeNull();
		expect(await readPackDownloadGrant(token, "wrong-secret-but-over-32-bytes-long", 1_800_000_000)).toBeNull();
	});

	it("requires an independently configured strong signing secret", async () => {
		expect(validPackDownloadGrantSecret(SECRET)).toBe(true);
		expect(validPackDownloadGrantSecret("short")).toBe(false);
		await expect(packKeyFingerprint(KEY_HASH, "short")).rejects.toThrow("invalid_pack_download_grant_secret");
	});

	it("uses a declared public origin instead of leaking an internal service URL", () => {
		expect(publicPackDownloadOrigin("http://api-gw:8000", "https://api.customer.example")).toBe("https://api.customer.example");
		expect(publicPackDownloadOrigin("https://project.supabase.co", undefined)).toBe("https://project.supabase.co");
		expect(publicPackDownloadOrigin("http://api-gw:8000", undefined)).toBeNull();
		expect(publicPackDownloadOrigin("http://api-gw:8000", "http://localhost:59100", true)).toBe("http://localhost:59100");
		for (const invalid of ["http://api.customer.example", "https://user:pass@api.customer.example", "https://api.customer.example/other", "https://api.customer.example/?token=x", "https://api.customer.example/#fragment"]) {
			expect(publicPackDownloadOrigin("http://api-gw:8000", invalid)).toBeNull();
		}
	});
});
