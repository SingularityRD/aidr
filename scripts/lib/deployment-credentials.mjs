import { createHash } from "node:crypto";

// Fingerprints of the public credentials in the pinned Supabase Docker
// .env.example. Keep the guard in the portable kit; it must not depend on a
// source checkout or print a configured credential to explain a failure.
const vendorCredentialHashes = new Set([
	"53d3eb3d9500cdcdbbe39c030eb2959438bcc459d5de9380db2a3c85b5de5360",
	"1453cea2dc3799e9026e42b3e465e455256d5a149582e4c5b92d4c8d604731a2",
	"fc6a5e9ae75f9160dacd38844789d90a04c85c29c3c95c8c8c6e9da3f58c2365",
	"2359b281e1fa0ec38bb10316e2b0e3a7b960fe5d271ee75a4735ff1b313a222c",
	"80d1c192cf2210c5282179cc9989f4be2e9b24605daabe1bc7da10fd9ed842ed",
	"52f004438faf780274c9c95f79d1cf39d2355fbcf035899fc0242b1437f30df3",
	"9fa03fc1cd78ff85aec9f901f9383bf5c3dfbee93c7da7d5b9f526898a9d7a84",
	"0a53c0992edae8ceb04c7a32ee47b49ad0b229c17b073e8c24683111c843d45e",
	"627507f04b33fb434001b83fa1d73b39c7d9a88f2b9a3aec652527a7f0ea571a",
	"4feb5df17e31da658971467f079e9dfa946712c0281386fe631830bdfa1e7332",
	"272b1f97285638be545049c9d56ed0c07b252faf0d47867068482d2b2374a2a9",
	"7f59edafa4d502ca0156b8fddf28394634d77b1843838b5783a7c9c95fcbd32f",
	"390d4757bf1b75e305984c99cdedfb1e7c201a2d143a53cfbc35075fa5f9a56f",
	"5bfa6b2a8e5415178fdcb40120fe401f54f9362f7617428b3379be332d676444",
	"be0d83bb286ee7fa1e5494317e25bd88ad915bbd8c92b5efbada63731d858201",
]);
const apiKeys = ["ANON_KEY", "SERVICE_ROLE_KEY"];
const credentialNames = [...apiKeys, "POSTGRES_PASSWORD", "JWT_SECRET", "DASHBOARD_PASSWORD", "SECRET_KEY_BASE", "REALTIME_DB_ENC_KEY", "VAULT_ENC_KEY", "PG_META_CRYPTO_KEY", "LOGFLARE_PUBLIC_ACCESS_TOKEN", "LOGFLARE_PRIVATE_ACCESS_TOKEN", "S3_PROTOCOL_ACCESS_KEY_SECRET", "MINIO_ROOT_PASSWORD", "SMTP_PASS", "OPENAI_API_KEY"];

export function deploymentCredentialFailures(env) {
	return credentialNames.filter((name) => {
		const raw = typeof env[name] === "string" ? env[name].trim() : "";
		const quoted = raw.match(/^("|')(.*)\1$/);
		const value = quoted ? quoted[2] : raw;
		if (/^REPLACE_/i.test(value) || (apiKeys.includes(name) && !value)) return true;
		if (!value) return false;
		if (vendorCredentialHashes.has(createHash("sha256").update(value).digest("hex"))) return true;
		if (apiKeys.includes(name) && value.split(".").length === 3) {
			try {
				// A different JWT serialization does not make a vendor demo key
				// private. Real project JWTs and opaque cloud keys remain supported.
				return JSON.parse(Buffer.from(value.split(".")[1], "base64url").toString("utf8")).iss === "supabase-demo";
			} catch { /* this guard is not the provider's authentication verifier */ }
		}
		return false;
	});
}
