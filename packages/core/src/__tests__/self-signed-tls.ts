import { createPublicKey, generateKeyPairSync, sign } from "node:crypto";

/**
 * Mints a throwaway self-signed loopback TLS identity in memory (ECDSA P-256, SAN
 * IP:127.0.0.1) with node:crypto only: no private key lives in the repository, no
 * openssl binary is needed, and nothing outside the test process is read.
 */
export function selfSignedLoopbackTls(): { key: string; cert: string } {
	const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
	const tlv = (tag: number, content: Buffer): Buffer => {
		const n = content.length;
		const header =
			n < 0x80
				? Buffer.from([tag, n])
				: n < 0x100
					? Buffer.from([tag, 0x81, n])
					: Buffer.from([tag, 0x82, n >> 8, n & 0xff]);
		return Buffer.concat([header, content]);
	};
	const seq = (...items: Buffer[]) => tlv(0x30, Buffer.concat(items));
	const oid = (dotted: string): Buffer => {
		const [a = 0, b = 0, ...rest] = dotted.split(".").map(Number);
		const bytes = [40 * a + b];
		for (const arc of rest) {
			const chunk = [arc & 0x7f];
			for (let value = arc >> 7; value > 0; value >>= 7) chunk.unshift((value & 0x7f) | 0x80);
			bytes.push(...chunk);
		}
		return tlv(0x06, Buffer.from(bytes));
	};
	const utcTime = (ms: number) => {
		const digits = new Date(ms).toISOString().slice(2, 19).replace(/[-:T]/g, "");
		return tlv(0x17, Buffer.from(`${digits}Z`));
	};
	const name = seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0c, Buffer.from("127.0.0.1")))));
	const ecdsaWithSha256 = seq(oid("1.2.840.10045.4.3.2"));
	const now = Date.now();
	const subjectAltName = seq(
		oid("2.5.29.17"),
		tlv(0x04, seq(tlv(0x87, Buffer.from([127, 0, 0, 1])))),
	);
	const tbs = seq(
		tlv(0xa0, tlv(0x02, Buffer.from([2]))),
		tlv(0x02, Buffer.from([1])),
		ecdsaWithSha256,
		name,
		seq(utcTime(now - 60_000), utcTime(now + 24 * 60 * 60_000)),
		name,
		createPublicKey(privateKey).export({ type: "spki", format: "der" }),
		tlv(0xa3, seq(subjectAltName)),
	);
	const signature = sign("sha256", tbs, privateKey);
	const der = seq(tbs, ecdsaWithSha256, tlv(0x03, Buffer.concat([Buffer.from([0]), signature])));
	const lines = der.toString("base64").match(/.{1,64}/g) ?? [];
	return {
		key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		cert: `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`,
	};
}
