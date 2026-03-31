import { createPublicKey, verify } from "node:crypto";

export function verifyEd25519Signature(params: {
	publicKeyPem: string;
	message: Uint8Array;
	signatureBase64: string;
}): boolean {
	try {
		const key = createPublicKey(params.publicKeyPem);
		const sig = Buffer.from(params.signatureBase64, "base64");
		return verify(null, Buffer.from(params.message), key, sig);
	} catch {
		return false;
	}
}
