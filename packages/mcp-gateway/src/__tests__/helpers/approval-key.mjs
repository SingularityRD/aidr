import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The operator approval key for tests. Gateways are configured with the public
// half (`approvalKeys`); approvals are signed with the private half, exactly as
// aidr-mcp-approve does with the operator's passphrase-protected key file.
const pair = generateKeyPairSync("ed25519");
const TEST_APPROVAL_KEY_ID = "operator-approval";
export const TEST_APPROVAL_KEY = { keyId: TEST_APPROVAL_KEY_ID, privateKey: pair.privateKey };
export const TEST_APPROVAL_KEYS = {
	[TEST_APPROVAL_KEY_ID]: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
};

const created = [];
process.once("exit", () => {
	for (const directory of created) rmSync(directory, { recursive: true, force: true });
});

/** A private (0700) absolute state directory, removed when the test process exits. */
export function testStateDir() {
	const directory = mkdtempSync(join(tmpdir(), "aidr-mcp-gateway-state-"));
	created.push(directory);
	return directory;
}
